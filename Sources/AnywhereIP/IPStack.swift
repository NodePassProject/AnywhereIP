//
//  IPStack.swift
//  AnywhereIP
//
//  Created by NodePassProject on 9/20/26.
//

import Foundation
import Synchronization

public final class IPStack: Sendable {
    public struct Configuration: Sendable {
        public var maximumConnections: Int
        public var pendingSendBytes: Int
        public var parallelism: Int

        public init(maximumConnections: Int = 1024, pendingSendBytes: Int = 64 * 1024, parallelism: Int = 4) {
            precondition(maximumConnections > 0 && pendingSendBytes > 0 && parallelism > 0)
            self.maximumConnections = maximumConnections
            self.pendingSendBytes = pendingSendBytes
            self.parallelism = parallelism
        }
    }

    private final class Shard: Sendable {
        let entries = Mutex<[ConnectionKey: Stream]>([:])
    }
    
    private struct Admission {
        var closed = false
        var count = 0
        var generation: UInt64 = 0
    }
    
    private struct TimerDriver {
        var running = false
        var continuation: AsyncStream<Void>.Continuation?
    }
    
    public static let tickInterval: Duration = .milliseconds(100)
    
    private let admission = Mutex(Admission())
    private let shards: [Shard]
    private let configuration: Configuration
    private let outputHandler: @Sendable ([OutboundPacket]) -> Void
    private let acceptHandler: @Sendable (PendingConnection) -> Void
    private let synFilter: @Sendable (IPEndpoint, IPEndpoint) -> AcceptVerdict
    private let strayFilter: @Sendable (IPEndpoint, IPEndpoint) -> Bool
    private let clockOrigin = ContinuousClock.now
    private let initialSequence = Atomic<UInt32>(UInt32.random(in: .min ... .max))
    private let timerDriver = Mutex(TimerDriver())
    
    public var isIdle: Bool { admission.withLock { $0.count == 0 } }
    public var connectionCount: Int { admission.withLock { $0.count } }
    public var activeConnectionCount: Int { connections().reduce(0) { $0 + ($1.isTimeWait ? 0 : 1) } }
    
    private var ticks: UInt32 {
        let duration = clockOrigin.duration(to: .now)
        guard duration > .zero else { return 0 }
        let parts = duration.components
        return UInt32(truncatingIfNeeded: parts.seconds &* 5 &+ parts.attoseconds / 200_000_000_000_000_000)
    }

    public init(
        configuration: Configuration = Configuration(),
        output: @escaping @Sendable ([OutboundPacket]) -> Void,
        accept: @escaping @Sendable (PendingConnection) -> Void,
        synFilter: @escaping @Sendable (IPEndpoint, IPEndpoint) -> AcceptVerdict = { _, _ in .accept },
        strayFilter: @escaping @Sendable (IPEndpoint, IPEndpoint) -> Bool = { _, _ in true }
    ) {
        precondition(configuration.maximumConnections > 0 && configuration.pendingSendBytes > 0 && configuration.parallelism > 0)
        self.configuration = configuration
        outputHandler = output
        acceptHandler = accept
        self.synFilter = synFilter
        self.strayFilter = strayFilter
        shards = (0..<max(16, configuration.parallelism * 4)).map { _ in Shard() }
    }
    
    public func input(_ packet: Data) {
        guard let generation = liveGeneration() else { return }
        var decoder = PacketDecoder()
        decoder.decode(packet)
        guard isLive(generation) else { return }
        if !decoder.output.isEmpty { outputHandler(decoder.output) }
        if let tcp = decoder.tcp { deliver(tcp, generation: generation) }
    }
    
    @concurrent public func inputBatch(_ packets: [Data]) async {
        guard let generation = liveGeneration(), !packets.isEmpty else { return }
        var partitions = Array(repeating: [ConnectionKey: [InboundTCP]](), count: configuration.parallelism)
        var control: [OutboundPacket] = []
        for packet in packets {
            var decoder = PacketDecoder()
            decoder.decode(packet)
            control.append(contentsOf: decoder.output)
            if let tcp = decoder.tcp {
                let index = Int(tcp.key.fingerprint % UInt64(partitions.count))
                partitions[index][tcp.key, default: []].append(tcp)
            }
        }
        guard isLive(generation) else { return }
        if !control.isEmpty { outputHandler(control) }
        if partitions.count(where: { !$0.isEmpty }) <= 1 {
            for partition in partitions where !partition.isEmpty {
                deliverPartition(partition, generation: generation)
            }
            return
        }
        await withTaskGroup(of: Void.self) { group in
            for partition in partitions where !partition.isEmpty {
                group.addTask { self.deliverPartition(partition, generation: generation) }
            }
        }
    }

    private func deliverPartition(_ partition: [ConnectionKey: [InboundTCP]], generation: UInt64) {
        for (_, packets) in partition {
            guard !Task.isCancelled, isLive(generation) else { return }
            deliverBatch(packets, generation: generation)
        }
    }

    private func liveGeneration() -> UInt64? {
        admission.withLock { $0.closed ? nil : $0.generation }
    }
    
    private func isLive(_ generation: UInt64) -> Bool {
        admission.withLock { !$0.closed && $0.generation == generation }
    }
    
    private func shard(for key: ConnectionKey) -> Shard {
        shards[Int(key.fingerprint % UInt64(shards.count))]
    }

    private func deliver(_ packet: InboundTCP, generation: UInt64) {
        let shard = shard(for: packet.key)
        if let connection = shard.entries.withLock({ $0[packet.key] }) {
            if connection.generation == generation { connection.input(packet) }
            return
        }
        let header = packet.header
        if header.flags.contains(.rst) { return }
        if header.flags.contains(.ack) {
            guard strayFilter(packet.key.remote, packet.key.local), isLive(generation) else { return }
            reset(packet, sequenceNumber: header.acknowledgmentNumber)
            return
        }
        guard header.flags.contains(.syn) else { return }
        switch synFilter(packet.key.remote, packet.key.local) {
        case .accept:
            break
        case .drop:
            return
        case .reset:
            guard isLive(generation) else { return }
            reset(packet, sequenceNumber: 0)
            return
        }
        if connectionCount >= configuration.maximumConnections {
            let candidates = connections()
            if let timeWait = candidates.first(where: { $0.isTimeWait }) {
                _ = timeWait.reclaimIfClosing()
            } else {
                _ = candidates.first(where: { $0.reclaimIfClosing() })
            }
        }
        let connection: Stream? = shard.entries.withLock { entries in
            if let existing = entries[packet.key] { return existing }
            let reserved = admission.withLock { admission in
                guard !admission.closed, admission.generation == generation,
                      admission.count < configuration.maximumConnections else { return false }
                admission.count += 1
                return true
            }
            guard reserved else { return nil }
            let connection = Stream(
                packet: packet,
                initialSequenceNumber: initialSequence.wrappingAdd(64001, ordering: .relaxed).oldValue,
                ticks: ticks,
                generation: generation,
                pendingLimit: configuration.pendingSendBytes,
                output: { [weak self] packets in self?.outputHandler(packets) },
                ready: { [weak self] pending in
                    guard let self else { pending.reject(); return }
                    self.acceptHandler(pending)
                },
                removed: { [weak self] in self?.remove($0) }
            )
            entries[packet.key] = connection
            return connection
        }
        if connection != nil { timerDriver.withLock { $0.continuation }?.yield(()) }
        connection?.input(packet)
    }

    private func reset(_ packet: InboundTCP, sequenceNumber: UInt32) {
        let header = packet.header
        let context = Context(initialSequenceNumber: 0, ticks: ticks)
        let length = UInt32(packet.payload.count) + (header.flags.contains(.syn) || header.flags.contains(.fin) ? 1 : 0)
        context.sendReset(
            from: packet.key.local,
            to: packet.key.remote,
            sequenceNumber: sequenceNumber,
            acknowledgmentNumber: header.sequenceNumber &+ length
        )
        let packets = context.effects.compactMap { effect -> OutboundPacket? in
            if case .packet(let packet) = effect { packet } else { nil }
        }
        outputHandler(packets)
    }

    private func deliverBatch(_ packets: [InboundTCP], generation: UInt64) {
        guard let first = packets.first else { return }
        var position = 0
        while position < packets.count {
            guard isLive(generation) else { return }
            if let connection = shard(for: first.key).entries.withLock({ $0[first.key] }),
               connection.generation == generation {
                let end = min(position + 32, packets.count)
                let processed = connection.inputBatch(packets[position..<end])
                if processed == 0 { remove(connection) }
                position += processed
            } else {
                deliver(packets[position], generation: generation)
                position += 1
            }
        }
    }

    private func remove(_ connection: Stream) {
        let removed = shard(for: connection.key).entries.withLock { entries in
            guard entries[connection.key] === connection else { return false }
            entries.removeValue(forKey: connection.key)
            return true
        }
        if removed { admission.withLock { $0.count -= 1 } }
    }

    public func connections() -> [Stream] {
        shards.flatMap { $0.entries.withLock { Array($0.values) } }
    }
    
    @discardableResult public func tick() -> Int {
        let now = ticks
        var active = 0
        for connection in connections() {
            if connection.advance(to: now) { active += 1 }
        }
        return active
    }
    
    @concurrent public func runTimer(_ onTick: @escaping @Sendable (Int) -> Void = { _ in }) async {
        let activity = timerDriver.withLock { driver -> AsyncStream<Void>? in
            guard !driver.running else { return nil }
            let (stream, continuation) = AsyncStream<Void>.makeStream(bufferingPolicy: .bufferingNewest(1))
            driver.running = true
            driver.continuation = continuation
            return stream
        }
        guard let activity else { return }
        defer {
            let continuation = timerDriver.withLock { driver in
                let continuation = driver.continuation
                driver.running = false
                driver.continuation = nil
                return continuation
            }
            continuation?.finish()
        }
        var events = activity.makeAsyncIterator()
        while !Task.isCancelled {
            guard liveGeneration() != nil else { return }
            if isIdle {
                onTick(0)
                guard await events.next() != nil else { return }
                continue
            }
            do { try await Task.sleep(for: Self.tickInterval, tolerance: .milliseconds(10)) }
            catch { return }
            guard liveGeneration() != nil else { return }
            onTick(tick())
        }
    }
    
    public func abortAllConnections() {
        let generation = admission.withLock { $0.generation &+= 1; return $0.generation }
        for connection in connections() {
            let age = generation &- connection.generation
            if age > 0 && age < 0x8000_0000_0000_0000 { connection.cancel() }
        }
    }

    public func shutdown() {
        admission.withLock { $0.closed = true; $0.generation &+= 1 }
        timerDriver.withLock { $0.continuation }?.finish()
        for connection in connections() { connection.cancel() }
    }

    deinit {
        timerDriver.withLock { $0.continuation }?.finish()
        for shard in shards {
            let live = shard.entries.withLock { entries in
                let live = Array(entries.values)
                entries.removeAll()
                return live
            }
            for connection in live { connection.cancel() }
        }
    }
}
