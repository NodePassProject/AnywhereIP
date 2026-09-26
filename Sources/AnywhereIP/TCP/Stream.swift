//
//  Stream.swift
//  AnywhereIP
//
//  Created by NodePassProject on 9/20/26.
//

import Foundation
import Synchronization

public final class Stream: Sendable {
    private enum Admission { case handshake, pending, accepted, rejected }
    
    private enum Publication: Sendable {
        case output(OutboundPacket)
        case ready
        case remove
        case wake(AsyncStream<Void>.Continuation)
    }
    
    private struct State {
        let core: ControlBlock
        var started = false
        var admission = Admission.handshake
        var admissionTick: UInt32 = 0
        var input: [Data] = []
        var inputOffset = 0
        var deferredAcknowledgment: OutboundPacket?
        var deliveredBytes = 0
        var receivedFIN = false
        var failure: ConnectionError?
        var ended = false
        var closing = false
        var sendingFinished = false
        var pending: [Data] = []
        var pendingOffset = 0
        var pendingBytes = 0
        var reading = false
        var writing = false
        var waitingForACK = false
        var readWaiter: AsyncStream<Void>.Continuation?
        var writeWaiter: AsyncStream<Void>.Continuation?
        var ackWaiter: AsyncStream<Void>.Continuation?
        var publications: [Publication] = []
        var draining = false

        init(packet: InboundTCP, initialSequenceNumber: UInt32, ticks: UInt32) {
            let context = Context(initialSequenceNumber: initialSequenceNumber, ticks: ticks)
            core = packet.options.withUnsafeBytes {
                ControlBlock(
                    stack: context,
                    key: packet.key,
                    initialSequenceNumber: packet.header.sequenceNumber,
                    peerWindow: packet.header.window,
                    options: $0
                )
            }
        }

        var deadline: UInt32? {
            var deadline = core.nextDeadline
            if case .pending = admission, core.state != .timeWait, core.state != .closed {
                let expiry = TickClock.align(admissionTick, after: Constants.synReceivedTimeout + 1)
                if deadline.map({ Sequence.lessThan(expiry, $0) }) ?? true { deadline = expiry }
            }
            guard let deadline else { return nil }
            let now = core.stack.ticks
            return Sequence.lessThan(now, deadline) ? deadline : now &+ 1
        }

        mutating func wakeReaders() {
            if let readWaiter { publications.append(.wake(readWaiter)) }
            readWaiter = nil
        }

        mutating func wakeWriters() {
            if let writeWaiter { publications.append(.wake(writeWaiter)) }
            writeWaiter = nil
            if let ackWaiter { publications.append(.wake(ackWaiter)) }
            ackWaiter = nil
        }

        mutating func harvest() {
            guard !core.stack.effects.isEmpty else { return }
            var effects = core.stack.effects
            core.stack.effects = []
            defer {
                effects.removeAll(keepingCapacity: true)
                if core.stack.effects.isEmpty { core.stack.effects = effects }
            }
            for effect in effects {
                switch effect {
                case .packet(let packet):
                    let flags = packet.data[packet.data.startIndex + (packet.isIPv6 ? 40 : 20) + 13]
                    if case .pending = admission, flags & TCPHeader.Flags.rst.rawValue == 0 {
                        deferredAcknowledgment = packet
                    } else {
                        publications.append(.output(packet))
                    }
                case .received(let bytes):
                    if !ended {
                        if input.count > inputOffset, input[input.count - 1].count + bytes.count <= 16 * 1024 {
                            input[input.count - 1].append(bytes)
                        } else {
                            input.append(bytes)
                        }
                        wakeReaders()
                    }
                case .acknowledged: wakeWriters()
                case .ready:
                    if case .handshake = admission {
                        admission = .pending
                        admissionTick = core.stack.ticks
                        publications.append(.ready)
                    }
                case .fin: receivedFIN = true; wakeReaders()
                case .failed(let error): finish(error)
                case .ended: finish(nil)
                case .removed: publications.append(.remove)
                case .timeWait: break
                }
            }
        }

        mutating func finish(_ error: ConnectionError?) {
            if !ended { failure = error }
            ended = true
            if error != nil {
                admission = .rejected
                input.removeAll(); inputOffset = 0
            }
            deferredAcknowledgment = nil
            pending.removeAll(); pendingOffset = 0; pendingBytes = 0
            wakeReaders(); wakeWriters()
        }

        mutating func pump() {
            guard !ended else { return }
            while let first = pending.first {
                let written = first.withUnsafeBytes { bytes in
                    core.write(UnsafeRawBufferPointer(rebasing: bytes[pendingOffset...]))
                }
                guard written > 0 else { break }
                pendingOffset += written
                pendingBytes -= written
                if pendingOffset == first.count {
                    pending.removeFirst()
                    pendingOffset = 0
                }
            }
            if sendingFinished && pendingBytes == 0 { core.shutdownSend() }
            if closing && pendingBytes == 0 {
                core.close()
                finish(nil)
            }
            core.output()
            harvest()
            wakeWriters()
        }
    }
    
    private enum WriteStep: Sendable {
        case written(Int), failure(ConnectionError), wait(AsyncStream<Void>)
    }
    
    private enum ReadStep: Sendable {
        case bytes(Data), end, failure(ConnectionError), wait(AsyncStream<Void>)
    }
    
    public let source: IPEndpoint
    public let destination: IPEndpoint
    let key: ConnectionKey
    let generation: UInt64
    private let state: Mutex<State>
    private let clock: TickClock
    private let scheduled = Atomic<UInt32>(0)
    private let lingering = Atomic<Bool>(false)
    private let pendingLimit: Int
    private let output: @Sendable ([OutboundPacket]) -> Void
    private let ready: @Sendable (PendingConnection) -> Void
    private let removed: @Sendable (Stream) -> Void
    private let schedule: @Sendable (UInt32) -> Void
    
    public var isAttached: Bool { state.withLock { !$0.ended && !$0.closing } }
    public var sendBufferSpace: Int { state.withLock { $0.core.sendBufferSpace } }
    var isTimeWait: Bool { state.withLock { $0.core.state == .timeWait } }
    var isLingering: Bool { lingering.load(ordering: .relaxed) }
    var scheduledDeadline: UInt32 { scheduled.load(ordering: .sequentiallyConsistent) }

    init(
        packet: InboundTCP,
        initialSequenceNumber: UInt32,
        clock: TickClock,
        generation: UInt64,
        pendingLimit: Int,
        output: @escaping @Sendable ([OutboundPacket]) -> Void,
        ready: @escaping @Sendable (PendingConnection) -> Void,
        removed: @escaping @Sendable (Stream) -> Void,
        schedule: @escaping @Sendable (UInt32) -> Void
    ) {
        key = packet.key
        self.generation = generation
        source = key.remote
        destination = key.local
        self.pendingLimit = pendingLimit
        self.output = output
        self.ready = ready
        self.removed = removed
        self.schedule = schedule
        self.clock = clock
        state = Mutex(State(packet: packet, initialSequenceNumber: initialSequenceNumber, ticks: clock.now))
    }

    private func update<T: Sendable>(_ body: (inout State) -> T) -> T {
        let (result, drain, previous, deadline) = state.withLock { state in
            state.core.stack.advance(to: clock.now)
            let result = body(&state)
            state.harvest()
            let drain = !state.draining && !state.publications.isEmpty
            if drain { state.draining = true }
            let deadline = state.deadline.map { $0 == 0 ? 1 : $0 } ?? 0
            let previous = scheduled.exchange(deadline, ordering: .sequentiallyConsistent)
            lingering.store(state.core.state == .timeWait || state.core.state == .closed, ordering: .relaxed)
            return (result, drain, previous, deadline)
        }
        if drain { drainPublications() }
        if deadline != 0, previous == 0 || Sequence.lessThan(deadline, previous) { schedule(deadline) }
        return result
    }
    
    private func drainPublications() {
        var batch: [Publication] = []
        while true {
            state.withLock { state in
                swap(&batch, &state.publications)
                if batch.isEmpty { state.draining = false }
            }
            if batch.isEmpty { return }
            var packets: [OutboundPacket] = []
            for publication in batch {
                if case .output(let packet) = publication { packets.append(packet); continue }
                if !packets.isEmpty { output(packets); packets.removeAll(keepingCapacity: true) }
                switch publication {
                case .output: break
                case .ready: ready(PendingConnection(stream: self))
                case .remove: removed(self)
                case .wake(let continuation): continuation.finish()
                }
            }
            if !packets.isEmpty { output(packets) }
            batch.removeAll(keepingCapacity: true)
        }
    }

    func input(_ packet: InboundTCP) {
        _ = inputBatch([packet][...])
    }

    func inputBatch(_ packets: ArraySlice<InboundTCP>) -> Int {
        update { state in
            let core = state.core
            core.stack.batching = true
            var processed = 0
            for packet in packets {
                guard core.state != .closed else { break }
                processed += 1
                if !state.started {
                    state.started = true
                    core.sendSynAck()
                    if packet.header.flags.contains(.syn) { continue }
                }
                if core.state == .timeWait {
                    core.timeWaitInput(header: packet.header, payloadCount: packet.payload.count)
                } else {
                    packet.options.withUnsafeBytes { options in
                        core.stack.withPayload(packet.payload) { payload in
                            core.input(header: packet.header, options: options, payload: payload)
                        }
                    }
                }
                state.harvest()
            }
            core.stack.batching = false
            state.harvest()
            state.pump()
            return processed
        }
    }

    func expire() -> UInt32 {
        update { state in
            let ticks = state.core.stack.ticks
            guard state.core.state != .closed else { return }
            if state.core.state == .timeWait {
                if ticks &- state.core.tmr > Constants.timeWaitTimeout {
                    state.core.state = .closed
                    state.publications.append(.remove)
                    state.finish(nil)
                }
            } else if case .pending = state.admission,
                      ticks &- state.admissionTick > Constants.synReceivedTimeout {
                state.core.terminate(sendingReset: true, error: .aborted)
            } else {
                state.core.slowTick(ticks: ticks)
                state.harvest()
                state.pump()
            }
        }
        return scheduledDeadline
    }

    func resolve(_ verdict: AcceptVerdict) -> Bool {
        update { state in
            guard case .pending = state.admission, !state.ended else { return false }
            switch verdict {
            case .accept:
                state.admission = .accepted
                if let packet = state.deferredAcknowledgment { state.publications.append(.output(packet)) }
                state.deferredAcknowledgment = nil
                state.wakeReaders()
            case .drop, .reset:
                state.admission = .rejected
                state.core.terminate(sendingReset: verdict == .reset, error: .aborted)
                state.finish(.aborted)
            }
            return true
        }
    }

    func reclaimIfClosing() -> Bool {
        update { state in
            switch state.core.state {
            case .timeWait, .lastAck, .closing:
                state.core.terminate(sendingReset: false, error: .aborted)
                state.finish(.aborted)
                return true
            default: return false
            }
        }
    }
    
    @discardableResult public func enqueue(_ data: Data) -> Bool {
        guard !data.isEmpty else { return true }
        return update { state in
            guard !state.ended, !state.closing, !state.sendingFinished, !state.writing,
                  case .accepted = state.admission,
                  data.count <= pendingLimit - state.pendingBytes else { return false }
            state.pending.append(data)
            state.pendingBytes += data.count
            state.pump()
            return true
        }
    }

    public func send(_ data: Data) async throws {
        try Task.checkCancellation()
        let claim: ConnectionError? = update { state in
            if state.ended || state.closing || state.sendingFinished { return state.failure ?? .closed }
            if state.writing { return .concurrentOperation }
            state.writing = true
            return nil
        }
        if let claim { throw claim }
        defer { update { $0.writing = false; $0.writeWaiter = nil } }
        var offset = 0
        while offset < data.count {
            try Task.checkCancellation()
            let step: WriteStep = update { state in
                if state.ended || state.closing || state.sendingFinished { return .failure(state.failure ?? .closed) }
                let count = min(data.count - offset, pendingLimit - state.pendingBytes)
                if count > 0 {
                    let start = data.startIndex + offset
                    state.pending.append(data[start..<(start + count)])
                    state.pendingBytes += count
                    state.pump()
                    return .written(count)
                }
                let (stream, continuation) = AsyncStream<Void>.makeStream()
                state.writeWaiter = continuation
                return .wait(stream)
            }
            switch step {
            case .written(let count): offset += count
            case .failure(let error): throw error
            case .wait(let signal): for await _ in signal { break }
            }
        }
    }

    public func receive() async throws -> Data? {
        try Task.checkCancellation()
        let claimed = update { state in
            guard !state.reading else { return false }
            state.reading = true
            return true
        }
        guard claimed else { throw ConnectionError.concurrentOperation }
        defer { update { $0.reading = false; $0.readWaiter = nil } }
        while true {
            try Task.checkCancellation()
            let step: ReadStep = update { state in
                if state.closing { return .end }
                if case .accepted = state.admission, state.inputOffset < state.input.count {
                    let data = state.input[state.inputOffset]
                    state.inputOffset += 1
                    state.deliveredBytes += data.count
                    if state.inputOffset == state.input.count {
                        state.input.removeAll(keepingCapacity: true); state.inputOffset = 0
                    } else if state.inputOffset >= 64 && state.inputOffset >= state.input.count / 2 {
                        state.input.removeFirst(state.inputOffset); state.inputOffset = 0
                    }
                    return .bytes(data)
                }
                if let error = state.failure { return .failure(error) }
                if state.ended || state.receivedFIN { return .end }
                let (stream, continuation) = AsyncStream<Void>.makeStream()
                state.readWaiter = continuation
                return .wait(stream)
            }
            switch step {
            case .bytes(let data): return data
            case .end: return nil
            case .failure(let error): throw error
            case .wait(let signal): for await _ in signal { break }
            }
        }
    }
    
    public func didConsume(_ byteCount: Int) {
        guard byteCount > 0 else { return }
        update { state in
            let consumed = min(byteCount, state.deliveredBytes)
            state.deliveredBytes -= consumed
            state.core.didConsume(consumed)
            state.core.output()
        }
    }
    
    public func finishSending() {
        update { state in
            state.sendingFinished = true
            state.pump()
        }
    }

    public func waitUntilAcknowledged() async throws {
        let claimed = update { state in
            guard !state.waitingForACK else { return false }
            state.waitingForACK = true
            return true
        }
        guard claimed else { throw ConnectionError.concurrentOperation }
        defer { update { $0.waitingForACK = false; $0.ackWaiter = nil } }
        while true {
            try Task.checkCancellation()
            let step: WriteStep = update { state in
                if let failure = state.failure { return .failure(failure) }
                if state.pendingBytes == 0 && state.core.sendQueueLength == 0 { return .written(0) }
                if state.ended { return .failure(.closed) }
                let (stream, continuation) = AsyncStream<Void>.makeStream()
                state.ackWaiter = continuation
                return .wait(stream)
            }
            switch step {
            case .written: return
            case .failure(let error): throw error
            case .wait(let signal): for await _ in signal { break }
            }
        }
    }
    
    public func close(discardingReceived: Bool = false) {
        update { state in
            guard !state.ended, !state.closing else { return }
            state.closing = true
            if discardingReceived {
                let unread = state.input[state.inputOffset...].reduce(state.deliveredBytes) { $0 + $1.count }
                state.deliveredBytes = 0
                state.core.didConsume(unread)
            }
            state.input.removeAll(); state.inputOffset = 0
            state.pump()
            state.wakeReaders(); state.wakeWriters()
        }
    }

    public func cancel() { terminate(sendingReset: true) }
    
    public func discard() { terminate(sendingReset: false) }

    private func terminate(sendingReset: Bool) {
        update { state in
            state.core.terminate(sendingReset: sendingReset, error: .aborted)
            state.finish(.aborted)
        }
    }
}
