//
//  IPStack.swift
//  AnywhereIP
//
//  Created by NodePassProject on 9/20/26.
//

enum TCPConstants {
    static let maximumSegmentSize: UInt16 = 1460
    static let window: UInt32 = 64 * 1460
    static let sendBufferSize: UInt32 = 64 * 1460
    static let sendQueueLimit = 256
    static let receiveScale: UInt8 = 7
    static let initialMSS: UInt16 = 536
    static let initialRTO: Int16 = 5
    static let maximumRetransmissions: UInt8 = 8
    static let synReceivedTimeout: UInt32 = 100
    static let finWait2Timeout: UInt32 = 100
    static let lastAckTimeout: UInt32 = 10
    static let timeWaitTimeout: UInt32 = 10
    static let windowUpdateThreshold: UInt32 = 11680
    static let resetWindow: UInt16 = 730
    static let hopLimit: UInt8 = 255
    static let mtu = 1500
    static let retransmissionBackoff: [Int16] = [1, 2, 3, 4, 5, 6, 7, 7, 7, 7, 7, 7, 7]
    static let persistBackoff: [UInt8] = [3, 6, 12, 24, 48, 96, 120]
}

struct ConnectionKey: Equatable {
    let remote: IPEndpoint
    let local: IPEndpoint
    let fingerprint: UInt64

    init(remote: IPEndpoint, local: IPEndpoint) {
        self.remote = remote
        self.local = local
        let ports = (UInt64(remote.port) << 16 | UInt64(local.port)) &* 0x9E37_79B9_7F4A_7C15
        switch (remote.address, local.address) {
        case (.v4(let remote), .v4(let local)):
            fingerprint = Self.mix(ports ^ (UInt64(remote.rawValue) << 32 | UInt64(local.rawValue)))
        case (.v6(let remote), .v6(let local)):
            fingerprint = Self.mix(Self.mix(Self.mix(Self.mix(ports ^ remote.high) ^ remote.low) ^ local.high) ^ local.low)
        default:
            fingerprint = Self.mix(ports)
        }
    }

    static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.fingerprint == rhs.fingerprint && lhs.remote == rhs.remote && lhs.local == rhs.local
    }

    private static func mix(_ value: UInt64) -> UInt64 {
        var z = value
        z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
        z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
        return z ^ (z >> 31)
    }
}

struct ConnectionTable: ~Copyable {
    private struct Slot {
        var connection: Unmanaged<IPStack.Connection>?
        var fingerprint: UInt64
    }

    private var slots: UnsafeMutablePointer<Slot>
    private var mask: Int
    private(set) var count = 0

    init(capacity: Int = 64) {
        slots = .allocate(capacity: capacity)
        slots.initialize(repeating: Slot(connection: nil, fingerprint: 0), count: capacity)
        mask = capacity - 1
    }

    deinit {
        for index in 0...mask {
            slots[index].connection?.release()
        }
        slots.deallocate()
    }

    func find(_ key: ConnectionKey) -> IPStack.Connection? {
        var index = Int(truncatingIfNeeded: key.fingerprint) & mask
        while let candidate = slots[index].connection {
            if slots[index].fingerprint == key.fingerprint, candidate._withUnsafeGuaranteedRef({ $0.key == key }) {
                return candidate.takeUnretainedValue()
            }
            index = (index + 1) & mask
        }
        return nil
    }

    mutating func insert(_ connection: IPStack.Connection) {
        if (count + 1) * 2 > mask + 1 {
            grow()
        }
        let fingerprint = connection.key.fingerprint
        var index = Int(truncatingIfNeeded: fingerprint) & mask
        while slots[index].connection != nil {
            index = (index + 1) & mask
        }
        slots[index] = Slot(connection: .passRetained(connection), fingerprint: fingerprint)
        count += 1
    }

    mutating func remove(_ connection: IPStack.Connection) -> Bool {
        let identity = Unmanaged.passUnretained(connection).toOpaque()
        var index = Int(truncatingIfNeeded: connection.key.fingerprint) & mask
        while let candidate = slots[index].connection {
            if candidate.toOpaque() == identity {
                candidate.release()
                count -= 1
                fill(hole: index)
                return true
            }
            index = (index + 1) & mask
        }
        return false
    }

    private mutating func fill(hole: Int) {
        var hole = hole
        var index = (hole + 1) & mask
        while slots[index].connection != nil {
            let home = Int(truncatingIfNeeded: slots[index].fingerprint) & mask
            if (index - home) & mask >= (index - hole) & mask {
                slots[hole] = slots[index]
                hole = index
            }
            index = (index + 1) & mask
        }
        slots[hole] = Slot(connection: nil, fingerprint: 0)
    }

    private mutating func grow() {
        let oldSlots = slots
        let oldCapacity = mask + 1
        let capacity = oldCapacity * 2
        slots = .allocate(capacity: capacity)
        slots.initialize(repeating: Slot(connection: nil, fingerprint: 0), count: capacity)
        mask = capacity - 1
        for old in 0..<oldCapacity where oldSlots[old].connection != nil {
            var index = Int(truncatingIfNeeded: oldSlots[old].fingerprint) & mask
            while slots[index].connection != nil {
                index = (index + 1) & mask
            }
            slots[index] = oldSlots[old]
        }
        oldSlots.deallocate()
    }
}

final class ConnectionList {
    private(set) var first: IPStack.Connection?
    private var cursor: IPStack.Connection?
    private(set) var count = 0

    var isEmpty: Bool {
        first == nil
    }

    func prepend(_ connection: IPStack.Connection) {
        connection.listNext = first
        connection.listPrevious = nil
        first?.listPrevious = connection
        first = connection
        count += 1
    }

    func remove(_ connection: IPStack.Connection) {
        if cursor === connection {
            cursor = connection.listNext
        }
        unlink(connection)
        count -= 1
    }

    func moveToFront(_ connection: IPStack.Connection) {
        guard first !== connection else { return }
        unlink(connection)
        count -= 1
        prepend(connection)
    }

    func removeAll() {
        while let connection = first {
            unlink(connection)
        }
        cursor = nil
        count = 0
    }

    func forEach(_ body: (IPStack.Connection) -> Void) {
        let outer = cursor
        cursor = first
        while let connection = cursor {
            cursor = connection.listNext
            body(connection)
        }
        cursor = outer
    }

    func leastRecent(at ticks: UInt32, where predicate: (IPStack.Connection) -> Bool) -> IPStack.Connection? {
        var inactivity: UInt32 = 0
        var found: IPStack.Connection?
        var node = first
        while let connection = node {
            if predicate(connection), ticks &- connection.tmr >= inactivity {
                inactivity = ticks &- connection.tmr
                found = connection
            }
            node = connection.listNext
        }
        return found
    }

    private func unlink(_ connection: IPStack.Connection) {
        if let previous = connection.listPrevious {
            previous.listNext = connection.listNext
        } else {
            first = connection.listNext
        }
        connection.listNext?.listPrevious = connection.listPrevious
        connection.listNext = nil
        connection.listPrevious = nil
    }
}

public final class IPStack {
    public static let tickInterval: Duration = .milliseconds(100)

    public var outputHandler: ((consuming OutboundPacket) -> Void)?
    public var acceptHandler: ((Connection) -> AcceptVerdict)?
    public var synFilter: ((_ source: IPEndpoint, _ destination: IPEndpoint) -> Bool)?
    public var strayFilter: ((_ source: IPEndpoint, _ destination: IPEndpoint) -> Bool)?
    public var maximumConnections = 1024

    let arena = SegmentArena()
    var ipv4Identification: UInt16 = 0
    private(set) var ticks: UInt32 = 0
    private(set) var isBatching = false
    private var timerCount: UInt32 = 0
    private var initialSequenceNumber: UInt32 = 6510
    private var table = ConnectionTable()
    private var activeList = ConnectionList()
    private var timeWaitList = ConnectionList()
    private var touched: [Connection] = []

    public init() {}

    deinit {
        activeList.forEach { $0.detach() }
        timeWaitList.forEach { $0.detach() }
    }

    public var isIdle: Bool {
        table.count == 0
    }

    public var activeConnectionCount: Int {
        activeList.count
    }

    public func inputBatch(_ body: (borrowing InputBatch) -> Void) {
        isBatching = true
        body(InputBatch(stack: self))
        isBatching = false
        flushTouched()
    }

    public func forEachConnection(_ body: (Connection) -> Void) {
        activeList.forEach { connection in
            if connection.isAttached {
                body(connection)
            }
        }
    }

    public func tick() {
        timerCount &+= 1
        if timerCount & 1 == 1 {
            slowTick()
        }
    }

    public func abortAllConnections() {
        activeList.forEach { $0.terminate(sendingReset: true, error: .aborted) }
        timeWaitList.forEach { expireTimeWait($0) }
    }

    public func shutdown() {
        abortAllConnections()
    }

    func deliverTCP(_ segment: UnsafeRawBufferPointer, source: IPAddress, destination: IPAddress) {
        guard let header = TCPHeader(parsing: segment) else { return }
        let remote = IPEndpoint(address: source, port: header.sourcePort)
        let local = IPEndpoint(address: destination, port: header.destinationPort)
        let key = ConnectionKey(remote: remote, local: local)
        let options = UnsafeRawBufferPointer(rebasing: segment[TCPHeader.length..<header.dataOffset])
        let payload = UnsafeRawBufferPointer(rebasing: segment[header.dataOffset...])
        if let connection = table.find(key) {
            if connection.isInTimeWait {
                connection.timeWaitInput(header: header, payloadCount: payload.count)
            } else {
                activeList.moveToFront(connection)
                touch(connection)
                connection.input(header: header, options: options, payload: payload)
            }
        } else {
            listenInput(remote: remote, local: local, header: header, options: options, payload: payload)
        }
    }

    private func listenInput(remote: IPEndpoint, local: IPEndpoint, header: TCPHeader, options: UnsafeRawBufferPointer, payload: UnsafeRawBufferPointer) {
        if header.flags.contains(.rst) { return }
        if header.flags.contains(.ack) {
            if let strayFilter, !strayFilter(remote, local) { return }
            let tcpLength = UInt32(payload.count) + (header.flags.contains(.syn) || header.flags.contains(.fin) ? 1 : 0)
            sendReset(from: local, to: remote, sequenceNumber: header.acknowledgmentNumber, acknowledgmentNumber: header.sequenceNumber &+ tcpLength)
        } else if header.flags.contains(.syn) {
            if let synFilter, !synFilter(remote, local) { return }
            guard table.count < maximumConnections || evictConnection() else { return }
            let key = ConnectionKey(remote: remote, local: local)
            let connection = Connection(stack: self, key: key, initialSequenceNumber: header.sequenceNumber, peerWindow: header.window, options: options)
            table.insert(connection)
            activeList.prepend(connection)
            touch(connection)
            connection.sendSynAck()
        }
    }

    private func evictConnection() -> Bool {
        if let victim = timeWaitList.leastRecent(at: ticks, where: { _ in true }) {
            expireTimeWait(victim)
            return true
        }
        for state in [Connection.State.lastAck, .closing] {
            if let victim = activeList.leastRecent(at: ticks, where: { $0.state == state }) {
                victim.terminate(sendingReset: false, error: .aborted)
                return true
            }
        }
        return false
    }

    private func expireTimeWait(_ connection: Connection) {
        remove(connection)
        connection.state = .closed
    }

    func touch(_ connection: Connection) {
        guard isBatching, !connection.isTouched else { return }
        connection.isTouched = true
        touched.append(connection)
    }

    private func flushTouched() {
        var index = 0
        while index < touched.count {
            let connection = touched[index]
            connection.isTouched = false
            connection.output()
            index += 1
        }
        touched.removeAll(keepingCapacity: true)
    }

    func seedInitialSequenceNumber(_ value: UInt32) {
        initialSequenceNumber = value
    }

    func nextInitialSequenceNumber() -> UInt32 {
        initialSequenceNumber &+= ticks
        return initialSequenceNumber
    }

    func remove(_ connection: Connection) {
        guard table.remove(connection) else { return }
        if connection.isInTimeWait {
            timeWaitList.remove(connection)
        } else {
            activeList.remove(connection)
        }
    }

    func moveToTimeWait(_ connection: Connection) {
        activeList.remove(connection)
        connection.isInTimeWait = true
        timeWaitList.prepend(connection)
    }

    private func slowTick() {
        ticks &+= 1
        activeList.forEach { connection in
            if connection.state != .closed {
                connection.slowTick(ticks: ticks)
            }
        }
        timeWaitList.forEach { connection in
            if ticks &- connection.tmr > TCPConstants.timeWaitTimeout {
                expireTimeWait(connection)
            }
        }
    }

    func sendReset(from local: IPEndpoint, to remote: IPEndpoint, sequenceNumber: UInt32, acknowledgmentNumber: UInt32) {
        let segment = arena.allocate(sequenceNumber: sequenceNumber, flags: [.rst, .ack])
        transmit(segment, from: local, to: remote, acknowledgmentNumber: acknowledgmentNumber, window: TCPConstants.resetWindow)
    }

    func transmit(_ segment: TCPSegment, from local: IPEndpoint, to remote: IPEndpoint, acknowledgmentNumber: UInt32, window: UInt16) {
        let isIPv6 = local.address.isIPv6
        let ipLength = isIPv6 ? IPv6Header.length : IPv4Header.length
        let start = IPv6Header.length - ipLength
        let tcpLength = TCPHeader.length + segment.options.encodedLength + segment.length
        let packet = UnsafeMutableRawBufferPointer(rebasing: segment.buffer[start..<(IPv6Header.length + tcpLength)])
        switch (local.address, remote.address) {
        case (.v4(let source), .v4(let destination)):
            IPv4Header(
                totalLength: ipLength + tcpLength,
                timeToLive: TCPConstants.hopLimit,
                protocol: 6,
                source: source,
                destination: destination,
                identification: nextIPv4Identification()
            ).write(to: packet)
        case (.v6(let source), .v6(let destination)):
            IPv6Header(
                payloadLength: tcpLength,
                nextHeader: 6,
                hopLimit: TCPConstants.hopLimit,
                source: source,
                destination: destination
            ).write(to: packet)
        default:
            return
        }
        let tcp = UnsafeMutableRawBufferPointer(rebasing: packet[ipLength...])
        TCPHeader(
            sourcePort: local.port,
            destinationPort: remote.port,
            sequenceNumber: segment.sequenceNumber,
            acknowledgmentNumber: acknowledgmentNumber,
            dataOffset: TCPHeader.length + segment.options.encodedLength,
            flags: segment.flags,
            window: window
        ).write(to: tcp)
        segment.options.write(to: UnsafeMutableRawBufferPointer(rebasing: tcp[TCPHeader.length...]))
        var checksum = InternetChecksum()
        checksum.update(pseudoHeaderFor: local.address, destination: remote.address, protocol: 6, length: tcpLength)
        checksum.update(bufferPointer: UnsafeRawBufferPointer(rebasing: UnsafeRawBufferPointer(tcp)[..<(tcpLength - segment.length)]))
        checksum.update(partialSum: segment.payloadSum, byteCount: segment.length)
        tcp.storeBytes(of: checksum.finalize(), toByteOffset: 16, as: UInt16.self)
        segment.inFlight += 1
        _ = segment.arena.retain()
        let outbound = OutboundPacket(
            bytes: UnsafeRawBufferPointer(packet),
            isIPv6: isIPv6,
            releaseContext: UnsafeMutableRawPointer(segment.storage),
            release: releaseSegment
        )
        outputHandler?(outbound)
    }
}

extension IPStack {
    public struct InputBatch: ~Copyable {
        private let stack: IPStack

        init(stack: IPStack) {
            self.stack = stack
        }

        public func feed(_ packet: UnsafeRawBufferPointer) {
            stack.receive(packet)
        }
    }
}
