//
//  TCPSegment.swift
//  AnywhereIP
//
//  Created by NodePassProject on 9/20/26.
//

struct TCPSegment: Equatable {
    struct Storage {
        var next: UnsafeMutablePointer<Storage>?
        var arena: Unmanaged<SegmentArena>
        var sequenceNumber: UInt32
        var length: Int
        var inFlight: Int
        var flags: TCPHeader.Flags
        var options: TCPHeader.Options
        var payloadSum: UInt16
        var isQueued: Bool
    }

    static let headroom = IPv6Header.length + TCPHeader.length + 8
    static let capacity = Int(TCPConstants.maximumSegmentSize)

    static var bufferOffset: Int {
        (MemoryLayout<Storage>.stride + 15) & ~15
    }

    static var stride: Int {
        (bufferOffset + headroom + capacity + 15) & ~15
    }

    let storage: UnsafeMutablePointer<Storage>

    var arena: Unmanaged<SegmentArena> {
        storage.pointee.arena
    }

    var sequenceNumber: UInt32 {
        storage.pointee.sequenceNumber
    }

    var length: Int {
        storage.pointee.length
    }

    var payloadSum: UInt16 {
        storage.pointee.payloadSum
    }

    func setPayload(_ bytes: UnsafeRawBufferPointer) {
        storage.pointee.length = bytes.count
        let payload = self.payload
        payload.copyMemory(from: bytes)
        storage.pointee.payloadSum = InternetChecksum.partialSum(of: UnsafeRawBufferPointer(payload))
    }

    func truncatePayload(to count: Int) {
        storage.pointee.length = count
        storage.pointee.payloadSum = InternetChecksum.partialSum(of: UnsafeRawBufferPointer(payload))
    }

    func appendPayload(_ bytes: UnsafeRawBufferPointer) {
        let end = payload.baseAddress.unsafelyUnwrapped + length
        UnsafeMutableRawBufferPointer(start: end, count: bytes.count).copyMemory(from: bytes)
        truncatePayload(to: length + bytes.count)
    }

    func dropPayloadPrefix(_ count: Int) {
        let payload = self.payload
        let start = payload.baseAddress.unsafelyUnwrapped
        start.copyMemory(from: start + count, byteCount: payload.count - count)
        storage.pointee.sequenceNumber &+= UInt32(count)
        truncatePayload(to: payload.count - count)
    }

    var inFlight: Int {
        get { storage.pointee.inFlight }
        nonmutating set { storage.pointee.inFlight = newValue }
    }

    var flags: TCPHeader.Flags {
        get { storage.pointee.flags }
        nonmutating set { storage.pointee.flags = newValue }
    }

    var options: TCPHeader.Options {
        storage.pointee.options
    }

    var isQueued: Bool {
        get { storage.pointee.isQueued }
        nonmutating set { storage.pointee.isQueued = newValue }
    }

    var next: TCPSegment? {
        get { storage.pointee.next.map(TCPSegment.init) }
        nonmutating set { storage.pointee.next = newValue?.storage }
    }

    var buffer: UnsafeMutableRawBufferPointer {
        UnsafeMutableRawBufferPointer(start: UnsafeMutableRawPointer(storage) + Self.bufferOffset, count: Self.headroom + Self.capacity)
    }

    var payloadOffset: Int {
        IPv6Header.length + TCPHeader.length + options.encodedLength
    }

    var payload: UnsafeMutableRawBufferPointer {
        UnsafeMutableRawBufferPointer(rebasing: buffer[payloadOffset..<(payloadOffset + length)])
    }

    var tcpLength: UInt32 {
        UInt32(length) + (flags.contains(.syn) || flags.contains(.fin) ? 1 : 0)
    }

    var isBusy: Bool {
        inFlight > 0
    }
}

final class SegmentArena {
    private static let chunkSlots = 64

    private var chunks: [UnsafeMutableRawPointer] = []
    private var free: UnsafeMutablePointer<TCPSegment.Storage>?

    deinit {
        for chunk in chunks {
            chunk.deallocate()
        }
    }

    func allocate(sequenceNumber: UInt32, flags: TCPHeader.Flags, options: TCPHeader.Options = TCPHeader.Options()) -> TCPSegment {
        if free == nil {
            grow()
        }
        let storage = free.unsafelyUnwrapped
        free = storage.pointee.next
        storage.pointee.next = nil
        storage.pointee.sequenceNumber = sequenceNumber
        storage.pointee.length = 0
        storage.pointee.inFlight = 0
        storage.pointee.flags = flags
        storage.pointee.options = options
        storage.pointee.payloadSum = 0
        storage.pointee.isQueued = false
        return TCPSegment(storage: storage)
    }

    func recycle(_ segment: TCPSegment) {
        segment.isQueued = false
        if segment.inFlight == 0 {
            release(segment)
        }
    }

    func release(_ segment: TCPSegment) {
        segment.storage.pointee.next = free
        free = segment.storage
    }

    private func grow() {
        let chunk = UnsafeMutableRawPointer.allocate(byteCount: Self.chunkSlots * TCPSegment.stride, alignment: 16)
        chunks.append(chunk)
        for index in stride(from: Self.chunkSlots - 1, through: 0, by: -1) {
            free = (chunk + index * TCPSegment.stride).initializeMemory(
                as: TCPSegment.Storage.self,
                to: TCPSegment.Storage(
                    next: free, arena: .passUnretained(self), sequenceNumber: 0, length: 0, inFlight: 0,
                    flags: [], options: TCPHeader.Options(), payloadSum: 0, isQueued: false
                )
            )
        }
    }
}

let releaseSegment: @convention(c) (UnsafeMutableRawPointer?) -> Void = { context in
    guard let context else { return }
    let segment = TCPSegment(storage: context.assumingMemoryBound(to: TCPSegment.Storage.self))
    let arena = segment.arena
    segment.inFlight -= 1
    if segment.inFlight == 0, !segment.isQueued {
        arena._withUnsafeGuaranteedRef { $0.release(segment) }
    }
    arena.release()
}

struct SegmentList {
    private(set) var first: TCPSegment?
    private(set) var last: TCPSegment?
    private(set) var count = 0

    var isEmpty: Bool {
        first == nil
    }

    mutating func append(_ segment: TCPSegment) {
        segment.next = nil
        segment.isQueued = true
        if let last {
            last.next = segment
        } else {
            first = segment
        }
        last = segment
        count += 1
    }

    mutating func prepend(_ segment: TCPSegment) {
        segment.next = first
        segment.isQueued = true
        first = segment
        if last == nil {
            last = segment
        }
        count += 1
    }

    mutating func insert(_ segment: TCPSegment, after predecessor: TCPSegment) {
        segment.next = predecessor.next
        segment.isQueued = true
        predecessor.next = segment
        if last == predecessor {
            last = segment
        }
        count += 1
    }

    mutating func insertOrdered(_ segment: TCPSegment) {
        var predecessor: TCPSegment?
        var candidate = first
        while let current = candidate, TCPSequence.lessThan(current.sequenceNumber, segment.sequenceNumber) {
            predecessor = current
            candidate = current.next
        }
        if let predecessor {
            insert(segment, after: predecessor)
        } else {
            prepend(segment)
        }
    }

    mutating func prepend(contentsOf list: consuming SegmentList) {
        guard let tail = list.last else { return }
        tail.next = first
        first = list.first
        if last == nil {
            last = tail
        }
        count += list.count
    }

    mutating func removeFirst() -> TCPSegment? {
        guard let head = first else { return nil }
        first = head.next
        if first == nil {
            last = nil
        }
        head.next = nil
        count -= 1
        return head
    }

    mutating func detachAll() -> SegmentList {
        let detached = self
        self = SegmentList()
        return detached
    }

    func contains(where predicate: (TCPSegment) -> Bool) -> Bool {
        var candidate = first
        while let segment = candidate {
            if predicate(segment) {
                return true
            }
            candidate = segment.next
        }
        return false
    }
}
