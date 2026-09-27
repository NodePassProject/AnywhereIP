//
//  Context.swift
//  AnywhereIP
//
//  Created by NodePassProject on 9/20/26.
//

import Foundation
import Synchronization

final class Context {
    enum CoreEffect {
        case packet(OutboundPacket)
        case received(Data)
        case acknowledged(Int)
        case ready, fin, ended, removed, timeWait
        case failed(ConnectionError)
    }
    
    let arena = SegmentArena()
    let initialSequenceNumber: UInt32
    var ticks: UInt32
    var batching = false
    var effects: [CoreEffect] = []
    private var input: Data?
    private var inputBase: UnsafeRawPointer?

    init(initialSequenceNumber: UInt32, ticks: UInt32) {
        self.initialSequenceNumber = initialSequenceNumber
        self.ticks = ticks
    }

    func advance(to ticks: UInt32) {
        if Sequence.lessThan(self.ticks, ticks) { self.ticks = ticks }
    }

    func withPayload(_ data: Data, _ body: (UnsafeRawBufferPointer) -> Void) {
        input = data
        defer { input = nil; inputBase = nil }
        data.withUnsafeBytes { bytes in
            inputBase = bytes.baseAddress
            body(bytes)
        }
    }

    func receive(_ bytes: UnsafeRawBufferPointer) {
        guard !bytes.isEmpty, let input, let inputBase, let base = bytes.baseAddress else { return }
        let offset = inputBase.distance(to: base)
        precondition(offset >= 0 && offset + bytes.count <= input.count)
        let start = input.startIndex + offset
        effects.append(.received(input[start..<(start + bytes.count)]))
    }

    func sendReset(from local: IPEndpoint, to remote: IPEndpoint, sequenceNumber: UInt32, acknowledgmentNumber: UInt32) {
        guard let packet = OutboundPacket(resetFrom: local, to: remote, sequenceNumber: sequenceNumber, acknowledgmentNumber: acknowledgmentNumber) else { return }
        effects.append(.packet(packet))
    }

    func transmit(_ segment: Segment, from local: IPEndpoint, to remote: IPEndpoint, acknowledgmentNumber: UInt32, window: UInt16) {
        defer { if !segment.isQueued { arena.recycle(segment) } }
        let isIPv6 = local.address.isIPv6
        let start = IPv6Header.length - (isIPv6 ? IPv6Header.length : IPv4Header.length)
        let end = IPv6Header.length + TCPHeader.length + segment.options.encodedLength + segment.length
        let packet = UnsafeMutableRawBufferPointer(rebasing: segment.buffer[start..<end])
        guard OutboundPacket.encodeTCP(
            into: packet,
            from: local,
            to: remote,
            sequenceNumber: segment.sequenceNumber,
            acknowledgmentNumber: acknowledgmentNumber,
            flags: segment.flags,
            options: segment.options,
            window: window,
            payloadLength: segment.length,
            payloadSum: segment.payloadSum
        ) else { return }
        effects.append(.packet(OutboundPacket(data: Data(packet), isIPv6: isIPv6)))
    }
}
