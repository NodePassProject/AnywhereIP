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
        let segment = arena.allocate(sequenceNumber: sequenceNumber, flags: [.rst, .ack])
        transmit(segment, from: local, to: remote, acknowledgmentNumber: acknowledgmentNumber, window: Constants.resetWindow)
    }

    func transmit(_ segment: Segment, from local: IPEndpoint, to remote: IPEndpoint, acknowledgmentNumber: UInt32, window: UInt16) {
        let isIPv6 = local.address.isIPv6
        let ipLength = isIPv6 ? IPv6Header.length : IPv4Header.length
        let start = IPv6Header.length - ipLength
        let tcpLength = TCPHeader.length + segment.options.encodedLength + segment.length
        let packet = UnsafeMutableRawBufferPointer(rebasing: segment.buffer[start..<(IPv6Header.length + tcpLength)])
        switch (local.address, remote.address) {
        case (.v4(let source), .v4(let destination)):
            IPv4Header(
                totalLength: ipLength + tcpLength,
                timeToLive: Constants.hopLimit,
                protocol: 6,
                source: source,
                destination: destination,
                identification: PacketIdentification.next()
            ).write(to: packet)
        case (.v6(let source), .v6(let destination)):
            IPv6Header(
                payloadLength: tcpLength,
                nextHeader: 6,
                hopLimit: Constants.hopLimit,
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
        let outbound = OutboundPacket(data: Data(packet), isIPv6: isIPv6)
        if !segment.isQueued { arena.recycle(segment) }
        effects.append(.packet(outbound))
    }
}
