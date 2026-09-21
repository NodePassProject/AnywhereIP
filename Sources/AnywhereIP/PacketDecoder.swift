//
//  PacketDecoder.swift
//  AnywhereIP
//
//  Created by NodePassProject on 9/20/26.
//

import Foundation

struct PacketDecoder {
    var tcp: InboundTCP?
    var output: [OutboundPacket] = []
    private var input = Data()
    private var inputBase: UnsafeRawPointer?

    mutating func decode(_ packet: Data) {
        input = packet
        packet.withUnsafeBytes { bytes in
            inputBase = bytes.baseAddress
            receive(bytes)
        }
        inputBase = nil
    }

    mutating func deliverTCP(_ segment: UnsafeRawBufferPointer, source: IPAddress, destination: IPAddress) {
        guard let header = TCPHeader(parsing: segment), let base = segment.baseAddress, let inputBase else { return }
        let offset = inputBase.distance(to: base) + header.dataOffset
        let start = input.startIndex + offset
        tcp = InboundTCP(key: ConnectionKey(remote: IPEndpoint(address: source, port: header.sourcePort), local: IPEndpoint(address: destination, port: header.destinationPort)), header: header, options: Data(segment[TCPHeader.length..<header.dataOffset]), payload: input[start..<(start + segment.count - header.dataOffset)])
    }
    
    mutating func receive(_ packet: UnsafeRawBufferPointer) {
        guard let first = packet.first else { return }
        switch first >> 4 {
        case 4: receiveIPv4(packet)
        case 6: receiveIPv6(packet)
        default: break
        }
    }

    private mutating func receiveIPv4(_ packet: UnsafeRawBufferPointer) {
        guard let header = IPv4Header(parsing: packet), !header.hasOptions, !header.isFragment,
              isRoutable(header.source), isRoutable(header.destination) else { return }
        let datagram = UnsafeRawBufferPointer(rebasing: packet[..<header.totalLength])
        let payload = UnsafeRawBufferPointer(rebasing: datagram[IPv4Header.length...])
        switch header.protocol {
        case 6: deliverTCP(payload, source: .v4(header.source), destination: .v4(header.destination))
        case 1: replyToEchoRequest(in: datagram, header: header, payload: payload)
        default: sendProtocolUnreachable(for: datagram, header: header)
        }
    }

    private func isRoutable(_ address: IPAddress.V4) -> Bool {
        !address.isUnspecified && !address.isBroadcast && !address.isMulticast && !address.isLoopback
    }

    private mutating func receiveIPv6(_ packet: UnsafeRawBufferPointer) {
        guard let header = IPv6Header(parsing: packet),
              !header.source.isUnspecified, !header.source.isMulticast, !header.source.isIPv4Mapped,
              !header.destination.isMulticast, !header.destination.isIPv4Mapped else { return }
        let datagram = UnsafeRawBufferPointer(rebasing: packet[..<header.totalLength])
        switch header.locatePayload(in: datagram) {
        case .dropped:
            return
        case .parameterProblem(let code, let pointer):
            sendParameterProblem(for: datagram, header: header, code: code, pointer: pointer)
        case .found(let payload):
            let bytes = UnsafeRawBufferPointer(rebasing: datagram[payload.offset...])
            switch payload.nextHeader {
            case 6: deliverTCP(bytes, source: .v6(header.source), destination: .v6(header.destination))
            case 58: replyToEchoRequest(in: datagram, header: header, payload: bytes)
            case 59: return
            default: sendParameterProblem(for: datagram, header: header, code: 1, pointer: UInt32(payload.nextHeaderFieldOffset))
            }
        }
    }

    private mutating func replyToEchoRequest(in datagram: UnsafeRawBufferPointer, header: IPv4Header, payload: UnsafeRawBufferPointer) {
        guard payload.count >= 8, payload[0] == 8 else { return }
        send(byteCount: datagram.count, isIPv6: false) { reply in
            reply.copyMemory(from: datagram)
            var replyHeader = header
            replyHeader.source = header.destination
            replyHeader.destination = header.source
            replyHeader.timeToLive = 255
            replyHeader.write(to: reply)
            reply[IPv4Header.length] = 0
            Self.storeChecksum(in: reply, from: IPv4Header.length, at: IPv4Header.length + 2)
        }
    }

    private mutating func sendProtocolUnreachable(for datagram: UnsafeRawBufferPointer, header: IPv4Header) {
        let quoted = min(datagram.count, IPv4Header.length + 8)
        let length = IPv4Header.length + 8 + quoted
        send(byteCount: length, isIPv6: false) { reply in
            IPv4Header(
                totalLength: length,
                timeToLive: 255,
                protocol: 1,
                source: header.destination,
                destination: header.source,
                identification: PacketIdentification.next()
            ).write(to: reply)
            let message = UnsafeMutableRawBufferPointer(rebasing: reply[IPv4Header.length...])
            message.storeBytes(of: UInt64(0), as: UInt64.self)
            message[0] = 3
            message[1] = 2
            UnsafeMutableRawBufferPointer(rebasing: message[8...]).copyMemory(from: UnsafeRawBufferPointer(rebasing: datagram[..<quoted]))
            Self.storeChecksum(in: reply, from: IPv4Header.length, at: IPv4Header.length + 2)
        }
    }

    private mutating func replyToEchoRequest(in datagram: UnsafeRawBufferPointer, header: IPv6Header, payload: UnsafeRawBufferPointer) {
        guard payload.count >= 8, payload[0] == 128 else { return }
        send(byteCount: IPv6Header.length + payload.count, isIPv6: true) { reply in
            IPv6Header(
                payloadLength: payload.count,
                nextHeader: 58,
                hopLimit: 255,
                source: header.destination,
                destination: header.source
            ).write(to: reply)
            UnsafeMutableRawBufferPointer(rebasing: reply[IPv6Header.length...]).copyMemory(from: payload)
            reply[IPv6Header.length] = 129
            Self.storeChecksum(
                in: reply, from: IPv6Header.length, at: IPv6Header.length + 2,
                pseudoHeaderFor: .v6(header.destination), destination: .v6(header.source), protocol: 58
            )
        }
    }

    private mutating func sendParameterProblem(for datagram: UnsafeRawBufferPointer, header: IPv6Header, code: UInt8, pointer: UInt32) {
        let quoted = min(datagram.count, 1280 - IPv6Header.length - 8)
        send(byteCount: IPv6Header.length + 8 + quoted, isIPv6: true) { reply in
            IPv6Header(
                payloadLength: 8 + quoted,
                nextHeader: 58,
                hopLimit: 255,
                source: header.destination,
                destination: header.source
            ).write(to: reply)
            let message = UnsafeMutableRawBufferPointer(rebasing: reply[IPv6Header.length...])
            message[0] = 4
            message[1] = code
            message[2] = 0
            message[3] = 0
            message.storeBytes(of: pointer.bigEndian, toByteOffset: 4, as: UInt32.self)
            UnsafeMutableRawBufferPointer(rebasing: message[8...]).copyMemory(from: UnsafeRawBufferPointer(rebasing: datagram[..<quoted]))
            Self.storeChecksum(
                in: reply, from: IPv6Header.length, at: IPv6Header.length + 2,
                pseudoHeaderFor: .v6(header.destination), destination: .v6(header.source), protocol: 58
            )
        }
    }

    private static func storeChecksum(
        in buffer: UnsafeMutableRawBufferPointer,
        from start: Int,
        at offset: Int,
        pseudoHeaderFor source: IPAddress? = nil,
        destination: IPAddress? = nil,
        protocol: UInt8 = 0
    ) {
        buffer.storeBytes(of: UInt16(0), toByteOffset: offset, as: UInt16.self)
        var checksum = InternetChecksum()
        if let source, let destination {
            checksum.update(pseudoHeaderFor: source, destination: destination, protocol: `protocol`, length: buffer.count - start)
        }
        checksum.update(bufferPointer: UnsafeRawBufferPointer(rebasing: UnsafeRawBufferPointer(buffer)[start...]))
        buffer.storeBytes(of: checksum.finalize(), toByteOffset: offset, as: UInt16.self)
    }

    mutating func send(byteCount: Int, isIPv6: Bool, _ fill: (UnsafeMutableRawBufferPointer) -> Void) {
        let buffer = UnsafeMutableRawBufferPointer.allocate(byteCount: byteCount, alignment: 8)
        fill(buffer)
        let packet = OutboundPacket(data: Data(buffer), isIPv6: isIPv6)
        buffer.deallocate()
        output.append(packet)
    }
}
