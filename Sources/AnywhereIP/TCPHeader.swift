//
//  TCPHeader.swift
//  AnywhereIP
//
//  Created by NodePassProject on 9/20/26.
//

public struct TCPHeader: Hashable, Sendable {
    public struct Flags: OptionSet, Hashable, Sendable {
        public let rawValue: UInt8

        public init(rawValue: UInt8) {
            self.rawValue = rawValue
        }

        public static let fin = Flags(rawValue: 0x01)
        public static let syn = Flags(rawValue: 0x02)
        public static let rst = Flags(rawValue: 0x04)
        public static let psh = Flags(rawValue: 0x08)
        public static let ack = Flags(rawValue: 0x10)
        public static let urg = Flags(rawValue: 0x20)
    }

    public struct Options: Hashable, Sendable {
        public var maximumSegmentSize: UInt16?
        public var windowScale: UInt8?

        public init(maximumSegmentSize: UInt16? = nil, windowScale: UInt8? = nil) {
            self.maximumSegmentSize = maximumSegmentSize
            self.windowScale = windowScale
        }

        public init(parsing bytes: UnsafeRawBufferPointer) {
            var index = 0
            while index < bytes.count {
                let kind = bytes[index]
                switch kind {
                case 0:
                    return
                case 1:
                    index += 1
                case 2:
                    guard index + 4 <= bytes.count, bytes[index + 1] == 4 else { return }
                    maximumSegmentSize = UInt16(bigEndian: bytes.loadUnaligned(fromByteOffset: index + 2, as: UInt16.self))
                    index += 4
                case 3:
                    guard index + 3 <= bytes.count, bytes[index + 1] == 3 else { return }
                    windowScale = bytes[index + 2]
                    index += 3
                default:
                    guard index + 1 < bytes.count else { return }
                    let length = Int(bytes[index + 1])
                    guard length >= 2 else { return }
                    index += length
                }
            }
        }

        public var encodedLength: Int {
            (maximumSegmentSize == nil ? 0 : 4) + (windowScale == nil ? 0 : 4)
        }

        public func write(to bytes: UnsafeMutableRawBufferPointer) {
            var offset = 0
            if let maximumSegmentSize {
                bytes[offset] = 2
                bytes[offset + 1] = 4
                bytes.storeBytes(of: maximumSegmentSize.bigEndian, toByteOffset: offset + 2, as: UInt16.self)
                offset += 4
            }
            if let windowScale {
                bytes[offset] = 1
                bytes[offset + 1] = 3
                bytes[offset + 2] = 3
                bytes[offset + 3] = windowScale
            }
        }
    }

    public static let length = 20

    public var sourcePort: UInt16
    public var destinationPort: UInt16
    public var sequenceNumber: UInt32
    public var acknowledgmentNumber: UInt32
    public var dataOffset: Int
    public var flags: Flags
    public var window: UInt16
    public var checksum: UInt16
    public var urgentPointer: UInt16

    public init(
        sourcePort: UInt16,
        destinationPort: UInt16,
        sequenceNumber: UInt32,
        acknowledgmentNumber: UInt32,
        dataOffset: Int = TCPHeader.length,
        flags: Flags,
        window: UInt16,
        checksum: UInt16 = 0,
        urgentPointer: UInt16 = 0
    ) {
        self.sourcePort = sourcePort
        self.destinationPort = destinationPort
        self.sequenceNumber = sequenceNumber
        self.acknowledgmentNumber = acknowledgmentNumber
        self.dataOffset = dataOffset
        self.flags = flags
        self.window = window
        self.checksum = checksum
        self.urgentPointer = urgentPointer
    }

    public init?(parsing bytes: UnsafeRawBufferPointer) {
        guard bytes.count >= Self.length, let base = bytes.baseAddress else { return nil }
        let dataOffset = Int(base.load(fromByteOffset: 12, as: UInt8.self) >> 4) * 4
        guard dataOffset >= Self.length, dataOffset <= bytes.count else { return nil }
        sourcePort = UInt16(bigEndian: base.loadUnaligned(as: UInt16.self))
        destinationPort = UInt16(bigEndian: base.loadUnaligned(fromByteOffset: 2, as: UInt16.self))
        sequenceNumber = UInt32(bigEndian: base.loadUnaligned(fromByteOffset: 4, as: UInt32.self))
        acknowledgmentNumber = UInt32(bigEndian: base.loadUnaligned(fromByteOffset: 8, as: UInt32.self))
        self.dataOffset = dataOffset
        flags = Flags(rawValue: base.load(fromByteOffset: 13, as: UInt8.self) & 0x3F)
        window = UInt16(bigEndian: base.loadUnaligned(fromByteOffset: 14, as: UInt16.self))
        checksum = UInt16(bigEndian: base.loadUnaligned(fromByteOffset: 16, as: UInt16.self))
        urgentPointer = UInt16(bigEndian: base.loadUnaligned(fromByteOffset: 18, as: UInt16.self))
    }

    public func write(to bytes: UnsafeMutableRawBufferPointer) {
        precondition(bytes.count >= Self.length)
        let base = bytes.baseAddress!
        base.storeBytes(of: sourcePort.bigEndian, as: UInt16.self)
        base.storeBytes(of: destinationPort.bigEndian, toByteOffset: 2, as: UInt16.self)
        base.storeBytes(of: sequenceNumber.bigEndian, toByteOffset: 4, as: UInt32.self)
        base.storeBytes(of: acknowledgmentNumber.bigEndian, toByteOffset: 8, as: UInt32.self)
        base.storeBytes(of: UInt8(dataOffset / 4) << 4, toByteOffset: 12, as: UInt8.self)
        base.storeBytes(of: flags.rawValue, toByteOffset: 13, as: UInt8.self)
        base.storeBytes(of: window.bigEndian, toByteOffset: 14, as: UInt16.self)
        base.storeBytes(of: checksum.bigEndian, toByteOffset: 16, as: UInt16.self)
        base.storeBytes(of: urgentPointer.bigEndian, toByteOffset: 18, as: UInt16.self)
    }
}

enum TCPSequence {
    static func lessThan(_ a: UInt32, _ b: UInt32) -> Bool {
        (a &- b) & 0x8000_0000 != 0
    }

    static func lessThanOrEqual(_ a: UInt32, _ b: UInt32) -> Bool {
        !lessThan(b, a)
    }

    static func between(_ value: UInt32, _ low: UInt32, _ high: UInt32) -> Bool {
        lessThanOrEqual(low, value) && lessThanOrEqual(value, high)
    }
}
