//
//  OutboundPacket.swift
//  AnywhereIP
//
//  Created by NodePassProject on 9/20/26.
//

typealias PacketReleaseFunction = @convention(c) (UnsafeMutableRawPointer?) -> Void

public struct OutboundPacket: ~Copyable {
    public let bytes: UnsafeRawBufferPointer
    public let isIPv6: Bool
    private let releaseContext: UnsafeMutableRawPointer?
    private let release: PacketReleaseFunction?

    init(
        bytes: UnsafeRawBufferPointer,
        isIPv6: Bool,
        releaseContext: UnsafeMutableRawPointer?,
        release: PacketReleaseFunction?
    ) {
        self.bytes = bytes
        self.isIPv6 = isIPv6
        self.releaseContext = releaseContext
        self.release = release
    }

    public consuming func deferRelease() -> PacketRelease {
        let deferred = PacketRelease(context: releaseContext, release: release)
        discard self
        return deferred
    }

    deinit {
        release?(releaseContext)
    }
}

public struct PacketRelease: @unchecked Sendable {
    private let context: UnsafeMutableRawPointer?
    private let release: PacketReleaseFunction?

    init(context: UnsafeMutableRawPointer?, release: PacketReleaseFunction?) {
        self.context = context
        self.release = release
    }

    public consuming func callAsFunction() {
        release?(context)
    }
}
