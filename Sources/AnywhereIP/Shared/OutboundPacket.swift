//
//  OutboundPacket.swift
//  AnywhereIP
//
//  Created by NodePassProject on 9/20/26.
//

import Foundation

public struct OutboundPacket: Sendable {
    public let data: Data
    public let isIPv6: Bool

    init(data: Data, isIPv6: Bool) {
        self.data = data
        self.isIPv6 = isIPv6
    }

    init(byteCount: Int, isIPv6: Bool, _ fill: (UnsafeMutableRawBufferPointer) -> Void) {
        var data = Data(count: byteCount)
        data.withUnsafeMutableBytes(fill)
        self.init(data: data, isIPv6: isIPv6)
    }
}
