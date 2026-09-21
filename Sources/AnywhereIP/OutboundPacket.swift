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
}
