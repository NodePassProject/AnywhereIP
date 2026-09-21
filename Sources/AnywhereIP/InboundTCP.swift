//
//  InboundTCP.swift
//  AnywhereIP
//
//  Created by NodePassProject on 9/20/26.
//

import Foundation

struct InboundTCP: Sendable {
    let key: ConnectionKey
    let header: TCPHeader
    let options: Data
    let payload: Data
}
