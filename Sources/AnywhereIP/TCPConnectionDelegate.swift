//
//  TCPConnectionDelegate.swift
//  AnywhereIP
//
//  Created by NodePassProject on 9/20/26.
//

public enum TCPConnectionError: Error, Hashable, Sendable {
    case reset
    case aborted
    case closed
}

public protocol TCPConnectionDelegate<Connection>: AnyObject {
    associatedtype Connection: AnyObject

    func connection(_ connection: Connection, didReceive bytes: UnsafeRawBufferPointer)
    func connectionDidReceiveFin(_ connection: Connection)
    func connection(_ connection: Connection, didAcknowledge byteCount: Int)
    func connection(_ connection: Connection, didFailWith error: TCPConnectionError)
}

extension TCPConnectionDelegate {
    public func connection(_ connection: Connection, didReceive bytes: UnsafeRawBufferPointer) {}
    public func connectionDidReceiveFin(_ connection: Connection) {}
    public func connection(_ connection: Connection, didAcknowledge byteCount: Int) {}
    public func connection(_ connection: Connection, didFailWith error: TCPConnectionError) {}
}
