//
//  IPStack+Connection.swift
//  AnywhereIP
//
//  Created by NodePassProject on 9/20/26.
//

extension IPStack {
    public final class Connection {
        enum State: Comparable {
            case synReceived
            case established
            case finWait1
            case finWait2
            case closeWait
            case closing
            case lastAck
            case timeWait
            case closed
        }

        struct Flags: OptionSet {
            let rawValue: UInt16

            static let ackNow = Flags(rawValue: 0x02)
            static let inFastRecovery = Flags(rawValue: 0x04)
            static let receiveClosed = Flags(rawValue: 0x10)
            static let fin = Flags(rawValue: 0x20)
            static let windowScale = Flags(rawValue: 0x100)
            static let rto = Flags(rawValue: 0x800)
        }

        struct ReceiveFlags: OptionSet {
            let rawValue: UInt8

            static let reset = ReceiveFlags(rawValue: 0x08)
            static let closed = ReceiveFlags(rawValue: 0x10)
            static let gotFin = ReceiveFlags(rawValue: 0x20)
        }

        public let source: IPEndpoint
        public let destination: IPEndpoint
        public var delegate: (any TCPConnectionDelegate<Connection>)?
        public private(set) var isAttached = true

        unowned(unsafe) let stack: IPStack
        let arena: SegmentArena
        let key: ConnectionKey
        var listNext: Connection?
        unowned(unsafe) var listPrevious: Connection?
        var state = State.synReceived
        var flags: Flags = []
        var tmr: UInt32
        var rcvNxt: UInt32
        var rcvWnd: UInt32 = 0xFFFF
        var rcvAnnWnd: UInt32 = 0xFFFF
        var rcvAnnRightEdge: UInt32
        var rtime: Int16 = -1
        var rto = TCPConstants.initialRTO
        var sa: Int16 = 0
        var sv = TCPConstants.initialRTO
        var nrtx: UInt8 = 0
        var dupacks: UInt8 = 0
        var mss = TCPConstants.initialMSS
        var rttest: UInt32 = 0
        var rtseq: UInt32 = 0
        var lastAck: UInt32
        var rtoEnd: UInt32 = 0
        var sndNxt: UInt32
        var sndWl1: UInt32
        var sndWl2: UInt32
        var sndLbb: UInt32
        var sndWnd: UInt32
        var sndWndMax: UInt32
        var sndBuf = TCPConstants.sendBufferSize
        var unsent = SegmentList()
        var unacked = SegmentList()
        var unsentOversize = 0
        var persistCount: UInt8 = 0
        var persistBackoff: UInt8 = 0
        var persistProbes: UInt8 = 0
        var sndScale: UInt8 = 0
        var rcvScale: UInt8 = 0
        var isProcessingInput = false
        var closeAfterInput = false
        var isTouched = false
        var isInTimeWait = false

        init(stack: IPStack, key: ConnectionKey, initialSequenceNumber: UInt32, peerWindow: UInt16, options: UnsafeRawBufferPointer) {
            self.stack = stack
            arena = stack.arena
            self.key = key
            source = key.remote
            destination = key.local
            tmr = stack.ticks
            let iss = stack.nextInitialSequenceNumber()
            rcvNxt = initialSequenceNumber &+ 1
            rcvAnnRightEdge = rcvNxt
            sndWl2 = iss
            sndNxt = iss
            lastAck = iss
            sndLbb = iss
            sndWl1 = initialSequenceNumber &- 1
            sndWnd = UInt32(peerWindow)
            sndWndMax = sndWnd
            parseOptions(options)
            mss = effectiveSendMSS(mss)
        }

        public var sendBufferSpace: Int {
            Int(sndBuf)
        }

        public var sendQueueLength: Int {
            unsent.count + unacked.count
        }

        @discardableResult
        public func write(_ bytes: UnsafeRawBufferPointer) -> Int {
            guard isAttached, let base = bytes.baseAddress else { return 0 }
            let count = min(bytes.count, Int(sndBuf))
            guard count > 0, enqueue(UnsafeRawBufferPointer(start: base, count: count)) else { return 0 }
            stack.touch(self)
            return count
        }

        public func flush() {
            guard isAttached else { return }
            output()
        }

        public func didConsume(_ count: Int) {
            guard isAttached, state != .timeWait, state != .closed else { return }
            var remaining = count
            while remaining > 0 {
                let chunk = UInt32(min(remaining, Int(UInt16.max)))
                remaining -= Int(chunk)
                let grown = rcvWnd &+ chunk
                rcvWnd = (grown > windowMax || grown < rcvWnd) ? windowMax : grown
                if updateAnnouncedWindow() >= TCPConstants.windowUpdateThreshold {
                    flags.insert(.ackNow)
                    output()
                }
            }
        }

        public func shutdownSend() {
            guard isAttached else { return }
            switch state {
            case .synReceived, .established, .closeWait:
                closeSendSide(resetOnUnreadData: false)
            default:
                break
            }
        }

        public func close() {
            guard isAttached else { return }
            detach()
            flags.insert(.receiveClosed)
            closeSendSide(resetOnUnreadData: true)
        }

        public func abort() {
            guard isAttached else { return }
            detach()
            terminate(sendingReset: true, error: nil)
        }

        public func discard() {
            guard isAttached else { return }
            detach()
            terminate(sendingReset: false, error: nil)
        }

        var windowMax: UInt32 {
            flags.contains(.windowScale) ? TCPConstants.window : 0xFFFF
        }

        func detach() {
            isAttached = false
            delegate = nil
        }

        private func effectiveSendMSS(_ value: UInt16) -> UInt16 {
            let overhead = (destination.address.isIPv6 ? IPv6Header.length : IPv4Header.length) + TCPHeader.length
            return min(value, UInt16(TCPConstants.mtu - overhead))
        }

        private func parseOptions(_ bytes: UnsafeRawBufferPointer) {
            let options = TCPHeader.Options(parsing: bytes)
            if let value = options.maximumSegmentSize {
                mss = (value > TCPConstants.maximumSegmentSize || value == 0) ? TCPConstants.maximumSegmentSize : value
            }
            if let scale = options.windowScale, !flags.contains(.windowScale) {
                sndScale = min(scale, 14)
                rcvScale = TCPConstants.receiveScale
                flags.insert(.windowScale)
                rcvWnd = TCPConstants.window
                rcvAnnWnd = TCPConstants.window
            }
        }

        func sendSynAck() {
            var options = TCPHeader.Options(maximumSegmentSize: effectiveSendMSS(TCPConstants.maximumSegmentSize))
            if flags.contains(.windowScale) {
                options.windowScale = TCPConstants.receiveScale
            }
            enqueueControl(flags: [.syn, .ack], options: options)
            output()
        }

        private func enqueueControl(flags controlFlags: TCPHeader.Flags, options: TCPHeader.Options = TCPHeader.Options()) {
            unsent.append(arena.allocate(sequenceNumber: sndLbb, flags: controlFlags, options: options))
            unsentOversize = 0
            sndLbb &+= 1
            if controlFlags.contains(.fin) {
                flags.insert(.fin)
            }
        }

        private func enqueueFin() {
            if let last = unsent.last, last.flags.isDisjoint(with: [.syn, .fin, .rst]) {
                last.flags.insert(.fin)
                flags.insert(.fin)
                return
            }
            enqueueControl(flags: [.fin])
        }

        private func enqueue(_ bytes: UnsafeRawBufferPointer) -> Bool {
            switch state {
            case .synReceived, .established, .closeWait:
                break
            default:
                return false
            }
            let length = bytes.count
            guard length > 0 else { return true }
            guard length <= Int(sndBuf), sendQueueLength < TCPConstants.sendQueueLimit else { return false }
            var segmentSize = Int(min(UInt32(mss), min(sndWndMax / 2, 0xFFFF)))
            if segmentSize == 0 {
                segmentSize = Int(mss)
            }
            var oversize = unsentOversize
            var position = 0
            if let last = unsent.last, oversize > 0 {
                position = min(segmentSize - last.length, min(oversize, length))
                oversize -= position
            }
            guard sendQueueLength + (length - position + segmentSize - 1) / segmentSize <= TCPConstants.sendQueueLimit else { return false }
            if position > 0 {
                unsent.last.unsafelyUnwrapped.appendPayload(UnsafeRawBufferPointer(rebasing: bytes[..<position]))
            }
            while position < length {
                let count = min(length - position, segmentSize)
                let segment = arena.allocate(sequenceNumber: sndLbb &+ UInt32(position), flags: [])
                segment.setPayload(UnsafeRawBufferPointer(rebasing: bytes[position..<(position + count)]))
                unsent.append(segment)
                oversize = segmentSize - count
                position += count
            }
            unsent.last.unsafelyUnwrapped.flags.insert(.psh)
            unsentOversize = oversize
            sndLbb &+= UInt32(length)
            sndBuf -= UInt32(length)
            return true
        }

        private func closeSendSide(resetOnUnreadData: Bool) {
            if resetOnUnreadData, state == .established || state == .closeWait, rcvWnd != windowMax {
                if isProcessingInput {
                    closeAfterInput = true
                } else {
                    terminate(sendingReset: true, error: nil)
                }
                return
            }
            switch state {
            case .synReceived, .established:
                enqueueFin()
                state = .finWait1
            case .closeWait:
                enqueueFin()
                state = .lastAck
            default:
                return
            }
            output()
        }

        func terminate(sendingReset: Bool, error: TCPConnectionError?) {
            guard state != .closed else { return }
            if sendingReset, state != .timeWait {
                sendReset(sequenceNumber: sndNxt, acknowledgmentNumber: rcvNxt)
            }
            purge()
            state = .closed
            stack.remove(self)
            if let error, isAttached {
                let delegate = self.delegate
                detach()
                delegate?.connection(self, didFailWith: error)
            }
        }

        private func purge() {
            while let segment = unsent.removeFirst() {
                arena.recycle(segment)
            }
            while let segment = unacked.removeFirst() {
                arena.recycle(segment)
            }
            unsentOversize = 0
            rtime = -1
        }

        private func enterTimeWait() {
            purge()
            state = .timeWait
            stack.moveToTimeWait(self)
        }

        private func updateAnnouncedWindow() -> UInt32 {
            let newRightEdge = rcvNxt &+ rcvWnd
            if TCPSequence.lessThanOrEqual(rcvAnnRightEdge &+ min(TCPConstants.window / 2, UInt32(mss)), newRightEdge) {
                rcvAnnWnd = rcvWnd
                return newRightEdge &- rcvAnnRightEdge
            }
            if TCPSequence.lessThan(rcvAnnRightEdge, rcvNxt) {
                rcvAnnWnd = 0
            } else {
                rcvAnnWnd = rcvAnnRightEdge &- rcvNxt
            }
            return 0
        }

        private var announcedWindow: UInt16 {
            UInt16(min(rcvAnnWnd >> rcvScale, 0xFFFF))
        }

        private func sendReset(sequenceNumber: UInt32, acknowledgmentNumber: UInt32) {
            stack.sendReset(from: destination, to: source, sequenceNumber: sequenceNumber, acknowledgmentNumber: acknowledgmentNumber)
        }

        private func sendEmptyAck(_ stack: IPStack) {
            let segment = arena.allocate(sequenceNumber: sndNxt, flags: [.ack])
            rcvAnnRightEdge = rcvNxt &+ rcvAnnWnd
            stack.transmit(segment, from: destination, to: source, acknowledgmentNumber: rcvNxt, window: announcedWindow)
            flags.remove(.ackNow)
        }

        private func transmit(_ segment: TCPSegment, _ stack: IPStack) {
            guard !segment.isBusy else { return }
            if rtime < 0 {
                rtime = 0
            }
            if rttest == 0, TCPSequence.lessThanOrEqual(sndNxt, segment.sequenceNumber) {
                rttest = stack.ticks
                rtseq = segment.sequenceNumber
            }
            let window = segment.options.windowScale != nil ? UInt16(min(rcvAnnWnd, 0xFFFF)) : announcedWindow
            rcvAnnRightEdge = rcvNxt &+ rcvAnnWnd
            stack.transmit(segment, from: destination, to: source, acknowledgmentNumber: rcvNxt, window: window)
        }

        func output() {
            guard state != .closed, !isProcessingInput else { return }
            let wnd = sndWnd
            guard let first = unsent.first else {
                if flags.contains(.ackNow) {
                    sendEmptyAck(stack)
                }
                return
            }
            if first.sequenceNumber &- lastAck &+ UInt32(first.length) > wnd {
                if unacked.isEmpty, persistBackoff == 0 {
                    persistCount = 0
                    persistBackoff = 1
                    persistProbes = 0
                }
                if flags.contains(.ackNow) {
                    sendEmptyAck(stack)
                }
                return
            }
            persistBackoff = 0
            let stack = self.stack
            while let segment = unsent.first, segment.sequenceNumber &- lastAck &+ UInt32(segment.length) <= wnd {
                segment.flags.insert(.ack)
                transmit(segment, stack)
                _ = unsent.removeFirst()
                flags.remove(.ackNow)
                let next = segment.sequenceNumber &+ segment.tcpLength
                if TCPSequence.lessThan(sndNxt, next) {
                    sndNxt = next
                }
                if segment.tcpLength > 0 {
                    insertUnacked(segment)
                } else {
                    arena.recycle(segment)
                }
            }
            if unsent.isEmpty {
                unsentOversize = 0
            }
        }

        private func insertUnacked(_ segment: TCPSegment) {
            if let last = unacked.last, TCPSequence.lessThan(segment.sequenceNumber, last.sequenceNumber) {
                unacked.insertOrdered(segment)
            } else {
                unacked.append(segment)
            }
        }

        private func moveFirstUnackedToUnsent() -> Bool {
            guard let segment = unacked.first, !segment.isBusy else { return false }
            _ = unacked.removeFirst()
            unsent.insertOrdered(segment)
            if unsent.last == segment {
                unsentOversize = 0
            }
            if nrtx < UInt8.max {
                nrtx += 1
            }
            rttest = 0
            return true
        }

        private func fastRetransmit() {
            guard !unacked.isEmpty, !flags.contains(.inFastRecovery) else { return }
            if moveFirstUnackedToUnsent() {
                flags.insert(.inFastRecovery)
                rtime = 0
            }
        }

        private func prepareRetransmission() -> Bool {
            guard let last = unacked.last, !unacked.contains(where: { $0.isBusy }) else { return false }
            unsent.prepend(contentsOf: unacked.detachAll())
            flags.insert(.rto)
            rtoEnd = last.sequenceNumber &+ last.tcpLength
            rttest = 0
            return true
        }

        private func splitFirstUnsent(at split: Int) -> Bool {
            guard let head = unsent.first, split > 0 else { return false }
            guard head.length > split else { return true }
            var remainderFlags: TCPHeader.Flags = []
            if head.flags.contains(.psh) {
                head.flags.remove(.psh)
                remainderFlags.insert(.psh)
            }
            if head.flags.contains(.fin) {
                head.flags.remove(.fin)
                remainderFlags.insert(.fin)
            }
            let segment = arena.allocate(sequenceNumber: head.sequenceNumber &+ UInt32(split), flags: remainderFlags)
            segment.setPayload(UnsafeRawBufferPointer(rebasing: head.payload[split...]))
            head.truncatePayload(to: split)
            unsent.insert(segment, after: head)
            if unsent.last == segment {
                unsentOversize = 0
            }
            return true
        }

        private func zeroWindowProbe() {
            guard let head = unsent.first else { return }
            if persistProbes < UInt8.max {
                persistProbes += 1
            }
            let offset = Int(lastAck &- head.sequenceNumber)
            let isFin = offset == head.length
            guard offset < head.length || (isFin && head.flags.contains(.fin)) else { return }
            let probe = arena.allocate(sequenceNumber: lastAck, flags: isFin ? [.ack, .fin] : [.ack])
            if !isFin {
                probe.setPayload(UnsafeRawBufferPointer(rebasing: head.payload[offset..<(offset + 1)]))
            }
            let next = lastAck &+ 1
            if TCPSequence.lessThan(sndNxt, next) {
                sndNxt = next
            }
            rcvAnnRightEdge = rcvNxt &+ rcvAnnWnd
            stack.transmit(probe, from: destination, to: source, acknowledgmentNumber: rcvNxt, window: announcedWindow)
        }

        func slowTick(ticks: UInt32) {
            var remove = false
            if nrtx >= TCPConstants.maximumRetransmissions {
                remove = true
            } else if persistBackoff > 0 {
                if persistProbes >= TCPConstants.maximumRetransmissions {
                    remove = true
                } else {
                    let backoff = TCPConstants.persistBackoff[Int(persistBackoff) - 1]
                    if persistCount < backoff {
                        persistCount += 1
                    }
                    if persistCount >= backoff {
                        var nextSlot = true
                        if sndWnd == 0 {
                            zeroWindowProbe()
                        } else if splitFirstUnsent(at: Int(min(sndWnd, 0xFFFF))) {
                            output()
                            nextSlot = false
                        }
                        if nextSlot {
                            persistCount = 0
                            if persistBackoff < UInt8(TCPConstants.persistBackoff.count) {
                                persistBackoff += 1
                            }
                        }
                    }
                }
            } else {
                if rtime >= 0, rtime < Int16.max {
                    rtime += 1
                }
                if rtime >= rto {
                    if prepareRetransmission() || (unacked.isEmpty && !unsent.isEmpty) {
                        let backoff = TCPConstants.retransmissionBackoff[min(Int(nrtx), TCPConstants.retransmissionBackoff.count - 1)]
                        rto = Int16(min(Int32((sa >> 3) &+ sv) << Int32(backoff), Int32(Int16.max)))
                        rtime = 0
                        if nrtx < UInt8.max {
                            nrtx += 1
                        }
                        output()
                    }
                }
            }
            if state == .finWait2, flags.contains(.receiveClosed), ticks &- tmr > TCPConstants.finWait2Timeout {
                remove = true
            }
            if state == .synReceived, ticks &- tmr > TCPConstants.synReceivedTimeout {
                remove = true
            }
            if state == .lastAck, ticks &- tmr > TCPConstants.lastAckTimeout {
                remove = true
            }
            if remove {
                terminate(sendingReset: false, error: .aborted)
            } else {
                output()
            }
        }

        func timeWaitInput(header: TCPHeader, payloadCount: Int) {
            if header.flags.contains(.rst) { return }
            let tcpLength = UInt32(payloadCount) + (header.flags.contains(.syn) || header.flags.contains(.fin) ? 1 : 0)
            if header.flags.contains(.syn) {
                if TCPSequence.between(header.sequenceNumber, rcvNxt, rcvNxt &+ rcvWnd) {
                    sendReset(sequenceNumber: header.acknowledgmentNumber, acknowledgmentNumber: header.sequenceNumber &+ tcpLength)
                    return
                }
            } else if header.flags.contains(.fin) {
                tmr = stack.ticks
            }
            if tcpLength > 0 {
                flags.insert(.ackNow)
                sendEmptyAck(stack)
            }
        }

        func input(header: TCPHeader, options: UnsafeRawBufferPointer, payload: UnsafeRawBufferPointer) {
            let seqno = header.sequenceNumber
            let ackno = header.acknowledgmentNumber
            let segmentFlags = header.flags
            var tcpLength = UInt32(payload.count) + (segmentFlags.contains(.syn) || segmentFlags.contains(.fin) ? 1 : 0)
            var received: ReceiveFlags = []
            var acked: UInt32 = 0
            var data: UnsafeRawBufferPointer?
            let stack = self.stack
            isProcessingInput = true
            defer { isProcessingInput = false }

            if segmentFlags.contains(.rst) {
                if seqno == rcvNxt {
                    let delegate = self.delegate
                    purge()
                    state = .closed
                    stack.remove(self)
                    detach()
                    delegate?.connection(self, didFailWith: .reset)
                    return
                }
                if TCPSequence.between(seqno, rcvNxt, rcvNxt &+ rcvWnd) {
                    flags.insert(.ackNow)
                }
                finishInput(stack)
                return
            }
            if segmentFlags.contains(.syn), state != .synReceived {
                flags.insert(.ackNow)
                finishInput(stack)
                return
            }
            if !flags.contains(.receiveClosed) {
                tmr = stack.ticks
            }
            persistProbes = 0
            if segmentFlags.contains(.syn) {
                parseOptions(options)
            }

            switch state {
            case .synReceived:
                if segmentFlags.contains(.syn) {
                    if seqno == rcvNxt &- 1 {
                        _ = moveFirstUnackedToUnsent()
                    }
                } else if segmentFlags.contains(.ack) {
                    if TCPSequence.between(ackno, lastAck &+ 1, sndNxt) {
                        state = .established
                        switch stack.acceptHandler?(self) ?? .reset {
                        case .accept:
                            break
                        case .reset:
                            detach()
                            terminate(sendingReset: true, error: nil)
                            return
                        case .drop:
                            detach()
                            terminate(sendingReset: false, error: nil)
                            return
                        }
                        receive(header: header, payload: payload, sequenceNumber: seqno, tcpLength: &tcpLength, received: &received, acked: &acked, data: &data, stack: stack)
                        if acked != 0 {
                            acked -= 1
                        }
                        if received.contains(.gotFin) {
                            flags.insert(.ackNow)
                            state = .closeWait
                        }
                    } else {
                        sendReset(sequenceNumber: ackno, acknowledgmentNumber: seqno &+ tcpLength)
                    }
                }
            case .established, .closeWait:
                receive(header: header, payload: payload, sequenceNumber: seqno, tcpLength: &tcpLength, received: &received, acked: &acked, data: &data, stack: stack)
                if received.contains(.gotFin) {
                    flags.insert(.ackNow)
                    state = .closeWait
                }
            case .finWait1:
                receive(header: header, payload: payload, sequenceNumber: seqno, tcpLength: &tcpLength, received: &received, acked: &acked, data: &data, stack: stack)
                if received.contains(.gotFin) {
                    flags.insert(.ackNow)
                    if segmentFlags.contains(.ack), ackno == sndNxt, unsent.isEmpty {
                        enterTimeWait()
                    } else {
                        state = .closing
                    }
                } else if segmentFlags.contains(.ack), ackno == sndNxt, unsent.isEmpty {
                    state = .finWait2
                }
            case .finWait2:
                receive(header: header, payload: payload, sequenceNumber: seqno, tcpLength: &tcpLength, received: &received, acked: &acked, data: &data, stack: stack)
                if received.contains(.gotFin) {
                    flags.insert(.ackNow)
                    enterTimeWait()
                }
            case .closing:
                receive(header: header, payload: payload, sequenceNumber: seqno, tcpLength: &tcpLength, received: &received, acked: &acked, data: &data, stack: stack)
                if segmentFlags.contains(.ack), ackno == sndNxt, unsent.isEmpty {
                    enterTimeWait()
                }
            case .lastAck:
                receive(header: header, payload: payload, sequenceNumber: seqno, tcpLength: &tcpLength, received: &received, acked: &acked, data: &data, stack: stack)
                if segmentFlags.contains(.ack), ackno == sndNxt, unsent.isEmpty {
                    received.insert(.closed)
                }
            case .timeWait, .closed:
                break
            }

            if acked > 0 {
                delegate?.connection(self, didAcknowledge: Int(acked))
                if state == .closed { return }
            }
            if received.contains(.closed) {
                let delegate = self.delegate
                purge()
                state = .closed
                stack.remove(self)
                if isAttached, !flags.contains(.receiveClosed) {
                    detach()
                    delegate?.connection(self, didFailWith: .closed)
                }
                return
            }
            if let data {
                if flags.contains(.receiveClosed) {
                    terminate(sendingReset: true, error: nil)
                    return
                }
                delegate?.connection(self, didReceive: data)
                if state == .closed { return }
            }
            if received.contains(.gotFin) {
                if rcvWnd != windowMax {
                    rcvWnd += 1
                }
                delegate?.connectionDidReceiveFin(self)
                if state == .closed { return }
            }
            finishInput(stack)
        }

        private func finishInput(_ stack: IPStack) {
            isProcessingInput = false
            if closeAfterInput {
                closeAfterInput = false
                terminate(sendingReset: true, error: nil)
                return
            }
            if state == .timeWait {
                if flags.contains(.ackNow) {
                    sendEmptyAck(stack)
                }
                return
            }
            if !stack.isBatching {
                output()
            }
        }

        private func receive(
            header: TCPHeader,
            payload: UnsafeRawBufferPointer,
            sequenceNumber: UInt32,
            tcpLength: inout UInt32,
            received: inout ReceiveFlags,
            acked: inout UInt32,
            data: inout UnsafeRawBufferPointer?,
            stack: IPStack
        ) {
            let ackno = header.acknowledgmentNumber
            var seqno = sequenceNumber
            var segmentFlags = header.flags
            var dataOffset = 0
            var dataLength = payload.count

            if segmentFlags.contains(.ack) {
                let rightWindowEdge = sndWnd &+ sndWl2
                let scaledWindow = UInt32(header.window) << UInt32(sndScale)
                if TCPSequence.lessThan(sndWl1, seqno)
                    || (sndWl1 == seqno && TCPSequence.lessThan(sndWl2, ackno))
                    || (sndWl2 == ackno && scaledWindow > sndWnd) {
                    sndWnd = scaledWindow
                    if sndWndMax < sndWnd {
                        sndWndMax = sndWnd
                    }
                    sndWl1 = seqno
                    sndWl2 = ackno
                }
                if TCPSequence.lessThanOrEqual(ackno, lastAck) {
                    if tcpLength == 0, sndWl2 &+ sndWnd == rightWindowEdge, rtime >= 0, lastAck == ackno {
                        if dupacks < UInt8.max {
                            dupacks += 1
                        }
                        if dupacks >= 3 {
                            fastRetransmit()
                        }
                    }
                } else if TCPSequence.between(ackno, lastAck &+ 1, sndNxt) {
                    flags.remove(.inFastRecovery)
                    nrtx = 0
                    rto = (sa >> 3) &+ sv
                    dupacks = 0
                    lastAck = ackno
                    acked += freeAcknowledged(&unacked)
                    acked += freeAcknowledged(&unsent)
                    acked += releaseAcknowledgedPrefix(of: unacked.first)
                    acked += releaseAcknowledgedPrefix(of: unsent.first)
                    if unsent.isEmpty {
                        unsentOversize = 0
                    }
                    rtime = unacked.isEmpty ? -1 : 0
                    sndBuf += acked
                    if flags.contains(.rto), (unacked.first ?? unsent.first).map({ TCPSequence.lessThanOrEqual(rtoEnd, $0.sequenceNumber) }) ?? true {
                        flags.remove(.rto)
                    }
                } else {
                    sendEmptyAck(stack)
                }
                if rttest != 0, TCPSequence.lessThan(rtseq, ackno) {
                    var m = Int16(truncatingIfNeeded: stack.ticks &- rttest)
                    m = m &- (sa >> 3)
                    sa = sa &+ m
                    if m < 0 {
                        m = 0 &- m
                    }
                    m = m &- (sv >> 2)
                    sv = sv &+ m
                    rto = (sa >> 3) &+ sv
                    rttest = 0
                }
            }

            if tcpLength > 0, state < .closeWait {
                if TCPSequence.between(rcvNxt, seqno &+ 1, seqno &+ tcpLength &- 1) {
                    let offset = Int(rcvNxt &- seqno)
                    dataOffset += offset
                    dataLength -= offset
                    seqno = rcvNxt
                } else if TCPSequence.lessThan(seqno, rcvNxt) {
                    flags.insert(.ackNow)
                }
                if TCPSequence.between(seqno, rcvNxt, rcvNxt &+ rcvWnd &- 1) {
                    if rcvNxt == seqno {
                        tcpLength = UInt32(dataLength) + (segmentFlags.contains(.syn) || segmentFlags.contains(.fin) ? 1 : 0)
                        if tcpLength > rcvWnd {
                            segmentFlags.remove(.fin)
                            dataLength = Int(rcvWnd)
                            if segmentFlags.contains(.syn) {
                                dataLength -= 1
                            }
                            tcpLength = UInt32(dataLength) + (segmentFlags.contains(.syn) ? 1 : 0)
                        }
                        rcvNxt = seqno &+ tcpLength
                        rcvWnd -= tcpLength
                        _ = updateAnnouncedWindow()
                        if dataLength > 0 {
                            data = UnsafeRawBufferPointer(rebasing: payload[dataOffset..<(dataOffset + dataLength)])
                        }
                        if segmentFlags.contains(.fin) {
                            received.insert(.gotFin)
                        }
                        flags.insert(.ackNow)
                    } else {
                        sendEmptyAck(stack)
                    }
                } else {
                    sendEmptyAck(stack)
                }
            } else if !TCPSequence.between(seqno, rcvNxt, rcvNxt &+ rcvWnd &- 1) {
                flags.insert(.ackNow)
            }
        }

        private func releaseAcknowledgedPrefix(of segment: TCPSegment?) -> UInt32 {
            guard let segment, !segment.isBusy, TCPSequence.lessThan(segment.sequenceNumber, lastAck) else { return 0 }
            let count = Int(lastAck &- segment.sequenceNumber)
            guard count <= segment.length else { return 0 }
            segment.dropPayloadPrefix(count)
            return UInt32(count)
        }

        private func freeAcknowledged(_ queue: inout SegmentList) -> UInt32 {
            var freed: UInt32 = 0
            while let first = queue.first, TCPSequence.lessThanOrEqual(first.sequenceNumber &+ first.tcpLength, lastAck) {
                freed += UInt32(first.length)
                _ = queue.removeFirst()
                arena.recycle(first)
            }
            return freed
        }
    }
}
