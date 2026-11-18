import Foundation

nonisolated enum SessionBuilder {
    /// Decode and fold every frame through the shared `SessionAccumulator`, then
    /// emit summaries in first-seen five-tuple order.
    ///
    /// Frames arrive in capture order, so first-seen order is chronological
    /// (oldest→newest): a rebuild with later packets for known five-tuples leaves
    /// their rows at the same indices, and a genuinely new session appends at the
    /// tail instead of shifting the whole table down. This is the exact same fold
    /// the live `LiveSessionEngine` runs incrementally, so a snapshot after
    /// ingesting a set of frames equals this batch build over the same frames —
    /// byte for byte.
    static func build(from frames: [CapturedFrame], linkType: UInt32) -> [SessionSummary] {
        buildDetailed(from: frames, linkType: linkType).sessions
    }

    /// The additive detailed build: decode and fold every frame once through the
    /// common ``SessionAccumulator`` path, then emit the session summaries plus the
    /// connection snapshot for the same ordered frames. `build` is exactly its
    /// `.sessions`, so the batch session semantics are unchanged byte for byte.
    ///
    /// - Parameter connectionConfiguration: bounds for the fold's connection table,
    ///   injectable so a bounds test can force tiny caps.
    static func buildDetailed(
        from frames: [CapturedFrame],
        linkType: UInt32,
        connectionConfiguration: ConnectionTable.Configuration = ConnectionTable.Configuration()
    )
        -> SessionFoldSnapshot
    {
        var accumulator = SessionAccumulator(connectionConfiguration: connectionConfiguration)
        var sequential = SequentialFrameDecoder()
        for (index, frame) in frames.enumerated() {
            let packet = sequential.decode(frame, linkType: linkType, ordinal: UInt64(index + 1))
            accumulator.add(
                packet,
                context: frameContext(
                    for: frame, linkType: linkType, reassembledFrom: sequential.lastReassembledFrom
                )
            )
        }
        return accumulator.foldSnapshot()
    }

    /// The format-neutral fold context for a `CapturedFrame`: its truthful captured
    /// length, the intrinsic per-frame link type (falling back to the source
    /// default), no evidence locator — batch and live frames fabricate none — and
    /// unknown loss. Shared by the batch build and the live engine so both supply
    /// identical frame metadata.
    static func frameContext(
        for frame: CapturedFrame,
        linkType: UInt32,
        reassembledFrom: [SessionFrameProvenance] = []
    )
        -> SessionFrameContext
    {
        SessionFrameContext(
            capturedLength: frame.capturedLength,
            linkType: frame.linkType ?? linkType,
            locator: nil,
            loss: .unknown,
            reassembledFrom: reassembledFrom
        )
    }

    /// Stable identity shared by session accumulation and explicit session export.
    /// Keeping the derivation here prevents an export from widening to frames
    /// belonging to another five-tuple.
    static func sessionID(for key: FiveTuple) -> UUID {
        stableID("\(key.proto.rawValue)|\(key.a.display)|\(key.b.display)")
    }

    /// Decode one frame into a `DecodedPacket`, carrying its raw bytes and process
    /// name through. The frame's own link type wins when present (live helper
    /// frames each carry their DLT); otherwise the batch/file link type is used.
    ///
    /// This is the single decode step shared by the batch `build` and the
    /// incremental `LiveSessionEngine`, so both produce byte-identical decodes.
    static func decodePacket(_ frame: CapturedFrame, linkType: UInt32) -> DecodedPacket {
        var packet = PacketDecoder.decode(
            PacketBuffer(frame.bytes), linkType: frame.linkType ?? linkType,
            timestamp: frame.timestamp, originalLength: frame.originalLength
        )
        packet.rawBytes = frame.bytes
        packet.processName = frame.processName
        packet.processProvenance = frame.processProvenance
        return packet
    }

    /// Fold one packet's DNS answers and Fake-IP TLS/QUIC SNI into the IP→hostname
    /// map. Applied in packet order (last write wins), identical whether accumulated
    /// incrementally or in a single batch pass.
    static func learnResolved(from packet: DecodedPacket, into resolved: inout [String: String]) {
        // Multicast DNS answers are how Bonjour devices name themselves on the local
        // network, so they teach names exactly like unicast DNS answers.
        if [.dns, .mdns, .llmnr].contains(packet.appProtocol),
           let name = packet.dnsQuery, !name.isEmpty
        {
            for answer in packet.dnsAnswers where !answer.hasPrefix("CNAME") {
                resolved[answer] = name
            }
        }
        // Transparent-proxy and TUN routers allocate virtual addresses from RFC 2544
        // 198.18.0.0/15 or IPv6 ULA fc00::/7. Learning SNI against that Fake-IP lets
        // sibling flows to the same virtual destination resolve their host in the same
        // pass even when DNS happened before capture started.
        if let sni = packet.sni, !sni.isEmpty {
            if let dstIP = packet.destinationEndpoint?.ip, isFakeIPAddress(dstIP) {
                resolved[dstIP] = sni
            } else if let src = packet.sourceEndpoint, isFakeIPAddress(src.ip) {
                let dstPort = packet.destinationEndpoint?.port ?? 0
                let isClientDialingService = !SessionAccumulator.isLikelyServerPort(src.port)
                    && SessionAccumulator.isLikelyServerPort(dstPort)
                if !isClientDialingService {
                    resolved[src.ip] = sni
                }
            }
        }
    }

    /// Whether `ip` falls in a Fake-IP virtual address pool: RFC 2544 benchmarking
    /// `198.18.0.0/15` (`198.18.0.0`–`198.19.255.255`) or IPv6 ULA `fc00::/7`.
    static func isFakeIPAddress(_ ip: String) -> Bool {
        guard let parsed = IPAddressValue(parsing: ip) else {
            return false
        }
        switch parsed.family {
        case .v4:
            return parsed.bytes[0] == 198 && (parsed.bytes[1] & 0xFE) == 18
        case .v6:
            return (parsed.bytes[0] & 0xFE) == 0xFC
        }
    }

    /// Resolve the display host from the session's decoded signals, in priority
    /// order: DNS query name, TLS SNI, HTTP Host header, a reverse-resolved name
    /// for the server IP, the raw server IP, then the client IP. Shared with
    /// `SessionAccumulator` so batch and live builds agree.
    static func resolveHost(
        appProto: ProtocolKind?, dnsQuery: String?, sni: String?,
        httpHost: String?, serverIP: String, resolved: [String: String], clientIP: String?
    )
        -> String
    {
        if appProto == .dns || appProto == .mdns || appProto == .llmnr, let query = dnsQuery {
            return query
        }
        if let sni {
            return sni
        }
        if let host = httpHost, !host.isEmpty, host != "—" {
            return host
        }
        if let name = resolved[serverIP] {
            return name
        }
        if !serverIP.isEmpty {
            return serverIP
        }
        return clientIP ?? "unknown"
    }

    /// A deterministic UUID derived from a string (two FNV-1a passes → 16 bytes).
    /// The same 5-tuple keeps the same session id across rebuilds, so the table
    /// selection survives when new packets arrive. Shared with `SessionAccumulator`.
    static func stableID(_ string: String) -> UUID {
        func fnv(_ seed: UInt64) -> UInt64 {
            var hash = seed
            for byte in string.utf8 {
                hash ^= UInt64(byte)
                hash &*= 1_099_511_628_211
            }
            return hash
        }
        let high = fnv(14_695_981_039_346_656_037).bigEndian
        let low = fnv(0xCBF29CE484222325).bigEndian
        return withUnsafeBytes(of: (high, low)) { raw in
            var uuid = uuid_t(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
            withUnsafeMutableBytes(of: &uuid) { $0.copyMemory(from: raw) }
            return UUID(uuid: uuid)
        }
    }
}
