import Foundation

// MARK: - DecodedField

nonisolated struct DecodedField: Hashable, Sendable {
    // MARK: Lifecycle

    init(name: String, value: String, byteRange: Range<Int>? = nil) {
        self.name = name
        self.value = value
        self.byteRange = byteRange
    }

    // MARK: Internal

    let name: String
    let value: String
    /// Absolute byte range of this field within the frame's `rawBytes`, for
    /// hex highlighting. `nil` when the field isn't backed by contiguous bytes.
    var byteRange: Range<Int>?

    /// Identity is name + value; `byteRange` is positional metadata and is
    /// deliberately excluded so golden-fixture equality in tests stays stable.
    static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.name == rhs.name && lhs.value == rhs.value
    }

    func hash(into hasher: inout Hasher) {
        hasher.combine(name)
        hasher.combine(value)
    }
}

// MARK: - DecodedLayer

/// One protocol layer in the decode tree (Eth → IP → TCP → TLS …).
nonisolated struct DecodedLayer: Hashable, Identifiable, Sendable {
    // MARK: Lifecycle

    init(
        proto: ProtocolKind,
        title: String,
        summary: String = "",
        fields: [DecodedField] = [],
        children: [DecodedLayer] = [],
        byteRange: Range<Int>? = nil
    ) {
        self.proto = proto
        self.title = title
        self.summary = summary
        self.fields = fields
        self.children = children
        self.byteRange = byteRange
        decodeAsTargets = DecodeAsPacketTargets.from(proto: proto, fields: fields)
    }

    // MARK: Internal

    let id = UUID()
    let proto: ProtocolKind
    let title: String
    var summary: String
    var fields: [DecodedField]
    var children: [DecodedLayer]
    /// Absolute byte range of this whole layer within the frame's `rawBytes`.
    var byteRange: Range<Int>?
    /// Port selectors from the complete decode, retained when a display projection
    /// hides unrelated fields such as source and destination ports.
    let decodeAsTargets: [DecodeAsPacketTarget]

    /// Identity is the decoded content, not the per-instance `id`. Two decodes of
    /// the same bytes produce structurally equal layers with *different* random
    /// ids; excluding `id` here keeps golden-fixture and session-equivalence
    /// comparisons stable (the same reasoning `DecodedField` applies to
    /// `byteRange`). `id` remains for SwiftUI `Identifiable` diffing.
    static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.proto == rhs.proto
            && lhs.title == rhs.title
            && lhs.summary == rhs.summary
            && lhs.fields == rhs.fields
            && lhs.children == rhs.children
            && lhs.decodeAsTargets == rhs.decodeAsTargets
    }

    func hash(into hasher: inout Hasher) {
        hasher.combine(proto)
        hasher.combine(title)
        hasher.combine(summary)
        hasher.combine(fields)
        hasher.combine(children)
        hasher.combine(decodeAsTargets)
    }
}

// MARK: - DecodeStop

/// Why decoding a frame stopped before its last header, as Wireshark's Expert
/// Info separates them: a header the decoder rejected, or a frame the capture's
/// snapshot length cut inside a header.
nonisolated enum DecodeStop: Hashable, Sendable {
    case malformed(String)
    case cutShort

    // MARK: Internal

    /// Wireshark's Info-column suffix.
    var infoSuffix: String {
        switch self {
        case .malformed: "[Malformed Packet]"
        case .cutShort: "[Packet size limited during capture]"
        }
    }

    var explanation: String {
        switch self {
        case let .malformed(reason):
            String(localized: "Malformed: \(reason). Layers after the problem were not decoded.")
        case .cutShort:
            String(
                localized: "The capture's snapshot length cut this frame inside a header, so later layers are missing."
            )
        }
    }
}

// MARK: - IPFragmentFacts

/// One IPv4 or IPv6 fragment, read from its own header.
nonisolated struct IPFragmentFacts: Equatable, Sendable {
    enum Version: Equatable, Sendable {
        case v4
        case v6
    }

    let version: Version
    let source: String
    let destination: String
    /// The IPv4 Identification or the IPv6 Fragment header's Identification.
    let identification: UInt32
    /// The protocol the reassembled datagram carries (IPv4 Protocol, or the IPv6
    /// Fragment header's Next Header).
    let protocolNumber: UInt8
    /// Byte offset of this fragment's payload in the datagram.
    let offset: Int
    let moreFragments: Bool
    /// This fragment's payload within the frame's `rawBytes`, bounded by the
    /// header's declared length.
    let payloadRange: Range<Int>
    /// `false` when the snapshot length cut the payload short, so the datagram can
    /// never be rebuilt from this capture.
    let isPayloadComplete: Bool
}

// MARK: - IPReassemblyFacts

/// What a reassembled datagram was built from, carried on the completing frame.
nonisolated struct IPReassemblyFacts: Equatable, Sendable {
    let version: IPFragmentFacts.Version
    /// Total reassembled length (the transport header and its payload).
    let length: Int
    /// The one-based ordinals of the frames whose fragments made the datagram, in
    /// datagram-offset order; the completing frame is among them.
    let frames: [UInt64]
}

// MARK: - DNSAddressBinding

/// One validated `(ip, hostname)` binding recovered from a DNS/mDNS/LLMNR answer or
/// additional resource record. Kept separate from raw `dnsQuery` / `dnsAnswers` wire
/// projections so multicast service-discovery frames (`_companion-link._tcp.local`,
/// `QDCOUNT == 0` announcements, Bonjour `Additional` glue) bind each unicast `A`/`AAAA`
/// address to its true owner hostname rather than the session's first question string.
nonisolated struct DNSAddressBinding: Codable, Equatable, Hashable, Sendable {
    let ip: String
    let hostname: String
}

// MARK: - DNSNameSanitizer

/// Pure validation and canonicalization gates shared across packet decoding, session
/// host learning, Resolved Addresses presentation, and persisted `AddressNameBook`
/// cache loading/scrubbing.
nonisolated enum DNSNameSanitizer {
    // MARK: Internal

    /// Returns a cleaned, display-worthy host/domain name, or `nil` when `raw` is empty,
    /// placeholder text, a DNS-SD/SRV underscore label (`_companion-link._tcp.local`,
    /// `lb._dns-sd._udp.local`, `_https._tcp.example.com`), a reverse-lookup `.arpa`
    /// zone, a bare IP literal, or an anonymous UUID pseudo-host. Valid `.local` device
    /// names (`TestPhone.local`, `OfficeMac.local`) are preserved.
    static func sanitizedHostname(_ raw: String) -> String? {
        var candidate = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !candidate.isEmpty, candidate != "—" else {
            return nil
        }
        if candidate.hasSuffix("."), !candidate.hasSuffix("..") {
            candidate.removeLast()
        }
        guard !candidate.isEmpty, candidate.count <= 253 else {
            return nil
        }
        guard !candidate.contains(where: { $0.isWhitespace }),
              !candidate.unicodeScalars.contains(where: { $0.value <= 0x1F || $0.value == 0x7F }) else
        {
            return nil
        }
        if IPAddressValue(parsing: candidate) != nil {
            return nil
        }
        if candidate.hasPrefix("["), candidate.hasSuffix("]"),
           IPAddressValue(parsing: String(candidate.dropFirst().dropLast())) != nil
        {
            return nil
        }
        let lower = candidate.lowercased()
        if lower == "in-addr.arpa" || lower.hasSuffix(".in-addr.arpa")
            || lower == "ip6.arpa" || lower.hasSuffix(".ip6.arpa")
        {
            return nil
        }
        let labels = candidate.split(separator: ".", omittingEmptySubsequences: false)
        guard !labels.isEmpty else {
            return nil
        }
        for label in labels {
            if label.isEmpty || label.count > 63 || label.hasPrefix("_") {
                return nil
            }
        }
        if labels.count == 1, isBareUUIDLabel(labels[0]) {
            return nil
        }
        if labels.count == 2, labels[1].lowercased() == "local", isBareUUIDLabel(labels[0]) {
            return nil
        }
        return candidate
    }

    static func isValidHostname(_ raw: String) -> Bool {
        sanitizedHostname(raw) != nil
    }

    /// Rejects non-unicast target addresses that must never receive a learned hostname:
    /// unspecified (`0.0.0.0`, `::`), limited broadcast (`255.255.255.255`), IPv4
    /// multicast (`224.0.0.0/4`), and IPv6 multicast (`ff00::/8`).
    static func isValidUnicastTargetIP(_ address: IPAddressValue) -> Bool {
        switch address.family {
        case .v4:
            guard address.bytes.count == 4 else {
                return false
            }
            if address.bytes == [0, 0, 0, 0] || address.bytes == [255, 255, 255, 255] {
                return false
            }
            if (address.bytes[0] & 0xF0) == 224 {
                return false
            }
            return true
        case .v6:
            guard address.bytes.count == 16 else {
                return false
            }
            if address.bytes.allSatisfy({ $0 == 0 }) {
                return false
            }
            if address.bytes[0] == 0xFF {
                return false
            }
            return true
        }
    }

    static func sanitizedUnicastIP(_ raw: String) -> IPAddressValue? {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let parsed = IPAddressValue(parsing: trimmed),
              isValidUnicastTargetIP(parsed) else
        {
            return nil
        }
        return parsed
    }

    /// Restricts IPv6 Fake-IP detection to virtual proxy pools actually used in practice:
    /// Sing-box default `fc00::/18` (`fc00:0000::`–`fc00:3fff:ffff:...`, 16 bits of
    /// `0xFC, 0x00` plus top 2 bits of `bytes[2]`) and Clash/Mihomo default
    /// `fdfe:dcba:9876::/48`, excluding standard `fd00::/8` home-router SLAAC ULA hosts.
    static func isIPv6FakeIP(_ address: IPAddressValue) -> Bool {
        guard address.family == .v6, address.bytes.count == 16 else {
            return false
        }
        let bytes = address.bytes
        let isSingBoxPool = bytes[0] == 0xFC && bytes[1] == 0x00 && (bytes[2] & 0xC0) == 0x00
        let isClashPool = bytes[0] == 0xFD
            && bytes[1] == 0xFE
            && bytes[2] == 0xDC
            && bytes[3] == 0xBA
            && bytes[4] == 0x98
            && bytes[5] == 0x76
        return isSingBoxPool || isClashPool
    }

    // MARK: Private

    private static func isBareUUIDLabel(_ label: Substring) -> Bool {
        let text = String(label)
        if UUID(uuidString: text) != nil {
            return true
        }
        if text.count == 32, text.allSatisfy(\.isHexDigit) {
            return true
        }
        return false
    }
}

// MARK: - DecodedPacket

nonisolated struct DecodedPacket {
    // MARK: Lifecycle

    init(timestamp: Date?, originalLength: Int) {
        self.timestamp = timestamp
        self.originalLength = originalLength
        layers = []
        dnsAnswers = []
    }

    // MARK: Internal

    /// When the frame was captured, or `nil` when the source carried no capture
    /// time at all (a pcapng Simple Packet Block). Absence stays absent: it is
    /// never replaced by the Unix epoch, the file's open instant, or "now".
    var timestamp: Date?
    var originalLength: Int
    /// The captured on-wire bytes of this packet (≤ snaplen), retained for the
    /// inspector's hex pane. Empty if not built from a real frame.
    var rawBytes: [UInt8] = []
    /// Originating process (from pktap), propagated to the session. nil = unknown.
    var processName: String?
    /// Originating process provenance (from pktap / root socket fallback), propagated to the session.
    var processProvenance: ProcessProvenance? = nil
    var layers: [DecodedLayer]
    /// Set when decoding stopped early; `nil` when every header read cleanly.
    var decodeStop: DecodeStop?
    var fiveTuple: FiveTuple?
    var transport: ProtocolKind?
    var appProtocol: ProtocolKind?
    /// A protocol this frame shows the session switched to or negotiated: HTTP/2 (a
    /// cleartext preface, or ALPN "h2" chosen in a visible ServerHello) or WebSocket
    /// (an HTTP/1 Upgrade). Added to the session's stack.
    var negotiatedApplication: ProtocolKind?
    var sni: String?
    var dnsQuery: String?
    var dnsAnswers: [String]
    /// Validated per-record `(ip, hostname)` bindings extracted from DNS/mDNS/LLMNR
    /// Answer and Additional sections, bounded to 64 entries per packet.
    var dnsResolvedBindings: [DNSAddressBinding] = []
    /// Number of valid DNS answer-record occurrences decoded beyond the per-packet
    /// retention cap. This is an occurrence count, not exact unique cardinality;
    /// exact uniqueness for an unbounded stream would itself require unbounded state.
    var dnsAnswersOmittedCount: Int = 0
    /// The first question's QTYPE, when the question section was intact.
    var dnsQueryType: UInt16?
    /// The first question's class (1 = IN).
    var dnsQueryClass: UInt16?
    /// Each answer record's type, in order, at most 64.
    var dnsAnswerTypes: [UInt16] = []
    /// The DNS message's length in bytes (without a TCP length prefix).
    var dnsMessageLength: Int?
    /// A SIP message's start line and dialog headers, for Statistics ▸ SIP.
    var sip: SIPMessageFacts?
    /// Human-readable answer records ("A 192.0.2.1", "CNAME host.example"), the same
    /// strings the decode tree shows, under the same retention cap as `dnsAnswers`.
    var dnsAnswerRecords: [String] = []
    /// Typed, decode-derived facts for a TCP segment, read from exact header
    /// offsets. `nil` for non-TCP packets. Session logic reads control bits from
    /// here rather than string-matching a rendered field.
    var tcpFacts: TCPSegmentFacts?
    /// Typed, decode-derived DNS fixed-header facts, read once from exact offsets.
    /// `nil` for non-DNS packets or when the fixed 12-byte header was incomplete.
    /// These are neutral wire facts only — no finding, name/answer values or raw bytes.
    var dnsFacts: DNSMessageFacts?
    /// Typed ICMP/ICMPv6 family/type/code facts. `nil` for non-ICMP packets or when
    /// both fixed bytes were not present. Family is the already-known IP protocol.
    var icmpFacts: ICMPMessageFacts?
    /// Typed SCTP common-header and chunk-type facts (RFC 4960). `nil` for non-SCTP
    /// packets and when the fixed 12-byte common header was not fully captured.
    /// Session logic reads control chunks from here, never from a rendered field.
    var sctpFacts: SCTPFacts?
    /// Neutral, decode-derived TLS record facts, one per recognized record in this
    /// packet's coalesced TLS payload. Bounded to the same 32-record walk as the
    /// renderer; these are numeric wire facts only — no policy label, SNI, or payload.
    var tlsRecords: [TLSRecordFact] = []
    /// `true` when the 32-record TLS walk stopped with a further recognizable record
    /// header still present, so `tlsRecords` is an explicit truncation, not exhaustion.
    var tlsRecordsTruncated: Bool = false
    var sourceEndpoint: IPEndpoint?
    var destinationEndpoint: IPEndpoint?
    /// Sequence number of the first TCP payload byte and its captured bytes.
    /// Session accumulation uses this bounded handoff for metadata-only stream
    /// reassembly; packet decoding itself remains stateless.
    var tcpPayloadSequence: UInt32?
    var tcpPayloadBytes: [UInt8] = []
    /// Absolute range of a UDP datagram's captured payload within `rawBytes`,
    /// clamped to the UDP-declared length when that length is trustworthy. A
    /// range, not a copy, so the always-on fold pays nothing for it; only an
    /// explicit on-demand reader slices the bytes out.
    var udpPayloadRange: Range<Int>?
    /// Payload length the UDP header declared (`length - 8`), or `nil` when the
    /// field was absent, zero (offload) or below the header size.
    var udpDeclaredPayloadLength: Int?
    /// How many tunnels (GRE, VXLAN) this frame was unwrapped through; bounds nesting.
    var tunnelDepth = 0
    /// True when a recognized IP tunnel could not be unwrapped because the depth
    /// limit was reached, so inner-header filters must retain unknown semantics.
    var undecodedInnerIPHeader = false
    /// Set when this frame is one fragment of a larger IP datagram. Decoding stops
    /// at the IP layer for every fragment — the first one too, since its transport
    /// payload is incomplete — and the fragment's payload range is kept for the
    /// sequential reassembler.
    var ipFragment: IPFragmentFacts?
    /// Set on the frame whose fragment completed a datagram: the transport and
    /// application layers above come from the reassembled bytes (they carry no byte
    /// ranges, since those bytes span several frames).
    var reassembly: IPReassemblyFacts?
    /// The reassembled transport payload of a UDP datagram, when this frame
    /// completed one. `udpPayloadRange` is `nil` then: the bytes are not in
    /// `rawBytes`.
    var reassembledUDPPayload: [UInt8]?

    /// Protocol stack outer→inner, e.g. [.tcp, .tls]. Used by the session list.
    ///
    /// Outer link framing is excluded: Ethernet and Linux cooked capture (SLL)
    /// describe how the frame was carried, not what the session is, and dropping
    /// them keeps the bounded history capacity for inner protocols.
    var protocolStack: [ProtocolKind] {
        var seen = Set<ProtocolKind>()
        // A tunnelled frame is a session of its *inner* flow: the stack starts at the
        // innermost tunnel, so outer transport never mixes with inner (a TCP flow
        // carried in VXLAN is not also a UDP session).
        let start = layers.lastIndex { $0.proto == .gre || $0.proto == .vxlan } ?? layers.startIndex
        return layers[start...].map(\.proto).filter {
            $0 != .ethernet && $0 != .linuxCooked && seen.insert($0).inserted
        }
    }
}
