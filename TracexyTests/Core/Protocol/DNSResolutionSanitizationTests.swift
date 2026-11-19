import Foundation
import Testing
@testable import Tracexy

// MARK: - DNSResolutionSanitizationTests

@Suite("DNS and mDNS owner-hostname binding, sanitization, and cache scrubbing")
struct DNSResolutionSanitizationTests {
    // MARK: Internal

    @Test("Bonjour PTR response binds Additional A/AAAA records to their own RR owner hostname")
    func mdnsPTRResponseBindsAdditionalAddressesToOwnerHostname() async throws {
        // Real Bonjour pattern: Question 0 asks PTR `_companion-link._tcp.local`,
        // Answer carries PTR `TestUnit._companion-link._tcp.local`, Authority carries
        // an NSEC record, and Additional carries SRV + TXT + cache-flush A/AAAA owned
        // by `TestPhone.local`.
        let mdnsPayload = Self.dnsWireMessage(
            id: 0,
            flags: 0x8400,
            questions: [("_companion-link._tcp.local", 12, 1)],
            answers: [
                Self.ptrRecord(owner: "_companion-link._tcp.local", target: "TestUnit._companion-link._tcp.local"),
            ],
            authorities: [
                Self.rawRecord(owner: "TestPhone.local", type: 47, rrClass: 0x8001, rdata: [0x00, 0x04, 0x40, 0x00, 0x00, 0x08]),
            ],
            additionals: [
                Self.srvRecord(owner: "TestUnit._companion-link._tcp.local", port: 49_152, target: "TestPhone.local"),
                Self.txtRecord(owner: "TestUnit._companion-link._tcp.local", text: "rpBA=00:11:22:33:44:55"),
                Self.aRecord(owner: "TestPhone.local", rrClass: 0x8001, ipv4: [192, 0, 2, 10]),
                Self.aaaaRecord(
                    owner: "TestPhone.local",
                    rrClass: 0x8001,
                    ipv6: [0xFD00, 0x0060, 0, 0, 0, 0, 0, 0x1234]
                ),
            ]
        )
        let mdnsBytes = PacketBuilder.ethernetIPv4(
            proto: 17,
            src: "192.0.2.10",
            dst: "224.0.0.251",
            payload: PacketBuilder.udp(srcPort: 5_353, dstPort: 5_353, payload: mdnsPayload)
        )
        let mdnsFrame = CapturedFrame(
            bytes: mdnsBytes,
            timestamp: Self.baseTime,
            originalLength: mdnsBytes.count
        )

        let decoded = SessionBuilder.decodePacket(mdnsFrame, linkType: LinkType.ethernet)
        #expect(decoded.appProtocol == .mdns)
        #expect(decoded.dnsQuery == "_companion-link._tcp.local")
        #expect(decoded.dnsResolvedBindings == [
            DNSAddressBinding(ip: "192.0.2.10", hostname: "TestPhone.local"),
            DNSAddressBinding(ip: "fd00:60::1234", hostname: "TestPhone.local"),
        ])

        let tcpV4Bytes = PacketBuilder.tcpSynFrame(
            src: "192.0.2.50", dst: "192.0.2.10", srcPort: 51_000, dstPort: 62_078
        )
        let tcpV6Bytes = PacketBuilder.ethernetIPv6(
            nextHeader: 6,
            src: [0xFD00, 0x0060, 0, 0, 0, 0, 0, 0x0001],
            dst: [0xFD00, 0x0060, 0, 0, 0, 0, 0, 0x1234],
            payload: PacketBuilder.tcp(srcPort: 51_001, dstPort: 443, flags: 0x02, payload: [])
        )
        let frames = [
            mdnsFrame,
            CapturedFrame(bytes: tcpV4Bytes, timestamp: Self.baseTime.addingTimeInterval(1), originalLength: tcpV4Bytes.count),
            CapturedFrame(bytes: tcpV6Bytes, timestamp: Self.baseTime.addingTimeInterval(2), originalLength: tcpV6Bytes.count),
        ]

        let sessions = SessionBuilder.build(from: frames, linkType: LinkType.ethernet)
        #expect(sessions.count == 3)
        #expect(sessions[1].host == "TestPhone.local")
        #expect(sessions[2].host == "TestPhone.local")

        let engine = LiveSessionEngine()
        await engine.reset(epoch: 1)
        await engine.ingest(frames, linkType: LinkType.ethernet, epoch: 1)
        let liveSessions = try #require(await engine.snapshot(epoch: 1))
        #expect(liveSessions == sessions)

        let rows = await MainActor.run {
            ResolvedAddresses.rows(sessions: sessions, namedAddresses: [:])
        }
        #expect(rows.map { "\($0.address)=\($0.name)" } == [
            "192.0.2.10=TestPhone.local",
            "fd00:60::1234=TestPhone.local",
        ])

        await MainActor.run {
            let book = AddressNameBook()
            book.learn(from: sessions)
            #expect(book.learnedName(for: "192.0.2.10") == "TestPhone.local")
            #expect(book.learnedName(for: "fd00:60::1234") == "TestPhone.local")
            #expect(!book.learnedNames.values.contains("_companion-link._tcp.local"))
        }
    }

    @Test("Gratuitous QDCOUNT=0 mDNS announcement on a shared five-tuple never inherits prior service query")
    func gratuitousMDNSOnSharedFiveTupleUsesRecordOwnerAndDropsBogusTargets() throws {
        // Packet 1 on (192.0.2.10:5353 -> 224.0.0.251:5353): service browse `lb._dns-sd._udp.local`.
        let browsePayload = Self.dnsWireMessage(
            id: 0,
            flags: 0x0000,
            questions: [("lb._dns-sd._udp.local", 12, 1)],
            answers: [],
            authorities: [],
            additionals: []
        )
        // Packet 2 on the SAME five-tuple: gratuitous announcement (QDCOUNT == 0) carrying
        // a valid device A record, a bogus 0.0.0.0 A record, a multicast A record, and a
        // service-named A record.
        let announcePayload = Self.dnsWireMessage(
            id: 0,
            flags: 0x8400,
            questions: [],
            answers: [
                Self.aRecord(owner: "OfficeMac.local", rrClass: 0x8001, ipv4: [192, 0, 2, 10]),
                Self.aRecord(owner: "OfficeMac.local", rrClass: 0x8001, ipv4: [0, 0, 0, 0]),
                Self.aRecord(owner: "OfficeMac.local", rrClass: 0x8001, ipv4: [224, 0, 0, 251]),
                Self.aRecord(owner: "_companion-link._tcp.local", rrClass: 0x8001, ipv4: [192, 0, 2, 99]),
            ],
            authorities: [],
            additionals: []
        )

        let frame1Bytes = PacketBuilder.ethernetIPv4(
            proto: 17, src: "192.0.2.10", dst: "224.0.0.251",
            payload: PacketBuilder.udp(srcPort: 5_353, dstPort: 5_353, payload: browsePayload)
        )
        let frame2Bytes = PacketBuilder.ethernetIPv4(
            proto: 17, src: "192.0.2.10", dst: "224.0.0.251",
            payload: PacketBuilder.udp(srcPort: 5_353, dstPort: 5_353, payload: announcePayload)
        )
        let peerGoodTCP = PacketBuilder.tcpSynFrame(
            src: "192.0.2.50", dst: "192.0.2.10", srcPort: 52_000, dstPort: 443
        )
        let peerServiceTCP = PacketBuilder.tcpSynFrame(
            src: "192.0.2.50", dst: "192.0.2.99", srcPort: 52_001, dstPort: 443
        )

        let frames = [frame1Bytes, frame2Bytes, peerGoodTCP, peerServiceTCP].enumerated().map { index, bytes in
            CapturedFrame(
                bytes: bytes,
                timestamp: Self.baseTime.addingTimeInterval(Double(index)),
                originalLength: bytes.count
            )
        }
        let sessions = SessionBuilder.build(from: frames, linkType: LinkType.ethernet)
        #expect(sessions.count == 3)
        let mdnsSession = try #require(sessions.first { $0.protocolStack.contains(.mdns) })
        #expect(mdnsSession.dnsQuery == "lb._dns-sd._udp.local")
        #expect(mdnsSession.dnsResolvedBindings == [
            DNSAddressBinding(ip: "192.0.2.10", hostname: "OfficeMac.local"),
        ])
        #expect(sessions[1].host == "OfficeMac.local")
        #expect(sessions[2].host == "192.0.2.99")
    }

    @Test("Unicast DNS CNAME chain maps target A/AAAA back to Question 0 while SRV glue uses RR owner")
    func unicastDNSCNAMEChainAndSRVGlueBindings() {
        let cnamePayload = Self.dnsWireMessage(
            id: 0x2222,
            flags: 0x8180,
            questions: [("api.example.test", 1, 1)],
            answers: [
                Self.cnameRecord(owner: "api.example.test", target: "edge.cdn.example.test"),
                Self.aRecord(owner: "edge.cdn.example.test", rrClass: 1, ipv4: [203, 0, 113, 25]),
                Self.aaaaRecord(
                    owner: "edge.cdn.example.test",
                    rrClass: 1,
                    ipv6: [0x2001, 0x0DB8, 0, 0, 0, 0, 0, 0x0025]
                ),
            ],
            authorities: [],
            additionals: []
        )
        let cnamePacket = Self.decodeUDP(cnamePayload, sport: 53, dport: 54_000)
        #expect(cnamePacket.dnsResolvedBindings == [
            DNSAddressBinding(ip: "203.0.113.25", hostname: "api.example.test"),
            DNSAddressBinding(ip: "2001:db8::25", hostname: "api.example.test"),
        ])

        // SRV query with EDNS0 OPT pseudo-record + Additional A glue.
        let srvPayload = Self.dnsWireMessage(
            id: 0x3333,
            flags: 0x8180,
            questions: [("_https._tcp.example.test", 33, 1)],
            answers: [
                Self.srvRecord(owner: "_https._tcp.example.test", port: 443, target: "gw.example.test"),
            ],
            authorities: [],
            additionals: [
                Self.rawRecord(owner: "", type: 41, rrClass: 4_096, rdata: []), // EDNS0 OPT root record
                Self.aRecord(owner: "gw.example.test", rrClass: 1, ipv4: [203, 0, 113, 30]),
            ]
        )
        let srvPacket = Self.decodeUDP(srvPayload, sport: 53, dport: 54_001)
        #expect(srvPacket.dnsResolvedBindings == [
            DNSAddressBinding(ip: "203.0.113.30", hostname: "gw.example.test"),
        ])

        // Truncated Additional tail keeps intact Question + Answer records without crashing.
        var truncatedTail = cnamePayload
        truncatedTail[10] = 0x00
        truncatedTail[11] = 0x02 // claim 2 Additional records when only 3 garbage bytes follow
        truncatedTail += [0x03, 0x62, 0x61]
        let truncatedPacket = Self.decodeUDP(truncatedTail, sport: 53, dport: 54_002)
        #expect(truncatedPacket.appProtocol == .dns)
        #expect(truncatedPacket.dnsAnswers == ["203.0.113.25", "2001:db8:0:0:0:0:0:25"])
        #expect(truncatedPacket.dnsResolvedBindings == [
            DNSAddressBinding(ip: "203.0.113.25", hostname: "api.example.test"),
            DNSAddressBinding(ip: "2001:db8::25", hostname: "api.example.test"),
        ])
    }

    @Test("DNSNameSanitizer enforces hostname and unicast-IP gates consistently")
    func sanitizerRejectsServiceReverseUUIDAndNonUnicastInputs() {
        let invalidHosts = [
            "",
            "   ",
            "—",
            ".",
            "..",
            "bad..example.test",
            "_companion-link._tcp.local",
            "lb._dns-sd._udp.local",
            "_https._tcp.example.com",
            "Unit._airplay._tcp.local",
            "10.2.0.192.in-addr.arpa",
            "10.2.0.192.IN-ADDR.ARPA.",
            "1.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa",
            "192.0.2.10",
            "2001:db8::1",
            "[2001:db8::1]",
            "550e8400-e29b-41d4-a716-446655440000",
            "550E8400-E29B-41D4-A716-446655440000.local",
            "550e8400e29b41d4a716446655440000",
        ]
        for host in invalidHosts {
            #expect(DNSNameSanitizer.sanitizedHostname(host) == nil, "Expected invalid hostname: \(host)")
        }

        #expect(DNSNameSanitizer.sanitizedHostname("TestPhone.local") == "TestPhone.local")
        #expect(DNSNameSanitizer.sanitizedHostname("OfficeMac.local.") == "OfficeMac.local")
        #expect(DNSNameSanitizer.sanitizedHostname("API.Example.test") == "API.Example.test")

        let invalidIPs = [
            "0.0.0.0",
            "::",
            "0:0:0:0:0:0:0:0",
            "255.255.255.255",
            "224.0.0.1",
            "224.0.0.251",
            "239.255.255.250",
            "ff00::1",
            "ff02::fb",
            "not-an-ip",
        ]
        for ip in invalidIPs {
            #expect(DNSNameSanitizer.sanitizedUnicastIP(ip) == nil, "Expected non-unicast/invalid IP: \(ip)")
        }

        for validIP in ["192.0.2.10", "198.18.0.42", "2001:db8::1", "fd00:60::1234", "fe80::1234"] {
            #expect(DNSNameSanitizer.sanitizedUnicastIP(validIP) != nil, "Expected valid unicast IP: \(validIP)")
        }
    }

    @Test("AddressNameBook.bind scrubs polluted persisted learnedAddresses.v1 entries and rewrites clean cache")
    @MainActor
    func addressNameBookScrubsPersistedCacheOnLoad() throws {
        struct LegacyEntry: Codable {
            let address: String
            let name: String
        }

        let suite = "com.amunx.tracexy.tests.learned-scrub.\(UUID().uuidString)"
        let defaults = try #require(UserDefaults(suiteName: suite))
        defer { TestPreferences.remove(suite) }

        let seededEntries: [LegacyEntry] = [
            LegacyEntry(address: "192.0.2.10", name: "TestPhone.local"),
            LegacyEntry(address: "FD00:60:0:0:0:0:0:1234", name: "OfficeMac.local."),
            LegacyEntry(address: "192.0.2.11", name: "_companion-link._tcp.local"),
            LegacyEntry(address: "192.0.2.12", name: "lb._dns-sd._udp.local"),
            LegacyEntry(address: "192.0.2.13", name: "13.2.0.192.in-addr.arpa"),
            LegacyEntry(address: "192.0.2.14", name: "550e8400-e29b-41d4-a716-446655440000"),
            LegacyEntry(address: "0.0.0.0", name: "TestPhone.local"),
            LegacyEntry(address: "::", name: "TestPhone.local"),
            LegacyEntry(address: "255.255.255.255", name: "TestPhone.local"),
            LegacyEntry(address: "224.0.0.251", name: "TestPhone.local"),
            LegacyEntry(address: "ff02::fb", name: "TestPhone.local"),
        ]
        defaults.set(try JSONEncoder().encode(seededEntries), forKey: ProjectScopedSettingsKeys.learnedAddressNames)

        let book = AddressNameBook()
        book.bind(to: defaults)

        #expect(book.learnedNames == [
            "192.0.2.10": "TestPhone.local",
            "fd00:60::1234": "OfficeMac.local",
        ])

        // Verify the scrubbed dictionary was persisted back to disk immediately.
        let persistedData = try #require(defaults.data(forKey: ProjectScopedSettingsKeys.learnedAddressNames))
        let persistedEntries = try JSONDecoder().decode([LegacyEntry].self, from: persistedData)
        #expect(persistedEntries.map { "\($0.address)=\($0.name)" } == [
            "192.0.2.10=TestPhone.local",
            "fd00:60::1234=OfficeMac.local",
        ])
    }

    // MARK: Private

    private static let baseTime = Date(timeIntervalSince1970: 1_750_000_000)

    private static func decodeUDP(_ payload: [UInt8], sport: UInt16, dport: UInt16) -> DecodedPacket {
        let bytes = PacketBuilder.ethernetIPv4(
            proto: 17,
            src: "192.0.2.53",
            dst: "192.0.2.10",
            payload: PacketBuilder.udp(srcPort: sport, dstPort: dport, payload: payload)
        )
        return SessionBuilder.decodePacket(
            CapturedFrame(bytes: bytes, timestamp: baseTime, originalLength: bytes.count),
            linkType: LinkType.ethernet
        )
    }

    private static func dnsWireMessage(
        id: UInt16,
        flags: UInt16,
        questions: [(name: String, qtype: UInt16, qclass: UInt16)],
        answers: [[UInt8]],
        authorities: [[UInt8]],
        additionals: [[UInt8]]
    )
        -> [UInt8]
    {
        var out = be16(id)
            + be16(flags)
            + be16(UInt16(questions.count))
            + be16(UInt16(answers.count))
            + be16(UInt16(authorities.count))
            + be16(UInt16(additionals.count))
        for question in questions {
            out += encodeName(question.name) + be16(question.qtype) + be16(question.qclass)
        }
        for rr in answers {
            out += rr
        }
        for rr in authorities {
            out += rr
        }
        for rr in additionals {
            out += rr
        }
        return out
    }

    private static func aRecord(owner: String, rrClass: UInt16, ipv4: [UInt8]) -> [UInt8] {
        rawRecord(owner: owner, type: 1, rrClass: rrClass, rdata: ipv4)
    }

    private static func aaaaRecord(owner: String, rrClass: UInt16, ipv6: [UInt16]) -> [UInt8] {
        rawRecord(owner: owner, type: 28, rrClass: rrClass, rdata: ipv6.flatMap(be16))
    }

    private static func cnameRecord(owner: String, target: String) -> [UInt8] {
        rawRecord(owner: owner, type: 5, rrClass: 1, rdata: encodeName(target))
    }

    private static func ptrRecord(owner: String, target: String) -> [UInt8] {
        rawRecord(owner: owner, type: 12, rrClass: 1, rdata: encodeName(target))
    }

    private static func srvRecord(owner: String, port: UInt16, target: String) -> [UInt8] {
        let rdata = be16(0) + be16(0) + be16(port) + encodeName(target)
        return rawRecord(owner: owner, type: 33, rrClass: 1, rdata: rdata)
    }

    private static func txtRecord(owner: String, text: String) -> [UInt8] {
        let utf8 = Array(text.utf8)
        let rdata = [UInt8(utf8.count)] + utf8
        return rawRecord(owner: owner, type: 16, rrClass: 1, rdata: rdata)
    }

    private static func rawRecord(owner: String, type: UInt16, rrClass: UInt16, rdata: [UInt8]) -> [UInt8] {
        encodeName(owner)
            + be16(type)
            + be16(rrClass)
            + [0x00, 0x00, 0x00, 0x78]
            + be16(UInt16(rdata.count))
            + rdata
    }

    private static func encodeName(_ name: String) -> [UInt8] {
        guard !name.isEmpty else {
            return [0x00]
        }
        var bytes: [UInt8] = []
        for label in name.split(separator: ".") {
            let utf8 = Array(label.utf8)
            bytes.append(UInt8(utf8.count))
            bytes += utf8
        }
        bytes.append(0x00)
        return bytes
    }

    private static func be16(_ value: UInt16) -> [UInt8] {
        [UInt8(value >> 8), UInt8(value & 0xFF)]
    }
}
