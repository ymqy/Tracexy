import Foundation
import Testing
@testable import Tracexy

// MARK: - IPv6HostResolutionTests

@Suite("IPv6 compressed lookup normalization, FiveTuple ID stability, and Fake-IP ULA tightening")
struct IPv6HostResolutionTests {
    // MARK: Internal

    @Test("Uncompressed PacketDecoder IPv6 endpoints match RFC 5952 compressed resolved keys without changing sessionID")
    func uncompressedIPv6MatchesCompressedResolvedNamesAndPreservesSessionID() async throws {
        // PacketDecoder formats 8 uncompressed hextets: fd00:60:0:0:14d4:8335:8095:8306,
        // while AddressNameBook stores RFC 5952 compressed fd00:60::14d4:8335:8095:8306.
        let clientHextets: [UInt16] = [0xFD00, 0x0060, 0, 0, 0, 0, 0, 0x0001]
        let peerHextets: [UInt16] = [0xFD00, 0x0060, 0, 0, 0x14D4, 0x8335, 0x8095, 0x8306]
        let uncompressedPeer = "fd00:60:0:0:14d4:8335:8095:8306"
        let compressedPeer = "fd00:60::14d4:8335:8095:8306"

        let tcpBytes = PacketBuilder.ethernetIPv6(
            nextHeader: 6,
            src: clientHextets,
            dst: peerHextets,
            payload: PacketBuilder.tcp(srcPort: 51_234, dstPort: 443, flags: 0x02, payload: [])
        )
        let tcpFrame = CapturedFrame(bytes: tcpBytes, timestamp: Self.baseTime, originalLength: tcpBytes.count)

        // Verify LiveSessionEngine seeded with compressed AddressNameBook.learnedNames
        // resolves session.host identically to AddressNameBook.displayHost, while ALSO
        // scrubbing any polluted seed entry.
        let engine = LiveSessionEngine()
        await engine.reset(
            epoch: 1,
            initialResolved: [
                compressedPeer: "TestPhone.local",
                "192.0.2.77": "_companion-link._tcp.local",
                "0.0.0.0": "InvalidHost.local",
            ]
        )
        await engine.ingest([tcpFrame], linkType: LinkType.ethernet, epoch: 1)
        let seededSession = try #require(await engine.snapshot(epoch: 1)?.first)
        #expect(seededSession.host == "TestPhone.local")
        #expect(seededSession.destinationEndpoint == "\(uncompressedPeer):443")

        // Compatibility Redline: IPEndpoint.display and SessionBuilder.sessionID(for:)
        // keep exact uncompressed wire formatting so sticky process attribution never drifts.
        let srcEndpoint = IPEndpoint(ip: "fd00:60:0:0:0:0:0:1", port: 51_234)
        let dstEndpoint = IPEndpoint(ip: uncompressedPeer, port: 443)
        #expect(dstEndpoint.display == "\(uncompressedPeer):443")
        let tuple = FiveTuple(proto: .tcp, source: srcEndpoint, destination: dstEndpoint)
        let expectedID = SessionBuilder.stableID("\(tuple.proto.rawValue)|\(tuple.a.display)|\(tuple.b.display)")
        #expect(SessionBuilder.sessionID(for: tuple) == expectedID)
        #expect(seededSession.id == expectedID)

        await MainActor.run {
            let book = AddressNameBook()
            var dnsSession = seededSession
            dnsSession.protocolStack = [.udp, .mdns]
            dnsSession.dnsResolvedBindings = [DNSAddressBinding(ip: uncompressedPeer, hostname: "TestPhone.local")]
            book.learn(from: [dnsSession])
            #expect(book.learnedName(for: uncompressedPeer) == "TestPhone.local")
            #expect(book.learnedName(for: compressedPeer) == "TestPhone.local")
            #expect(book.displayHost(for: seededSession) == seededSession.host)
        }
    }

    @Test("IPv6 Fake-IP range is restricted strictly to fc00::/18 and fdfe:dcba:9876::/48, excluding fd00::/8 SLAAC ULA")
    func ipv6FakeIPRangeTighteningExcludesHomeRouterULA() {
        // Virtual proxy Fake-IP pools (IPv4 198.18.0.0/15, Sing-box fc00::/18, Clash fdfe:dcba:9876::/48)
        let fakeIPs = [
            "198.18.0.42",
            "198.19.255.254",
            "fc00::1",
            "fc00:0:0:0:0:0:0:42",
            "fc00:3fff:ffff:ffff:ffff:ffff:ffff:ffff",
            "fdfe:dcba:9876::1",
            "fdfe:dcba:9876:0:0:0:0:42",
        ]
        for ip in fakeIPs {
            #expect(SessionBuilder.isFakeIPAddress(ip), "Expected Fake-IP match for \(ip)")
        }

        // Standard home-router SLAAC ULA (fd00::/8) and out-of-pool addresses MUST NOT be treated as Fake-IP.
        let realUnicastIPs = [
            "fd00:60::1234",
            "fd00:60:0:0:14d4:8335:8095:8306",
            "fd00::1",
            "fd12:3456:789a::1",
            "fdfe:dcba:9877::1",
            "fc00:4000::1",
            "fc01::1",
            "2001:db8::1",
            "fe80::1",
            "192.0.2.10",
        ]
        for ip in realUnicastIPs {
            #expect(!SessionBuilder.isFakeIPAddress(ip), "Expected non-Fake-IP for \(ip)")
        }
    }

    @Test("TLS SNI on a local fd00::/8 ULA peer does not overwrite the peer IP, whereas fc00::/18 and fdfe:dcba:9876::/48 learn SNI")
    func tlsSNILearningRespectsTightenedIPv6FakeIPPools() async throws {
        let client: [UInt16] = [0xFD00, 0x0060, 0, 0, 0, 0, 0, 0x0001]
        let lanPeer: [UInt16] = [0xFD00, 0x0060, 0, 0, 0, 0, 0, 0x1234]
        let singBoxFake: [UInt16] = [0xFC00, 0x0000, 0, 0, 0, 0, 0, 0x0042]
        let clashFake: [UInt16] = [0xFDFE, 0xDCBA, 0x9876, 0, 0, 0, 0, 0x0042]

        let frames: [CapturedFrame] = [
            // 1. LAN ULA peer TLS with SNI followed by plain TCP to the same LAN ULA peer.
            Self.ipv6TCPFrame(
                src: client, dst: lanPeer, sport: 53_001, dport: 443,
                payload: PacketBuilder.tlsClientHello(sni: "sni.example.test"), offset: 0
            ),
            Self.ipv6TCPFrame(
                src: client, dst: lanPeer, sport: 53_002, dport: 8_080,
                payload: [], flags: 0x02, offset: 1
            ),
            // 2. Sing-box fc00::/18 Fake-IP TLS with SNI followed by plain TCP to same Fake-IP.
            Self.ipv6TCPFrame(
                src: client, dst: singBoxFake, sport: 53_003, dport: 443,
                payload: PacketBuilder.tlsClientHello(sni: "singbox.example.test"), offset: 2
            ),
            Self.ipv6TCPFrame(
                src: client, dst: singBoxFake, sport: 53_004, dport: 8_080,
                payload: [], flags: 0x02, offset: 3
            ),
            // 3. Clash fdfe:dcba:9876::/48 Fake-IP TLS with SNI followed by plain TCP to same Fake-IP.
            Self.ipv6TCPFrame(
                src: client, dst: clashFake, sport: 53_005, dport: 443,
                payload: PacketBuilder.tlsClientHello(sni: "clash.example.test"), offset: 4
            ),
            Self.ipv6TCPFrame(
                src: client, dst: clashFake, sport: 53_006, dport: 8_080,
                payload: [], flags: 0x02, offset: 5
            ),
        ]

        let sessions = SessionBuilder.build(from: frames, linkType: LinkType.ethernet)
        #expect(sessions.count == 6)

        // LAN fd00:60::1234 plain TCP session is NOT overwritten by the earlier TLS SNI!
        #expect(sessions[0].host == "sni.example.test")
        #expect(sessions[1].host == "fd00:60:0:0:0:0:0:1234")

        // Sing-box fc00::42 and Clash fdfe:dcba:9876::42 sibling flows DO resolve via Fake-IP SNI!
        #expect(sessions[3].host == "singbox.example.test")
        #expect(sessions[5].host == "clash.example.test")

        await MainActor.run {
            let book = AddressNameBook()
            book.learn(from: sessions)
            #expect(book.learnedName(for: "fd00:60::1234") == nil)
            #expect(book.learnedName(for: "fc00::42") == "singbox.example.test")
            #expect(book.learnedName(for: "fdfe:dcba:9876::42") == "clash.example.test")
        }
    }

    // MARK: Private

    private static let baseTime = Date(timeIntervalSince1970: 1_750_000_000)

    private static func ipv6TCPFrame(
        src: [UInt16],
        dst: [UInt16],
        sport: UInt16,
        dport: UInt16,
        payload: [UInt8],
        flags: UInt8 = 0x18,
        offset: TimeInterval
    )
        -> CapturedFrame
    {
        let bytes = PacketBuilder.ethernetIPv6(
            nextHeader: 6,
            src: src,
            dst: dst,
            payload: PacketBuilder.tcp(srcPort: sport, dstPort: dport, flags: flags, payload: payload)
        )
        return CapturedFrame(
            bytes: bytes,
            timestamp: baseTime.addingTimeInterval(offset),
            originalLength: bytes.count
        )
    }
}
