import Foundation
import Testing
@testable import Tracexy

// MARK: - SessionStatusAndLatencyTests

@Suite("Session TCP status disambiguation and Tier-3 payload latency cap")
struct SessionStatusAndLatencyTests {
    // MARK: Internal

    // MARK: Module C — Graceful FIN + trailing RST vs abortive RST

    @Test("Post-FIN trailing RST after payload keeps status OK while preserving .rst completeness")
    func postFINTrailingRSTAfterPayloadStaysOK() async throws {
        let client = "192.0.2.10"
        let server = "203.0.113.20"
        let clientPort: UInt16 = 52_100
        let serverPort: UInt16 = 443

        let frames = [
            tcpFrame(
                src: client, dst: server, srcPort: clientPort, dstPort: serverPort,
                seq: 1_000, ack: 0, flags: 0x02, payload: [], at: 0.000
            ),
            tcpFrame(
                src: server, dst: client, srcPort: serverPort, dstPort: clientPort,
                seq: 5_000, ack: 1_001, flags: 0x12, payload: [], at: 0.015
            ),
            tcpFrame(
                src: client, dst: server, srcPort: clientPort, dstPort: serverPort,
                seq: 1_001, ack: 5_001, flags: 0x10, payload: [], at: 0.016
            ),
            tcpFrame(
                src: client, dst: server, srcPort: clientPort, dstPort: serverPort,
                seq: 1_001, ack: 5_001, flags: 0x18, payload: [0x47, 0x45, 0x54, 0x20], at: 0.020
            ),
            tcpFrame(
                src: server, dst: client, srcPort: serverPort, dstPort: clientPort,
                seq: 5_001, ack: 1_005, flags: 0x18, payload: [UInt8](repeating: 0xAB, count: 64), at: 0.055
            ),
            // Graceful FIN+ACK teardown before any reset arrives.
            tcpFrame(
                src: server, dst: client, srcPort: serverPort, dstPort: clientPort,
                seq: 5_065, ack: 1_005, flags: 0x11, payload: [], at: 0.060
            ),
            // Late ACK / close_notify elicits trailing socket-cleanup RST segments.
            tcpFrame(
                src: client, dst: server, srcPort: clientPort, dstPort: serverPort,
                seq: 1_005, ack: 5_066, flags: 0x11, payload: [], at: 0.061
            ),
            tcpFrame(
                src: server, dst: client, srcPort: serverPort, dstPort: clientPort,
                seq: 5_066, ack: 0, flags: 0x04, payload: [], at: 0.062
            ),
            tcpFrame(
                src: server, dst: client, srcPort: serverPort, dstPort: clientPort,
                seq: 5_066, ack: 0, flags: 0x04, payload: [], at: 0.063
            ),
        ]

        let session = try #require(SessionBuilder.build(from: frames, linkType: LinkType.ethernet).first)
        #expect(session.status == .ok)
        #expect(session.tcpCompleteness == [.syn, .synAck, .ack, .data, .fin, .rst])
        #expect(session.tcpCompleteness.rawValue == 63)

        // Incremental per-frame live fold must produce the identical session summary.
        let engine = LiveSessionEngine()
        await engine.reset(epoch: 1)
        for frame in frames {
            await engine.ingest([frame], linkType: LinkType.ethernet, epoch: 1)
        }
        let live = try #require(await engine.snapshot(epoch: 1)).first
        #expect(live == session)
    }

    @Test("Piggybacked DATA+FIN segment followed by trailing RST stays OK")
    func piggybackedDataAndFINFollowedByRSTStaysOK() throws {
        let client = "192.0.2.11"
        let server = "203.0.113.21"
        let frames = [
            tcpFrame(
                src: client, dst: server, srcPort: 52_101, dstPort: 8_080,
                seq: 100, ack: 0, flags: 0x02, payload: [], at: 0.000
            ),
            tcpFrame(
                src: server, dst: client, srcPort: 8_080, dstPort: 52_101,
                seq: 200, ack: 101, flags: 0x12, payload: [], at: 0.010
            ),
            tcpFrame(
                src: client, dst: server, srcPort: 52_101, dstPort: 8_080,
                seq: 101, ack: 201, flags: 0x19, payload: [0x01, 0x02, 0x03, 0x04], at: 0.012
            ),
            tcpFrame(
                src: server, dst: client, srcPort: 8_080, dstPort: 52_101,
                seq: 201, ack: 106, flags: 0x14, payload: [], at: 0.020
            ),
        ]

        let session = try #require(SessionBuilder.build(from: frames, linkType: LinkType.ethernet).first)
        #expect(session.status == .ok)
        #expect(session.tcpCompleteness.contains(.data))
        #expect(session.tcpCompleteness.contains(.fin))
        #expect(session.tcpCompleteness.contains(.rst))
    }

    @Test("Mid-stream captured DATA then FIN followed by trailing RST stays OK")
    func midstreamCapturedDataAndFINFollowedByRSTStaysOK() throws {
        let client = "192.0.2.12"
        let server = "203.0.113.22"
        let frames = [
            tcpFrame(
                src: server, dst: client, srcPort: 443, dstPort: 52_102,
                seq: 9_000, ack: 3_000, flags: 0x18, payload: [UInt8](repeating: 0xCD, count: 128), at: 1.000
            ),
            tcpFrame(
                src: server, dst: client, srcPort: 443, dstPort: 52_102,
                seq: 9_128, ack: 3_000, flags: 0x11, payload: [], at: 1.010
            ),
            tcpFrame(
                src: client, dst: server, srcPort: 52_102, dstPort: 443,
                seq: 3_000, ack: 9_129, flags: 0x14, payload: [], at: 1.015
            ),
        ]

        let session = try #require(SessionBuilder.build(from: frames, linkType: LinkType.ethernet).first)
        #expect(session.status == .ok)
        #expect(session.tcpCompleteness == [.data, .fin, .rst])
    }

    @Test("Connection refusal (SYN -> RST) and mid-transfer abort (DATA -> RST without prior FIN) remain error")
    func abortiveRSTWithoutPriorFINRemainsError() throws {
        let client = "192.0.2.13"
        let server = "203.0.113.23"

        // 1. Connection refused: SYN -> RST+ACK.
        let refusedFrames = [
            tcpFrame(
                src: client, dst: server, srcPort: 52_200, dstPort: 443,
                seq: 1_000, ack: 0, flags: 0x02, payload: [], at: 0.000
            ),
            tcpFrame(
                src: server, dst: client, srcPort: 443, dstPort: 52_200,
                seq: 0, ack: 1_001, flags: 0x14, payload: [], at: 0.012
            ),
        ]
        let refused = try #require(SessionBuilder.build(from: refusedFrames, linkType: LinkType.ethernet).first)
        #expect(refused.status == .error)
        #expect(refused.tcpCompleteness == [.syn, .rst])

        // 2. Mid-download abrupt reset: DATA -> RST, even if a racing peer FIN arrives *after* the first RST.
        let midDownloadAbortFrames = [
            tcpFrame(
                src: client, dst: server, srcPort: 52_201, dstPort: 443,
                seq: 2_000, ack: 0, flags: 0x02, payload: [], at: 1.000
            ),
            tcpFrame(
                src: server, dst: client, srcPort: 443, dstPort: 52_201,
                seq: 7_000, ack: 2_001, flags: 0x12, payload: [], at: 1.010
            ),
            tcpFrame(
                src: client, dst: server, srcPort: 52_201, dstPort: 443,
                seq: 2_001, ack: 7_001, flags: 0x18, payload: [0x16, 0x03, 0x01, 0x00], at: 1.015
            ),
            // Abrupt server reset with no prior FIN.
            tcpFrame(
                src: server, dst: client, srcPort: 443, dstPort: 52_201,
                seq: 7_001, ack: 2_005, flags: 0x14, payload: [], at: 1.040
            ),
            // Late racing FIN from client after the connection was already reset.
            tcpFrame(
                src: client, dst: server, srcPort: 52_201, dstPort: 443,
                seq: 2_005, ack: 7_001, flags: 0x11, payload: [], at: 1.041
            ),
        ]
        let aborted = try #require(SessionBuilder.build(from: midDownloadAbortFrames, linkType: LinkType.ethernet).first)
        #expect(aborted.status == .error)
        #expect(aborted.tcpCompleteness == [.syn, .synAck, .ack, .data, .fin, .rst])
    }

    @Test("Zero-payload SYN -> FIN -> RST and simultaneous FIN+RST without prior FIN remain error")
    func zeroPayloadFINRSTAndSimultaneousFINRSTRemainError() throws {
        let client = "192.0.2.14"
        let server = "203.0.113.24"

        // 1. Zero application payload before RST (SYN -> SYN+ACK -> ACK -> FIN+ACK -> RST).
        let emptyFINRSTFrames = [
            tcpFrame(
                src: client, dst: server, srcPort: 52_300, dstPort: 443,
                seq: 1_000, ack: 0, flags: 0x02, payload: [], at: 0.000
            ),
            tcpFrame(
                src: server, dst: client, srcPort: 443, dstPort: 52_300,
                seq: 4_000, ack: 1_001, flags: 0x12, payload: [], at: 0.010
            ),
            tcpFrame(
                src: client, dst: server, srcPort: 52_300, dstPort: 443,
                seq: 1_001, ack: 4_001, flags: 0x11, payload: [], at: 0.015
            ),
            tcpFrame(
                src: server, dst: client, srcPort: 443, dstPort: 52_300,
                seq: 4_001, ack: 1_002, flags: 0x14, payload: [0x72, 0x65, 0x73, 0x65, 0x74], at: 0.020
            ),
        ]
        let emptySession = try #require(SessionBuilder.build(from: emptyFINRSTFrames, linkType: LinkType.ethernet).first)
        #expect(emptySession.status == .error)
        #expect(emptySession.tcpCompleteness.contains(.fin))
        #expect(emptySession.tcpCompleteness.contains(.rst))

        // 2. Simultaneous FIN+RST flags on the same packet with no prior FIN segment.
        let simultaneousFINRSTFrames = [
            tcpFrame(
                src: client, dst: server, srcPort: 52_301, dstPort: 443,
                seq: 1_000, ack: 0, flags: 0x02, payload: [], at: 2.000
            ),
            tcpFrame(
                src: server, dst: client, srcPort: 443, dstPort: 52_301,
                seq: 4_000, ack: 1_001, flags: 0x12, payload: [], at: 2.010
            ),
            tcpFrame(
                src: client, dst: server, srcPort: 52_301, dstPort: 443,
                seq: 1_001, ack: 4_001, flags: 0x18, payload: [0xAA, 0xBB], at: 2.015
            ),
            tcpFrame(
                src: server, dst: client, srcPort: 443, dstPort: 52_301,
                seq: 4_001, ack: 1_003, flags: 0x15, payload: [], at: 2.025
            ),
        ]
        let simultaneous = try #require(
            SessionBuilder.build(from: simultaneousFINRSTFrames, linkType: LinkType.ethernet).first
        )
        #expect(simultaneous.status == .error)
        #expect(simultaneous.tcpCompleteness.contains(.fin))
        #expect(simultaneous.tcpCompleteness.contains(.rst))
    }

    // MARK: Module E.1 — Tier-3 first-payload RTT 5.0 s upper bound

    @Test("Tier-3 first-payload RTT up to and including 5.0 s is published over local transport RTT")
    func tier3PayloadRTTWithinFiveSecondsIsPublished() throws {
        let client = "192.0.2.30"
        let server = "203.0.113.30"

        // Exact 5.0 s boundary on a raw non-TLS / non-DNS TCP stream: Tier 3 (5_000 ms) wins over Tier 4 (15 ms).
        let boundaryFrames = [
            tcpFrame(
                src: client, dst: server, srcPort: 53_100, dstPort: 9_000,
                seq: 1_000, ack: 0, flags: 0x02, payload: [], at: 0.000
            ),
            tcpFrame(
                src: server, dst: client, srcPort: 9_000, dstPort: 53_100,
                seq: 8_000, ack: 1_001, flags: 0x12, payload: [], at: 0.015
            ),
            tcpFrame(
                src: client, dst: server, srcPort: 53_100, dstPort: 9_000,
                seq: 1_001, ack: 8_001, flags: 0x18, payload: [0x01, 0x02, 0x03, 0x04], at: 1.000
            ),
            tcpFrame(
                src: server, dst: client, srcPort: 9_000, dstPort: 53_100,
                seq: 8_001, ack: 1_005, flags: 0x10, payload: [], at: 1.015
            ),
            tcpFrame(
                src: server, dst: client, srcPort: 9_000, dstPort: 53_100,
                seq: 8_001, ack: 1_005, flags: 0x18, payload: [0x05, 0x06, 0x07, 0x08], at: 6.000
            ),
        ]

        let session = try #require(SessionBuilder.build(from: boundaryFrames, linkType: LinkType.ethernet).first)
        let latency = try #require(session.latencyMilliseconds)
        #expect(abs(latency - 5_000.0) < 0.001)
    }

    @Test("Idle persistent connection payload gap > 5.0 s falls back to Tier-4 SYN -> SYN+ACK RTT")
    func tier3IdleLongConnectionOverFiveSecondsFallsBackToTier4SynRTT() throws {
        let client = "192.0.2.31"
        let server = "203.0.113.31"

        // Reproduces the 266,855 ms idle-push pseudo-latency case: SYN -> SYN+ACK is 18 ms,
        // client sends keepalive/subscription payload at t = 1.000, and server pushes data at t = 267.855.
        let idlePushFrames = [
            tcpFrame(
                src: client, dst: server, srcPort: 53_101, dstPort: 5_223,
                seq: 1_000, ack: 0, flags: 0x02, payload: [], at: 0.000
            ),
            tcpFrame(
                src: server, dst: client, srcPort: 5_223, dstPort: 53_101,
                seq: 9_000, ack: 1_001, flags: 0x12, payload: [], at: 0.018
            ),
            tcpFrame(
                src: client, dst: server, srcPort: 53_101, dstPort: 5_223,
                seq: 1_001, ack: 9_001, flags: 0x18, payload: [0x10, 0x20, 0x30], at: 1.000
            ),
            tcpFrame(
                src: server, dst: client, srcPort: 5_223, dstPort: 53_101,
                seq: 9_001, ack: 1_004, flags: 0x10, payload: [], at: 1.012
            ),
            tcpFrame(
                src: server, dst: client, srcPort: 5_223, dstPort: 53_101,
                seq: 9_001, ack: 1_004, flags: 0x18, payload: [0x40, 0x50], at: 267.855
            ),
        ]

        let session = try #require(SessionBuilder.build(from: idlePushFrames, linkType: LinkType.ethernet).first)
        let latency = try #require(session.latencyMilliseconds)
        #expect(abs(latency - 18.0) < 0.001)
    }

    @Test("Mid-stream idle TCP connection payload gap > 5.0 s falls back to Tier-5 Data -> ACK RTT")
    func tier3MidstreamIdleConnectionFallsBackToTier5DataAckRTT() throws {
        let client = "192.0.2.32"
        let server = "203.0.113.32"

        // No SYN/SYN+ACK captured; client sends 8 bytes at t = 10.000, server ACKs at t = 10.024 (24 ms),
        // and server pushes payload 90 s later (t = 100.000).
        let midstreamIdleFrames = [
            tcpFrame(
                src: client, dst: server, srcPort: 53_102, dstPort: 8_443,
                seq: 4_000, ack: 7_000, flags: 0x18, payload: [UInt8](repeating: 0x11, count: 8), at: 10.000
            ),
            tcpFrame(
                src: server, dst: client, srcPort: 8_443, dstPort: 53_102,
                seq: 7_000, ack: 4_008, flags: 0x10, payload: [], at: 10.024
            ),
            tcpFrame(
                src: server, dst: client, srcPort: 8_443, dstPort: 53_102,
                seq: 7_000, ack: 4_008, flags: 0x18, payload: [0x22, 0x33], at: 100.000
            ),
        ]

        let session = try #require(SessionBuilder.build(from: midstreamIdleFrames, linkType: LinkType.ethernet).first)
        let latency = try #require(session.latencyMilliseconds)
        #expect(abs(latency - 24.0) < 0.001)
    }

    @Test("Idle raw UDP exchange > 5.0 s with no transport fallback publishes nil instead of pseudo-latency")
    func tier3IdleUDPWithoutFallbackPublishesNil() throws {
        let outbound = PacketBuilder.ethernetIPv4(
            proto: 17, src: "192.0.2.33", dst: "203.0.113.33",
            payload: PacketBuilder.udp(srcPort: 53_103, dstPort: 9_999, payload: [0x01, 0x02, 0x03, 0x04])
        )
        let lateInbound = PacketBuilder.ethernetIPv4(
            proto: 17, src: "203.0.113.33", dst: "192.0.2.33",
            payload: PacketBuilder.udp(srcPort: 9_999, dstPort: 53_103, payload: [0x05, 0x06, 0x07, 0x08])
        )
        let frames = [
            CapturedFrame(bytes: outbound, timestamp: Self.epoch, originalLength: outbound.count),
            CapturedFrame(
                bytes: lateInbound,
                timestamp: Self.epoch.addingTimeInterval(5.001),
                originalLength: lateInbound.count
            ),
        ]

        let session = try #require(SessionBuilder.build(from: frames, linkType: LinkType.ethernet).first)
        #expect(session.latencyMilliseconds == nil)
    }

    @Test("Tier-1 DNS and Tier-2 TLS latencies remain unbounded above 5.0 s")
    func tier1DNSAndTier2TLSLatenciesRemainUnbounded() throws {
        let client = "192.0.2.34"
        let dnsServer = "203.0.113.53"
        let tlsServer = "203.0.113.44"

        // 1. Tier 1: slow DNS lookup taking 6.5 s still reports 6_500 ms.
        let dnsQueryBytes = PacketBuilder.dnsQueryFrame(
            name: "slow.example", src: client, dst: dnsServer, srcPort: 54_200
        )
        let dnsResponseBytes = PacketBuilder.dnsResponseFrame(
            name: "slow.example", answers: ["203.0.113.44"], src: dnsServer, dst: client, dstPort: 54_200
        )
        let dnsFrames = [
            CapturedFrame(bytes: dnsQueryBytes, timestamp: Self.epoch, originalLength: dnsQueryBytes.count),
            CapturedFrame(
                bytes: dnsResponseBytes,
                timestamp: Self.epoch.addingTimeInterval(6.5),
                originalLength: dnsResponseBytes.count
            ),
        ]
        let dnsSession = try #require(SessionBuilder.build(from: dnsFrames, linkType: LinkType.ethernet).first)
        let dnsLatency = try #require(dnsSession.latencyMilliseconds)
        #expect(abs(dnsLatency - 6_500.0) < 0.001)

        // 2. Tier 2: slow TLS ClientHello -> ServerHello taking 6.2 s still reports 6_200 ms.
        let clientHelloBytes = PacketBuilder.tlsClientHelloFrame(
            sni: "slow.example", src: client, dst: tlsServer, srcPort: 54_201
        )
        let serverHelloBody = Self.tlsServerHelloHandshake()
        let serverHelloBytes = PacketBuilder.tlsRecordFrame(
            contentType: 22, body: serverHelloBody,
            src: tlsServer, dst: client, srcPort: 443, dstPort: 54_201
        )
        let tlsFrames = [
            CapturedFrame(bytes: clientHelloBytes, timestamp: Self.epoch, originalLength: clientHelloBytes.count),
            CapturedFrame(
                bytes: serverHelloBytes,
                timestamp: Self.epoch.addingTimeInterval(6.2),
                originalLength: serverHelloBytes.count
            ),
        ]
        let tlsSession = try #require(SessionBuilder.build(from: tlsFrames, linkType: LinkType.ethernet).first)
        let tlsLatency = try #require(tlsSession.latencyMilliseconds)
        #expect(abs(tlsLatency - 6_200.0) < 0.001)
    }

    // MARK: Private

    private static let epoch = Date(timeIntervalSince1970: 1_700_000_000)

    private static func tlsServerHelloHandshake() -> [UInt8] {
        var body: [UInt8] = [0x03, 0x03] // legacy TLS 1.2 version
        body += [UInt8](repeating: 0x11, count: 32) // server random
        body += [0x00] // session_id length 0
        body += [0x13, 0x01] // TLS_AES_128_GCM_SHA256
        body += [0x00] // compression method null
        let supportedVersions: [UInt8] = [0x00, 0x2B, 0x00, 0x02, 0x03, 0x04]
        body += [UInt8(supportedVersions.count >> 8), UInt8(supportedVersions.count & 0xFF)]
        body += supportedVersions
        let count = body.count
        return [0x02, UInt8((count >> 16) & 0xFF), UInt8((count >> 8) & 0xFF), UInt8(count & 0xFF)] + body
    }

    private func tcpFrame(
        src: String,
        dst: String,
        srcPort: UInt16,
        dstPort: UInt16,
        seq: UInt32,
        ack: UInt32,
        flags: UInt8,
        payload: [UInt8],
        at offset: TimeInterval
    )
        -> CapturedFrame
    {
        var header: [UInt8] = [
            UInt8(srcPort >> 8), UInt8(srcPort & 0xFF),
            UInt8(dstPort >> 8), UInt8(dstPort & 0xFF),
            UInt8((seq >> 24) & 0xFF), UInt8((seq >> 16) & 0xFF), UInt8((seq >> 8) & 0xFF), UInt8(seq & 0xFF),
            UInt8((ack >> 24) & 0xFF), UInt8((ack >> 16) & 0xFF), UInt8((ack >> 8) & 0xFF), UInt8(ack & 0xFF),
            0x50, flags,
            0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
        ]
        header += payload
        let bytes = PacketBuilder.ethernetIPv4(proto: 6, src: src, dst: dst, payload: header)
        return CapturedFrame(
            bytes: bytes,
            timestamp: Self.epoch.addingTimeInterval(offset),
            originalLength: bytes.count
        )
    }
}
