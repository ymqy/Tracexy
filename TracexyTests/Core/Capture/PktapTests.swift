import Foundation
import Testing
@testable import Tracexy

@Suite("pktap process attribution")
struct PktapTests {
    // MARK: Internal

    @Test
    func parsesProcessAndInnerFrame() {
        let inner = PacketBuilder.httpRequestFrame(
            host: "example.com", path: "/", src: "192.168.1.10", dst: "93.184.216.34"
        )
        let packet = makePktapPacket(
            process: "Safari",
            pid: 501,
            epid: 777,
            interface: "en0",
            innerDLT: 1,
            frame: inner
        )

        let parsed = PktapHeader.parse(packet)
        #expect(parsed?.process == "Safari")
        #expect(parsed?.pid == 501)
        #expect(parsed?.effectivePID == 777)
        #expect(parsed?.interface == "en0")
        #expect(parsed?.innerDLT == 1)
        #expect(parsed?.frame == inner)
    }

    @Test
    func rejectsTruncatedHeader() {
        #expect(PktapHeader.parse([0x10, 0x00]) == nil)
        #expect(PktapHeader.isPktapDLT(PktapHeader.darwinDLT))
        #expect(PktapHeader.isPktapDLT(PktapHeader.dlt))
        #expect(!PktapHeader.isPktapDLT(1))
    }

    @Test
    func acceptsPacketAndEmptyNoneRecordsWhileRejectingDropNotifications() throws {
        let inner = [UInt8](repeating: 0x5A, count: 48)

        // Real XNU wire packet: `pth_type_next == 1` (`PTH_TYPE_PACKET`).
        let packetRecord = makePktapPacket(
            process: "Safari",
            pid: 501,
            epid: 777,
            effectiveProcess: "Safari",
            typeNext: PktapHeader.typeNextPacket,
            interface: "en0",
            innerDLT: 1,
            frame: inner
        )
        let parsedPacket = try #require(PktapHeader.parse(packetRecord))
        #expect(parsedPacket.typeNext == PktapHeader.typeNextPacket)
        #expect(parsedPacket.frame == inner)
        #expect(parsedPacket.effectiveProcess == "Safari")

        // XNU metadata-only record: `pth_type_next == 0` (`PTH_TYPE_NONE`) with 0 payload bytes.
        let metadataOnlyRecord = makePktapPacket(
            process: "Safari",
            pid: 501,
            epid: 777,
            typeNext: PktapHeader.typeNextNone,
            interface: "en0",
            innerDLT: 1,
            frame: []
        )
        let parsedMetadataOnly = try #require(PktapHeader.parse(metadataOnlyRecord))
        #expect(parsedMetadataOnly.typeNext == PktapHeader.typeNextNone)
        #expect(parsedMetadataOnly.frame.isEmpty)

        // XNU kernel drop notification: `pth_type_next == 2` (`PTH_TYPE_DROP`) MUST be rejected.
        let dropRecord = makePktapPacket(
            process: "Safari",
            pid: 501,
            epid: 777,
            typeNext: PktapHeader.typeNextDrop,
            interface: "en0",
            innerDLT: 1,
            frame: inner
        )
        #expect(PktapHeader.parse(dropRecord) == nil)

        // Unknown future non-packet record types must also be rejected.
        let unknownRecord = makePktapPacket(
            process: "Safari",
            pid: 501,
            epid: 777,
            typeNext: 99,
            interface: "en0",
            innerDLT: 1,
            frame: inner
        )
        #expect(PktapHeader.parse(unknownRecord) == nil)
    }

    @Test
    func parsesEffectiveProcessClampedToHeaderLengthAndPrefersItOverExitedDaemonComm() throws {
        let inner = [UInt8](repeating: 0x33, count: 32)
        let delegatedExited = makePktapPacket(
            process: "nsurlsessiond",
            pid: 312,
            epid: 9_876,
            effectiveProcess: "curl",
            typeNext: PktapHeader.typeNextPacket,
            interface: "en0",
            innerDLT: 1,
            frame: inner
        )
        let parsed = try #require(PktapHeader.parse(delegatedExited))
        #expect(parsed.process == "nsurlsessiond")
        #expect(parsed.effectiveProcess == "curl")
        // When both PIDs have exited (`pidLookup` -> nil), `effectiveProcess` (`pth_ecomm`)
        // wins over daemon `process` (`pth_comm`).
        #expect(PktapHeader.resolveProcessName(parsed: parsed) { _ in nil } == "curl")

        // Header ending exactly at offset 88 has no `pth_ecomm` bytes (`effectiveProcess == ""`).
        let noEcommPacket = makePktapPacket(
            process: "dig",
            pid: 410,
            epid: 410,
            typeNext: PktapHeader.typeNextPacket,
            headerLength: 88,
            interface: "en0",
            innerDLT: 1,
            frame: inner
        )
        let parsedNoEcomm = try #require(PktapHeader.parse(noEcommPacket))
        #expect(parsedNoEcomm.effectiveProcess.isEmpty)
        #expect(PktapHeader.resolveProcessName(parsed: parsedNoEcomm) { _ in nil } == "dig")

        // Header of 92 bytes (only 4 bytes at 88..<92) clamps `pth_ecomm` without reading inner frame bytes.
        var clampedHeader = [UInt8](repeating: 0, count: 92)
        writeU32LE(&clampedHeader, at: 0, 92)
        writeU32LE(&clampedHeader, at: 4, Int(PktapHeader.typeNextPacket))
        writeU32LE(&clampedHeader, at: 8, 1)
        writeCString(&clampedHeader, at: 12, "en0", max: 24)
        writeU32LE(&clampedHeader, at: 52, 500)
        writeCString(&clampedHeader, at: 56, "daemon", max: 17)
        writeU32LE(&clampedHeader, at: 84, 501)
        clampedHeader[88] = UInt8(ascii: "n")
        clampedHeader[89] = UInt8(ascii: "o")
        clampedHeader[90] = UInt8(ascii: "d")
        clampedHeader[91] = UInt8(ascii: "e")
        let parsedClamped = try #require(PktapHeader.parse(clampedHeader + inner))
        #expect(parsedClamped.effectiveProcess == "node")
        #expect(parsedClamped.frame == inner)
    }

    @Test
    func derivesAppNameFromExecutablePath() {
        #expect(PktapHeader.appName(
            fromExecutablePath: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
        ) == "Google Chrome")
        #expect(PktapHeader.appName(
            fromExecutablePath: "/System/Applications/Mail.app/Contents/MacOS/Mail"
        ) == "Mail")
        // Non-bundled daemon → executable file name.
        #expect(PktapHeader.appName(fromExecutablePath: "/usr/libexec/nsurlsessiond") == "nsurlsessiond")
    }

    @Test
    func extractsOutermostAppBundleForNestedHelpers() throws {
        let chromeHelper = "/Applications/Google Chrome.app/Contents/Frameworks/"
            + "Google Chrome Framework.framework/Versions/131.0.0.0/Helpers/"
            + "Google Chrome Helper (Networking).app/Contents/MacOS/Google Chrome Helper (Networking)"
        #expect(
            PktapHeader.outermostAppBundlePath(fromExecutablePath: chromeHelper) == "/Applications/Google Chrome.app"
        )
        #expect(PktapHeader.appName(fromExecutablePath: chromeHelper) == "Google Chrome")
        #expect(PktapHeader.outermostAppBundlePath(fromExecutablePath: "/usr/libexec/nsurlsessiond") == nil)

        // Real nested bundle on disk: `displayName(fromExecutablePath:)` reads the
        // outermost `.app`'s `CFBundleDisplayName` rather than the inner helper's.
        let tempRoot = FileManager.default.temporaryDirectory
            .appendingPathComponent("TracexyPktapTests-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: tempRoot) }

        let outerContents = tempRoot
            .appendingPathComponent("Acme Browser.app/Contents", isDirectory: true)
        let innerMacOS = outerContents
            .appendingPathComponent("Frameworks/Acme Helper (Networking).app/Contents/MacOS", isDirectory: true)
        try FileManager.default.createDirectory(at: innerMacOS, withIntermediateDirectories: true)

        let outerPlist: [String: Any] = [
            "CFBundleIdentifier": "com.example.acme.browser",
            "CFBundleDisplayName": "Acme Browser Pro",
            "CFBundleName": "AcmeBrowser",
        ]
        let outerPlistData = try PropertyListSerialization.data(
            fromPropertyList: outerPlist,
            format: .xml,
            options: 0
        )
        try outerPlistData.write(to: outerContents.appendingPathComponent("Info.plist"))

        let innerPlist: [String: Any] = [
            "CFBundleIdentifier": "com.example.acme.helper",
            "CFBundleDisplayName": "Acme Helper (Networking)",
        ]
        let innerPlistData = try PropertyListSerialization.data(
            fromPropertyList: innerPlist,
            format: .xml,
            options: 0
        )
        let innerContents = outerContents
            .appendingPathComponent("Frameworks/Acme Helper (Networking).app/Contents", isDirectory: true)
        try innerPlistData.write(to: innerContents.appendingPathComponent("Info.plist"))

        let helperExecPath = innerMacOS.appendingPathComponent("Acme Helper (Networking)").path
        #expect(PktapHeader.displayName(fromExecutablePath: helperExecPath) == "Acme Browser Pro")
    }

    @Test
    func resolvesProcessNameWithEffectivePIDFallbackChain() throws {
        let inner = [UInt8](repeating: 0x42, count: 64)
        let delegatedPacket = makePktapPacket(
            process: "nsurlsessiond",
            pid: 312,
            epid: 9_001,
            interface: "en0",
            innerDLT: 1,
            frame: inner
        )
        let parsed = try #require(PktapHeader.parse(delegatedPacket))

        // 1. Prefer `effectivePID` (real client app) over daemon `pid`.
        let preferred = PktapHeader.resolveProcessName(parsed: parsed) { pid in
            switch pid {
            case 9_001:
                "Safari"
            case 312:
                "nsurlsessiond"
            default:
                nil
            }
        }
        #expect(preferred == "Safari")

        // 2. When `effectivePID` lookup returns `nil`, fall back to `pid`.
        let fallbackToPID = PktapHeader.resolveProcessName(parsed: parsed) { pid in
            pid == 312 ? "nsurlsessiond" : nil
        }
        #expect(fallbackToPID == "nsurlsessiond")

        // 3. When both PIDs have already exited (`nil`), fall back to `pth_comm`.
        let fallbackToComm = PktapHeader.resolveProcessName(parsed: parsed) { _ in nil }
        #expect(fallbackToComm == "nsurlsessiond")

        // 4. Empty `pth_comm` and unresolvable PIDs resolve to `nil`.
        let anonymousPacket = makePktapPacket(
            process: "",
            pid: 0,
            epid: 0,
            interface: "en0",
            innerDLT: 1,
            frame: inner
        )
        let anonymousParsed = try #require(PktapHeader.parse(anonymousPacket))
        #expect(PktapHeader.resolveProcessName(parsed: anonymousParsed) { _ in nil } == nil)

        // Live current process resolves non-empty via `proc_pidpath`.
        let selfName = PktapHeader.resolveDisplayName(forPID: ProcessInfo.processInfo.processIdentifier)
        #expect(selfName?.isEmpty == false)
        #expect(PktapHeader.resolveDisplayName(forPID: -1) == nil)
    }

    @Test
    func capturedFrameMessageSecureCodingRoundTripsProcessName() throws {
        let payload = Data([0xDE, 0xAD, 0xBE, 0xEF])
        let attributed = CapturedFrameMessage(
            bytes: payload,
            timestampSeconds: 1_700_000_000,
            timestampMicroseconds: 123_456,
            capturedLength: Int64(payload.count),
            originalLength: 1_500,
            linkType: 1,
            processName: "Google Chrome"
        )
        let unattributed = CapturedFrameMessage(
            bytes: payload,
            timestampSeconds: 1_700_000_001,
            timestampMicroseconds: 654_321,
            capturedLength: Int64(payload.count),
            originalLength: Int64(payload.count),
            linkType: 0
        )

        let batch = FrameBatchMessage(
            frames: [attributed, unattributed],
            bufferDroppedCount: 0,
            captureLinkType: 1,
            stats: nil
        )
        let data = try NSKeyedArchiver.archivedData(withRootObject: batch, requiringSecureCoding: true)
        let decodedBatch = try #require(
            try NSKeyedUnarchiver.unarchivedObject(ofClass: FrameBatchMessage.self, from: data)
        )
        #expect(decodedBatch.frames.count == 2)
        #expect(decodedBatch.frames[0].processName == "Google Chrome")
        #expect(decodedBatch.frames[1].processName == nil)
    }

    @Test
    func capturedFrameConversionPreservesProcessNameAndSnaplenTruncatedInnerLengths() throws {
        // Simulates unwrapping a snaplen-truncated DLT_PKTAP packet:
        // outer caplen = 208 (108-byte pktap header + 100 captured inner bytes),
        // outer len    = 1608 (108-byte pktap header + 1500 on-wire inner bytes).
        let fullInner = [UInt8](repeating: 0xAB, count: 1_500)
        let truncatedInner = Array(fullInner.prefix(100))
        let outerCapturedPacket = makePktapPacket(
            process: "curl",
            pid: 4_321,
            epid: 4_321,
            interface: "en0",
            innerDLT: 1,
            frame: truncatedInner
        )
        let outerWireLen = 108 + fullInner.count

        let parsed = try #require(PktapHeader.parse(outerCapturedPacket))
        let innerBytes = parsed.frame
        let pktapHeaderLen = outerCapturedPacket.count - innerBytes.count
        let innerCaplen = innerBytes.count
        let innerOrigLen = max(innerCaplen, outerWireLen - pktapHeaderLen)

        let message = CapturedFrameMessage(
            bytes: Data(innerBytes),
            timestampSeconds: 1_700_000_100,
            timestampMicroseconds: 500,
            capturedLength: Int64(innerCaplen),
            originalLength: Int64(innerOrigLen),
            linkType: parsed.innerDLT,
            processName: PktapHeader.resolveProcessName(parsed: parsed) { _ in nil }
        )
        let frame = try #require(CapturedFrame(message: message))
        #expect(frame.processName == "curl")
        #expect(frame.capturedLength == 100)
        #expect(frame.originalLength == 1_500)
        #expect(frame.bytes.count == 100)
        #expect(frame.linkType == 1)

        // Empty string processName normalizes cleanly to `nil` on `CapturedFrame`.
        let emptyProcessMessage = CapturedFrameMessage(
            bytes: Data(innerBytes),
            timestampSeconds: 1_700_000_100,
            timestampMicroseconds: 500,
            capturedLength: Int64(innerCaplen),
            originalLength: Int64(innerOrigLen),
            linkType: parsed.innerDLT,
            processName: ""
        )
        let normalizedFrame = try #require(CapturedFrame(message: emptyProcessMessage))
        #expect(normalizedFrame.processName == nil)
    }

    @Test
    func processNamePropagatesToSession() {
        let frameBytes = PacketBuilder.tlsClientHelloFrame(
            sni: "secure.example.com", src: "192.168.1.10", dst: "93.184.216.34"
        )
        let frame = CapturedFrame(
            bytes: frameBytes, timestamp: Date(), originalLength: frameBytes.count, processName: "Google Chrome"
        )
        let sessions = SessionBuilder.build(from: [frame], linkType: LinkType.ethernet)
        #expect(sessions.first?.processName == "Google Chrome")
    }

    // MARK: Private

    /// Builds a synthetic DLT_PKTAP packet: a header (process at offset 56,
    /// interface at 12, DLT at 8, typeNext at 4, length at 0) followed by the inner frame.
    private func makePktapPacket(
        process: String,
        pid: Int = 0,
        epid: Int = 0,
        effectiveProcess: String = "",
        typeNext: UInt32 = 0,
        headerLength: Int = 108,
        interface: String,
        innerDLT: UInt32,
        frame: [UInt8]
    )
        -> [UInt8]
    {
        var header = [UInt8](repeating: 0, count: headerLength)
        writeU32LE(&header, at: 0, headerLength)
        writeU32LE(&header, at: 4, Int(typeNext))
        writeU32LE(&header, at: 8, Int(innerDLT))
        writeCString(&header, at: 12, interface, max: 24)
        writeU32LE(&header, at: 52, pid)
        writeCString(&header, at: 56, process, max: 17)
        if headerLength >= 88 {
            writeU32LE(&header, at: 84, epid)
        }
        if headerLength > 88, !effectiveProcess.isEmpty {
            writeCString(&header, at: 88, effectiveProcess, max: min(17, headerLength - 88))
        }
        return header + frame
    }

    private func writeU32LE(_ bytes: inout [UInt8], at offset: Int, _ value: Int) {
        let v = UInt32(value)
        bytes[offset] = UInt8(v & 0xFF)
        bytes[offset + 1] = UInt8((v >> 8) & 0xFF)
        bytes[offset + 2] = UInt8((v >> 16) & 0xFF)
        bytes[offset + 3] = UInt8((v >> 24) & 0xFF)
    }

    private func writeCString(_ bytes: inout [UInt8], at offset: Int, _ string: String, max: Int) {
        for (index, byte) in Array(string.utf8).prefix(max - 1).enumerated() {
            bytes[offset + index] = byte
        }
    }
}
