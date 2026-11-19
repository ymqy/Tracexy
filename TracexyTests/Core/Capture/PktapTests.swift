import Darwin
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

    @Test
    func processProvenanceSecureCodingRoundTripsViaXPCAllowListAndPropagatesToCapturedFrame() throws {
        let payload = Data([0x45, 0x00, 0x00, 0x28])
        let appProvenance = ProcessProvenance(
            executablePath: "/Applications/Safari.app/Contents/MacOS/Safari",
            bundleIdentifier: "com.apple.Safari",
            viaProcessName: "nsurlsessiond",
            parentProcessName: "Dock",
            hasControllingTTY: false,
            isRootUser: false,
            isKernelTask: false
        )
        let cliProvenance = ProcessProvenance(
            executablePath: "/opt/homebrew/bin/curl",
            bundleIdentifier: nil,
            viaProcessName: nil,
            parentProcessName: "Antigravity",
            hasControllingTTY: true,
            isRootUser: false,
            isKernelTask: false
        )
        let rootProvenance = ProcessProvenance(
            executablePath: "/usr/sbin/mDNSResponderHelper",
            isRootUser: true
        )
        let kernelProvenance = ProcessProvenance(isKernelTask: true)
        let emptyStructProvenance = ProcessProvenance()

        let messages = [
            CapturedFrameMessage(
                bytes: payload,
                timestampSeconds: 1_700_000_010,
                timestampMicroseconds: 100,
                capturedLength: Int64(payload.count),
                originalLength: Int64(payload.count),
                linkType: 1,
                processName: "Safari",
                processProvenance: appProvenance
            ),
            CapturedFrameMessage(
                bytes: payload,
                timestampSeconds: 1_700_000_011,
                timestampMicroseconds: 200,
                capturedLength: Int64(payload.count),
                originalLength: Int64(payload.count),
                linkType: 1,
                processName: "curl",
                processProvenance: cliProvenance
            ),
            CapturedFrameMessage(
                bytes: payload,
                timestampSeconds: 1_700_000_012,
                timestampMicroseconds: 300,
                capturedLength: Int64(payload.count),
                originalLength: Int64(payload.count),
                linkType: 1,
                processName: "mDNSResponderHelper",
                processProvenance: rootProvenance
            ),
            CapturedFrameMessage(
                bytes: payload,
                timestampSeconds: 1_700_000_013,
                timestampMicroseconds: 400,
                capturedLength: Int64(payload.count),
                originalLength: Int64(payload.count),
                linkType: 1,
                processName: nil,
                processProvenance: kernelProvenance
            ),
            CapturedFrameMessage(
                bytes: payload,
                timestampSeconds: 1_700_000_014,
                timestampMicroseconds: 500,
                capturedLength: Int64(payload.count),
                originalLength: Int64(payload.count),
                linkType: 1,
                processName: "exited-tool",
                processProvenance: emptyStructProvenance
            ),
            CapturedFrameMessage(
                bytes: payload,
                timestampSeconds: 1_700_000_015,
                timestampMicroseconds: 600,
                capturedLength: Int64(payload.count),
                originalLength: Int64(payload.count),
                linkType: 1
            ),
        ]

        let batch = FrameBatchMessage(
            frames: messages,
            bufferDroppedCount: 0,
            captureLinkType: 1,
            stats: nil
        )
        let archived = try NSKeyedArchiver.archivedData(withRootObject: batch, requiringSecureCoding: true)

        // Decode strictly against TracexyHelperInterface's fetchFrames XPC allow-list!
        let interface = TracexyHelperInterface.make()
        let allowedSet = interface.classes(
            for: #selector(TracexyHelperProtocol.fetchFrames(withReply:)),
            argumentIndex: 0,
            ofReply: true
        )
        let allowedClasses = allowedSet.compactMap { $0.base as? AnyClass }
        let unarchiver = try NSKeyedUnarchiver(forReadingFrom: archived)
        unarchiver.requiresSecureCoding = true
        let decodedBatch = try #require(
            unarchiver.decodeObject(of: allowedClasses, forKey: NSKeyedArchiveRootObjectKey) as? FrameBatchMessage
        )
        unarchiver.finishDecoding()

        #expect(decodedBatch.frames.count == 6)
        #expect(decodedBatch.frames[0].processName == "Safari")
        #expect(decodedBatch.frames[0].processProvenance == appProvenance)
        #expect(decodedBatch.frames[1].processName == "curl")
        #expect(decodedBatch.frames[1].processProvenance == cliProvenance)
        #expect(decodedBatch.frames[2].processProvenance == rootProvenance)
        #expect(decodedBatch.frames[3].processName == nil)
        #expect(decodedBatch.frames[3].processProvenance == kernelProvenance)
        #expect(decodedBatch.frames[4].processProvenance == emptyStructProvenance)
        #expect(decodedBatch.frames[5].processName == nil)
        #expect(decodedBatch.frames[5].processProvenance == nil)

        let convertedFrames = decodedBatch.frames.compactMap(CapturedFrame.init(message:))
        #expect(convertedFrames.count == 6)
        #expect(convertedFrames[0].processProvenance == appProvenance)
        #expect(convertedFrames[1].processProvenance == cliProvenance)
        #expect(convertedFrames[2].processProvenance == rootProvenance)
        #expect(convertedFrames[3].processName == nil)
        #expect(convertedFrames[3].processProvenance?.isKernelTask == true)
        #expect(convertedFrames[4].processProvenance == emptyStructProvenance)
        #expect(convertedFrames[5].processProvenance == nil)
    }

    @Test
    func resolvesDelegatedEffectivePIDWithViaProcessNameAndParentProvenance() throws {
        let inner = [UInt8](repeating: 0x42, count: 48)
        let delegatedPacket = makePktapPacket(
            process: "nsurlsessiond",
            pid: 312,
            epid: 9_001,
            effectiveProcess: "Safari",
            typeNext: PktapHeader.typeNextPacket,
            interface: "en0",
            innerDLT: 1,
            frame: inner
        )
        let parsed = try #require(PktapHeader.parse(delegatedPacket))

        let safariExec = "/Applications/Safari.app/Contents/MacOS/Safari"
        let daemonExec = "/usr/libexec/nsurlsessiond"
        let dockExec = "/System/Library/CoreServices/Dock.app/Contents/MacOS/Dock"

        let resolved = PktapHeader.resolveAttribution(
            parsed: parsed,
            executablePathLookup: { pid in
                switch pid {
                case 9_001: safariExec
                case 312: daemonExec
                case 450: dockExec
                default: nil
                }
            },
            bsdProcessLookup: { pid in
                pid == 9_001 ? (ppid: 450, uid: 501, hasTTY: false) : nil
            },
            displayNameFromPath: { path in
                switch path {
                case safariExec: "Safari"
                case daemonExec: "nsurlsessiond"
                case dockExec: "Dock"
                default: PktapHeader.displayName(fromExecutablePath: path)
                }
            },
            bundleIdentifierFromPath: { path in
                path == safariExec ? "com.apple.Safari" : nil
            },
            outerMainExecutableFromAppPath: { _ in "Safari" }
        )

        #expect(resolved.processName == "Safari")
        #expect(resolved.provenance == ProcessProvenance(
            executablePath: safariExec,
            bundleIdentifier: "com.apple.Safari",
            viaProcessName: "nsurlsessiond",
            parentProcessName: "Dock",
            originProcessName: "Safari",
            hasControllingTTY: false,
            isRootUser: false,
            isKernelTask: false
        ))

        // Exited `effectivePID` still attributes to `effectiveProcess` (`Safari`) via `nsurlsessiond`.
        let exitedClientResolved = PktapHeader.resolveAttribution(
            parsed: parsed,
            executablePathLookup: { pid in pid == 312 ? daemonExec : nil },
            bsdProcessLookup: { _ in nil },
            displayNameFromPath: { path in PktapHeader.displayName(fromExecutablePath: path) },
            bundleIdentifierFromPath: { _ in nil },
            outerMainExecutableFromAppPath: { _ in nil }
        )
        #expect(exitedClientResolved.processName == "Safari")
        #expect(exitedClientResolved.provenance?.viaProcessName == "nsurlsessiond")

        // CLI process launched by an IDE with TTY attached (`ppid > 1`).
        let cliPacket = makePktapPacket(
            process: "node",
            pid: 7_700,
            epid: 7_700,
            effectiveProcess: "node",
            typeNext: PktapHeader.typeNextPacket,
            interface: "en0",
            innerDLT: 1,
            frame: inner
        )
        let parsedCLI = try #require(PktapHeader.parse(cliPacket))
        let nodeExec = "/opt/homebrew/bin/node"
        let ideExec = "/Applications/Antigravity.app/Contents/MacOS/Antigravity"
        let cliResolved = PktapHeader.resolveAttribution(
            parsed: parsedCLI,
            executablePathLookup: { pid in
                switch pid {
                case 7_700: nodeExec
                case 3_580: ideExec
                default: nil
                }
            },
            bsdProcessLookup: { pid in
                pid == 7_700 ? (ppid: 3_580, uid: 501, hasTTY: true) : nil
            },
            displayNameFromPath: { path in
                path == ideExec ? "Antigravity" : PktapHeader.displayName(fromExecutablePath: path)
            },
            bundleIdentifierFromPath: { _ in nil },
            outerMainExecutableFromAppPath: { _ in nil }
        )
        #expect(cliResolved.processName == "node")
        #expect(cliResolved.provenance == ProcessProvenance(
            executablePath: nodeExec,
            bundleIdentifier: nil,
            viaProcessName: nil,
            parentProcessName: "Antigravity",
            originProcessName: "node",
            hostAppName: "Antigravity",
            spawnerProcessName: nil,
            viaShellName: nil,
            callerKind: .app,
            hasControllingTTY: true,
            isRootUser: false,
            isKernelTask: false
        ))
    }

    @Test
    func resolvesMultiHopAncestorChainsAcrossAppsTerminalsSystemDaemonsAndDelegatedHelpers() throws {
        let inner = [UInt8](repeating: 0x33, count: 40)

        // 1. 4-hop embedded CLI: Antigravity.app -> language_server_macos_arm -> zsh -> curl.
        let curlPacket = makePktapPacket(
            process: "curl",
            pid: 9_500,
            epid: 9_500,
            effectiveProcess: "curl",
            typeNext: PktapHeader.typeNextPacket,
            interface: "en0",
            innerDLT: 1,
            frame: inner
        )
        let parsedCurl = try #require(PktapHeader.parse(curlPacket))
        let curlExec = "/usr/bin/curl"
        let zshExec = "/bin/zsh"
        let langServerExec = "/Applications/Antigravity.app/Contents/Resources/"
            + "app/extensions/antigravity/bin/language_server_macos_arm"
        let appMainExec = "/Applications/Antigravity.app/Contents/MacOS/Electron"

        let embeddedCurl = PktapHeader.resolveAttribution(
            parsed: parsedCurl,
            executablePathLookup: { pid in
                switch pid {
                case 9_500: curlExec
                case 9_400: zshExec
                case 9_300: langServerExec
                case 9_000: appMainExec
                default: nil
                }
            },
            bsdProcessLookup: { pid in
                switch pid {
                case 9_500: (ppid: 9_400, uid: 501, hasTTY: false)
                case 9_400: (ppid: 9_300, uid: 501, hasTTY: false)
                case 9_300: (ppid: 9_000, uid: 501, hasTTY: false)
                case 9_000: (ppid: 1, uid: 501, hasTTY: false)
                default: nil
                }
            },
            displayNameFromPath: { path in
                if path.hasPrefix("/Applications/Antigravity.app/") {
                    return "Antigravity"
                }
                return PktapHeader.displayName(fromExecutablePath: path)
            },
            bundleIdentifierFromPath: { path in
                path.hasPrefix("/Applications/Antigravity.app/") ? "com.amunx.antigravity" : nil
            },
            outerMainExecutableFromAppPath: { _ in "Electron" }
        )
        #expect(embeddedCurl.processName == "curl")
        #expect(embeddedCurl.provenance == ProcessProvenance(
            executablePath: curlExec,
            bundleIdentifier: nil,
            viaProcessName: nil,
            parentProcessName: "Antigravity",
            originProcessName: "curl",
            hostAppName: "Antigravity",
            spawnerProcessName: "language_server_macos_arm",
            viaShellName: "zsh",
            callerKind: .app,
            hasControllingTTY: false,
            isRootUser: false,
            isKernelTask: false
        ))

        // 2. Secure-coding round-trip of full multi-hop ProcessProvenance inside CapturedFrameMessage.
        let msg = CapturedFrameMessage(
            bytes: Data(inner),
            timestampSeconds: 1_700_000_010,
            timestampMicroseconds: 500,
            capturedLength: Int64(inner.count),
            originalLength: Int64(inner.count),
            linkType: 1,
            processName: embeddedCurl.processName,
            processProvenance: embeddedCurl.provenance
        )
        let archived = try NSKeyedArchiver.archivedData(withRootObject: msg, requiringSecureCoding: true)
        let unarchived = try #require(
            try NSKeyedUnarchiver.unarchivedObject(ofClass: CapturedFrameMessage.self, from: archived)
        )
        #expect(unarchived.processName == "curl")
        #expect(unarchived.processProvenance == embeddedCurl.provenance)

        // 3. Interactive terminal chain: iTerm2.app -> login -> -zsh -> curl -> `.terminal` (NOT `.app`).
        let itermExec = "/Applications/iTerm.app/Contents/MacOS/iTerm2"
        let loginExec = "/usr/bin/login"
        let terminalCurl = PktapHeader.resolveAttribution(
            parsed: parsedCurl,
            executablePathLookup: { pid in
                switch pid {
                case 9_500: curlExec
                case 9_400: "/bin/-zsh"
                case 9_300: loginExec
                case 9_200: itermExec
                default: nil
                }
            },
            bsdProcessLookup: { pid in
                switch pid {
                case 9_500: (ppid: 9_400, uid: 501, hasTTY: true)
                case 9_400: (ppid: 9_300, uid: 501, hasTTY: true)
                case 9_300: (ppid: 9_200, uid: 0, hasTTY: true)
                case 9_200: (ppid: 1, uid: 501, hasTTY: false)
                default: nil
                }
            },
            displayNameFromPath: { path in
                path == itermExec ? "iTerm2" : PktapHeader.displayName(fromExecutablePath: path)
            },
            bundleIdentifierFromPath: { path in
                path == itermExec ? "com.googlecode.iterm2" : nil
            },
            outerMainExecutableFromAppPath: { _ in "iTerm2" }
        )
        #expect(terminalCurl.provenance?.callerKind == .terminal)
        #expect(terminalCurl.provenance?.hostAppName == nil)
        #expect(terminalCurl.provenance?.parentProcessName == "iTerm2")
        #expect(terminalCurl.provenance?.viaShellName == "zsh")

        // 4. System daemon chain: launchd (1) -> softwareupdated -> sh -> curl -> `.system`.
        let softwareUpdatedExec = "/System/Library/CoreServices/Software Update.app/Contents/Resources/softwareupdated"
        let systemCurl = PktapHeader.resolveAttribution(
            parsed: parsedCurl,
            executablePathLookup: { pid in
                switch pid {
                case 9_500: curlExec
                case 9_400: "/bin/sh"
                case 9_300: softwareUpdatedExec
                default: nil
                }
            },
            bsdProcessLookup: { pid in
                switch pid {
                case 9_500: (ppid: 9_400, uid: 0, hasTTY: false)
                case 9_400: (ppid: 9_300, uid: 0, hasTTY: false)
                case 9_300: (ppid: 1, uid: 0, hasTTY: false)
                default: nil
                }
            },
            displayNameFromPath: { path in PktapHeader.displayName(fromExecutablePath: path) },
            bundleIdentifierFromPath: { _ in "com.apple.SoftwareUpdate" },
            outerMainExecutableFromAppPath: { _ in nil }
        )
        #expect(systemCurl.provenance?.callerKind == .system)
        #expect(systemCurl.provenance?.hostAppName == nil)
        #expect(systemCurl.provenance?.spawnerProcessName == "softwareupdated")
        #expect(systemCurl.provenance?.parentProcessName == "softwareupdated")
        #expect(systemCurl.provenance?.viaShellName == "sh")

        // 5. Delegated DNS (`pid = mDNSResponder`, `effectivePID = language_server_macos_arm`):
        // preserves BOTH `originProcessName == "language_server_macos_arm"` and `viaProcessName == "mDNSResponder"`.
        let delegatedDNSPacket = makePktapPacket(
            process: "mDNSResponder",
            pid: 412,
            epid: 9_300,
            effectiveProcess: "language_server_",
            typeNext: PktapHeader.typeNextPacket,
            interface: "en0",
            innerDLT: 1,
            frame: inner
        )
        let parsedDelegatedDNS = try #require(PktapHeader.parse(delegatedDNSPacket))
        let delegatedHelper = PktapHeader.resolveAttribution(
            parsed: parsedDelegatedDNS,
            executablePathLookup: { pid in
                switch pid {
                case 412: "/usr/sbin/mDNSResponder"
                case 9_300: langServerExec
                case 9_000: appMainExec
                default: nil
                }
            },
            bsdProcessLookup: { pid in
                pid == 9_300 ? (ppid: 9_000, uid: 501, hasTTY: false) : nil
            },
            displayNameFromPath: { path in
                if path.hasPrefix("/Applications/Antigravity.app/") {
                    return "Antigravity"
                }
                return PktapHeader.displayName(fromExecutablePath: path)
            },
            bundleIdentifierFromPath: { _ in "com.amunx.antigravity" },
            outerMainExecutableFromAppPath: { _ in "Electron" }
        )
        #expect(delegatedHelper.processName == "Antigravity")
        #expect(delegatedHelper.provenance?.originProcessName == "language_server_macos_arm")
        #expect(delegatedHelper.provenance?.viaProcessName == "mDNSResponder")
    }

    @Test
    func resolvesNestedHelperViaProcessNameAndFrameworkBundleIdentifier() throws {
        let inner = [UInt8](repeating: 0x55, count: 40)

        // 1. `UU远程.app/Contents/MacOS/UURemoteDaemon` -> `UU远程` via `UURemoteDaemon` (root).
        let uuPacket = makePktapPacket(
            process: "UURemoteDaemon",
            pid: 572,
            epid: 572,
            effectiveProcess: "UURemoteDaemon",
            typeNext: PktapHeader.typeNextPacket,
            interface: "en0",
            innerDLT: 1,
            frame: inner
        )
        let parsedUU = try #require(PktapHeader.parse(uuPacket))
        let uuDaemonExec = "/Applications/UU远程.app/Contents/MacOS/UURemoteDaemon"
        let resolvedUU = PktapHeader.resolveAttribution(
            parsed: parsedUU,
            executablePathLookup: { pid in pid == 572 ? uuDaemonExec : nil },
            bsdProcessLookup: { pid in pid == 572 ? (ppid: 1, uid: 0, hasTTY: false) : nil },
            displayNameFromPath: { _ in "UU远程" },
            bundleIdentifierFromPath: { _ in "com.netease.uuremote" },
            outerMainExecutableFromAppPath: { _ in "UURemote" }
        )
        #expect(resolvedUU.processName == "UU远程")
        #expect(resolvedUU.provenance == ProcessProvenance(
            executablePath: uuDaemonExec,
            bundleIdentifier: "com.netease.uuremote",
            viaProcessName: "UURemoteDaemon",
            parentProcessName: nil,
            originProcessName: "UURemoteDaemon",
            hasControllingTTY: false,
            isRootUser: true,
            isKernelTask: false
        ))

        // Main UI binary of a localized bundle (`UURemote.app/Contents/MacOS/UURemote`
        // whose localized display name is `"UU远程"`) must NOT emit a spurious `via UURemote`.
        #expect(
            PktapHeader.nestedHelperViaName(
                executablePath: "/Applications/UURemote.app/Contents/MacOS/UURemote",
                outerAppDisplayName: "UU远程",
                outerMainExecutableLookup: { _ in "UURemote" }
            ) == nil
        )
        #expect(
            PktapHeader.nestedHelperViaName(
                executablePath: "/Applications/UURemote.app/Contents/MacOS/UURemoteDaemon",
                outerAppDisplayName: "UU远程",
                outerMainExecutableLookup: { _ in "UURemote" }
            ) == "UURemoteDaemon"
        )

        // 2. Nested Helper `.app` inside `Contents/Frameworks/` -> `Antigravity` via `Antigravity Helper`.
        let helperExec = "/Applications/Antigravity.app/Contents/Frameworks/"
            + "Antigravity Helper.app/Contents/MacOS/Antigravity Helper"
        let helperPacket = makePktapPacket(
            process: "Antigravity Help",
            pid: 3_631,
            epid: 3_631,
            typeNext: PktapHeader.typeNextPacket,
            interface: "en0",
            innerDLT: 1,
            frame: inner
        )
        let parsedHelper = try #require(PktapHeader.parse(helperPacket))
        let resolvedHelper = PktapHeader.resolveAttribution(
            parsed: parsedHelper,
            executablePathLookup: { pid in
                switch pid {
                case 3_631: helperExec
                case 3_580: "/Applications/Antigravity.app/Contents/MacOS/Antigravity"
                default: nil
                }
            },
            bsdProcessLookup: { pid in pid == 3_631 ? (ppid: 3_580, uid: 501, hasTTY: false) : nil },
            displayNameFromPath: { _ in "Antigravity" },
            bundleIdentifierFromPath: { _ in "com.amunx.antigravity" },
            outerMainExecutableFromAppPath: { _ in "Antigravity" }
        )
        #expect(resolvedHelper.processName == "Antigravity")
        #expect(resolvedHelper.provenance?.viaProcessName == "Antigravity Helper")
        #expect(resolvedHelper.provenance?.parentProcessName == "Antigravity")

        // 3. Framework bundle identifier extraction when not inside an `.app/`.
        let ampExec = "/System/Library/PrivateFrameworks/AMPDevices.framework/"
            + "Versions/A/Support/AMPDeviceDiscoveryAgent"
        let ampBundleID = PktapHeader.bundleIdentifier(fromExecutablePath: ampExec) { bundlePath in
            bundlePath == "/System/Library/PrivateFrameworks/AMPDevices.framework"
                ? "com.apple.AMPDevices"
                : nil
        }
        #expect(ampBundleID == "com.apple.AMPDevices")
    }

    @Test
    func resolvesKernelTaskPIDZeroAndInspectsLiveBSDProcesses() throws {
        let inner = [UInt8](repeating: 0x11, count: 40)

        for comm in ["", "kernel_task"] {
            let kernelPacket = makePktapPacket(
                process: comm,
                pid: 0,
                epid: 0,
                typeNext: PktapHeader.typeNextPacket,
                interface: "en0",
                innerDLT: 1,
                frame: inner
            )
            let parsedKernel = try #require(PktapHeader.parse(kernelPacket))
            let resolved = PktapHeader.resolveAttribution(parsed: parsedKernel)
            #expect(resolved.processName == nil)
            #expect(resolved.provenance == ProcessProvenance(isKernelTask: true))
        }

        // Pure inbound packet before XNU socket demux (`pid == -1, epid == -1, comm == ""`):
        // NOT kernel_task, resolves to `(nil, nil)` so helper socket fallback can take over.
        let unattributedInbound = makePktapPacket(
            process: "",
            pid: -1,
            epid: -1,
            typeNext: PktapHeader.typeNextPacket,
            interface: "en0",
            innerDLT: 1,
            frame: inner
        )
        let parsedInbound = try #require(PktapHeader.parse(unattributedInbound))
        let unattributed = PktapHeader.resolveAttribution(parsed: parsedInbound)
        #expect(unattributed.processName == nil)
        #expect(unattributed.provenance == nil)

        // Live Darwin.sysctl `KERN_PROC_PID` verification:
        let launchdInfo = try #require(PktapHeader.inspectBSDProcess(pid: 1))
        #expect(launchdInfo.uid == 0)
        #expect(launchdInfo.hasTTY == false)

        let selfPID = ProcessInfo.processInfo.processIdentifier
        let selfInfo = try #require(PktapHeader.inspectBSDProcess(pid: selfPID))
        #expect(selfInfo.uid == getuid())
        #expect(PktapHeader.inspectBSDProcess(pid: -1) == nil)
        #expect(PktapHeader.inspectBSDProcess(pid: 999_999) == nil)

        let selfSnapshot = try #require(PktapHeader.inspectBSDProcessSnapshot(pid: getpid()))
        #expect(selfSnapshot.ppid > 0)
        #expect(selfSnapshot.uid == getuid())
        #expect(selfSnapshot.startTimeSec > 0)
        #expect(selfSnapshot.startTimeUsec >= 0)
        #expect(selfSnapshot.startTimeUsec < 1_000_000)
        #expect(selfSnapshot.basicInfo.ppid == selfInfo.ppid)
        #expect(selfSnapshot.basicInfo.uid == selfInfo.uid)
        #expect(selfSnapshot.basicInfo.hasTTY == selfInfo.hasTTY)
        #expect(PktapHeader.inspectBSDProcessSnapshot(pid: -1) == nil)
        #expect(PktapHeader.inspectBSDProcessSnapshot(pid: 999_999) == nil)
    }

    @Test
    func attributionCacheDoesNotNegativeCacheShortLivedPIDAndResolvesFullAncestryOnReuse() throws {
        let inner = [UInt8](repeating: 0x22, count: 40)
        let reusedPID: Int32 = 8_100
        var clock: UInt64 = 1_000_000_000

        var execByPID: [Int32: String] = [:]
        var bsdByPID: [Int32: PktapHeader.BSDProcessSnapshot] = [:]

        var cache = PktapHeader.AttributionCache(
            nowNanoseconds: { clock },
            ttlNanoseconds: 10_000_000_000,
            executablePathLookup: { execByPID[$0] },
            bsdSnapshotLookup: { bsdByPID[$0] },
            displayNameFromPath: { path in
                if path.hasPrefix("/Applications/Antigravity.app/") {
                    return "Antigravity"
                }
                return PktapHeader.displayName(fromExecutablePath: path)
            },
            bundleIdentifierFromPath: { path in
                if path.hasPrefix("/Library/Frameworks/AcmeCLI.framework/") {
                    return "com.example.acme.cli"
                }
                if path.hasPrefix("/Applications/Antigravity.app/") {
                    return "com.amunx.antigravity"
                }
                return nil
            },
            outerMainExecutableFromAppPath: { appPath in
                appPath == "/Applications/Antigravity.app" ? "Electron" : nil
            }
        )

        // 1. Short-lived process has already exited (`execPath == nil && bsdSnapshot == nil`):
        // falls back to `pth_comm` but MUST create zero negative entries in either cache.
        let exitedPacket = makePktapPacket(
            process: "shortlived",
            pid: Int(reusedPID),
            epid: Int(reusedPID),
            effectiveProcess: "shortlived",
            typeNext: PktapHeader.typeNextPacket,
            interface: "en0",
            innerDLT: 1,
            frame: inner
        )
        let parsedExited = try #require(PktapHeader.parse(exitedPacket))
        let exitedResult = cache.resolve(parsed: parsedExited)
        #expect(exitedResult.processName == "shortlived")
        #expect(exitedResult.provenance?.executablePath == nil)
        #expect(exitedResult.provenance?.bundleIdentifier == nil)
        #expect(cache.metadataCacheCount == 0)
        #expect(cache.pairCacheCount == 0)

        // 2. Immediately afterwards (well within TTL), macOS recycles `reusedPID` for a live
        // process with a bundle ID and a full 12-hop ancestor chain rooted at Antigravity.app.
        clock += 50_000_000
        let leafExec = "/Library/Frameworks/AcmeCLI.framework/Versions/A/Helpers/acme-fetch"
        let hostAppExec = "/Applications/Antigravity.app/Contents/MacOS/Electron"

        // Build 12 ancestor hops above `reusedPID`:
        // hop 1 (`8_101`): `/bin/zsh`
        // hops 2..10 (`8_102`..`8_110`): `/usr/bin/env` (skipped launcher wrappers)
        // hop 11 (`8_111`): `/opt/homebrew/bin/build-runner` (non-shell spawner)
        // hop 12 (`8_112`): `/Applications/Antigravity.app/Contents/MacOS/Electron` (host app)
        execByPID[reusedPID] = leafExec
        bsdByPID[reusedPID] = PktapHeader.BSDProcessSnapshot(
            ppid: 8_101, uid: 501, hasTTY: false, startTimeSec: 1_700_000_200, startTimeUsec: 11_000
        )
        execByPID[8_101] = "/bin/zsh"
        bsdByPID[8_101] = PktapHeader.BSDProcessSnapshot(
            ppid: 8_102, uid: 501, hasTTY: false, startTimeSec: 1_700_000_190, startTimeUsec: 10_000
        )
        for hop in 2 ... 10 {
            let pid = Int32(8_100 + hop)
            execByPID[pid] = "/usr/bin/env"
            bsdByPID[pid] = PktapHeader.BSDProcessSnapshot(
                ppid: pid + 1,
                uid: 501,
                hasTTY: false,
                startTimeSec: 1_700_000_190 - Int64(hop),
                startTimeUsec: 5_000
            )
        }
        execByPID[8_111] = "/opt/homebrew/bin/build-runner"
        bsdByPID[8_111] = PktapHeader.BSDProcessSnapshot(
            ppid: 8_112, uid: 501, hasTTY: false, startTimeSec: 1_700_000_150, startTimeUsec: 2_000
        )
        execByPID[8_112] = hostAppExec
        bsdByPID[8_112] = PktapHeader.BSDProcessSnapshot(
            ppid: 1, uid: 501, hasTTY: false, startTimeSec: 1_700_000_100, startTimeUsec: 1_000
        )

        // Reuse the SAME PID (even with the same comm or a new comm) -> full attribution resolves.
        let reusedPacket = makePktapPacket(
            process: "shortlived",
            pid: Int(reusedPID),
            epid: Int(reusedPID),
            effectiveProcess: "shortlived",
            typeNext: PktapHeader.typeNextPacket,
            interface: "en0",
            innerDLT: 1,
            frame: inner
        )
        let parsedReused = try #require(PktapHeader.parse(reusedPacket))
        let reusedResult = cache.resolve(parsed: parsedReused)
        #expect(reusedResult.processName == "acme-fetch")
        #expect(reusedResult.provenance == ProcessProvenance(
            executablePath: leafExec,
            bundleIdentifier: "com.example.acme.cli",
            viaProcessName: nil,
            parentProcessName: "Antigravity",
            originProcessName: "acme-fetch",
            hostAppName: "Antigravity",
            spawnerProcessName: "build-runner",
            viaShellName: "zsh",
            callerKind: .app,
            hasControllingTTY: false,
            isRootUser: false,
            isKernelTask: false
        ))
        #expect(cache.pairCacheCount == 1)
        #expect(cache.metadataCacheCount == 13)
    }

    @Test
    func attributionCacheRefreshesSamePIDAfterExecveWithIdenticalStartTime() throws {
        let inner = [UInt8](repeating: 0x33, count: 40)
        let pid: Int32 = 6_001
        let terminalPID: Int32 = 6_000
        let sameStartSec: Int64 = 1_700_000_500
        let sameStartUsec: Int32 = 77_000
        var clock: UInt64 = 2_000_000_000

        let itermExec = "/Applications/iTerm.app/Contents/MacOS/iTerm2"
        var execByPID: [Int32: String] = [
            pid: "/bin/zsh",
            terminalPID: itermExec,
        ]
        let bsdByPID: [Int32: PktapHeader.BSDProcessSnapshot] = [
            pid: PktapHeader.BSDProcessSnapshot(
                ppid: terminalPID,
                uid: 501,
                hasTTY: true,
                startTimeSec: sameStartSec,
                startTimeUsec: sameStartUsec
            ),
            terminalPID: PktapHeader.BSDProcessSnapshot(
                ppid: 1,
                uid: 501,
                hasTTY: false,
                startTimeSec: 1_700_000_010,
                startTimeUsec: 1_000
            ),
        ]

        var cache = PktapHeader.AttributionCache(
            nowNanoseconds: { clock },
            ttlNanoseconds: 10_000_000_000,
            executablePathLookup: { execByPID[$0] },
            bsdSnapshotLookup: { bsdByPID[$0] },
            displayNameFromPath: { path in
                path == itermExec ? "iTerm2" : PktapHeader.displayName(fromExecutablePath: path)
            },
            bundleIdentifierFromPath: { path in
                path == itermExec ? "com.googlecode.iterm2" : nil
            },
            outerMainExecutableFromAppPath: { _ in "iTerm2" }
        )

        // 1. Before `execve`: shell `zsh` owns PID 6001.
        let zshPacket = makePktapPacket(
            process: "zsh",
            pid: Int(pid),
            epid: Int(pid),
            effectiveProcess: "zsh",
            typeNext: PktapHeader.typeNextPacket,
            interface: "en0",
            innerDLT: 1,
            frame: inner
        )
        let parsedZsh = try #require(PktapHeader.parse(zshPacket))
        let zshResult = cache.resolve(parsed: parsedZsh)
        #expect(zshResult.processName == "zsh")
        #expect(zshResult.provenance?.executablePath == "/bin/zsh")
        #expect(zshResult.provenance?.callerKind == .terminal)
        #expect(zshResult.provenance?.parentProcessName == "iTerm2")

        // 2. `zsh` calls `execve("/usr/bin/curl")`: SAME PID, SAME `p_starttime`,
        // NEW `parsed.process` and NEW `executablePath`, well inside TTL.
        clock += 200_000_000
        execByPID[pid] = "/usr/bin/curl"

        let curlPacket = makePktapPacket(
            process: "curl",
            pid: Int(pid),
            epid: Int(pid),
            effectiveProcess: "curl",
            typeNext: PktapHeader.typeNextPacket,
            interface: "en0",
            innerDLT: 1,
            frame: inner
        )
        let parsedCurl = try #require(PktapHeader.parse(curlPacket))
        let curlResult = cache.resolve(parsed: parsedCurl)
        #expect(curlResult.processName == "curl")
        #expect(curlResult.provenance?.executablePath == "/usr/bin/curl")
        #expect(curlResult.provenance?.originProcessName == "curl")
        #expect(curlResult.provenance?.callerKind == .terminal)
        #expect(curlResult.provenance?.parentProcessName == "iTerm2")
    }

    @Test
    func attributionCacheRefreshesOnStartTimeChangeAndTTLExpirationForReusedPIDsAndAncestors() throws {
        let inner = [UInt8](repeating: 0x44, count: 40)
        let leafPID: Int32 = 7_500
        let parentPID: Int32 = 7_400
        let itermPID: Int32 = 7_100
        let idePID: Int32 = 7_200
        let ttl: UInt64 = 10_000_000_000
        var clock: UInt64 = 5_000_000_000
        var execLookupCount = 0

        let itermExec = "/Applications/iTerm.app/Contents/MacOS/iTerm2"
        let ideExec = "/Applications/Antigravity.app/Contents/MacOS/Antigravity"

        var execByPID: [Int32: String] = [
            leafPID: "/usr/bin/curl",
            parentPID: "/bin/zsh",
            itermPID: itermExec,
            idePID: ideExec,
        ]
        var bsdByPID: [Int32: PktapHeader.BSDProcessSnapshot] = [
            leafPID: PktapHeader.BSDProcessSnapshot(
                ppid: parentPID, uid: 501, hasTTY: true, startTimeSec: 1_700_001_000, startTimeUsec: 100
            ),
            parentPID: PktapHeader.BSDProcessSnapshot(
                ppid: itermPID, uid: 501, hasTTY: true, startTimeSec: 1_700_000_900, startTimeUsec: 200
            ),
            itermPID: PktapHeader.BSDProcessSnapshot(
                ppid: 1, uid: 501, hasTTY: false, startTimeSec: 1_700_000_100, startTimeUsec: 300
            ),
            idePID: PktapHeader.BSDProcessSnapshot(
                ppid: 1, uid: 501, hasTTY: false, startTimeSec: 1_700_000_200, startTimeUsec: 400
            ),
        ]

        var cache = PktapHeader.AttributionCache(
            nowNanoseconds: { clock },
            ttlNanoseconds: ttl,
            executablePathLookup: { pid in
                execLookupCount += 1
                return execByPID[pid]
            },
            bsdSnapshotLookup: { bsdByPID[$0] },
            displayNameFromPath: { path in
                switch path {
                case itermExec: "iTerm2"
                case ideExec: "Antigravity"
                default: PktapHeader.displayName(fromExecutablePath: path)
                }
            },
            bundleIdentifierFromPath: { path in
                switch path {
                case itermExec: "com.googlecode.iterm2"
                case ideExec: "com.amunx.antigravity"
                default: nil
                }
            },
            outerMainExecutableFromAppPath: { appPath in
                switch appPath {
                case "/Applications/iTerm.app": "iTerm2"
                case "/Applications/Antigravity.app": "Antigravity"
                default: nil
                }
            }
        )

        let curlPacket = makePktapPacket(
            process: "curl",
            pid: Int(leafPID),
            epid: Int(leafPID),
            effectiveProcess: "curl",
            typeNext: PktapHeader.typeNextPacket,
            interface: "en0",
            innerDLT: 1,
            frame: inner
        )
        let parsedCurl = try #require(PktapHeader.parse(curlPacket))

        // 1. Cold miss resolves `curl` under `iTerm2` via `zsh`.
        let first = cache.resolve(parsed: parsedCurl)
        #expect(first.processName == "curl")
        #expect(first.provenance?.callerKind == .terminal)
        #expect(first.provenance?.parentProcessName == "iTerm2")
        #expect(first.provenance?.viaShellName == "zsh")
        let lookupsAfterColdMiss = execLookupCount
        #expect(lookupsAfterColdMiss == 3)

        // 2. Warm hit within TTL with unchanged `startTime` avoids `executablePathLookup`.
        clock += 1_000_000_000
        let warmHit = cache.resolve(parsed: parsedCurl)
        #expect(warmHit == first)
        #expect(execLookupCount == lookupsAfterColdMiss)

        // 3. Same PID reused with the SAME process name (`curl`), STILL within TTL,
        //    but `startTimeUsec` changed and parent is now `Antigravity` (direct `.app` host).
        clock += 1_000_000_000
        execByPID[leafPID] = "/opt/homebrew/bin/curl"
        bsdByPID[leafPID] = PktapHeader.BSDProcessSnapshot(
            ppid: idePID, uid: 501, hasTTY: false, startTimeSec: 1_700_001_000, startTimeUsec: 999
        )
        let recycledSameName = cache.resolve(parsed: parsedCurl)
        #expect(recycledSameName.processName == "curl")
        #expect(recycledSameName.provenance?.executablePath == "/opt/homebrew/bin/curl")
        #expect(recycledSameName.provenance?.callerKind == .app)
        #expect(recycledSameName.provenance?.hostAppName == "Antigravity")
        #expect(recycledSameName.provenance?.viaShellName == nil)
        #expect(recycledSameName.provenance?.hasControllingTTY == false)

        // 4. Ancestor PID `parentPID` is recycled within TTL (`startTimeSec` changed, now `node`
        //    under `Antigravity`), and a new child PID `7_501` points to `parentPID`.
        clock += 500_000_000
        let childPID: Int32 = 7_501
        execByPID[parentPID] = "/opt/homebrew/bin/node"
        bsdByPID[parentPID] = PktapHeader.BSDProcessSnapshot(
            ppid: idePID, uid: 501, hasTTY: false, startTimeSec: 1_700_002_000, startTimeUsec: 55
        )
        execByPID[childPID] = "/usr/bin/curl"
        bsdByPID[childPID] = PktapHeader.BSDProcessSnapshot(
            ppid: parentPID, uid: 501, hasTTY: false, startTimeSec: 1_700_002_100, startTimeUsec: 66
        )
        let childPacket = makePktapPacket(
            process: "curl",
            pid: Int(childPID),
            epid: Int(childPID),
            effectiveProcess: "curl",
            typeNext: PktapHeader.typeNextPacket,
            interface: "en0",
            innerDLT: 1,
            frame: inner
        )
        let parsedChild = try #require(PktapHeader.parse(childPacket))
        let childResult = cache.resolve(parsed: parsedChild)
        #expect(childResult.provenance?.hostAppName == "Antigravity")
        #expect(childResult.provenance?.spawnerProcessName == "node")
        #expect(childResult.provenance?.viaShellName == nil)

        // 5. After `ttlNanoseconds` elapses, even a same-name + same-startTime entry expires
        //    and refreshes cleanly to pick up new metadata & ancestry.
        clock += ttl
        execByPID[leafPID] = "/usr/bin/python3"
        bsdByPID[leafPID] = PktapHeader.BSDProcessSnapshot(
            ppid: 1, uid: 0, hasTTY: false, startTimeSec: 1_700_001_000, startTimeUsec: 999
        )
        let afterTTL = cache.resolve(parsed: parsedCurl)
        #expect(afterTTL.processName == "python3")
        #expect(afterTTL.provenance?.executablePath == "/usr/bin/python3")
        #expect(afterTTL.provenance?.isRootUser == true)
        #expect(afterTTL.provenance?.callerKind == .system)
        #expect(afterTTL.provenance?.hostAppName == nil)
    }

    @Test
    func attributionCacheDebouncesSysctlReverificationDuringHighThroughputBurst() throws {
        let inner = [UInt8](repeating: 0x55, count: 40)
        let leafPID: Int32 = 8_500
        let siblingPID: Int32 = 8_501
        let shellPID: Int32 = 8_400
        let terminalPID: Int32 = 8_300
        let startClock: UInt64 = 10_000_000_000
        var clock = startClock
        var execLookupCount = 0
        var bsdLookupCounts: [Int32: Int] = [:]

        let itermExec = "/Applications/iTerm.app/Contents/MacOS/iTerm2"
        let execByPID: [Int32: String] = [
            leafPID: "/usr/bin/curl",
            siblingPID: "/usr/bin/git",
            shellPID: "/bin/zsh",
            terminalPID: itermExec,
        ]
        let bsdByPID: [Int32: PktapHeader.BSDProcessSnapshot] = [
            leafPID: PktapHeader.BSDProcessSnapshot(
                ppid: shellPID, uid: 501, hasTTY: true, startTimeSec: 1_700_010_000, startTimeUsec: 100
            ),
            siblingPID: PktapHeader.BSDProcessSnapshot(
                ppid: shellPID, uid: 501, hasTTY: true, startTimeSec: 1_700_010_001, startTimeUsec: 200
            ),
            shellPID: PktapHeader.BSDProcessSnapshot(
                ppid: terminalPID, uid: 501, hasTTY: true, startTimeSec: 1_700_009_000, startTimeUsec: 300
            ),
            terminalPID: PktapHeader.BSDProcessSnapshot(
                ppid: 1, uid: 501, hasTTY: false, startTimeSec: 1_700_000_100, startTimeUsec: 400
            ),
        ]

        var cache = PktapHeader.AttributionCache(
            nowNanoseconds: { clock },
            ttlNanoseconds: 10_000_000_000,
            executablePathLookup: { pid in
                execLookupCount += 1
                return execByPID[pid]
            },
            bsdSnapshotLookup: { pid in
                bsdLookupCounts[pid, default: 0] += 1
                return bsdByPID[pid]
            },
            displayNameFromPath: { path in
                path == itermExec ? "iTerm2" : PktapHeader.displayName(fromExecutablePath: path)
            },
            bundleIdentifierFromPath: { path in
                path == itermExec ? "com.googlecode.iterm2" : nil
            },
            outerMainExecutableFromAppPath: { appPath in
                appPath == "/Applications/iTerm.app" ? "iTerm2" : nil
            }
        )
        #expect(cache.reverifyIntervalNanoseconds == 250_000_000)

        let curlPacket = makePktapPacket(
            process: "curl",
            pid: Int(leafPID),
            epid: Int(leafPID),
            effectiveProcess: "curl",
            typeNext: PktapHeader.typeNextPacket,
            interface: "en0",
            innerDLT: 1,
            frame: inner
        )
        let parsedCurl = try #require(PktapHeader.parse(curlPacket))

        // 1. Burst of 10,000 packets spanning 199.98ms (< 250ms): each unique PID in the
        //    3-hop chain is probed via `bsdSnapshotLookup` at most once (NOT 10,000 times).
        let expectedFirst = cache.resolve(parsed: parsedCurl)
        #expect(expectedFirst.processName == "curl")
        #expect(expectedFirst.provenance?.parentProcessName == "iTerm2")
        #expect(expectedFirst.provenance?.viaShellName == "zsh")
        #expect(expectedFirst.provenance?.callerKind == .terminal)
        for _ in 1 ..< 10_000 {
            clock += 20_000
            let hit = cache.resolve(parsed: parsedCurl)
            #expect(hit == expectedFirst)
        }
        #expect(clock - startClock < 250_000_000)
        #expect(execLookupCount == 3)
        #expect(bsdLookupCounts[leafPID] == 1)
        #expect(bsdLookupCounts[shellPID] == 1)
        #expect(bsdLookupCounts[terminalPID] == 1)
        #expect(bsdLookupCounts.values.reduce(0, +) == 3)

        // 2. Sibling child spawned under the same ancestors within `< 250ms` reuses cached
        //    ancestor metadata without extra `bsdSnapshotLookup` calls on `shellPID`/`terminalPID`.
        let gitPacket = makePktapPacket(
            process: "git",
            pid: Int(siblingPID),
            epid: Int(siblingPID),
            effectiveProcess: "git",
            typeNext: PktapHeader.typeNextPacket,
            interface: "en0",
            innerDLT: 1,
            frame: inner
        )
        let parsedGit = try #require(PktapHeader.parse(gitPacket))
        let gitResult = cache.resolve(parsed: parsedGit)
        #expect(gitResult.processName == "git")
        #expect(gitResult.provenance?.parentProcessName == "iTerm2")
        #expect(gitResult.provenance?.viaShellName == "zsh")
        #expect(bsdLookupCounts[siblingPID] == 1)
        #expect(bsdLookupCounts[shellPID] == 1)
        #expect(bsdLookupCounts[terminalPID] == 1)

        // 3. Advancing clock to exactly `+250ms` triggers exactly 1 leaf re-verification probe
        //    and resets the 250ms debounce window for the next 10,000-packet burst.
        clock = startClock + 250_000_000
        let reverified = cache.resolve(parsed: parsedCurl)
        #expect(reverified == expectedFirst)
        #expect(bsdLookupCounts[leafPID] == 2)
        #expect(execLookupCount == 4)

        let secondBurstStart = clock
        for _ in 0 ..< 10_000 {
            clock += 20_000
            let hit = cache.resolve(parsed: parsedCurl)
            #expect(hit == expectedFirst)
        }
        #expect(clock - secondBurstStart < 250_000_000)
        #expect(bsdLookupCounts[leafPID] == 2)
        #expect(bsdLookupCounts[shellPID] == 1)
        #expect(bsdLookupCounts[terminalPID] == 1)
    }

    @Test
    func attributionCacheInvalidatesReusedPIDAtReverifyBoundaryWithinTTL() throws {
        let inner = [UInt8](repeating: 0x66, count: 40)
        let leafPID: Int32 = 8_600
        let itermPID: Int32 = 8_601
        let idePID: Int32 = 8_602
        var clock: UInt64 = 15_000_000_000
        var bsdLookupCount = 0

        let itermExec = "/Applications/iTerm.app/Contents/MacOS/iTerm2"
        let ideExec = "/Applications/Antigravity.app/Contents/MacOS/Antigravity"

        var execByPID: [Int32: String] = [
            leafPID: "/usr/bin/curl",
            itermPID: itermExec,
            idePID: ideExec,
        ]
        var bsdByPID: [Int32: PktapHeader.BSDProcessSnapshot] = [
            leafPID: PktapHeader.BSDProcessSnapshot(
                ppid: itermPID, uid: 501, hasTTY: true, startTimeSec: 1_700_020_000, startTimeUsec: 100
            ),
            itermPID: PktapHeader.BSDProcessSnapshot(
                ppid: 1, uid: 501, hasTTY: false, startTimeSec: 1_700_000_100, startTimeUsec: 10
            ),
            idePID: PktapHeader.BSDProcessSnapshot(
                ppid: 1, uid: 501, hasTTY: false, startTimeSec: 1_700_000_200, startTimeUsec: 20
            ),
        ]

        var cache = PktapHeader.AttributionCache(
            nowNanoseconds: { clock },
            ttlNanoseconds: 10_000_000_000,
            executablePathLookup: { execByPID[$0] },
            bsdSnapshotLookup: { pid in
                bsdLookupCount += 1
                return bsdByPID[pid]
            },
            displayNameFromPath: { path in
                switch path {
                case itermExec: "iTerm2"
                case ideExec: "Antigravity"
                default: PktapHeader.displayName(fromExecutablePath: path)
                }
            },
            bundleIdentifierFromPath: { path in
                switch path {
                case itermExec: "com.googlecode.iterm2"
                case ideExec: "com.amunx.antigravity"
                default: nil
                }
            },
            outerMainExecutableFromAppPath: { appPath in
                switch appPath {
                case "/Applications/iTerm.app": "iTerm2"
                case "/Applications/Antigravity.app": "Antigravity"
                default: nil
                }
            }
        )

        let curlPacket = makePktapPacket(
            process: "curl",
            pid: Int(leafPID),
            epid: Int(leafPID),
            effectiveProcess: "curl",
            typeNext: PktapHeader.typeNextPacket,
            interface: "en0",
            innerDLT: 1,
            frame: inner
        )
        let parsedCurl = try #require(PktapHeader.parse(curlPacket))

        let initial = cache.resolve(parsed: parsedCurl)
        #expect(initial.processName == "curl")
        #expect(initial.provenance?.executablePath == "/usr/bin/curl")
        #expect(initial.provenance?.callerKind == .terminal)
        #expect(initial.provenance?.parentProcessName == "iTerm2")
        #expect(bsdLookupCount == 2)

        // Advance by +300ms (>= 250ms debounce window, well within 10s TTL) and simulate
        // PID reuse with a different start time and parent while keeping the same comm.
        clock += 300_000_000
        execByPID[leafPID] = "/opt/homebrew/bin/curl"
        bsdByPID[leafPID] = PktapHeader.BSDProcessSnapshot(
            ppid: idePID, uid: 501, hasTTY: false, startTimeSec: 1_700_020_001, startTimeUsec: 555
        )

        let recycled = cache.resolve(parsed: parsedCurl)
        #expect(recycled.processName == "curl")
        #expect(recycled.provenance?.executablePath == "/opt/homebrew/bin/curl")
        #expect(recycled.provenance?.callerKind == .app)
        #expect(recycled.provenance?.hostAppName == "Antigravity")
        #expect(recycled.provenance?.hasControllingTTY == false)

        // Setting `reverifyIntervalNanoseconds: 0` probes on every hit, catching same-tick reuse.
        var unthrottled = PktapHeader.AttributionCache(
            nowNanoseconds: { clock },
            ttlNanoseconds: 10_000_000_000,
            reverifyIntervalNanoseconds: 0,
            executablePathLookup: { execByPID[$0] },
            bsdSnapshotLookup: { bsdByPID[$0] },
            displayNameFromPath: { path in
                switch path {
                case itermExec: "iTerm2"
                case ideExec: "Antigravity"
                default: PktapHeader.displayName(fromExecutablePath: path)
                }
            },
            bundleIdentifierFromPath: { _ in nil },
            outerMainExecutableFromAppPath: { _ in nil }
        )
        let beforeReuse = unthrottled.resolve(parsed: parsedCurl)
        #expect(beforeReuse.provenance?.executablePath == "/opt/homebrew/bin/curl")
        execByPID[leafPID] = "/usr/local/bin/curl"
        bsdByPID[leafPID] = PktapHeader.BSDProcessSnapshot(
            ppid: itermPID, uid: 501, hasTTY: true, startTimeSec: 1_700_020_002, startTimeUsec: 777
        )
        let afterImmediateReuse = unthrottled.resolve(parsed: parsedCurl)
        #expect(afterImmediateReuse.provenance?.executablePath == "/usr/local/bin/curl")
        #expect(afterImmediateReuse.provenance?.parentProcessName == "iTerm2")
    }

    @Test
    func attributionCacheInvalidatesSamePIDExecveWithinDebounceWindow() throws {
        let inner = [UInt8](repeating: 0x77, count: 40)
        let pid: Int32 = 8_700
        let terminalPID: Int32 = 8_701
        let sameStartSec: Int64 = 1_700_030_000
        let sameStartUsec: Int32 = 12_345
        var clock: UInt64 = 20_000_000_000
        var bsdLookupCounts: [Int32: Int] = [:]

        let itermExec = "/Applications/iTerm.app/Contents/MacOS/iTerm2"
        var execByPID: [Int32: String] = [
            pid: "/bin/zsh",
            terminalPID: itermExec,
        ]
        let bsdByPID: [Int32: PktapHeader.BSDProcessSnapshot] = [
            pid: PktapHeader.BSDProcessSnapshot(
                ppid: terminalPID,
                uid: 501,
                hasTTY: true,
                startTimeSec: sameStartSec,
                startTimeUsec: sameStartUsec
            ),
            terminalPID: PktapHeader.BSDProcessSnapshot(
                ppid: 1,
                uid: 501,
                hasTTY: false,
                startTimeSec: 1_700_000_100,
                startTimeUsec: 10
            ),
        ]

        var cache = PktapHeader.AttributionCache(
            nowNanoseconds: { clock },
            ttlNanoseconds: 10_000_000_000,
            executablePathLookup: { execByPID[$0] },
            bsdSnapshotLookup: { targetPID in
                bsdLookupCounts[targetPID, default: 0] += 1
                return bsdByPID[targetPID]
            },
            displayNameFromPath: { path in
                path == itermExec ? "iTerm2" : PktapHeader.displayName(fromExecutablePath: path)
            },
            bundleIdentifierFromPath: { path in
                path == itermExec ? "com.googlecode.iterm2" : nil
            },
            outerMainExecutableFromAppPath: { _ in "iTerm2" }
        )

        let zshPacket = makePktapPacket(
            process: "zsh",
            pid: Int(pid),
            epid: Int(pid),
            effectiveProcess: "zsh",
            typeNext: PktapHeader.typeNextPacket,
            interface: "en0",
            innerDLT: 1,
            frame: inner
        )
        let parsedZsh = try #require(PktapHeader.parse(zshPacket))
        let zshResult = cache.resolve(parsed: parsedZsh)
        #expect(zshResult.processName == "zsh")
        #expect(zshResult.provenance?.executablePath == "/bin/zsh")
        #expect(zshResult.provenance?.parentProcessName == "iTerm2")
        #expect(bsdLookupCounts[pid] == 1)
        #expect(bsdLookupCounts[terminalPID] == 1)

        // Only +1ms later (well inside the 250ms debounce window), `zsh` calls `execve` to `curl`.
        // Because `PIDPair.process` changed, `pidPairCache` misses and leaf `pid` is evicted
        // immediately while ancestor `terminalPID` stays debounced.
        clock += 1_000_000
        execByPID[pid] = "/usr/bin/curl"

        let curlPacket = makePktapPacket(
            process: "curl",
            pid: Int(pid),
            epid: Int(pid),
            effectiveProcess: "curl",
            typeNext: PktapHeader.typeNextPacket,
            interface: "en0",
            innerDLT: 1,
            frame: inner
        )
        let parsedCurl = try #require(PktapHeader.parse(curlPacket))
        let curlResult = cache.resolve(parsed: parsedCurl)
        #expect(curlResult.processName == "curl")
        #expect(curlResult.provenance?.executablePath == "/usr/bin/curl")
        #expect(curlResult.provenance?.originProcessName == "curl")
        #expect(curlResult.provenance?.callerKind == .terminal)
        #expect(curlResult.provenance?.parentProcessName == "iTerm2")
        #expect(bsdLookupCounts[pid] == 2)
        #expect(bsdLookupCounts[terminalPID] == 1)
    }

    @Test
    func parsesInboundTargetsAcrossLinkTypesAndResolvesLiveSocketPortMap() throws {
        // 1. Ethernet IPv4 TCP (`93.184.216.34:443 -> 192.168.1.10:54321`)
        let ethIPv4TCP = makeEthernetIPv4Packet(
            proto: 6,
            srcIP: [93, 184, 216, 34],
            dstIP: [192, 168, 1, 10],
            srcPort: 443,
            dstPort: 54_321
        )
        let parsedEthV4 = try #require(PktapHeader.parseInboundTarget(innerBytes: ethIPv4TCP, innerDLT: 1))
        #expect(parsedEthV4.proto == .tcp)
        #expect(parsedEthV4.destinationIP == .v4(0xC0A8_010A))
        #expect(parsedEthV4.destinationPort == 54_321)
        #expect(!parsedEthV4.destinationIP.isMulticastOrBroadcast)

        // 2. Ethernet 802.1Q VLAN-tagged IPv4 UDP (`-> 224.0.0.251:5353` multicast)
        let vlanHeader: [UInt8] = [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
            0x81, 0x00, 0x00, 0x0A, 0x08, 0x00,
        ]
        let rawIPv4MulticastUDP = Array(makeEthernetIPv4Packet(
            proto: 17,
            srcIP: [192, 168, 1, 78],
            dstIP: [224, 0, 0, 251],
            srcPort: 5_353,
            dstPort: 5_353
        ).dropFirst(14))
        let parsedVLANMulticast = try #require(
            PktapHeader.parseInboundTarget(innerBytes: vlanHeader + rawIPv4MulticastUDP, innerDLT: 1)
        )
        #expect(parsedVLANMulticast.proto == .udp)
        #expect(parsedVLANMulticast.destinationPort == 5_353)
        #expect(parsedVLANMulticast.destinationIP.isMulticastOrBroadcast)

        // 3. BSD Loopback (`DLT_NULL = 0`) IPv6 UDP (`[::1]:53 -> [::1]:59123`)
        var loopbackIPv6: [UInt8] = [UInt8(AF_INET6), 0, 0, 0]
        loopbackIPv6.append(contentsOf: makeRawIPv6Packet(
            nextHeader: 17,
            dstIP: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            srcPort: 53,
            dstPort: 59_123
        ))
        let parsedLoopV6 = try #require(PktapHeader.parseInboundTarget(innerBytes: loopbackIPv6, innerDLT: 0))
        #expect(parsedLoopV6.proto == .udp)
        #expect(parsedLoopV6.destinationIP == .v6(0, 1))
        #expect(parsedLoopV6.destinationPort == 59_123)

        // 4. Raw IP (`DLT_RAW = 12` & `LINKTYPE_RAW = 101`) IPv4 TCP
        let rawIPv4 = Array(ethIPv4TCP.dropFirst(14))
        #expect(PktapHeader.parseInboundTarget(innerBytes: rawIPv4, innerDLT: 12) == parsedEthV4)
        #expect(PktapHeader.parseInboundTarget(innerBytes: rawIPv4, innerDLT: 101) == parsedEthV4)

        // 5. Rejects ARP (`0x0806`) and non-initial IPv4 fragments (`fragOffset != 0`)
        let arpFrame: [UInt8] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x06] + [UInt8](repeating: 0, count: 28)
        #expect(PktapHeader.parseInboundTarget(innerBytes: arpFrame, innerDLT: 1) == nil)

        var nonInitialFrag = ethIPv4TCP
        nonInitialFrag[14 + 6] = 0x00
        nonInitialFrag[14 + 7] = 0x20
        #expect(PktapHeader.parseInboundTarget(innerBytes: nonInitialFrag, innerDLT: 1) == nil)

        // 6. Live `<libproc.h>` inbound socket port map resolves local sockets and rejects multicast/wrong-proto.
        let tcpFD = socket(AF_INET, SOCK_STREAM, 0)
        try #require(tcpFD >= 0)
        defer { close(tcpFD) }

        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = 0
        addr.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))
        let bindRC = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { saPtr in
                bind(tcpFD, saPtr, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        try #require(bindRC == 0)
        try #require(listen(tcpFD, 1) == 0)

        var bound = sockaddr_in()
        var boundLen = socklen_t(MemoryLayout<sockaddr_in>.size)
        let nameRC = withUnsafeMutablePointer(to: &bound) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { saPtr in
                getsockname(tcpFD, saPtr, &boundLen)
            }
        }
        try #require(nameRC == 0)
        let tcpPort = UInt16(bigEndian: bound.sin_port)
        try #require(tcpPort > 0)

        let portMap = PktapHeader.collectInboundSocketPortMap()
        let inboundLoopbackTCP = [UInt8(AF_INET), 0, 0, 0] + Array(makeEthernetIPv4Packet(
            proto: 6,
            srcIP: [127, 0, 0, 1],
            dstIP: [127, 0, 0, 1],
            srcPort: 60_000,
            dstPort: tcpPort
        ).dropFirst(14))
        let inboundTarget = try #require(PktapHeader.parseInboundTarget(innerBytes: inboundLoopbackTCP, innerDLT: 0))
        let owner = try #require(portMap.lookup(target: inboundTarget))
        #expect(owner.pid == ProcessInfo.processInfo.processIdentifier)
        #expect(!owner.command.isEmpty)

        // Wrong protocol (UDP packet to that TCP port) and multicast destination must not match.
        let wrongProtoTarget = PktapHeader.InboundPacketTarget(
            proto: .udp,
            destinationIP: .v4(0x7F00_0001),
            destinationPort: tcpPort
        )
        #expect(portMap.lookup(target: wrongProtoTarget) == nil)
        #expect(portMap.lookup(target: parsedVLANMulticast) == nil)
    }

    // MARK: Private

    private func makeEthernetIPv4Packet(
        proto: UInt8,
        srcIP: [UInt8],
        dstIP: [UInt8],
        srcPort: UInt16,
        dstPort: UInt16
    )
        -> [UInt8]
    {
        var bytes = [UInt8](repeating: 0, count: 14 + 20 + 8)
        bytes[12] = 0x08
        bytes[13] = 0x00
        bytes[14] = 0x45
        bytes[14 + 2] = 0x00
        bytes[14 + 3] = 28
        bytes[14 + 8] = 64
        bytes[14 + 9] = proto
        for index in 0 ..< 4 {
            bytes[14 + 12 + index] = srcIP[index]
            bytes[14 + 16 + index] = dstIP[index]
        }
        bytes[34] = UInt8((srcPort >> 8) & 0xFF)
        bytes[35] = UInt8(srcPort & 0xFF)
        bytes[36] = UInt8((dstPort >> 8) & 0xFF)
        bytes[37] = UInt8(dstPort & 0xFF)
        return bytes
    }

    private func makeRawIPv6Packet(
        nextHeader: UInt8,
        dstIP: [UInt8],
        srcPort: UInt16,
        dstPort: UInt16
    )
        -> [UInt8]
    {
        var bytes = [UInt8](repeating: 0, count: 40 + 8)
        bytes[0] = 0x60
        bytes[4] = 0x00
        bytes[5] = 0x08
        bytes[6] = nextHeader
        bytes[7] = 64
        for index in 0 ..< 16 {
            bytes[24 + index] = dstIP[index]
        }
        bytes[40] = UInt8((srcPort >> 8) & 0xFF)
        bytes[41] = UInt8(srcPort & 0xFF)
        bytes[42] = UInt8((dstPort >> 8) & 0xFF)
        bytes[43] = UInt8(dstPort & 0xFF)
        return bytes
    }

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
        let v = UInt32(bitPattern: Int32(truncatingIfNeeded: value))
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
