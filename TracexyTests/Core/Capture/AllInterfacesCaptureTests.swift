import Foundation
import Testing
@testable import Tracexy

@Suite("All-Interfaces (pktap) capture support")
struct AllInterfacesCaptureTests {
    // MARK: Internal

    @Test("allInterfacesID and predicate recognize pktap case- and whitespace-insensitively")
    func allInterfacesIdentifierMatching() {
        #expect(NetworkInterfaces.allInterfacesID == "pktap")
        #expect(NetworkInterfaces.isAllInterfaces("pktap"))
        #expect(NetworkInterfaces.isAllInterfaces("PKTAP"))
        #expect(NetworkInterfaces.isAllInterfaces("  pktap \n"))
        #expect(!NetworkInterfaces.isAllInterfaces("en0"))
        #expect(!NetworkInterfaces.isAllInterfaces("lo0"))
        #expect(!NetworkInterfaces.isAllInterfaces("pktap,en0"))
        #expect(!NetworkInterfaces.isAllInterfaces(""))
    }

    @Test("NetworkInterfaces.available() and grouped() place All Interfaces (pktap) first")
    @MainActor
    func availableAndGroupedPlaceAllInterfacesFirst() throws {
        #expect(InterfaceCategory.allCases.first == .all)

        let available = NetworkInterfaces.available()
        let first = try #require(available.first)
        #expect(first.id == NetworkInterfaces.allInterfacesID)
        #expect(first.category == .all)
        #expect(first.symbol == "globe")
        #expect(first.isUp)
        #expect(!first.isLoopback)
        #expect(first.ipv4 == nil)
        #expect(available.count { $0.id == NetworkInterfaces.allInterfacesID } == 1)

        let grouped = NetworkInterfaces.grouped()
        let firstGroup = try #require(grouped.first)
        #expect(firstGroup.category == .all)
        #expect(firstGroup.interfaces.map(\.id) == [NetworkInterfaces.allInterfacesID])

        // Manage Interfaces settings hide pktap unless it is the kept active source.
        var settings = InterfaceSettings()
        settings.hidden.insert(NetworkInterfaces.allInterfacesID)
        settings.friendlyNames[NetworkInterfaces.allInterfacesID] = "Every Link"
        let hiddenGroups = NetworkInterfaces.grouped(settings, keeping: "en0", includingPipes: false)
        #expect(!hiddenGroups.contains { $0.category == .all })

        let keptGroups = NetworkInterfaces.grouped(
            settings,
            keeping: NetworkInterfaces.allInterfacesID,
            includingPipes: false
        )
        let keptAll = try #require(keptGroups.first { $0.category == .all }?.interfaces.first)
        #expect(keptAll.id == NetworkInterfaces.allInterfacesID)
        #expect(keptAll.displayName == "Every Link")
        #expect(keptAll.category == .all)
    }

    @Test("primaryIPv4() skips pktap and returns the primary physical LAN IPv4")
    @MainActor
    func primaryIPv4SkipsPktap() {
        let expected = NetworkInterfaces.available()
            .first { !NetworkInterfaces.isAllInterfaces($0.id) && !$0.isLoopback && $0.isUp && $0.ipv4 != nil }?
            .ipv4
        let primary = NetworkInterfaces.primaryIPv4()
        #expect(primary == expected)
        #expect(primary != NetworkInterfaces.allInterfacesID)
    }

    @Test("resolvedDefaultInterface honors explicit pktap while Automatic stays on a physical interface")
    @MainActor
    func resolvedDefaultInterfaceRespectsExplicitPktapAndAutomatic() throws {
        let suiteName = "tracexy.tests.allInterfacesDefault.\(UUID().uuidString)"
        let defaults = try #require(UserDefaults(suiteName: suiteName))
        defer { TestPreferences.remove(suiteName) }

        // Unset / Automatic ("") must not pick pktap or loopback.
        let automaticUnset = MainContentCoordinator.resolvedDefaultInterface(defaults: defaults)
        #expect(!NetworkInterfaces.isAllInterfaces(automaticUnset))
        #expect(!automaticUnset.hasPrefix("lo"))

        defaults.set("", forKey: SettingsKeys.defaultInterface)
        let automaticEmpty = MainContentCoordinator.resolvedDefaultInterface(defaults: defaults)
        #expect(!NetworkInterfaces.isAllInterfaces(automaticEmpty))
        #expect(!automaticEmpty.hasPrefix("lo"))

        // Explicit "pktap" saved as default interface must be returned verbatim.
        defaults.set(NetworkInterfaces.allInterfacesID, forKey: SettingsKeys.defaultInterface)
        let explicit = MainContentCoordinator.resolvedDefaultInterface(defaults: defaults)
        #expect(explicit == NetworkInterfaces.allInterfacesID)
    }

    @Test("CaptureReadinessPresentation shows pktap as ready and suppresses promiscuous mode")
    @MainActor
    func readinessPresentationForPktap() throws {
        let pktap = NetworkInterface.allInterfaces()
        let configWithPromisc = CaptureConfiguration(
            interface: NetworkInterfaces.allInterfacesID,
            snapLength: 65_536,
            promiscuous: true,
            bpf: nil
        )
        let presentation = CaptureReadinessPresentation(
            displayState: .stopped,
            captureError: nil,
            interfaceID: NetworkInterfaces.allInterfacesID,
            interface: pktap,
            configuration: configWithPromisc,
            retentionCapacity: 8_000,
            helperStatus: .installedCompatible,
            isDirectCapture: false,
            captureStatistics: nil,
            helperDropCount: 0,
            retentionEvictionCount: 0
        )

        let interfaceItem = try #require(presentation.items.first { $0.label == "Interface" })
        #expect(interfaceItem.level == .ready)
        #expect(interfaceItem.systemImage == "globe")
        #expect(interfaceItem.value == "\(pktap.menuLabel), \(pktap.detail)")

        let snapshotItem = try #require(presentation.items.first { $0.label == "Packet snapshot" })
        #expect(snapshotItem.value == "\(configWithPromisc.snapLength.formatted()) bytes")
        #expect(!snapshotItem.value.contains("promiscuous"))

        // Contrast: a physical interface with promiscuous mode still surfaces it.
        let wifi = NetworkInterface(
            id: "en0",
            displayName: "Wi-Fi",
            category: .wifi,
            ipv4: "192.0.2.10",
            isUp: true,
            isLoopback: false
        )
        let wifiPresentation = CaptureReadinessPresentation(
            displayState: .stopped,
            captureError: nil,
            interfaceID: "en0",
            interface: wifi,
            configuration: CaptureConfiguration(
                interface: "en0",
                snapLength: 65_536,
                promiscuous: true,
                bpf: nil
            ),
            retentionCapacity: 8_000,
            helperStatus: .installedCompatible,
            isDirectCapture: false,
            captureStatistics: nil,
            helperDropCount: 0,
            retentionEvictionCount: 0
        )
        let wifiSnapshot = try #require(wifiPresentation.items.first { $0.label == "Packet snapshot" })
        #expect(wifiSnapshot.value == "\(Int(65_536).formatted()) bytes, promiscuous mode")
    }

    @Test("All Interfaces category, displayName, detail, pickerLabel, and readiness localize live in en, zh-Hans, and vi")
    @MainActor
    func liveLocalizationAcrossSupportedLanguages() throws {
        let bundles = try makeCatalogBundles()
        defer { bundles.teardown() }

        let expectations: [(
            lang: String,
            title: String,
            detail: String,
            pickerLabel: String,
            ethernetTitle: String,
            tunnelsTitle: String
        )] = [
            (
                "en",
                "All Interfaces",
                "Wi-Fi, Loopback & Tunnels",
                "All Interfaces (pktap) — Wi-Fi, Loopback & Tunnels",
                "Ethernet",
                "Tunnels"
            ),
            (
                "zh-Hans",
                "全部接口",
                "Wi-Fi、本地回环与隧道",
                "全部接口 (pktap) — Wi-Fi、本地回环与隧道",
                "以太网",
                "隧道"
            ),
            (
                "vi",
                "Tất cả giao diện",
                "Wi-Fi, Loopback & Đường hầm",
                "Tất cả giao diện (pktap) — Wi-Fi, Loopback & Đường hầm",
                "Ethernet",
                "Đường hầm"
            ),
        ]

        for expected in expectations {
            try AppLanguage.withTemporaryLanguageForTesting(expected.lang, baseBundle: bundles.root) {
                #expect(InterfaceCategory.all.title == expected.title)
                #expect(InterfaceCategory.ethernet.title == expected.ethernetTitle)
                #expect(InterfaceCategory.tunnels.title == expected.tunnelsTitle)

                let allIface = NetworkInterface.allInterfaces()
                #expect(allIface.displayName == expected.title)
                #expect(allIface.detail == expected.detail)
                #expect(allIface.pickerLabel == expected.pickerLabel)

                let readiness = CaptureReadinessPresentation(
                    displayState: .capturing,
                    captureError: nil,
                    interfaceID: NetworkInterfaces.allInterfacesID,
                    interface: allIface,
                    configuration: CaptureConfiguration(
                        interface: NetworkInterfaces.allInterfacesID,
                        snapLength: 65_536,
                        promiscuous: true,
                        bpf: nil
                    ),
                    retentionCapacity: 8_000,
                    helperStatus: .installedCompatible,
                    isDirectCapture: false,
                    captureStatistics: nil,
                    helperDropCount: 0,
                    retentionEvictionCount: 0
                )
                let interfaceRow = try #require(readiness.items.first { $0.label == "Interface" })
                #expect(interfaceRow.value == "\(expected.title) (pktap), \(expected.detail)")
                #expect(interfaceRow.level == .ready)
            }
        }
    }

    @Test("Multi-DLT Ethernet + BSD Loopback (127.0.0.1) + Raw IP frames round-trip through LiveCaptureSpool and SessionAccumulator")
    func multiDLTSpoolAndSessionAccumulatorRoundTrip() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("AllInterfacesCaptureTests-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let base = Date(timeIntervalSince1970: 1_700_000_000)

        // 1. Ethernet (DLT 1) TLS ClientHello on en0.
        let ethBytes = PacketBuilder.tlsClientHelloFrame(
            sni: "lan.example",
            src: "192.0.2.25",
            dst: "203.0.113.44",
            srcPort: 51_001
        )
        let ethFrame = CapturedFrame(
            bytes: ethBytes,
            timestamp: base,
            originalLength: ethBytes.count,
            linkType: LinkType.ethernet,
            processName: "Safari"
        )

        // 2. BSD Loopback (DLT 0, 4-byte little-endian AF_INET = 2) local 127.0.0.1 HTTP traffic on lo0.
        let loopbackIPv4 = Array(PacketBuilder.tlsClientHelloFrame(
            sni: "localhost.internal",
            src: "127.0.0.1",
            dst: "127.0.0.1",
            srcPort: 52_002
        ).dropFirst(14))
        let bsdNullHeader: [UInt8] = [0x02, 0x00, 0x00, 0x00] // PF_INET (2), host little-endian on macOS
        let loopbackBytes = bsdNullHeader + loopbackIPv4
        let loopbackFrame = CapturedFrame(
            bytes: loopbackBytes,
            timestamp: base.addingTimeInterval(0.05),
            originalLength: loopbackBytes.count,
            linkType: LinkType.null,
            processName: "node"
        )

        // 3. Raw IP (LINKTYPE_RAW = 101) DNS query on a tunnel interface (utun*).
        let rawTunnelBytes = Array(PacketBuilder.dnsQueryFrame(
            name: "vpn.example",
            src: "198.51.100.10",
            dst: "198.51.100.1",
            srcPort: 53_003
        ).dropFirst(14))
        let rawTunnelFrame = CapturedFrame(
            bytes: rawTunnelBytes,
            timestamp: base.addingTimeInterval(0.10),
            originalLength: rawTunnelBytes.count,
            linkType: LinkType.raw,
            processName: "curl"
        )

        let spool = LiveCaptureSpool(directory: directory)
        try await spool.reset(epoch: 1)
        let appendResult = try await spool.append(
            [ethFrame, loopbackFrame, rawTunnelFrame],
            defaultLinkType: LinkType.ethernet,
            epoch: 1
        )
        guard case let .appended(locators) = appendResult else {
            Issue.record("Expected .appended result for multi-DLT batch")
            return
        }
        #expect(locators.count == 3)

        let roundTripped = try await spool.capture()
        #expect(roundTripped.frames.count == 3)
        #expect(roundTripped.frames.map(\.linkType) == [LinkType.ethernet, LinkType.null, LinkType.raw])
        #expect(roundTripped.frames[0].bytes == ethBytes)
        #expect(roundTripped.frames[1].bytes == loopbackBytes)
        #expect(roundTripped.frames[2].bytes == rawTunnelBytes)

        // Fold each spooled frame with its preserved per-frame DLT through PacketDecoder + SessionAccumulator.
        let processNames = [ethFrame.processName, loopbackFrame.processName, rawTunnelFrame.processName]
        var accumulator = SessionAccumulator()
        for (index, spooledFrame) in roundTripped.frames.enumerated() {
            let linkType = try #require(spooledFrame.linkType)
            var decoded = SessionBuilder.decodePacket(spooledFrame, linkType: linkType)
            decoded.processName = processNames[index]
            let context = SessionFrameContext(
                capturedLength: spooledFrame.bytes.count,
                linkType: linkType,
                locator: locators[index]
            )
            accumulator.add(decoded, context: context)
        }

        let summaries = accumulator.summaries()
        #expect(summaries.count == 3)

        let ethSession = try #require(summaries.first { $0.host == "lan.example" })
        #expect(ethSession.sourceEndpointValue?.ip == "192.0.2.25")
        #expect(ethSession.destinationEndpointValue?.ip == "203.0.113.44")
        #expect(ethSession.processName == "Safari")

        let loopbackSession = try #require(summaries.first { $0.host == "localhost.internal" })
        #expect(loopbackSession.sourceEndpointValue?.ip == "127.0.0.1")
        #expect(loopbackSession.destinationEndpointValue?.ip == "127.0.0.1")
        #expect(loopbackSession.processName == "node")

        let tunnelSession = try #require(summaries.first { $0.host == "vpn.example" })
        #expect(tunnelSession.sourceEndpointValue?.ip == "198.51.100.10")
        #expect(tunnelSession.destinationEndpointValue?.ip == "198.51.100.1")
        #expect(tunnelSession.processName == "curl")
    }

    // MARK: Private

    private enum CatalogError: Error {
        case rootNotFound
        case invalidCatalog
        case bundleCreationFailed
    }

    private struct CatalogBundles {
        let root: Bundle
        let teardown: () -> Void
    }

    private func makeCatalogBundles() throws -> CatalogBundles {
        var root = URL(fileURLWithPath: #filePath)
        while root.lastPathComponent != "TracexyTests", root.path != "/" {
            root.deleteLastPathComponent()
        }
        guard root.lastPathComponent == "TracexyTests" else {
            throw CatalogError.rootNotFound
        }
        root.deleteLastPathComponent()

        let xcstringsURL = root.appendingPathComponent("Tracexy/Localizable.xcstrings")
        let data = try Data(contentsOf: xcstringsURL)
        guard let catalog = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let stringsMap = catalog["strings"] as? [String: [String: Any]] else
        {
            throw CatalogError.invalidCatalog
        }

        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("tracexy-all-interfaces-i18n-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)

        for language in ["en", "zh-Hans", "vi"] {
            var dict: [String: String] = [:]
            for (key, entry) in stringsMap {
                if let locs = entry["localizations"] as? [String: Any],
                   let langObj = locs[language] as? [String: Any],
                   let unit = langObj["stringUnit"] as? [String: Any],
                   let value = unit["value"] as? String
                {
                    dict[key] = value
                } else if language == "en" {
                    dict[key] = key
                }
            }
            let lprojURL = tempDir.appendingPathComponent("\(language).lproj", isDirectory: true)
            try FileManager.default.createDirectory(at: lprojURL, withIntermediateDirectories: true)
            let plistData = try PropertyListSerialization.data(
                fromPropertyList: dict,
                format: .binary,
                options: 0
            )
            try plistData.write(to: lprojURL.appendingPathComponent("Localizable.strings"))
        }

        guard let rootBundle = Bundle(url: tempDir) else {
            try? FileManager.default.removeItem(at: tempDir)
            throw CatalogError.bundleCreationFailed
        }
        return CatalogBundles(root: rootBundle) {
            try? FileManager.default.removeItem(at: tempDir)
        }
    }
}
