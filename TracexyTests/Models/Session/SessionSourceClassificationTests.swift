import Foundation
import Testing
@testable import Tracexy

@Suite("7-Dimension Traffic Source Classification & Semantic Annotations")
struct SessionSourceClassificationTests {
    private static let liveLocalIPs: Set<String> = [
        "192.168.0.130",
        "127.0.0.1",
        "::1",
        "fe80::10%en0",
    ]

    // MARK: - 1. Category Metadata & Contracts

    @Test("TrafficSourceCategory exposes all 7 dimensions in display order with exact UI policies")
    func categoryMetadataContract() {
        let categories = TrafficSourceCategory.allCases
        #expect(categories == [
            .app,
            .cli,
            .thirdPartyService,
            .systemService,
            .lanDiscovery,
            .kernelAndLink,
            .unattributed,
        ])

        #expect(TrafficSourceCategory.app.systemImage == "app.badge")
        #expect(TrafficSourceCategory.cli.systemImage == "apple.terminal")
        #expect(TrafficSourceCategory.thirdPartyService.systemImage == "gearshape.2")
        #expect(TrafficSourceCategory.systemService.systemImage == "cpu")
        #expect(TrafficSourceCategory.lanDiscovery.systemImage == "dot.radiowaves.left.and.right")
        #expect(TrafficSourceCategory.kernelAndLink.systemImage == "network")
        #expect(TrafficSourceCategory.unattributed.systemImage == "questionmark.app.dashed")

        #expect(TrafficSourceCategory.app.opensOnCaptureStart == true)
        #expect(TrafficSourceCategory.cli.opensOnCaptureStart == true)
        #expect(TrafficSourceCategory.thirdPartyService.opensOnCaptureStart == true)
        #expect(TrafficSourceCategory.systemService.opensOnCaptureStart == false)
        #expect(TrafficSourceCategory.lanDiscovery.opensOnCaptureStart == false)
        #expect(TrafficSourceCategory.kernelAndLink.opensOnCaptureStart == false)
        #expect(TrafficSourceCategory.unattributed.opensOnCaptureStart == false)

        for category in categories {
            #expect(category.id == category.rawValue)
            #expect(category.hidesWhenEmpty == (category == .unattributed))
        }
    }

    @Test("SessionProcessContext Codable round-trip and defaults")
    func processContextCodableRoundTrip() throws {
        let empty = SessionProcessContext()
        #expect(empty.executablePath == nil)
        #expect(empty.bundleIdentifier == nil)
        #expect(empty.viaProcessName == nil)
        #expect(empty.parentProcessName == nil)
        #expect(empty.hasControllingTTY == false)
        #expect(empty.isRootUser == false)
        #expect(empty.isKernelTask == false)

        let populated = SessionProcessContext(
            executablePath: "/opt/homebrew/bin/codex",
            bundleIdentifier: nil,
            viaProcessName: "mDNSResponder",
            parentProcessName: "Antigravity",
            hasControllingTTY: true,
            isRootUser: false,
            isKernelTask: false
        )
        let encoded = try JSONEncoder().encode(populated)
        let decoded = try JSONDecoder().decode(SessionProcessContext.self, from: encoded)
        #expect(decoded == populated)
    }

    // MARK: - 2. GUI Apps (.app)

    @Test("Classifies /Applications, /System/Applications, Xcode, and home ~/Applications bundles as .app")
    func classifiesGUIAppBundlesAndViaProvenance() {
        let safari = makeSession(
            processName: "Safari",
            host: "apple.com",
            src: ("192.168.0.130", 51_200),
            dst: ("17.253.144.10", 443),
            protos: [.tcp, .tls, .http2]
        )
        let safariClassified = SessionSourceClassifier.classify(
            safari,
            context: SessionProcessContext(
                executablePath: "/System/Applications/Safari.app/Contents/MacOS/Safari",
                bundleIdentifier: "com.apple.Safari",
                viaProcessName: "nsurlsessiond"
            ),
            localIPs: Self.liveLocalIPs
        )
        #expect(safariClassified.category == .app)
        #expect(safariClassified.filterKey == "Safari")
        #expect(safariClassified.title == "Safari")
        #expect(safariClassified.subtitle == String(format: String(localized: "via %@"), "nsurlsessiond"))
        #expect(safariClassified.tableLabel == "Safari")
        #expect(safariClassified.tableDetail == safariClassified.subtitle)
        #expect(safariClassified.symbolName == nil)
        #expect(safariClassified.childTarget == SourceChildTarget(kind: .host, value: "apple.com", label: "apple.com"))

        // Xcode has com.apple.dt.Xcode bundle ID under /Applications/Xcode.app — must be .app, not .systemService.
        let xcode = makeSession(processName: "Xcode", host: "developer.apple.com")
        let xcodeClassified = SessionSourceClassifier.classify(
            xcode,
            context: SessionProcessContext(
                executablePath: "/Applications/Xcode.app/Contents/MacOS/Xcode",
                bundleIdentifier: "com.apple.dt.Xcode"
            ),
            localIPs: Self.liveLocalIPs
        )
        #expect(xcodeClassified.category == .app)
        #expect(xcodeClassified.subtitle == nil)

        // User home ~/Applications bundle (tested with synthetic /tmp/test-home).
        let homeApp = makeSession(processName: "Foo", host: "api.example.com")
        let homeAppClassified = SessionSourceClassifier.classify(
            homeApp,
            context: SessionProcessContext(
                executablePath: "/tmp/test-home/Applications/Foo.app/Contents/MacOS/FooHelper",
                bundleIdentifier: "com.example.Foo",
                viaProcessName: "FooHelper"
            ),
            localIPs: Self.liveLocalIPs,
            homeDirectoryPath: "/tmp/test-home"
        )
        #expect(homeAppClassified.category == .app)
        #expect(homeAppClassified.subtitle == String(format: String(localized: "via %@"), "FooHelper"))

        // Same-name viaProcessName is suppressed rather than producing redundant "via Arc".
        let sameVia = SessionSourceClassifier.classify(
            makeSession(processName: "Arc", host: "example.com"),
            context: SessionProcessContext(
                executablePath: "/Applications/Arc.app/Contents/MacOS/Arc",
                viaProcessName: "Arc"
            )
        )
        #expect(sameVia.category == .app)
        #expect(sameVia.subtitle == nil)
    }

    @Test("Classifies exited GUI apps via appBundleExistsLookup when executablePath is nil")
    func classifiesGUIAppWithoutExecutablePath() {
        let customApp = makeSession(processName: "CustomStudio", host: "cdn.example.com")
        let classified = SessionSourceClassifier.classify(
            customApp,
            context: nil,
            localIPs: Self.liveLocalIPs,
            appBundleExistsLookup: { $0 == "CustomStudio" }
        )
        #expect(classified.category == .app)
        #expect(classified.filterKey == "CustomStudio")
        #expect(classified.symbolName == nil)
    }

    // MARK: - 3. CLI Tools (.cli)

    @Test("Classifies Homebrew, System, Developer Toolchain, and TTY CLI tools with parent launcher annotations")
    func classifiesCLIToolsAndSubtitles() {
        // 1. Homebrew CLI + non-shell parent IDE launcher
        let codex = SessionSourceClassifier.classify(
            makeSession(processName: "codex", host: "api.example.com"),
            context: SessionProcessContext(
                executablePath: "/opt/homebrew/bin/codex",
                parentProcessName: "Antigravity",
                hasControllingTTY: false
            )
        )
        #expect(codex.category == .cli)
        #expect(codex.filterKey == "codex")
        #expect(codex.symbolName == "apple.terminal")
        let expectedCodexSub = String(localized: "Homebrew CLI")
            + " · "
            + String(format: String(localized: "Launched by %@"), "Antigravity")
        #expect(codex.subtitle == expectedCodexSub)

        // 2. System CLI + ignored shell parent (zsh)
        let curl = SessionSourceClassifier.classify(
            makeSession(processName: "curl", host: "example.org"),
            context: SessionProcessContext(
                executablePath: "/usr/bin/curl",
                parentProcessName: "zsh",
                hasControllingTTY: true
            )
        )
        #expect(curl.category == .cli)
        #expect(curl.subtitle == String(localized: "System CLI"))

        // 3. Developer Toolchain (.nvm / .cargo / /Library/Developer)
        let nvmNode = SessionSourceClassifier.classify(
            makeSession(processName: "node", host: "registry.npmjs.org"),
            context: SessionProcessContext(
                executablePath: "/tmp/test-home/.nvm/versions/node/v22.0.0/bin/node",
                parentProcessName: "Code"
            )
        )
        #expect(nvmNode.category == .cli)
        let expectedNodeSub = String(localized: "Developer Toolchain")
            + " · "
            + String(format: String(localized: "Launched by %@"), "Code")
        #expect(nvmNode.subtitle == expectedNodeSub)

        // 4. Custom path with controlling TTY
        let customTTY = SessionSourceClassifier.classify(
            makeSession(processName: "myprobe", host: "198.51.100.1"),
            context: SessionProcessContext(
                executablePath: "/opt/tools/myprobe",
                parentProcessName: "fish",
                hasControllingTTY: true
            )
        )
        #expect(customTTY.category == .cli)
        #expect(customTTY.subtitle == String(localized: "Terminal CLI"))

        // 5. Fallback known CLI command when executablePath is nil
        let bareGit = SessionSourceClassifier.classify(
            makeSession(processName: "git", host: "github.com"),
            context: nil
        )
        #expect(bareGit.category == .cli)
        #expect(bareGit.subtitle == String(localized: "Terminal CLI"))
    }

    // MARK: - 4. Third-Party Services (.thirdPartyService)

    @Test("Classifies SystemExtensions, Root Daemons, and Background Agents under .thirdPartyService")
    func classifiesThirdPartyServices() {
        let sysExt = SessionSourceClassifier.classify(
            makeSession(processName: "io.tailscale.ipn.macsys", host: "controlplane.tailscale.com"),
            context: SessionProcessContext(
                executablePath: "/Library/SystemExtensions/ABC-123/io.tailscale.ipn.systemextension/Contents/MacOS/ext",
                bundleIdentifier: "io.tailscale.ipn.macsys",
                isRootUser: true
            )
        )
        #expect(sysExt.category == .thirdPartyService)
        #expect(sysExt.symbolName == "gearshape.2")
        #expect(sysExt.subtitle == String(localized: "System Network Extension"))

        let rootDaemon = SessionSourceClassifier.classify(
            makeSession(processName: "mihomo", host: "198.51.100.10"),
            context: SessionProcessContext(
                executablePath: "/Library/PrivilegedHelperTools/mihomo",
                hasControllingTTY: false,
                isRootUser: true
            )
        )
        #expect(rootDaemon.category == .thirdPartyService)
        #expect(rootDaemon.subtitle == String(localized: "Root Background Daemon"))

        let userAgent = SessionSourceClassifier.classify(
            makeSession(processName: "com.example.syncd", host: "sync.example.com"),
            context: nil,
            appBundleExistsLookup: { _ in false }
        )
        #expect(userAgent.category == .thirdPartyService)
        #expect(userAgent.subtitle == String(localized: "Background Agent"))
    }

    // MARK: - 5. System Services (.systemService)

    @Test("Classifies macOS system daemons and annotates curated roles and framework names")
    func classifiesSystemServicesAndDaemonRoles() {
        let daemonExpectations: [(String, String)] = [
            ("mDNSResponder", String(localized: "System DNS & Bonjour resolver")),
            ("usbmuxd", String(localized: "iOS device wireless & USB mux")),
            ("AMPDeviceDiscoveryAgent", String(localized: "Apple device discovery service")),
            ("rapportd", String(localized: "AirDrop, Handoff & Continuity")),
            ("apsd", String(localized: "Apple Push Notification service")),
            ("trustd", String(localized: "TLS certificate trust & revocation")),
            ("nsurlsessiond", String(localized: "iCloud sync & background transfer")),
            ("amsengagementd", String(localized: "App Store & media account service")),
            ("softwareupdated", String(localized: "macOS Software Update service")),
            ("configd", String(localized: "Network configuration & diagnostics")),
            ("identityservicesd", String(localized: "iMessage & FaceTime identity")),
            ("timed", String(localized: "Network time synchronization")),
            ("locationd", String(localized: "Location & Maps service")),
            ("parsecd", String(localized: "Spotlight & Siri suggestions")),
            ("Control Center", String(localized: "macOS Control Center")),
            ("WindowServer", String(localized: "macOS Window & Login session")),
            ("weatherd", String(localized: "Widget & System Extension")),
        ]

        for (daemonName, expectedSubtitle) in daemonExpectations {
            let classified = SessionSourceClassifier.classify(
                makeSession(processName: daemonName, host: "apple.com"),
                context: nil
            )
            #expect(classified.category == .systemService)
            #expect(classified.filterKey == daemonName)
            #expect(classified.symbolName == "cpu")
            #expect(classified.subtitle == expectedSubtitle)
        }

        // Unknown system daemon inside a PrivateFramework extracts <FrameworkName>.
        let frameworkDaemon = SessionSourceClassifier.classify(
            makeSession(processName: "biomeagent", host: "icloud.com"),
            context: SessionProcessContext(
                executablePath: "/System/Library/PrivateFrameworks/BiomeStreams.framework/Support/biomeagent"
            )
        )
        #expect(frameworkDaemon.category == .systemService)
        #expect(frameworkDaemon.subtitle == String(format: String(localized: "macOS %@ service"), "BiomeStreams"))

        // Unknown /usr/libexec daemon without .framework falls back to generic macOS System Service.
        let libexecDaemon = SessionSourceClassifier.classify(
            makeSession(processName: "customapplehelperd", host: "apple.com"),
            context: SessionProcessContext(executablePath: "/usr/libexec/customapplehelperd")
        )
        #expect(libexecDaemon.category == .systemService)
        #expect(libexecDaemon.subtitle == String(localized: "macOS System Service"))
    }

    // MARK: - 6. LAN & Discovery (.lanDiscovery — All 6 Sub-Items & Peer Enrichment)

    @Test("Classifies peer mDNS traffic as lan:mdns and enriches peerIP from .local dnsQuery")
    func classifiesLanMDNSWithLocalQueryHint() {
        let session = makeSession(
            processName: nil,
            host: "iPhone.local",
            src: ("192.168.0.78", 5_353),
            dst: ("224.0.0.251", 5_353),
            protos: [.udp, .mdns],
            dnsQuery: "iPhone.local.",
            dnsAnswers: ["192.168.0.78"]
        )
        let classified = SessionSourceClassifier.classify(session, localIPs: Self.liveLocalIPs)
        #expect(classified.category == .lanDiscovery)
        #expect(classified.filterKey == "lan:mdns")
        #expect(classified.title == String(localized: "Bonjour / mDNS"))
        #expect(classified.subtitle == String(localized: "Local network service discovery (UDP 5353)"))
        #expect(classified.tableLabel == String(localized: "LAN · Bonjour"))
        #expect(classified.symbolName == "dot.radiowaves.left.and.right")
        #expect(
            classified.childTarget
                == SourceChildTarget(kind: .peerIP, value: "192.168.0.78", label: "192.168.0.78 · iPhone.local")
        )
    }

    @Test("Classifies peer SSDP traffic as lan:ssdp and enriches peerIP from resolvedNames")
    func classifiesLanSSDPWithResolvedName() {
        let session = makeSession(
            processName: nil,
            host: "239.255.255.250",
            src: ("192.168.0.42", 52_100),
            dst: ("239.255.255.250", 1_900),
            protos: [.udp, .ssdp]
        )
        let classified = SessionSourceClassifier.classify(
            session,
            localIPs: Self.liveLocalIPs,
            resolvedNames: ["192.168.0.42": "LivingRoom-TV"]
        )
        #expect(classified.category == .lanDiscovery)
        #expect(classified.filterKey == "lan:ssdp")
        #expect(classified.title == String(localized: "SSDP / UPnP"))
        #expect(classified.tableLabel == String(localized: "LAN · SSDP"))
        #expect(
            classified.childTarget
                == SourceChildTarget(kind: .peerIP, value: "192.168.0.42", label: "192.168.0.42 · LivingRoom-TV")
        )
    }

    @Test("Classifies DHCP broadcast traffic as lan:dhcp and labels .1 router as LAN Gateway")
    func classifiesLanDHCPAndGatewayHint() {
        // 0.0.0.0:68 -> 255.255.255.255:67 pre-IP DHCP Discover has no unicast peer IP.
        let discover = makeSession(
            processName: nil,
            host: "255.255.255.255",
            src: ("0.0.0.0", 68),
            dst: ("255.255.255.255", 67),
            protos: [.udp, .dhcp]
        )
        let discoverClassified = SessionSourceClassifier.classify(discover, localIPs: Self.liveLocalIPs)
        #expect(discoverClassified.category == .lanDiscovery)
        #expect(discoverClassified.filterKey == "lan:dhcp")
        #expect(discoverClassified.title == String(localized: "DHCP Lease Broadcast"))
        #expect(discoverClassified.tableLabel == String(localized: "LAN · DHCP"))
        #expect(discoverClassified.childTarget == nil)

        // Router DHCP Offer from 192.168.0.1 gets automatic LAN Gateway label.
        let offer = makeSession(
            processName: nil,
            host: "255.255.255.255",
            src: ("192.168.0.1", 67),
            dst: ("255.255.255.255", 68),
            protos: [.udp, .dhcp]
        )
        let offerClassified = SessionSourceClassifier.classify(offer, localIPs: Self.liveLocalIPs)
        #expect(offerClassified.category == .lanDiscovery)
        #expect(offerClassified.filterKey == "lan:dhcp")
        #expect(
            offerClassified.childTarget
                == SourceChildTarget(
                    kind: .peerIP,
                    value: "192.168.0.1",
                    label: "192.168.0.1 · \(String(localized: "LAN Gateway"))"
                )
        )
    }

    @Test("Classifies NetBIOS and LLMNR broadcasts as lan:naming")
    func classifiesLanNaming() {
        let nbns = makeSession(
            processName: nil,
            host: "192.168.0.255",
            src: ("192.168.0.88", 137),
            dst: ("192.168.0.255", 137),
            protos: [.udp, .nbns]
        )
        let nbnsClassified = SessionSourceClassifier.classify(nbns, localIPs: Self.liveLocalIPs)
        #expect(nbnsClassified.category == .lanDiscovery)
        #expect(nbnsClassified.filterKey == "lan:naming")
        #expect(nbnsClassified.title == String(localized: "NetBIOS / LLMNR"))
        #expect(nbnsClassified.tableLabel == String(localized: "LAN · Naming"))
        #expect(
            nbnsClassified.childTarget
                == SourceChildTarget(kind: .peerIP, value: "192.168.0.88", label: "192.168.0.88")
        )

        let llmnr = makeSession(
            processName: nil,
            host: "NAS-SERVER",
            src: ("fe80::99", 54_111),
            dst: ("ff02::1:3", 5_355),
            protos: [.udp, .llmnr]
        )
        let llmnrClassified = SessionSourceClassifier.classify(llmnr, localIPs: Self.liveLocalIPs)
        #expect(llmnrClassified.category == .lanDiscovery)
        #expect(llmnrClassified.filterKey == "lan:naming")
    }

    @Test("Classifies non-local ARP as lan:arp and generic LAN broadcast/multicast as lan:multicast")
    func classifiesLanPeerARPAndGenericMulticast() {
        let peerARP = makeSession(
            processName: nil,
            host: "192.168.0.1",
            src: ("192.168.0.55", 0),
            dst: ("192.168.0.1", 0),
            protos: [.arp]
        )
        let arpClassified = SessionSourceClassifier.classify(peerARP, localIPs: Self.liveLocalIPs)
        #expect(arpClassified.category == .lanDiscovery)
        #expect(arpClassified.filterKey == "lan:arp")
        #expect(arpClassified.title == String(localized: "Peer ARP Resolution"))
        #expect(arpClassified.tableLabel == String(localized: "LAN · Peer ARP"))
        #expect(
            arpClassified.childTarget
                == SourceChildTarget(kind: .peerIP, value: "192.168.0.55", label: "192.168.0.55")
        )

        let customBroadcast = makeSession(
            processName: nil,
            host: "192.168.0.255",
            src: ("192.168.0.66", 9_999),
            dst: ("192.168.0.255", 9_999),
            protos: [.udp]
        )
        let multicastClassified = SessionSourceClassifier.classify(customBroadcast, localIPs: Self.liveLocalIPs)
        #expect(multicastClassified.category == .lanDiscovery)
        #expect(multicastClassified.filterKey == "lan:multicast")
        #expect(multicastClassified.title == String(localized: "LAN Broadcast / Multicast"))
        #expect(multicastClassified.tableLabel == String(localized: "LAN · Multicast"))
        #expect(
            multicastClassified.childTarget
                == SourceChildTarget(kind: .peerIP, value: "192.168.0.66", label: "192.168.0.66")
        )
    }

    // MARK: - 7. Kernel & Link (.kernelAndLink — All 6 Sub-Items + kernel_task)

    @Test("Classifies local ARP as kernel:arp")
    func classifiesKernelARP() {
        let localARP = makeSession(
            processName: nil,
            host: "192.168.0.1",
            src: ("192.168.0.130", 0),
            dst: ("192.168.0.1", 0),
            protos: [.arp]
        )
        let classified = SessionSourceClassifier.classify(localARP, localIPs: Self.liveLocalIPs)
        #expect(classified.category == .kernelAndLink)
        #expect(classified.filterKey == "kernel:arp")
        #expect(classified.title == String(localized: "ARP Resolution"))
        #expect(classified.tableLabel == String(localized: "Kernel · ARP"))
        #expect(classified.symbolName == "network")
    }

    @Test("Classifies ICMPv6 Router/Neighbor Discovery as kernel:ndp even from non-local router")
    func classifiesKernelIPv6NDP() {
        let routerAdv = makeSession(
            processName: nil,
            host: "ff02::1",
            src: ("fe80::1", 0),
            dst: ("ff02::1", 0),
            protos: [.icmpv6],
            decodedLayers: [
                DecodedLayer(
                    proto: .icmpv6,
                    title: "Internet Control Message Protocol v6",
                    summary: "Router Advertisement",
                    fields: [DecodedField(name: "Type", value: "Router Advertisement (134)")]
                ),
            ]
        )
        let classified = SessionSourceClassifier.classify(routerAdv, localIPs: Self.liveLocalIPs)
        #expect(classified.category == .kernelAndLink)
        #expect(classified.filterKey == "kernel:ndp")
        #expect(classified.title == String(localized: "IPv6 Neighbor & Router Discovery"))
        #expect(classified.tableLabel == String(localized: "Kernel · IPv6 NDP"))
    }

    @Test("Classifies IPv4 IGMP and IPv6 MLDv2 reports as kernel:igmp")
    func classifiesKernelIGMPAndMLD() {
        let igmp = makeSession(
            processName: nil,
            host: "224.0.0.22",
            src: ("192.168.0.130", 0),
            dst: ("224.0.0.22", 0),
            protos: [.other]
        )
        let igmpClassified = SessionSourceClassifier.classify(igmp, localIPs: Self.liveLocalIPs)
        #expect(igmpClassified.category == .kernelAndLink)
        #expect(igmpClassified.filterKey == "kernel:igmp")
        #expect(igmpClassified.title == String(localized: "IGMP / MLD Multicast Control"))
        #expect(igmpClassified.tableLabel == String(localized: "Kernel · Multicast"))

        let mld = makeSession(
            processName: nil,
            host: "ff02::16",
            src: ("fe80::10", 0),
            dst: ("ff02::16", 0),
            protos: [.icmpv6],
            decodedLayers: [
                DecodedLayer(
                    proto: .icmpv6,
                    title: "Internet Control Message Protocol v6",
                    summary: "Type 143",
                    fields: [DecodedField(name: "Type", value: "Type 143 (143)")]
                ),
            ]
        )
        let mldClassified = SessionSourceClassifier.classify(mld, localIPs: Self.liveLocalIPs)
        #expect(mldClassified.category == .kernelAndLink)
        #expect(mldClassified.filterKey == "kernel:igmp")
    }

    @Test("Classifies IPv4 ICMP and IPv6 Echo Ping as kernel:icmp")
    func classifiesKernelICMP() {
        let icmpPing = makeSession(
            processName: nil,
            host: "1.1.1.1",
            src: ("192.168.0.130", 0),
            dst: ("1.1.1.1", 0),
            protos: [.icmp]
        )
        let icmpClassified = SessionSourceClassifier.classify(icmpPing, localIPs: Self.liveLocalIPs)
        #expect(icmpClassified.category == .kernelAndLink)
        #expect(icmpClassified.filterKey == "kernel:icmp")
        #expect(icmpClassified.title == String(localized: "ICMP Probe & Diagnostics"))
        #expect(icmpClassified.tableLabel == String(localized: "Kernel · ICMP"))

        let icmpv6Echo = makeSession(
            processName: nil,
            host: "fe80::1",
            src: ("fe80::10", 0),
            dst: ("fe80::1", 0),
            protos: [.icmpv6],
            decodedLayers: [
                DecodedLayer(
                    proto: .icmpv6,
                    title: "Internet Control Message Protocol v6",
                    summary: "Echo Request",
                    fields: [DecodedField(name: "Type", value: "Echo Request (128)")]
                ),
            ]
        )
        let echoClassified = SessionSourceClassifier.classify(icmpv6Echo, localIPs: Self.liveLocalIPs)
        #expect(echoClassified.category == .kernelAndLink)
        #expect(echoClassified.filterKey == "kernel:icmp")
    }

    @Test("Classifies no-payload TCP RST/FIN-ACK and XNU kernel_task frames as kernel:tcp-teardown")
    func classifiesKernelTCPTeardownAndKernelTask() {
        let lateRST = makeSession(
            processName: nil,
            host: "198.51.100.25",
            src: ("192.168.0.130", 54_321),
            dst: ("198.51.100.25", 443),
            protos: [.tcp],
            bytesUp: 54,
            bytesDown: 54,
            packetsUp: 1,
            packetsDown: 1,
            tcpCompleteness: [.fin, .rst]
        )
        let rstClassified = SessionSourceClassifier.classify(lateRST, localIPs: Self.liveLocalIPs)
        #expect(rstClassified.category == .kernelAndLink)
        #expect(rstClassified.filterKey == "kernel:tcp-teardown")
        #expect(rstClassified.title == String(localized: "Kernel TCP Teardown / Reset"))
        #expect(rstClassified.tableLabel == String(localized: "Kernel · TCP Reset"))

        // Explicit XNU PID 0 `isKernelTask: true` routes directly into `.kernelAndLink`.
        let kernelTaskSession = makeSession(
            processName: "kernel_task",
            host: "198.51.100.88",
            src: ("192.168.0.130", 55_000),
            dst: ("198.51.100.88", 443),
            protos: [.tcp],
            tcpCompleteness: [.ack]
        )
        let kernelClassified = SessionSourceClassifier.classify(
            kernelTaskSession,
            context: SessionProcessContext(isKernelTask: true),
            localIPs: Self.liveLocalIPs
        )
        #expect(kernelClassified.category == .kernelAndLink)
        #expect(kernelClassified.filterKey == "kernel:tcp-teardown")
    }

    @Test("Classifies unsolicited inbound TCP SYN and unanswered inbound UDP as kernel:inbound")
    func classifiesKernelInboundClosedPort() {
        // Remote SYN to closed local port (local replied only with RST, no SYN-ACK, no data).
        let inboundSYN = makeSession(
            processName: nil,
            host: "192.168.0.130",
            src: ("198.51.100.77", 61_000),
            dst: ("192.168.0.130", 8_888),
            protos: [.tcp],
            bytesUp: 60,
            bytesDown: 54,
            packetsUp: 1,
            packetsDown: 1,
            tcpCompleteness: [.syn, .rst]
        )
        let synClassified = SessionSourceClassifier.classify(inboundSYN, localIPs: Self.liveLocalIPs)
        #expect(synClassified.category == .kernelAndLink)
        #expect(synClassified.filterKey == "kernel:inbound")
        #expect(synClassified.title == String(localized: "Inbound Unanswered Port"))
        #expect(synClassified.tableLabel == String(localized: "Kernel · Closed Port"))

        // Unsolicited inbound UDP packet with zero local reply.
        let inboundUDP = makeSession(
            processName: nil,
            host: "192.168.0.130",
            src: ("198.51.100.99", 53_000),
            dst: ("192.168.0.130", 34_567),
            protos: [.udp],
            bytesUp: 0,
            bytesDown: 120,
            packetsUp: 0,
            packetsDown: 1
        )
        let udpClassified = SessionSourceClassifier.classify(inboundUDP, localIPs: Self.liveLocalIPs)
        #expect(udpClassified.category == .kernelAndLink)
        #expect(udpClassified.filterKey == "kernel:inbound")
    }

    // MARK: - 8. Saved Capture Honesty (.unattributed)

    @Test(
        "Saved captures keep unicast TCP/UDP honest in .unattributed while classifying LAN & control-plane protocols"
    )
    func savedCaptureUnattributedHonesty() {
        // Even if an IP happens to match this Mac's live interface IP, `isViewingSavedCapture: true`
        // refuses to guess local ownership on unicast TCP/UDP.
        let savedTCPReset = makeSession(
            processName: nil,
            host: "example.com",
            src: ("192.168.0.130", 50_100),
            dst: ("93.184.216.34", 443),
            protos: [.tcp],
            bytesUp: 60,
            bytesDown: 0,
            packetsUp: 1,
            packetsDown: 0,
            tcpCompleteness: [.rst]
        )
        let tcpClassified = SessionSourceClassifier.classify(
            savedTCPReset,
            localIPs: Self.liveLocalIPs,
            isViewingSavedCapture: true
        )
        #expect(tcpClassified.category == .unattributed)
        #expect(tcpClassified.filterKey == "—")
        #expect(tcpClassified.title == String(localized: "Unattributed"))
        #expect(tcpClassified.tableLabel == "—")
        #expect(tcpClassified.symbolName == "questionmark.app.dashed")

        let savedUDP = makeSession(
            processName: nil,
            host: "198.51.100.4",
            src: ("198.51.100.4", 40_000),
            dst: ("192.168.0.130", 9_001),
            protos: [.udp],
            bytesUp: 0,
            bytesDown: 80
        )
        let udpClassified = SessionSourceClassifier.classify(
            savedUDP,
            localIPs: Self.liveLocalIPs,
            isViewingSavedCapture: true
        )
        #expect(udpClassified.category == .unattributed)

        // Wire-explicit ARP and mDNS in saved captures still classify accurately.
        let savedARP = makeSession(
            processName: nil,
            host: "10.0.0.1",
            src: ("10.0.0.50", 0),
            dst: ("10.0.0.1", 0),
            protos: [.arp]
        )
        #expect(
            SessionSourceClassifier.classify(
                savedARP,
                localIPs: Self.liveLocalIPs,
                isViewingSavedCapture: true
            ).filterKey == "kernel:arp"
        )

        let savedMDNS = makeSession(
            processName: nil,
            host: "MacMini.local",
            src: ("10.0.0.12", 5_353),
            dst: ("224.0.0.251", 5_353),
            protos: [.udp, .mdns]
        )
        #expect(
            SessionSourceClassifier.classify(
                savedMDNS,
                localIPs: Self.liveLocalIPs,
                isViewingSavedCapture: true
            ).filterKey == "lan:mdns"
        )
    }

    // MARK: - 9. Category & Item Grouping, Sorting, Via Merging, and Display Titles

    @Test(
        "Groups sessions by category, merges up to 2 viaProcessNames, dedupes children, and sorts by count desc"
    )
    func aggregatesAndSortsCategoryGroups() {
        let s1 = makeSession(processName: "Safari", host: "apple.com")
        let s2 = makeSession(processName: "Safari", host: "icloud.com")
        let s3 = makeSession(processName: "Safari", host: "apple.com")
        let arc = makeSession(processName: "Arc", host: "browser.company")
        let zed = makeSession(processName: "Zed", host: "zed.dev")

        let mdnsEarly = makeSession(
            processName: nil,
            host: "224.0.0.251",
            src: ("192.168.0.78", 5_353),
            dst: ("224.0.0.251", 5_353),
            protos: [.udp, .mdns]
        )
        let mdnsEnriched = makeSession(
            processName: nil,
            host: "iPad.local",
            src: ("192.168.0.78", 5_353),
            dst: ("224.0.0.251", 5_353),
            protos: [.udp, .mdns],
            dnsQuery: "iPad.local",
            dnsAnswers: ["192.168.0.78"]
        )

        let contexts: [UUID: SessionProcessContext] = [
            s1.id: SessionProcessContext(
                executablePath: "/System/Applications/Safari.app/Contents/MacOS/Safari",
                viaProcessName: "nsurlsessiond"
            ),
            s2.id: SessionProcessContext(
                executablePath: "/System/Applications/Safari.app/Contents/MacOS/Safari",
                viaProcessName: "WebKit.Networking"
            ),
            s3.id: SessionProcessContext(
                executablePath: "/System/Applications/Safari.app/Contents/MacOS/Safari",
                viaProcessName: "mDNSResponder"
            ),
            zed.id: SessionProcessContext(
                executablePath: "/Applications/Zed.app/Contents/MacOS/zed"
            ),
        ]

        let groups = SessionSourceClassifier.group(
            sessions: [s1, s2, s3, zed, arc, mdnsEarly, mdnsEnriched],
            contextsBySessionID: contexts,
            localIPs: Self.liveLocalIPs
        )

        #expect(groups.map(\.category) == [.app, .lanDiscovery])

        let appCategory = groups[0]
        #expect(appCategory.totalSessions == 5)
        // Safari (3) first, then Arc (1) before Zed (1) alphabetically!
        #expect(appCategory.items.map(\.title) == ["Safari", "Arc", "Zed"])
        #expect(appCategory.items.map(\.count) == [3, 1, 1])

        let safariItem = appCategory.items[0]
        #expect(
            safariItem.subtitle
                == String(format: String(localized: "via %@"), "nsurlsessiond, WebKit.Networking")
        )
        #expect(safariItem.children.map(\.value) == ["apple.com", "icloud.com"])

        let lanCategory = groups[1]
        #expect(lanCategory.totalSessions == 2)
        #expect(lanCategory.items.count == 1)
        #expect(lanCategory.items[0].filterKey == "lan:mdns")
        #expect(lanCategory.items[0].children == [
            SourceChildTarget(kind: .peerIP, value: "192.168.0.78", label: "192.168.0.78 · iPad.local"),
        ])
    }

    @Test("Propagates provenance across sticky-attributed sessions when a later snapshot lacks context")
    func propagatesFallbackContextAcrossSameProcessName() {
        let first = makeSession(processName: "CustomApp", host: "one.example.com")
        let stickyLater = makeSession(processName: "CustomApp", host: "two.example.com")

        let groups = SessionSourceClassifier.group(
            sessions: [first, stickyLater],
            contextsBySessionID: [
                first.id: SessionProcessContext(
                    executablePath: "/tmp/test-home/Applications/CustomApp.app/Contents/MacOS/CustomApp"
                ),
            ],
            localIPs: Self.liveLocalIPs,
            homeDirectoryPath: "/tmp/test-home",
            appBundleExistsLookup: { _ in false }
        )

        #expect(groups.count == 1)
        #expect(groups[0].category == .app)
        #expect(groups[0].items.count == 1)
        #expect(groups[0].items[0].count == 2)
        #expect(groups[0].items[0].children.map(\.value) == ["one.example.com", "two.example.com"])
    }

    @Test("displayTitle(forFilterKey:) and matchesFilterKey map all synthetic and process filter keys")
    func displayTitleAndMatchesFilterKey() {
        #expect(SessionSourceClassifier.displayTitle(forFilterKey: "lan:mdns") == String(localized: "Bonjour / mDNS"))
        #expect(SessionSourceClassifier.displayTitle(forFilterKey: "lan:ssdp") == String(localized: "SSDP / UPnP"))
        #expect(
            SessionSourceClassifier.displayTitle(forFilterKey: "lan:dhcp")
                == String(localized: "DHCP Lease Broadcast")
        )
        #expect(
            SessionSourceClassifier.displayTitle(forFilterKey: "lan:naming")
                == String(localized: "NetBIOS / LLMNR")
        )
        #expect(
            SessionSourceClassifier.displayTitle(forFilterKey: "lan:arp")
                == String(localized: "Peer ARP Resolution")
        )
        #expect(
            SessionSourceClassifier.displayTitle(forFilterKey: "lan:multicast")
                == String(localized: "LAN Broadcast / Multicast")
        )
        #expect(
            SessionSourceClassifier.displayTitle(forFilterKey: "kernel:arp")
                == String(localized: "ARP Resolution")
        )
        #expect(
            SessionSourceClassifier.displayTitle(forFilterKey: "kernel:ndp")
                == String(localized: "IPv6 Neighbor & Router Discovery")
        )
        #expect(
            SessionSourceClassifier.displayTitle(forFilterKey: "kernel:igmp")
                == String(localized: "IGMP / MLD Multicast Control")
        )
        #expect(
            SessionSourceClassifier.displayTitle(forFilterKey: "kernel:icmp")
                == String(localized: "ICMP Probe & Diagnostics")
        )
        #expect(
            SessionSourceClassifier.displayTitle(forFilterKey: "kernel:tcp-teardown")
                == String(localized: "Kernel TCP Teardown / Reset")
        )
        #expect(
            SessionSourceClassifier.displayTitle(forFilterKey: "kernel:inbound")
                == String(localized: "Inbound Unanswered Port")
        )
        #expect(SessionSourceClassifier.displayTitle(forFilterKey: "—") == String(localized: "Unattributed"))
        #expect(SessionSourceClassifier.displayTitle(forFilterKey: "Safari") == "Safari")

        let safariSession = makeSession(processName: "Safari", host: "apple.com")
        #expect(SessionSourceClassifier.matchesFilterKey("Safari", session: safariSession, localIPs: Self.liveLocalIPs))
        #expect(!SessionSourceClassifier.matchesFilterKey("curl", session: safariSession, localIPs: Self.liveLocalIPs))
        #expect(!SessionSourceClassifier.matchesFilterKey("—", session: safariSession, localIPs: Self.liveLocalIPs))

        let mdnsSession = makeSession(
            processName: nil,
            host: "224.0.0.251",
            src: ("192.168.0.78", 5_353),
            dst: ("224.0.0.251", 5_353),
            protos: [.udp, .mdns]
        )
        #expect(SessionSourceClassifier.matchesFilterKey("lan:mdns", session: mdnsSession, localIPs: Self.liveLocalIPs))
        #expect(!SessionSourceClassifier.matchesFilterKey("Safari", session: mdnsSession, localIPs: Self.liveLocalIPs))
    }

    // MARK: - 10. Additional Edge Cases & Orientation Contracts

    @Test("Parses string-only IPv4/IPv6 endpoints when typed sourceEndpointValue is nil")
    func parsesStringFallbackEndpointsWithZonesAndBrackets() {
        let bracketedLinkLocal = SessionSummary(
            id: UUID(),
            startTime: Date(timeIntervalSince1970: 1_700_000_100),
            duration: 0.05,
            processName: nil,
            host: "ff02::fb",
            sourceEndpoint: "[fe80::77%en0]:5353",
            destinationEndpoint: "[ff02::fb]:5353",
            sourceEndpointValue: nil,
            destinationEndpointValue: nil,
            protocolStack: [.udp, .mdns],
            status: .ok,
            latencyMilliseconds: nil,
            bytesUp: 80,
            bytesDown: 0
        )
        let classified = SessionSourceClassifier.classify(bracketedLinkLocal, localIPs: Self.liveLocalIPs)
        #expect(classified.category == .lanDiscovery)
        #expect(classified.filterKey == "lan:mdns")
        #expect(
            classified.childTarget
                == SourceChildTarget(kind: .peerIP, value: "fe80::77", label: "fe80::77")
        )

        let unbracketedDecoderIPv6 = SessionSummary(
            id: UUID(),
            startTime: Date(timeIntervalSince1970: 1_700_000_101),
            duration: 0.05,
            processName: nil,
            host: "ff02::c",
            sourceEndpoint: "fe80:0:0:0:0:0:0:88:50000",
            destinationEndpoint: "ff02:0:0:0:0:0:0:c:1900",
            sourceEndpointValue: nil,
            destinationEndpointValue: nil,
            protocolStack: [.udp, .ssdp],
            status: .ok,
            latencyMilliseconds: nil,
            bytesUp: 120,
            bytesDown: 0
        )
        let ssdpClassified = SessionSourceClassifier.classify(unbracketedDecoderIPv6, localIPs: Self.liveLocalIPs)
        #expect(ssdpClassified.category == .lanDiscovery)
        #expect(ssdpClassified.filterKey == "lan:ssdp")
        #expect(ssdpClassified.childTarget?.value == "fe80::88")
    }

    @Test("Distinguishes SessionAccumulator-oriented unanswered inbound UDP from bidirectional unattributed UDP")
    func accumulatorInboundUDPWidthVsBidirectionalUnattributed() {
        // SessionAccumulator sets client = remote sender (bytesUp = 96), server = local Mac (bytesDown = 0).
        let accumulatorInbound = makeSession(
            processName: nil,
            host: "192.168.0.130",
            src: ("198.51.100.200", 51_111),
            dst: ("192.168.0.130", 19_999),
            protos: [.udp],
            bytesUp: 96,
            bytesDown: 0,
            packetsUp: 1,
            packetsDown: 0
        )
        let inboundClassified = SessionSourceClassifier.classify(accumulatorInbound, localIPs: Self.liveLocalIPs)
        #expect(inboundClassified.category == .kernelAndLink)
        #expect(inboundClassified.filterKey == "kernel:inbound")

        // Bidirectional unattributed UDP (both sides sent bytes) stays honestly in `.unattributed`.
        let bidirectionalUDP = makeSession(
            processName: nil,
            host: "198.51.100.200",
            src: ("192.168.0.130", 54_000),
            dst: ("198.51.100.200", 3_478),
            protos: [.udp, .stun],
            bytesUp: 120,
            bytesDown: 140,
            packetsUp: 2,
            packetsDown: 2
        )
        let biClassified = SessionSourceClassifier.classify(bidirectionalUDP, localIPs: Self.liveLocalIPs)
        #expect(biClassified.category == .unattributed)
        #expect(biClassified.filterKey == "—")
    }

    @Test("SourceChildTarget id formatting, placeholder host suppression, and RFC1918 gateway boundaries")
    func childTargetIDAndGatewayBoundaries() {
        let noHostSession = makeSession(processName: "curl", host: "—")
        let noHostClassified = SessionSourceClassifier.classify(noHostSession)
        #expect(noHostClassified.childTarget == nil)

        // 172.16.0.1 is RFC1918 private gateway -> LAN Gateway hint.
        let rfc1918Gateway = makeSession(
            processName: nil,
            host: "239.255.255.250",
            src: ("172.16.0.1", 1_900),
            dst: ("239.255.255.250", 1_900),
            protos: [.udp, .ssdp]
        )
        let gwClassified = SessionSourceClassifier.classify(rfc1918Gateway, localIPs: Self.liveLocalIPs)
        #expect(gwClassified.childTarget?.id == "peerIP:172.16.0.1")
        #expect(gwClassified.childTarget?.label == "172.16.0.1 · \(String(localized: "LAN Gateway"))")

        // 172.32.0.1 is public (outside 172.16.0.0/12) -> must NOT claim LAN Gateway!
        let nonPrivateDotOne = makeSession(
            processName: nil,
            host: "239.255.255.250",
            src: ("172.32.0.1", 1_900),
            dst: ("239.255.255.250", 1_900),
            protos: [.udp, .ssdp]
        )
        let publicClassified = SessionSourceClassifier.classify(nonPrivateDotOne, localIPs: Self.liveLocalIPs)
        #expect(publicClassified.childTarget?.label == "172.32.0.1")
    }

    @Test("group(includeEmptyCategories: true) emits all 7 categories in canonical order")
    func groupIncludeEmptyCategoriesAndClosureProvider() {
        let singleSession = makeSession(processName: "curl", host: "example.com")
        let allGroups = SessionSourceClassifier.group(
            sessions: [singleSession],
            contextProvider: { _ in SessionProcessContext(executablePath: "/usr/bin/curl") },
            localIPs: Self.liveLocalIPs,
            includeEmptyCategories: true
        )
        #expect(allGroups.map(\.category) == TrafficSourceCategory.allCases)
        #expect(allGroups.first { $0.category == .cli }?.totalSessions == 1)
        #expect(allGroups.first { $0.category == .unattributed }?.items.isEmpty == true)
    }

    @Test("Distinguishes Cryptex Safari .app from non-GUI com.apple.* system service bundles")
    func cryptexSafariVsAppleBackgroundServiceBundle() {
        let cryptexSafari = SessionSourceClassifier.classify(
            makeSession(processName: "Safari", host: "webkit.org"),
            context: SessionProcessContext(
                executablePath: "/System/Cryptexes/App/System/Applications/Safari.app/Contents/MacOS/Safari",
                bundleIdentifier: "com.apple.Safari"
            )
        )
        #expect(cryptexSafari.category == .app)

        let appleXPCService = SessionSourceClassifier.classify(
            makeSession(processName: "com.apple.geod", host: "gs-loc.apple.com"),
            context: SessionProcessContext(
                executablePath: "/Library/Apple/System/Library/CoreServices/GeoHelper",
                bundleIdentifier: "com.apple.geod"
            ),
            appBundleExistsLookup: { _ in false }
        )
        #expect(appleXPCService.category == .systemService)
        #expect(appleXPCService.subtitle == String(localized: "macOS System Service"))
    }

    // MARK: - Helpers

    private func makeSession(
        processName: String?,
        host: String,
        src: (String, UInt16) = ("192.168.0.130", 52_000),
        dst: (String, UInt16) = ("93.184.216.34", 443),
        protos: [ProtocolKind] = [.tcp, .tls],
        bytesUp: Int = 512,
        bytesDown: Int = 1_024,
        packetsUp: Int = 4,
        packetsDown: Int = 6,
        tcpCompleteness: TCPCompleteness = [.syn, .synAck, .ack, .data],
        decodedLayers: [DecodedLayer] = [],
        dnsQuery: String? = nil,
        dnsAnswers: [String] = []
    )
        -> SessionSummary
    {
        let srcEndpoint = IPEndpoint(ip: src.0, port: src.1)
        let dstEndpoint = IPEndpoint(ip: dst.0, port: dst.1)
        return SessionSummary(
            id: UUID(),
            startTime: Date(timeIntervalSince1970: 1_700_000_000),
            duration: 0.25,
            processName: processName,
            host: host,
            sourceEndpoint: srcEndpoint.display,
            destinationEndpoint: dstEndpoint.display,
            sourceEndpointValue: srcEndpoint,
            destinationEndpointValue: dstEndpoint,
            protocolStack: protos,
            status: .ok,
            latencyMilliseconds: 12.0,
            bytesUp: bytesUp,
            bytesDown: bytesDown,
            packetsUp: packetsUp,
            packetsDown: packetsDown,
            tcpCompleteness: tcpCompleteness,
            decodedLayers: decodedLayers,
            dnsQuery: dnsQuery,
            dnsAnswers: dnsAnswers
        )
    }
}
