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

        // 6. System CLI commands under /sbin and /usr/sbin (e.g. ping, traceroute)
        // must classify under .cli rather than .systemService, even without a TTY.
        let sbinPing = SessionSourceClassifier.classify(
            makeSession(processName: "ping", host: "1.1.1.1"),
            context: SessionProcessContext(
                executablePath: "/sbin/ping",
                parentProcessName: "Antigravity",
                hasControllingTTY: false
            )
        )
        #expect(sbinPing.category == .cli)
        let expectedPingSub = String(localized: "System CLI")
            + " · "
            + String(format: String(localized: "Launched by %@"), "Antigravity")
        #expect(sbinPing.subtitle == expectedPingSub)

        let usrSbinTraceroute = SessionSourceClassifier.classify(
            makeSession(processName: "traceroute", host: "8.8.8.8"),
            context: SessionProcessContext(
                executablePath: "/usr/sbin/traceroute",
                parentProcessName: "zsh",
                hasControllingTTY: true
            )
        )
        #expect(usrSbinTraceroute.category == .cli)
        #expect(usrSbinTraceroute.subtitle == String(localized: "System CLI"))

        // 7. CommandLineTools embedded Python.app carries com.apple.python3 bundle ID
        // under /Library/Developer and must classify as .cli Developer Toolchain, not .systemService.
        let cltPython = SessionSourceClassifier.classify(
            makeSession(processName: "Python", host: "www.apple.com"),
            context: SessionProcessContext(
                executablePath: "/Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions/3.9/Resources/Python.app/Contents/MacOS/Python",
                bundleIdentifier: "com.apple.python3",
                parentProcessName: "Antigravity"
            )
        )
        #expect(cltPython.category == .cli)
        let expectedCltPythonSub = String(localized: "Developer Toolchain")
            + " · "
            + String(format: String(localized: "Launched by %@"), "Antigravity")
        #expect(cltPython.subtitle == expectedCltPythonSub)
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

    // MARK: - 11. Scheme A Caller-Scoped CLI Separation & App Per-Process Breakdown

    @Test("Separates CLI tools by caller scope (App embedded vs Terminal vs System) and aggregates all related App subprocesses")
    func separatesCallerScopedCLIAccordingToSchemeAAndBreaksDownAppSubprocesses() throws {
        // 1. Antigravity main binary session
        let agyMain = makeSession(processName: "Antigravity", host: "update.antigravity.dev")
        // 2. Antigravity nested helper (`language_server_macos_arm`) sessions (direct + delegated DNS)
        let agyHelper1 = makeSession(processName: "Antigravity", host: "daily-cloudcode-pa.googleapis.com")
        let agyHelper2 = makeSession(processName: "Antigravity", host: "oauth2.googleapis.com")
        // 3. Antigravity embedded `curl` (spawned via `language_server_macos_arm -> zsh -> curl`)
        let agyCurl1 = makeSession(processName: "curl", host: "example.com")
        let agyCurl2 = makeSession(processName: "curl", host: "api.github.com")
        // 4. Antigravity embedded `ping` (`/sbin/ping` via `sh`)
        let agyPing = makeSession(processName: "ping", host: "1.1.1.1")
        // 5. Interactive Terminal `curl` (`Terminal -> zsh -> curl`) — MUST NOT mix into Antigravity!
        let termCurl = makeSession(processName: "curl", host: "brew.sh")
        // 6. System-invoked `curl` (`launchd -> softwareupdated -> sh -> curl`) — MUST NOT mix into Antigravity!
        let sysDaemonCurl = makeSession(processName: "curl", host: "swscan.apple.com")
        // 7. Direct `launchd -> sh` call
        let directSysSh = makeSession(processName: "sh", host: "time.apple.com")
        // 8. OrbStack helper (`OrbStack Helper`) — table label deduplicates prefix to `OrbStack · Helper`
        let orbHelper = makeSession(processName: "OrbStack", host: "cdn.orbstack.dev")

        let agyMainCtx = SessionProcessContext(
            executablePath: "/Applications/Antigravity.app/Contents/MacOS/Electron",
            bundleIdentifier: "com.amunx.antigravity",
            originProcessName: "Antigravity"
        )
        let agyHelperDirectCtx = SessionProcessContext(
            executablePath: "/Applications/Antigravity.app/Contents/Resources/app/bin/language_server_macos_arm",
            bundleIdentifier: "com.amunx.antigravity",
            viaProcessName: "language_server_macos_arm",
            originProcessName: "language_server_macos_arm"
        )
        let agyHelperDNSCtx = SessionProcessContext(
            executablePath: "/Applications/Antigravity.app/Contents/Resources/app/bin/language_server_macos_arm",
            bundleIdentifier: "com.amunx.antigravity",
            viaProcessName: "mDNSResponder",
            originProcessName: "language_server_macos_arm"
        )
        let agyCurlCtx = SessionProcessContext(
            executablePath: "/usr/bin/curl",
            parentProcessName: "Antigravity",
            originProcessName: "curl",
            hostAppName: "Antigravity",
            spawnerProcessName: "language_server_macos_arm",
            viaShellName: "zsh",
            callerKind: .app
        )
        let agyPingCtx = SessionProcessContext(
            executablePath: "/sbin/ping",
            parentProcessName: "Antigravity",
            originProcessName: "ping",
            hostAppName: "Antigravity",
            viaShellName: "sh",
            callerKind: .app
        )
        let termCurlCtx = SessionProcessContext(
            executablePath: "/usr/bin/curl",
            parentProcessName: "Terminal",
            originProcessName: "curl",
            viaShellName: "zsh",
            callerKind: .terminal,
            hasControllingTTY: true
        )
        let sysDaemonCurlCtx = SessionProcessContext(
            executablePath: "/usr/bin/curl",
            parentProcessName: "softwareupdated",
            originProcessName: "curl",
            spawnerProcessName: "softwareupdated",
            viaShellName: "sh",
            callerKind: .system
        )
        let directSysShCtx = SessionProcessContext(
            executablePath: "/bin/sh",
            originProcessName: "sh",
            callerKind: .system
        )
        let orbHelperCtx = SessionProcessContext(
            executablePath: "/Applications/OrbStack.app/Contents/Frameworks/OrbStack Helper.app/Contents/MacOS/OrbStack Helper",
            bundleIdentifier: "dev.kdrag0n.MacVirt",
            viaProcessName: "OrbStack Helper",
            originProcessName: "OrbStack Helper"
        )

        // Verify per-session table labels and caller-scoped CLI keys.
        let classifiedHelper = SessionSourceClassifier.classify(agyHelperDNSCtxSession(agyHelper2), context: agyHelperDNSCtx)
        #expect(classifiedHelper.tableLabel == "Antigravity · language_server_macos_arm")
        #expect(classifiedHelper.subtitle == String(format: String(localized: "via %@"), "language_server_macos_arm, mDNSResponder"))

        let classifiedOrb = SessionSourceClassifier.classify(orbHelper, context: orbHelperCtx)
        #expect(classifiedOrb.tableLabel == "OrbStack · Helper")

        let classifiedAgyCurl = SessionSourceClassifier.classify(agyCurl1, context: agyCurlCtx)
        #expect(classifiedAgyCurl.category == .cli)
        #expect(classifiedAgyCurl.filterKey == "cli:app:Antigravity:curl")
        #expect(classifiedAgyCurl.title == "curl · Antigravity")
        #expect(classifiedAgyCurl.tableLabel == "Antigravity · curl")

        let classifiedTermCurl = SessionSourceClassifier.classify(termCurl, context: termCurlCtx)
        #expect(classifiedTermCurl.filterKey == "cli:term:Terminal:curl")
        #expect(classifiedTermCurl.title == "curl · Terminal")
        #expect(classifiedTermCurl.tableLabel == "Terminal · curl")

        let classifiedSysCurl = SessionSourceClassifier.classify(sysDaemonCurl, context: sysDaemonCurlCtx)
        #expect(classifiedSysCurl.filterKey == "cli:sys:softwareupdated:curl")
        #expect(classifiedSysCurl.title == "curl · softwareupdated")
        #expect(classifiedSysCurl.tableLabel == "softwareupdated · curl")

        let classifiedDirectSh = SessionSourceClassifier.classify(directSysSh, context: directSysShCtx)
        #expect(classifiedDirectSh.filterKey == "cli:sys:launchd:sh")
        #expect(classifiedDirectSh.title == "sh · \(String(localized: "System Call"))")
        #expect(classifiedDirectSh.tableLabel == "\(String(localized: "System")) · sh")

        // Verify sidebar grouping:
        let contexts: [UUID: SessionProcessContext] = [
            agyMain.id: agyMainCtx,
            agyHelper1.id: agyHelperDirectCtx,
            agyHelper2.id: agyHelperDNSCtx,
            agyCurl1.id: agyCurlCtx,
            agyCurl2.id: agyCurlCtx,
            agyPing.id: agyPingCtx,
            termCurl.id: termCurlCtx,
            sysDaemonCurl.id: sysDaemonCurlCtx,
            directSysSh.id: directSysShCtx,
            orbHelper.id: orbHelperCtx,
        ]
        let allSessions = [
            agyMain, agyHelper1, agyHelper2, agyCurl1, agyCurl2, agyPing,
            termCurl, sysDaemonCurl, directSysSh, orbHelper,
        ]
        let groups = SessionSourceClassifier.group(
            sessions: allSessions,
            contextsBySessionID: contexts,
            localIPs: Self.liveLocalIPs
        )

        let appCategory = try #require(groups.first { $0.category == .app })
        let agyItem = try #require(appCategory.items.first { $0.filterKey == "Antigravity" })
        // 1 main + 2 helper + 2 embedded curl + 1 embedded ping = 6 total related sessions!
        #expect(agyItem.count == 6)
        #expect(agyItem.subprocesses.count == 4)
        // Sorted by count desc, then title asc: curl (2), language_server_macos_arm (2), Antigravity (1), ping (1)
        #expect(agyItem.subprocesses.map(\.title) == [
            "curl",
            "language_server_macos_arm",
            "Antigravity",
            "ping",
        ])
        #expect(agyItem.subprocesses.map(\.count) == [2, 2, 1, 1])
        #expect(agyItem.subprocesses.map(\.filterKey) == [
            "cli:app:Antigravity:curl",
            "app-proc:Antigravity:language_server_macos_arm",
            "app-proc:Antigravity:Antigravity",
            "cli:app:Antigravity:ping",
        ])

        // CLI category has 5 distinct caller-scoped items (never merging Antigravity curl, Terminal curl, and softwareupdated curl!).
        let cliCategory = try #require(groups.first { $0.category == .cli })
        #expect(cliCategory.items.map(\.filterKey) == [
            "cli:app:Antigravity:curl",
            "cli:term:Terminal:curl",
            "cli:sys:softwareupdated:curl",
            "cli:app:Antigravity:ping",
            "cli:sys:launchd:sh",
        ])

        // Verify filter matching across App top-level, App subprocess, and Caller-scoped CLI keys:
        let matchedAgyAll = allSessions.filter {
            SessionSourceClassifier.matchesFilterKey("Antigravity", session: $0, context: contexts[$0.id])
        }
        #expect(matchedAgyAll.count == 6)

        let matchedLangServerOnly = allSessions.filter {
            SessionSourceClassifier.matchesFilterKey(
                "app-proc:Antigravity:language_server_macos_arm",
                session: $0,
                context: contexts[$0.id]
            )
        }
        #expect(matchedLangServerOnly.map(\.id) == [agyHelper1.id, agyHelper2.id])

        let matchedAgyMainOnly = allSessions.filter {
            SessionSourceClassifier.matchesFilterKey(
                "app-proc:Antigravity:Antigravity",
                session: $0,
                context: contexts[$0.id]
            )
        }
        #expect(matchedAgyMainOnly.map(\.id) == [agyMain.id])

        let matchedAgyCurlOnly = allSessions.filter {
            SessionSourceClassifier.matchesFilterKey(
                "cli:app:Antigravity:curl",
                session: $0,
                context: contexts[$0.id]
            )
        }
        #expect(matchedAgyCurlOnly.map(\.id) == [agyCurl1.id, agyCurl2.id])

        let matchedTermCurlOnly = allSessions.filter {
            SessionSourceClassifier.matchesFilterKey(
                "cli:term:Terminal:curl",
                session: $0,
                context: contexts[$0.id]
            )
        }
        #expect(matchedTermCurlOnly.map(\.id) == [termCurl.id])

        // Verify displayTitle(forFilterKey:) and SourceIconView symbol resolution:
        #expect(
            SessionSourceClassifier.displayTitle(forFilterKey: "app-proc:Antigravity:language_server_macos_arm")
                == "Antigravity › language_server_macos_arm"
        )
        #expect(
            SessionSourceClassifier.displayTitle(forFilterKey: "cli:app:Antigravity:curl")
                == "Antigravity · curl"
        )
        #expect(
            SourceIconView.resolvedSymbolName(
                category: .cli,
                filterKey: "cli:app:Antigravity:curl",
                title: "curl · Antigravity"
            ) == "arrow.up.arrow.down"
        )
        #expect(
            SourceIconView.resolvedSymbolName(
                category: .cli,
                filterKey: "cli:app:Antigravity:Python",
                title: "Python · Antigravity"
            ) == "curlybraces"
        )
        #expect(
            SourceIconView.resolvedSymbolName(
                category: .cli,
                filterKey: "cli:app:Antigravity:ping",
                title: "ping · Antigravity"
            ) == "waveform.path.ecg"
        )
        #expect(
            SourceIconView.resolvedSymbolName(
                category: .thirdPartyService,
                filterKey: "app-proc:Antigravity:language_server_macos_arm",
                title: "language_server_macos_arm",
                subtitle: String(localized: "App Helper Process"),
                fallbackSymbol: "gearshape.2"
            ) == "gearshape.2"
        )
    }

    // MARK: - 12. Round 3 — Unified Fallback Provenance, mDNS Sanitization, Framework Python & Localization

    @MainActor
    @Test("Sticky session with nil direct context inherits caller provenance consistently across group, filter matcher, and coordinator")
    func unifiedFallbackContextAcrossGroupMatcherAndCoordinator() throws {
        let embeddedCurlWithProvenance = makeSession(
            processName: "curl",
            host: "api.example.com",
            processProvenance: ProcessProvenance(
                executablePath: "/usr/bin/curl",
                parentProcessName: "Antigravity",
                originProcessName: "curl",
                hostAppName: "Antigravity",
                spawnerProcessName: "language_server_macos_arm",
                viaShellName: "zsh",
                callerKind: .app
            )
        )
        let stickyCurlWithoutDirectContext = makeSession(
            processName: "curl",
            host: "cdn.example.com",
            processProvenance: nil
        )
        let sessions = [embeddedCurlWithProvenance, stickyCurlWithoutDirectContext]
        let directProvider: (SessionSummary) -> SessionProcessContext? = {
            $0.processProvenance.map(SessionProcessContext.init)
        }

        // 1. Pure classifier fallback + effectiveProcessContext + group + makeFilterMatcher agree.
        let fallbacks = SessionSourceClassifier.fallbackContextsByProcessName(
            for: sessions,
            contextProvider: directProvider
        )
        let effectiveSticky = SessionSourceClassifier.effectiveProcessContext(
            for: stickyCurlWithoutDirectContext,
            direct: nil,
            fallbacks: fallbacks
        )
        #expect(effectiveSticky?.hostAppName == "Antigravity")
        #expect(effectiveSticky?.callerKind == .app)

        let groups = SessionSourceClassifier.group(
            sessions: sessions,
            contextProvider: directProvider,
            localIPs: Self.liveLocalIPs
        )
        let cliCategory = try #require(groups.first { $0.category == .cli })
        let curlItem = try #require(cliCategory.items.first { $0.filterKey == "cli:app:Antigravity:curl" })
        #expect(curlItem.count == 2)

        let matcher = SessionSourceClassifier.makeFilterMatcher(
            for: "cli:app:Antigravity:curl",
            localIPs: Self.liveLocalIPs
        )
        let matchedPure = sessions.filter { session in
            let eff = SessionSourceClassifier.effectiveProcessContext(
                for: session,
                direct: directProvider(session),
                fallbacks: fallbacks
            )
            return matcher(session, eff)
        }
        #expect(matchedPure.count == curlItem.count)

        // 2. MainContentCoordinator classifiedSource, sourceCategoryGroups, and visibleSessions agree (badge count == row count).
        let suiteName = "tracexy.test.r3.fallback.\(UUID().uuidString)"
        let defaults = try #require(UserDefaults(suiteName: suiteName))
        defer { defaults.removePersistentDomain(forName: suiteName) }

        let coordinator = MainContentCoordinator(settingsDefaults: defaults)
        coordinator.sessions = sessions

        let stickyRow = coordinator.classifiedSource(for: stickyCurlWithoutDirectContext)
        #expect(stickyRow.category == .cli)
        #expect(stickyRow.filterKey == "cli:app:Antigravity:curl")
        #expect(stickyRow.tableLabel == "Antigravity · curl")

        let coordGroups = coordinator.sourceCategoryGroups
        let coordCLI = try #require(coordGroups.first { $0.category == .cli })
        let coordCurlItem = try #require(coordCLI.items.first { $0.filterKey == "cli:app:Antigravity:curl" })
        #expect(coordCurlItem.count == 2)

        coordinator.activeWorkspace.processFilter = "cli:app:Antigravity:curl"
        let visible = coordinator.visibleSessions(in: coordinator.activeWorkspace)
        #expect(visible.count == coordCurlItem.count)
        #expect(Set(visible.map(\.id)) == Set(sessions.map(\.id)))

        // 3. Cache invalidates cleanly when conflicting caller provenance arrives on a new session.
        let terminalCurl = makeSession(
            processName: "curl",
            host: "brew.sh",
            processProvenance: ProcessProvenance(
                executablePath: "/usr/bin/curl",
                parentProcessName: "Terminal",
                originProcessName: "curl",
                viaShellName: "zsh",
                callerKind: .terminal,
                hasControllingTTY: true
            )
        )
        coordinator.sessions = [embeddedCurlWithProvenance, stickyCurlWithoutDirectContext, terminalCurl]
        let stickyAfterConflict = coordinator.effectiveSessionProcessContext(for: stickyCurlWithoutDirectContext)
        #expect(stickyAfterConflict?.hostAppName == nil)
        #expect(stickyAfterConflict?.callerKind == nil)
        #expect(coordinator.classifiedSource(for: stickyCurlWithoutDirectContext).filterKey == "curl")
        #expect(coordinator.visibleSessions(in: coordinator.activeWorkspace).map(\.id) == [embeddedCurlWithProvenance.id])
    }

    @Test("mdnsPeerNameHint rejects DNS-SD service labels and prefers sanitized dnsResolvedBindings")
    func mdnsPeerNameHintSanitizationAndBindingsPriority() {
        // 1. Service / meta queries in dnsQuery are NEVER appended as LAN peer device hints.
        let companionLink = makeSession(
            processName: nil,
            host: "_companion-link._tcp.local",
            src: ("192.0.2.10", 5_353),
            dst: ("224.0.0.251", 5_353),
            protos: [.udp, .mdns],
            dnsQuery: "_companion-link._tcp.local.",
            dnsAnswers: ["192.0.2.10"]
        )
        let companionClassified = SessionSourceClassifier.classify(companionLink, localIPs: Self.liveLocalIPs)
        #expect(companionClassified.category == .lanDiscovery)
        #expect(companionClassified.filterKey == "lan:mdns")
        #expect(
            companionClassified.childTarget
                == SourceChildTarget(kind: .peerIP, value: "192.0.2.10", label: "192.0.2.10")
        )

        let browseMeta = makeSession(
            processName: nil,
            host: "lb._dns-sd._udp.local",
            src: ("192.0.2.11", 5_353),
            dst: ("224.0.0.251", 5_353),
            protos: [.udp, .mdns],
            dnsQuery: "lb._dns-sd._udp.local",
            dnsAnswers: ["192.0.2.11"]
        )
        let browseClassified = SessionSourceClassifier.classify(browseMeta, localIPs: Self.liveLocalIPs)
        #expect(
            browseClassified.childTarget
                == SourceChildTarget(kind: .peerIP, value: "192.0.2.11", label: "192.0.2.11")
        )

        // 2. Prefers sanitized dnsResolvedBindings over raw dnsQuery (even when dnsQuery is a service name).
        let withBindings = makeSession(
            processName: nil,
            host: "_companion-link._tcp.local",
            src: ("192.0.2.10", 5_353),
            dst: ("224.0.0.251", 5_353),
            protos: [.udp, .mdns],
            dnsQuery: "_companion-link._tcp.local",
            dnsAnswers: ["192.0.2.10"],
            dnsResolvedBindings: [
                DNSAddressBinding(ip: "192.0.2.10", hostname: "_companion-link._tcp.local"),
                DNSAddressBinding(ip: "192.0.2.10", hostname: "TestPhone.local."),
            ]
        )
        let bindingsClassified = SessionSourceClassifier.classify(withBindings, localIPs: Self.liveLocalIPs)
        #expect(
            bindingsClassified.childTarget
                == SourceChildTarget(kind: .peerIP, value: "192.0.2.10", label: "192.0.2.10 · TestPhone.local")
        )

        // 3. When dnsResolvedBindings is non-empty but has no valid binding for peerIP, does NOT fall back to dnsQuery.
        let unmatchedBindings = makeSession(
            processName: nil,
            host: "TestPhone.local",
            src: ("192.0.2.12", 5_353),
            dst: ("224.0.0.251", 5_353),
            protos: [.udp, .mdns],
            dnsQuery: "TestPhone.local",
            dnsAnswers: ["192.0.2.12"],
            dnsResolvedBindings: [
                DNSAddressBinding(ip: "192.0.2.99", hostname: "OtherDevice.local"),
            ]
        )
        let unmatchedClassified = SessionSourceClassifier.classify(unmatchedBindings, localIPs: Self.liveLocalIPs)
        #expect(
            unmatchedClassified.childTarget
                == SourceChildTarget(kind: .peerIP, value: "192.0.2.12", label: "192.0.2.12")
        )
    }

    @Test("Classifies framework-embedded Python.app and non-standard path CLI commands as .cli")
    func classifiesFrameworkPythonAndNonStandardPathCLI() {
        let mockHome = "/var/tmp/mockhome"

        let condaPython = SessionSourceClassifier.classify(
            makeSession(processName: "Python", host: "pypi.org"),
            context: SessionProcessContext(
                executablePath: "\(mockHome)/miniconda3/envs/dev/lib/Python.framework/Versions/3.11/Resources/Python.app/Contents/MacOS/Python",
                hasControllingTTY: false
            ),
            localIPs: Self.liveLocalIPs,
            homeDirectoryPath: mockHome,
            appBundleExistsLookup: { _ in false }
        )
        #expect(condaPython.category == .cli)
        #expect(condaPython.filterKey == "Python")

        let frameworkPython = SessionSourceClassifier.classify(
            makeSession(processName: "Python", host: "pypi.org"),
            context: SessionProcessContext(
                executablePath: "/Library/Frameworks/Python.framework/Versions/3.12/Resources/Python.app/Contents/MacOS/Python",
                hasControllingTTY: false
            ),
            localIPs: Self.liveLocalIPs,
            homeDirectoryPath: mockHome,
            appBundleExistsLookup: { _ in false }
        )
        #expect(frameworkPython.category == .cli)
        #expect(frameworkPython.filterKey == "Python")

        let nixCurl = SessionSourceClassifier.classify(
            makeSession(processName: "curl", host: "example.org"),
            context: SessionProcessContext(
                executablePath: "/nix/store/00000000000000000000000000000000-curl/bin/curl",
                hasControllingTTY: false
            ),
            localIPs: Self.liveLocalIPs,
            homeDirectoryPath: mockHome,
            appBundleExistsLookup: { _ in false }
        )
        #expect(nixCurl.category == .cli)
        #expect(nixCurl.filterKey == "curl")
    }

    @Test("Threads explicit localization bundle through TrafficSourceCategory, classify, group, and displayTitle")
    func supportsExplicitLocalizationBundle() throws {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("tracexy-source-classify-lproj-\(UUID().uuidString)", isDirectory: true)
        let lprojDir = tempDir.appendingPathComponent("zh-Hans.lproj", isDirectory: true)
        try FileManager.default.createDirectory(at: lprojDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let strings: [String: String] = [
            "Apps": "应用",
            "LAN & Discovery": "局域网与发现",
            "Bonjour / mDNS": "Bonjour / mDNS 发现",
            "LAN · Bonjour": "局域网 · Bonjour",
            "System CLI": "系统命令行",
        ]
        let plist = try PropertyListSerialization.data(fromPropertyList: strings, format: .binary, options: 0)
        try plist.write(to: lprojDir.appendingPathComponent("Localizable.strings"))
        let zhBundle = try #require(Bundle(url: lprojDir))

        #expect(TrafficSourceCategory.app.title(in: zhBundle) == "应用")
        #expect(TrafficSourceCategory.lanDiscovery.title(in: zhBundle) == "局域网与发现")
        #expect(SessionSourceClassifier.displayTitle(forFilterKey: "lan:mdns", bundle: zhBundle) == "Bonjour / mDNS 发现")

        let mdnsSession = makeSession(
            processName: nil,
            host: "224.0.0.251",
            src: ("192.0.2.10", 5_353),
            dst: ("224.0.0.251", 5_353),
            protos: [.udp, .mdns]
        )
        let classified = SessionSourceClassifier.classify(
            mdnsSession,
            localIPs: Self.liveLocalIPs,
            bundle: zhBundle
        )
        #expect(classified.title == "Bonjour / mDNS 发现")
        #expect(classified.tableLabel == "局域网 · Bonjour")

        let curlSession = makeSession(processName: "curl", host: "example.com")
        let grouped = SessionSourceClassifier.group(
            sessions: [curlSession],
            contextsBySessionID: [curlSession.id: SessionProcessContext(executablePath: "/usr/bin/curl")],
            localIPs: Self.liveLocalIPs,
            bundle: zhBundle
        )
        #expect(grouped.first?.items.first?.subtitle == "系统命令行")
    }

    @Test("Classifies nested Chromium/Electron/CEF framework helpers inside host .app bundles as .app with helper subprocess")
    func classifiesNestedFrameworkAppHelpersAsApps() throws {
        let mockHome = "/var/tmp/mockhome"

        // (a) ego lite helper nested inside ego Framework.framework classifies as .app with localized via subtitle and groups under Apps with ego Helper subprocess.
        let egoHelperPath = "/Applications/ego lite.app/Contents/Frameworks/ego Framework.framework/Versions/0.6.3.14/Helpers/ego Helper.app/Contents/MacOS/ego Helper"
        let egoSession = makeSession(processName: "ego lite", host: "api.example.com")
        let egoContext = SessionProcessContext(
            executablePath: egoHelperPath,
            bundleIdentifier: "com.example.egolite",
            viaProcessName: "ego Helper",
            originProcessName: "ego Helper"
        )

        let egoClassified = SessionSourceClassifier.classify(
            egoSession,
            context: egoContext,
            localIPs: Self.liveLocalIPs,
            homeDirectoryPath: mockHome,
            appBundleExistsLookup: { _ in false }
        )
        #expect(egoClassified.category == .app)
        #expect(egoClassified.title == "ego lite")
        #expect(egoClassified.tableLabel == "ego lite · ego Helper")
        #expect(egoClassified.subtitle == String(format: String(localized: "via %@"), "ego Helper"))
        #expect(egoClassified.symbolName == nil)

        // Verify localized Chinese "经由 ego Helper" subtitle with explicit bundle.
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("tracexy-r5-ego-lproj-\(UUID().uuidString)", isDirectory: true)
        let zhDir = tempDir.appendingPathComponent("zh-Hans.lproj", isDirectory: true)
        try FileManager.default.createDirectory(at: zhDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let zhPlist = try PropertyListSerialization.data(
            fromPropertyList: ["via %@": "经由 %@"],
            format: .binary,
            options: 0
        )
        try zhPlist.write(to: zhDir.appendingPathComponent("Localizable.strings"))
        let zhBundle = try #require(Bundle(url: zhDir))
        let egoZh = SessionSourceClassifier.classify(
            egoSession,
            context: egoContext,
            localIPs: Self.liveLocalIPs,
            homeDirectoryPath: mockHome,
            appBundleExistsLookup: { _ in false },
            bundle: zhBundle
        )
        #expect(egoZh.subtitle == "经由 ego Helper")

        // Verify grouping under Apps with subprocess "ego Helper".
        let groups = SessionSourceClassifier.group(
            sessions: [egoSession],
            contextsBySessionID: [egoSession.id: egoContext],
            localIPs: Self.liveLocalIPs,
            homeDirectoryPath: mockHome,
            appBundleExistsLookup: { _ in false }
        )
        let appsGroup = try #require(groups.first { $0.category == .app })
        let egoItem = try #require(appsGroup.items.first { $0.filterKey == "ego lite" })
        #expect(egoItem.title == "ego lite")
        #expect(egoItem.subprocesses.map(\.title) == ["ego Helper"])

        // (b) Google Chrome, ChatGPT (Codex Framework), and LarkSuite (Lark Framework) nested helpers ALL classify as .app.
        let helperCases: [(name: String, path: String, helper: String)] = [
            (
                "Google Chrome",
                "/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Versions/130.0/Helpers/Google Chrome Helper.app/Contents/MacOS/Google Chrome Helper",
                "Google Chrome Helper"
            ),
            (
                "ChatGPT",
                "/Applications/ChatGPT.app/Contents/Frameworks/Codex Framework.framework/Versions/1.0/Helpers/ChatGPT Helper.app/Contents/MacOS/ChatGPT Helper",
                "ChatGPT Helper"
            ),
            (
                "Lark",
                "/Applications/LarkSuite.app/Contents/Frameworks/Lark Framework.framework/Versions/7.0/Helpers/Lark Helper.app/Contents/MacOS/Lark Helper",
                "Lark Helper"
            ),
        ]
        for testCase in helperCases {
            let classified = SessionSourceClassifier.classify(
                makeSession(processName: testCase.name, host: "edge.example.com"),
                context: SessionProcessContext(
                    executablePath: testCase.path,
                    viaProcessName: testCase.helper,
                    originProcessName: testCase.helper
                ),
                localIPs: Self.liveLocalIPs,
                homeDirectoryPath: mockHome,
                appBundleExistsLookup: { _ in false }
            )
            #expect(classified.category == .app)
            #expect(classified.title == testCase.name)
            #expect(classified.tableLabel == "\(testCase.name) · Helper")
        }

        // (c) Framework-embedded Python.app (both /Library/Frameworks and <mockhome>/miniconda3) STILL classifies as .cli.
        let libPython = SessionSourceClassifier.classify(
            makeSession(processName: "Python", host: "pypi.org"),
            context: SessionProcessContext(
                executablePath: "/Library/Frameworks/Python.framework/Versions/3.11/Resources/Python.app/Contents/MacOS/Python"
            ),
            localIPs: Self.liveLocalIPs,
            homeDirectoryPath: mockHome,
            appBundleExistsLookup: { _ in false }
        )
        #expect(libPython.category == .cli)

        let condaPython = SessionSourceClassifier.classify(
            makeSession(processName: "Python", host: "pypi.org"),
            context: SessionProcessContext(
                executablePath: "\(mockHome)/miniconda3/lib/Python.framework/Versions/3.11/Resources/Python.app/Contents/MacOS/Python"
            ),
            localIPs: Self.liveLocalIPs,
            homeDirectoryPath: mockHome,
            appBundleExistsLookup: { _ in false }
        )
        #expect(condaPython.category == .cli)

        // (d) Background support .app inside ~/Library/Application Support/ classifies as .thirdPartyService,
        // while ~/Applications/MyStudio.app classifies as .app.
        let supportServer = SessionSourceClassifier.classify(
            makeSession(processName: "Foo Server", host: "sync.example.com"),
            context: SessionProcessContext(
                executablePath: "\(mockHome)/Library/Application Support/com.example.foo/Foo Server.app/Contents/MacOS/foo-server"
            ),
            localIPs: Self.liveLocalIPs,
            homeDirectoryPath: mockHome,
            appBundleExistsLookup: { _ in false }
        )
        #expect(supportServer.category == .thirdPartyService)

        let userHomeApp = SessionSourceClassifier.classify(
            makeSession(processName: "MyStudio", host: "updates.example.com"),
            context: SessionProcessContext(
                executablePath: "\(mockHome)/Applications/MyStudio.app/Contents/MacOS/MyStudio"
            ),
            localIPs: Self.liveLocalIPs,
            homeDirectoryPath: mockHome,
            appBundleExistsLookup: { _ in false }
        )
        #expect(userHomeApp.category == .app)
        #expect(userHomeApp.title == "MyStudio")

        // Known CLI commands and system daemons are never falsely reported as installed GUI apps.
        #expect(!SessionSourceClassifier.defaultAppBundleExists("curl"))
        #expect(!SessionSourceClassifier.defaultAppBundleExists("python3"))
        #expect(!SessionSourceClassifier.defaultAppBundleExists("mDNSResponder"))
    }

    @Test("InstalledAppCatalog indexes localized InfoPlist.strings, Info.plist display names, bundle IDs, and depth-2 apps without descending into .app packages")
    func installedAppCatalogIndexesLocalizedAndNestedAppsSafely() throws {
        let tempRoot = FileManager.default.temporaryDirectory
            .appendingPathComponent("tracexy-r5-catalog-\(UUID().uuidString)", isDirectory: true)
        let primaryApps = tempRoot.appendingPathComponent("PrimaryApps", isDirectory: true)
        let secondaryApps = tempRoot.appendingPathComponent("SecondaryApps", isDirectory: true)
        try FileManager.default.createDirectory(at: primaryApps, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: secondaryApps, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempRoot) }

        // 1. SampleRemote.app with Info.plist + zh-Hans.lproj/InfoPlist.strings + nested Helper.app inside Frameworks
        let sampleRemote = primaryApps.appendingPathComponent("SampleRemote.app", isDirectory: true)
        let sampleContents = sampleRemote.appendingPathComponent("Contents", isDirectory: true)
        let sampleZh = sampleContents.appendingPathComponent("Resources/zh-Hans.lproj", isDirectory: true)
        let nestedHelper = sampleContents.appendingPathComponent(
            "Frameworks/Sample Framework.framework/Versions/1.0/Helpers/Hidden Nested Helper.app/Contents",
            isDirectory: true
        )
        try FileManager.default.createDirectory(at: sampleZh, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: nestedHelper, withIntermediateDirectories: true)

        let infoPlistData = try PropertyListSerialization.data(
            fromPropertyList: [
                "CFBundleDisplayName": "Sample Remote",
                "CFBundleName": "SampleRemoteShort",
                "CFBundleIdentifier": "com.example.SampleRemote",
            ],
            format: .xml,
            options: 0
        )
        try infoPlistData.write(to: sampleContents.appendingPathComponent("Info.plist"))

        let zhStringsData = try PropertyListSerialization.data(
            fromPropertyList: [
                "CFBundleDisplayName": "示例远程",
            ],
            format: .binary,
            options: 0
        )
        try zhStringsData.write(to: sampleZh.appendingPathComponent("InfoPlist.strings"))

        // 2. Depth-2 app inside a non-.app subfolder
        let subfolderApp = primaryApps.appendingPathComponent("Tools/DepthTwoTool.app/Contents", isDirectory: true)
        try FileManager.default.createDirectory(at: subfolderApp, withIntermediateDirectories: true)

        // 3. Duplicate app in secondary root (primary root should win)
        let duplicateRemote = secondaryApps.appendingPathComponent("SampleRemote.app/Contents", isDirectory: true)
        try FileManager.default.createDirectory(at: duplicateRemote, withIntermediateDirectories: true)

        let catalog = InstalledAppCatalog(searchRootURLs: [primaryApps, secondaryApps])
        let canonicalize: (String?) -> String? = { path in
            path.map { URL(fileURLWithPath: $0).resolvingSymlinksInPath().path }
        }
        let expectedSamplePath = canonicalize(sampleRemote.path)

        #expect(catalog.containsApp(named: "示例远程"))
        #expect(canonicalize(catalog.appBundlePath(forName: "示例远程")) == expectedSamplePath)
        #expect(canonicalize(catalog.appBundlePath(forName: "Sample Remote")) == expectedSamplePath)
        #expect(canonicalize(catalog.appBundlePath(forName: "sample remote")) == expectedSamplePath)
        #expect(canonicalize(catalog.appBundlePath(forName: "SampleRemote")) == expectedSamplePath)
        #expect(canonicalize(catalog.appBundlePath(forName: "SampleRemoteShort")) == expectedSamplePath)
        #expect(canonicalize(catalog.appBundlePath(forBundleIdentifier: "com.example.sampleremote")) == expectedSamplePath)

        // Depth-2 app is discovered, while nested Helper.app inside SampleRemote.app is NOT indexed.
        #expect(catalog.containsApp(named: "DepthTwoTool"))
        #expect(!catalog.containsApp(named: "Hidden Nested Helper"))
    }

    // MARK: - 14. Presentation Cache Performance, Parity & Invalidation (R6)

    @Test("Coordinator presentation caches classify 1,000 sessions with 4,000 learned DNS names in <50ms with 100% parity")
    @MainActor
    func coordinatorPresentationCacheBenchmarkAndParity() {
        let suiteName = "tracexy.tests.r6.perf.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)!
        defer { defaults.removePersistentDomain(forName: suiteName) }

        let coordinator = MainContentCoordinator(settingsDefaults: defaults)

        // Seed 4,000 learned DNS entries in AddressNameBook (maximumLearnedEntries).
        var bindings: [DNSAddressBinding] = []
        bindings.reserveCapacity(4_000)
        for index in 0 ..< 4_000 {
            let third = index / 250
            let fourth = (index % 250) + 1
            bindings.append(DNSAddressBinding(
                ip: "10.200.\(third).\(fourth)",
                hostname: "svc-\(third)-\(fourth).example.com"
            ))
        }
        let dnsSeeder = makeSession(
            processName: "mDNSResponder",
            host: "dns.example.com",
            protos: [.udp, .dns],
            dnsResolvedBindings: bindings
        )
        coordinator.addressNames.learn(from: [dnsSeeder])
        #expect(coordinator.addressNames.learnedNames.count == 4_000)

        // Build 1,000 realistic sessions across all traffic categories.
        let safariProv = ProcessProvenance(
            executablePath: "/System/Applications/Safari.app/Contents/MacOS/Safari",
            bundleIdentifier: "com.apple.Safari",
            viaProcessName: "nsurlsessiond"
        )
        let curlProv = ProcessProvenance(
            executablePath: "/usr/bin/curl",
            parentProcessName: "zsh",
            hasControllingTTY: true
        )
        let mdnsProv = ProcessProvenance(
            executablePath: "/usr/sbin/mDNSResponder"
        )

        var sessions: [SessionSummary] = []
        sessions.reserveCapacity(1_000)
        for idx in 0 ..< 1_000 {
            switch idx % 10 {
            case 0, 1, 2, 3:
                sessions.append(makeSession(
                    processName: "Safari",
                    host: "app-\(idx % 40).example.com",
                    src: ("192.168.0.130", UInt16(40_000 + idx)),
                    dst: ("93.184.216.\((idx % 200) + 1)", 443),
                    protos: [.tcp, .tls, .http2],
                    processProvenance: safariProv
                ))
            case 4, 5:
                sessions.append(makeSession(
                    processName: "curl",
                    host: "api-\(idx % 20).example.org",
                    src: ("192.168.0.130", UInt16(45_000 + idx)),
                    dst: ("198.51.100.\((idx % 200) + 1)", 443),
                    protos: [.tcp, .tls],
                    processProvenance: curlProv
                ))
            case 6:
                sessions.append(makeSession(
                    processName: "mDNSResponder",
                    host: idx % 20 == 6 ? "_companion-link._tcp.local" : "Device-\(idx % 12).local",
                    src: ("192.168.0.130", 5_353),
                    dst: ("224.0.0.251", 5_353),
                    protos: [.udp, .mdns],
                    processProvenance: mdnsProv
                ))
            case 7:
                let third = (idx * 3) / 250
                let fourth = ((idx * 3) % 250) + 1
                sessions.append(makeSession(
                    processName: "Safari",
                    host: "10.200.\(third).\(fourth)",
                    src: ("192.168.0.130", UInt16(50_000 + idx)),
                    dst: ("10.200.\(third).\(fourth)", 443),
                    protos: [.tcp, .tls],
                    processProvenance: safariProv
                ))
            case 8:
                sessions.append(makeSession(
                    processName: "kernel_task",
                    host: "198.51.100.88",
                    src: ("192.168.0.130", UInt16(55_000 + idx)),
                    dst: ("198.51.100.88", 443),
                    protos: [.tcp],
                    tcpCompleteness: [.ack],
                    processProvenance: ProcessProvenance(isKernelTask: true)
                ))
            default:
                let peerIdx = idx % 250
                sessions.append(makeSession(
                    processName: nil,
                    host: "239.255.255.250",
                    src: ("10.200.0.\(peerIdx + 1)", UInt16(52_000 + (idx % 500))),
                    dst: ("239.255.255.250", 1_900),
                    protos: [.udp, .ssdp]
                ))
            }
        }

        coordinator.sessions = sessions
        // Ensure one-time singleton initialization (`ProcessResolver.shared` libproc scan)
        // happens before timing the steady-state classification & scroll workload.
        _ = ProcessResolver.shared.localIPsRevision

        // Run under an explicit language selection so the benchmark measures our
        // classification & rollup caches directly (isolating `.system` bundle resolution).
        AppLanguage.withTemporaryLanguageForTesting("en") {
            let clock = ContinuousClock()
            let start = clock.now
            var firstPass: [ClassifiedSessionSource] = []
            firstPass.reserveCapacity(sessions.count)
            for session in sessions {
                firstPass.append(coordinator.classifiedSource(for: session))
            }
            var secondPass: [ClassifiedSessionSource] = []
            secondPass.reserveCapacity(sessions.count)
            for session in sessions {
                secondPass.append(coordinator.classifiedSource(for: session))
            }
            let categories = coordinator.sourceCategoryGroups
            let domains = coordinator.domainGroups
            let localDiscovery = coordinator.localDiscoveryGroups
            let ips = coordinator.ipHosts
            // Second read of sidebar rollups (warm cache hits)
            #expect(coordinator.sourceCategoryGroups == categories)
            #expect(coordinator.domainGroups.map(\.domain) == domains.map(\.domain))
            #expect(coordinator.domainGroups.map(\.count) == domains.map(\.count))
            #expect(coordinator.localDiscoveryGroups == localDiscovery)
            #expect(coordinator.ipHosts.count == ips.count)
            let elapsed = clock.now - start

            #expect(elapsed < .milliseconds(50), "Expected <50ms total, measured \(elapsed)")
            #expect(firstPass == secondPass)
            #expect(!categories.isEmpty)
            #expect(!domains.isEmpty)
            #expect(!localDiscovery.isEmpty)
            #expect(!ips.isEmpty)

            // Verify 100% parity against direct `SessionSourceClassifier.classify(...)` using
            // pre-normalized inputs equivalent to direct classification.
            let localIPs = ProcessResolver.shared.currentLocalIPs
            let mergedNames = coordinator.mergedResolvedNames
            let isSaved = coordinator.isViewingSavedCapture
            let normalizedLocal = SessionSourceClassifier.normalizeLocalIPs(localIPs)
            let normalizedNames = SessionSourceClassifier.normalizeResolvedNameMap(mergedNames)
            for (index, session) in sessions.enumerated() {
                let direct = SessionSourceClassifier.classifyPreNormalized(
                    session,
                    context: coordinator.effectiveSessionProcessContext(for: session),
                    normalizedLocalIPsProvider: { normalizedLocal },
                    isViewingSavedCapture: isSaved,
                    normalizedResolvedNamesProvider: { normalizedNames }
                )
                #expect(firstPass[index] == direct, "Mismatch at session index \(index)")
            }
            // Spot-check unattributed SSDP peer session against direct uncached `classify(...)`.
            let ssdpSample = sessions[9]
            let directSSDP = SessionSourceClassifier.classify(
                ssdpSample,
                context: coordinator.effectiveSessionProcessContext(for: ssdpSample),
                localIPs: localIPs,
                isViewingSavedCapture: isSaved,
                resolvedNames: mergedNames
            )
            #expect(firstPass[9] == directSSDP)
            #expect(firstPass[9].childTarget?.label == "10.200.0.10 · svc-0-10.example.com")
        }
    }

    @Test("AddressNameBook fast-path displayHost preserves IPv4, IPv6, bracketed/zone IPv6, and domain parity")
    @MainActor
    func addressNameBookDisplayHostFastPathParity() {
        let suiteName = "tracexy.tests.r6.addr.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)!
        defer { defaults.removePersistentDomain(forName: suiteName) }

        let book = AddressNameBook()
        book.bind(to: defaults)
        let rev0 = book.revision
        #expect(book.setName("Gateway", for: "192.168.0.1"))
        let rev1 = book.revision
        #expect(rev1 > rev0)
        #expect(book.setName("IPv6-Lab", for: "fe80::1"))
        #expect(book.setName("Doc-V6", for: "2001:db8::1"))
        #expect(book.setSubnetName("office", for: "10.42.0.0/24"))

        // Domain names and special tokens fast-reject cleanly.
        #expect(!AddressNameBook.mayBeIPLiteral(""))
        #expect(!AddressNameBook.mayBeIPLiteral("—"))
        #expect(!AddressNameBook.mayBeIPLiteral("www.google.com"))
        #expect(!AddressNameBook.mayBeIPLiteral("anon.local"))
        #expect(!AddressNameBook.mayBeIPLiteral("_companion-link._tcp.local"))
        // IPv4, IPv6 (including leading hex a-f), bracketed IPv6, and zone-indexed IPv6 pass prefilter.
        #expect(AddressNameBook.mayBeIPLiteral("192.168.0.1"))
        #expect(AddressNameBook.mayBeIPLiteral("fe80::1"))
        #expect(AddressNameBook.mayBeIPLiteral("2001:db8::1"))
        #expect(AddressNameBook.mayBeIPLiteral("::1"))
        #expect(AddressNameBook.mayBeIPLiteral("[2001:db8::1]"))
        #expect(AddressNameBook.mayBeIPLiteral("fe80::1%en0"))

        #expect(book.displayHost(for: makeSession(processName: "Safari", host: "www.google.com")) == "www.google.com")
        #expect(book.displayHost(for: makeSession(processName: "Safari", host: "—")) == "—")
        #expect(book.displayHost(for: makeSession(processName: "Safari", host: "192.168.0.1")) == "Gateway (192.168.0.1)")
        #expect(book.displayHost(for: makeSession(processName: "Safari", host: "10.42.0.7")) == "office.7 (10.42.0.7)")
        #expect(book.displayHost(for: makeSession(processName: "Safari", host: "fe80::1")) == "IPv6-Lab (fe80::1)")
        #expect(book.displayHost(for: makeSession(processName: "Safari", host: "2001:0DB8::1")) == "Doc-V6 (2001:0DB8::1)")
        // Bracketed & zone-indexed forms are not accepted by IPAddressValue(parsing:), so returned verbatim.
        #expect(book.displayHost(for: makeSession(processName: "Safari", host: "[2001:db8::1]")) == "[2001:db8::1]")
        #expect(book.displayHost(for: makeSession(processName: "Safari", host: "fe80::1%en0")) == "fe80::1%en0")
    }

    @Test("Mutating AddressNameBook, attributedProvenancesBySessionID, isViewingSavedCapture, or removedSessionIDs immediately invalidates caches")
    @MainActor
    func coordinatorPresentationCacheInvalidation() {
        let suiteName = "tracexy.tests.r6.inval.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)!
        defer { defaults.removePersistentDomain(forName: suiteName) }

        let coordinator = MainContentCoordinator(settingsDefaults: defaults)
        let ssdpSession = makeSession(
            processName: nil,
            host: "239.255.255.250",
            src: ("192.168.0.42", 52_100),
            dst: ("239.255.255.250", 1_900),
            protos: [.udp, .ssdp]
        )
        let toolSession = makeSession(
            processName: "mycustomprobe",
            host: "api.example.com",
            src: ("192.168.0.130", 51_000),
            dst: ("93.184.216.34", 443),
            protos: [.tcp, .tls]
        )
        let localResetSession = makeSession(
            processName: nil,
            host: "93.184.216.34",
            src: ("127.0.0.1", 50_100),
            dst: ("93.184.216.34", 443),
            protos: [.tcp],
            bytesUp: 60,
            bytesDown: 0,
            packetsUp: 1,
            packetsDown: 0,
            tcpCompleteness: [.rst]
        )

        coordinator.sessions = [ssdpSession, toolSession, localResetSession]

        // 1. Warm cache and check initial classifications.
        #expect(coordinator.classifiedSource(for: ssdpSession).childTarget?.label == "192.168.0.42")
        #expect(coordinator.classifiedSource(for: toolSession).category == .thirdPartyService)
        #expect(coordinator.classifiedSource(for: localResetSession).category == .kernelAndLink)
        #expect(coordinator.domainGroups.map(\.domain) == ["api.example.com"])

        // 2. Mutate AddressNameBook -> cache invalidates immediately.
        #expect(coordinator.addressNames.setName("LivingRoom-TV", for: "192.168.0.42"))
        #expect(coordinator.classifiedSource(for: ssdpSession).childTarget?.label == "192.168.0.42 · LivingRoom-TV")
        let lanGroup = coordinator.sourceCategoryGroups.first { $0.category == .lanDiscovery }
        #expect(lanGroup?.items.first?.children.first?.label == "192.168.0.42 · LivingRoom-TV")

        // 3. Mutate attributedProvenancesBySessionID -> cache invalidates immediately.
        coordinator.attributedProvenancesBySessionID[toolSession.id] = ProcessProvenance(
            executablePath: "/opt/homebrew/bin/mycustomprobe",
            hasControllingTTY: true
        )
        #expect(coordinator.classifiedSource(for: toolSession).category == .cli)
        #expect(coordinator.sourceCategoryGroups.contains { $0.category == .cli })

        // 4. Flip isViewingSavedCapture -> cache invalidates immediately.
        coordinator.isViewingSavedCapture = true
        #expect(coordinator.classifiedSource(for: localResetSession).category == .unattributed)

        // 5. Remove session -> domainGroups cache invalidates immediately.
        coordinator.removedSessionIDs.insert(toolSession.id)
        #expect(coordinator.domainGroups.isEmpty)

        // 6. Empty appendRetainedFrames is a no-op.
        coordinator.appendRetainedFrames([])
        #expect(coordinator.retainedFrameCount == 0)
    }

    @Test(
        "Unattributed sessions report honest localized diagnostic reasons and tally per-target childCounts"
    )
    func unattributedDiagnosticReasonsAndChildCounts() throws {
        let bundles = try makeCatalogLanguageBundles()
        defer { bundles.teardown() }

        let savedUnattributed = makeSession(
            processName: nil,
            host: "api.example.com",
            src: ("192.168.0.130", 51_200),
            dst: ("93.184.216.34", 443),
            protos: [.tcp, .tls]
        )
        let savedEn = SessionSourceClassifier.classify(
            savedUnattributed,
            localIPs: Self.liveLocalIPs,
            isViewingSavedCapture: true,
            bundle: bundles.en
        )
        let savedZh = SessionSourceClassifier.classify(
            savedUnattributed,
            localIPs: Self.liveLocalIPs,
            isViewingSavedCapture: true,
            bundle: bundles.zhHans
        )
        #expect(savedEn.category == .unattributed)
        #expect(savedEn.filterKey == "—")
        #expect(savedEn.tableLabel == "—")
        #expect(savedEn.subtitle == "Saved capture file contains no local process metadata")
        #expect(savedEn.tableDetail == savedEn.subtitle)
        #expect(savedZh.subtitle == "已保存抓包文件不包含本机进程元数据")
        #expect(savedZh.tableDetail == savedZh.subtitle)

        let liveDNS = makeSession(
            processName: nil,
            host: "slardar-bd-sg.larksuite.com",
            src: ("192.168.0.130", 53_100),
            dst: ("8.8.8.8", 53),
            protos: [.udp, .dns],
            bytesUp: 64,
            bytesDown: 128,
            packetsUp: 1,
            packetsDown: 1
        )
        let dnsEn = SessionSourceClassifier.classify(
            liveDNS,
            localIPs: Self.liveLocalIPs,
            isViewingSavedCapture: false,
            bundle: bundles.en
        )
        let dnsZh = SessionSourceClassifier.classify(
            liveDNS,
            localIPs: Self.liveLocalIPs,
            isViewingSavedCapture: false,
            bundle: bundles.zhHans
        )
        #expect(dnsEn.category == .unattributed)
        #expect(dnsEn.subtitle == "Ephemeral DNS socket closed before sampling or outbound query missed")
        #expect(dnsEn.tableDetail == dnsEn.subtitle)
        #expect(dnsZh.subtitle == "瞬态 DNS 套接字在采样前已关闭或未捕获出站请求")
        #expect(dnsZh.tableDetail == dnsZh.subtitle)

        let liveGeneral = makeSession(
            processName: nil,
            host: "cdn.example.net",
            src: ("192.168.0.130", 54_200),
            dst: ("198.51.100.10", 443),
            protos: [.tcp, .tls]
        )
        let generalEn = SessionSourceClassifier.classify(
            liveGeneral,
            localIPs: Self.liveLocalIPs,
            isViewingSavedCapture: false,
            bundle: bundles.en
        )
        let generalZh = SessionSourceClassifier.classify(
            liveGeneral,
            localIPs: Self.liveLocalIPs,
            isViewingSavedCapture: false,
            bundle: bundles.zhHans
        )
        #expect(generalEn.category == .unattributed)
        #expect(generalEn.subtitle == "Short-lived socket closed before sampling or started before capture")
        #expect(generalEn.tableDetail == generalEn.subtitle)
        #expect(generalZh.subtitle == "短生命周期套接字在采样前已关闭或在抓包前已建立")
        #expect(generalZh.tableDetail == generalZh.subtitle)

        // Grouping tallies per-host childCounts across multiple unattributed sessions.
        let liveDNS2 = makeSession(
            processName: nil,
            host: "slardar-bd-sg.larksuite.com",
            src: ("192.168.0.130", 53_101),
            dst: ("8.8.8.8", 53),
            protos: [.udp, .dns],
            bytesUp: 64,
            bytesDown: 128
        )
        let liveDNS3 = makeSession(
            processName: nil,
            host: "slardar-bd-sg.larksuite.com",
            src: ("192.168.0.130", 53_102),
            dst: ("8.8.8.8", 53),
            protos: [.udp, .dns],
            bytesUp: 64,
            bytesDown: 128
        )
        let groups = SessionSourceClassifier.group(
            sessions: [liveDNS, liveDNS2, liveDNS3, liveGeneral],
            localIPs: Self.liveLocalIPs,
            isViewingSavedCapture: false,
            bundle: bundles.en
        )
        let unattributedGroup = try #require(groups.first { $0.category == .unattributed })
        #expect(unattributedGroup.totalSessions == 4)
        #expect(unattributedGroup.items.count == 1)
        let item = try #require(unattributedGroup.items.first)
        #expect(item.count == 4)
        #expect(item.childCounts["host:slardar-bd-sg.larksuite.com"] == 3)
        #expect(item.childCounts["host:cdn.example.net"] == 1)
        #expect(Set(item.children.map(\.value)) == ["slardar-bd-sg.larksuite.com", "cdn.example.net"])
    }

    private func makeCatalogLanguageBundles() throws -> (en: Bundle, zhHans: Bundle, teardown: () -> Void) {
        var root = URL(fileURLWithPath: #filePath)
        while root.lastPathComponent != "TracexyTests", root.path != "/" {
            root.deleteLastPathComponent()
        }
        root.deleteLastPathComponent()
        let data = try Data(contentsOf: root.appendingPathComponent("Tracexy/Localizable.xcstrings"))
        let catalog = try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        let stringsMap = try #require(catalog["strings"] as? [String: [String: Any]])

        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("tracexy-unattr-i18n-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)

        for language in ["en", "zh-Hans"] {
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
            let lproj = tempDir.appendingPathComponent("\(language).lproj", isDirectory: true)
            try FileManager.default.createDirectory(at: lproj, withIntermediateDirectories: true)
            let plist = try PropertyListSerialization.data(fromPropertyList: dict, format: .binary, options: 0)
            try plist.write(to: lproj.appendingPathComponent("Localizable.strings"))
        }

        let enBundle = try #require(Bundle(url: tempDir.appendingPathComponent("en.lproj", isDirectory: true)))
        let zhBundle = try #require(Bundle(url: tempDir.appendingPathComponent("zh-Hans.lproj", isDirectory: true)))
        return (enBundle, zhBundle, { try? FileManager.default.removeItem(at: tempDir) })
    }

    private func agyHelperDNSCtxSession(_ session: SessionSummary) -> SessionSummary {
        session
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
        dnsAnswers: [String] = [],
        dnsResolvedBindings: [DNSAddressBinding] = [],
        processProvenance: ProcessProvenance? = nil
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
            processProvenance: processProvenance,
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
            dnsAnswers: dnsAnswers,
            dnsResolvedBindings: dnsResolvedBindings
        )
    }
}
