import Foundation
import Testing
@testable import Tracexy

@Suite("Local Discovery Name Classification & Coordinator Separation")
struct LocalDiscoveryNameClassifierTests {
    // MARK: - 1. Normalization & Non-Discovery Inputs

    @Test("Returns nil for empty strings, missing-host placeholder, IP literals, and public domains")
    func ignoresNonDiscoveryInputs() {
        let nonDiscovery = [
            "",
            "   ",
            ".",
            "...",
            "—",
            "192.168.1.10",
            "224.0.0.251",
            "fe80::1",
            "ff02::fb",
            "2001:db8::1",
            "apple.com",
            "api.github.com",
            "sub.example.org.",
            ".local",
            "_incomplete.local",
            "resolver.arpa",
            "in-addr.arpa",
            "ip6.arpa",
        ]

        for host in nonDiscovery {
            #expect(LocalDiscoveryNameClassifier.classify(host) == nil, "Expected nil for \(host)")
            #expect(!LocalDiscoveryNameClassifier.isLocalOrSpecialDiscoveryName(host), "Expected false for \(host)")
        }

        #expect(LocalDiscoveryNameClassifier.isPublicOrUnicastDomainName("apple.com"))
        #expect(LocalDiscoveryNameClassifier.isPublicOrUnicastDomainName("api.github.com"))
        #expect(LocalDiscoveryNameClassifier.isPublicOrUnicastDomainName("sub.example.org."))
        #expect(!LocalDiscoveryNameClassifier.isPublicOrUnicastDomainName("192.168.1.10"))
        #expect(!LocalDiscoveryNameClassifier.isPublicOrUnicastDomainName("2001:db8::1"))
        #expect(!LocalDiscoveryNameClassifier.isPublicOrUnicastDomainName("—"))
        #expect(!LocalDiscoveryNameClassifier.isPublicOrUnicastDomainName(""))
        #expect(!LocalDiscoveryNameClassifier.isPublicOrUnicastDomainName("_companion-link._tcp.local"))
        #expect(!LocalDiscoveryNameClassifier.isPublicOrUnicastDomainName("Office-Phone.local"))
        #expect(!LocalDiscoveryNameClassifier.isPublicOrUnicastDomainName("1.0.168.192.in-addr.arpa"))
        #expect(!LocalDiscoveryNameClassifier.isPublicOrUnicastDomainName("_dns.resolver.arpa"))
        #expect(!LocalDiscoveryNameClassifier.isPublicOrUnicastDomainName("ipv4only.arpa"))
    }

    // MARK: - 2. Tier A — DNS-SD Meta Queries

    @Test("Classifies DNS-SD meta queries with exact badges, details, symbols, and LAN-only tooltips")
    func classifiesDNSSDMetaQueries() throws {
        let en = try makeBundle(language: "en", strings: [:])
        defer { en.teardown() }

        let cases: [(host: String, expectedClean: String, badge: String, detail: String)] = [
            (
                "lb._dns-sd._udp.local.",
                "lb._dns-sd._udp.local",
                "Browse Domain Probe",
                "DNS-SD legacy browse domain enumeration"
            ),
            (
                "lb._dns-sd._udp.0.1.168.192.in-addr.arpa",
                "lb._dns-sd._udp.0.1.168.192.in-addr.arpa",
                "Browse Domain Probe",
                "DNS-SD legacy browse domain enumeration"
            ),
            (
                "b._dns-sd._udp.local",
                "b._dns-sd._udp.local",
                "Browse Domain Query",
                "DNS-SD browse domain discovery"
            ),
            (
                "db._dns-sd._udp.example.com",
                "db._dns-sd._udp.example.com",
                "Browse Domain Query",
                "DNS-SD browse domain discovery"
            ),
            (
                "r._dns-sd._udp.local",
                "r._dns-sd._udp.local",
                "Registration Domain",
                "DNS-SD registration domain discovery"
            ),
            (
                "dr._dns-sd._udp.local",
                "dr._dns-sd._udp.local",
                "Registration Domain",
                "DNS-SD registration domain discovery"
            ),
            (
                "_services._dns-sd._udp.local",
                "_services._dns-sd._udp.local",
                "Service Enumeration",
                "All local Bonjour service types query"
            ),
        ]

        for item in cases {
            let annotation = try #require(LocalDiscoveryNameClassifier.classify(item.host, bundle: en.bundle))
            #expect(annotation.kind == .dnsSDMeta)
            #expect(annotation.badgeTitle == item.badge)
            #expect(annotation.detailTitle == item.detail)
            #expect(annotation.symbolName == "bonjour")
            #expect(
                annotation.tooltip ==
                    "\(item.expectedClean) — \(item.detail) (local LAN discovery only, not public internet)"
            )
            #expect(LocalDiscoveryNameClassifier.isLocalOrSpecialDiscoveryName(item.host))
            #expect(!LocalDiscoveryNameClassifier.isPublicOrUnicastDomainName(item.host))
        }
    }

    // MARK: - 3. Tier B & C — Curated Bonjour Services, Subtypes, and Instance Prefixes

    @Test("Classifies all curated Bonjour service types across aliases, TCP/UDP, subtypes, and instance prefixes")
    func classifiesCuratedBonjourServices() throws {
        let en = try makeBundle(language: "en", strings: [:])
        defer { en.teardown() }

        let cases: [(host: String, badge: String, detail: String, symbol: String)] = [
            (
                "  _companion-link._tcp.local. ",
                "Apple Continuity",
                "Apple Continuity & Companion Link",
                "laptopcomputer.and.iphone"
            ),
            ("_airplay._tcp.local", "AirPlay Video", "AirPlay video & screen mirroring", "airplayvideo"),
            ("_raop._tcp.local", "AirPlay Audio", "AirPlay remote audio streaming (RAOP)", "airplayaudio"),
            ("_airdrop._tcp.local", "AirDrop", "AirDrop peer discovery", "airplayaudio"),
            ("_rdlink._tcp.local", "Remote Dev Link", "Apple remote device development link", "iphone"),
            ("_remoted._tcp.local", "Remote Dev Link", "Apple remote device development link", "iphone"),
            ("_remote-pairing._tcp.local", "Remote Dev Link", "Apple remote device development link", "iphone"),
            ("_apple-mobdev2._tcp.local", "iOS Wireless Sync", "iPhone & iPad wireless sync and debug", "iphone"),
            ("_apple-mobdev._tcp.local", "iOS Wireless Sync", "iPhone & iPad wireless sync and debug", "iphone"),
            ("_hap._tcp.local", "HomeKit", "Apple HomeKit smart home accessory", "homekit"),
            ("_homekit._tcp.local", "HomeKit", "Apple HomeKit smart home accessory", "homekit"),
            ("_matter._tcp.local", "Matter / Thread", "Matter & Thread smart home mesh", "homekit"),
            ("_matterc._udp.local", "Matter / Thread", "Matter & Thread smart home mesh", "homekit"),
            ("_matterd._udp.local", "Matter / Thread", "Matter & Thread smart home mesh", "homekit"),
            ("_meshcop._udp.local", "Matter / Thread", "Matter & Thread smart home mesh", "homekit"),
            ("_sleep-proxy._udp.local", "Sleep Proxy", "Bonjour Wake-on-LAN sleep proxy", "moon.zzz"),
            ("_adisk._tcp.local", "Time Machine", "Time Machine wireless backup disk", "externaldrive.badge.timemachine"),
            ("_smb._tcp.local", "LAN File Sharing", "SMB / AFP local network file sharing", "folder.badge.person.crop"),
            ("_afpovertcp._tcp.local", "LAN File Sharing", "SMB / AFP local network file sharing", "folder.badge.person.crop"),
            ("_nfs._tcp.local", "LAN File Sharing", "SMB / AFP local network file sharing", "folder.badge.person.crop"),
            ("_webdav._tcp.local", "LAN File Sharing", "SMB / AFP local network file sharing", "folder.badge.person.crop"),
            ("_rfb._tcp.local", "Screen Sharing", "VNC / macOS screen sharing discovery", "rectangle.on.rectangle"),
            ("_eppc._tcp.local", "Remote Apple Events", "macOS Remote Apple Events (EPPC)", "macwindow"),
            ("_ipp._tcp.local", "AirPrint", "LAN printer & AirPrint discovery", "printer"),
            ("_ipps._tcp.local", "AirPrint", "LAN printer & AirPrint discovery", "printer"),
            ("_printer._tcp.local", "AirPrint", "LAN printer & AirPrint discovery", "printer"),
            ("_pdl-datastream._tcp.local", "AirPrint", "LAN printer & AirPrint discovery", "printer"),
            ("_riousbprint._tcp.local", "AirPrint", "LAN printer & AirPrint discovery", "printer"),
            ("_uscan._tcp.local", "AirScan", "LAN scanner & AirScan discovery", "scanner"),
            ("_uscans._tcp.local", "AirScan", "LAN scanner & AirScan discovery", "scanner"),
            ("_scanner._tcp.local", "AirScan", "LAN scanner & AirScan discovery", "scanner"),
            ("_googlecast._tcp.local", "Google Cast", "Chromecast media device discovery", "tv"),
            ("_spotify-connect._tcp.local", "Spotify Connect", "Spotify Connect speaker discovery", "hifispeaker"),
            ("_sonos._tcp.local", "Sonos", "Sonos speaker system discovery", "hifispeaker.2"),
            ("_esphomelib._tcp.local", "Smart Home", "Smart home LAN device discovery", "lightbulb"),
            ("_home-assistant._tcp.local", "Smart Home", "Smart home LAN device discovery", "lightbulb"),
            ("_miio._udp.local", "Smart Home", "Smart home LAN device discovery", "lightbulb"),
            ("_aqara._tcp.local", "Smart Home", "Smart home LAN device discovery", "lightbulb"),
            ("_http._tcp.local", "LAN Web Service", "Local HTTP web interface discovery", "globe"),
            ("_https._tcp.local", "LAN Web Service", "Local HTTP web interface discovery", "globe"),
            ("_ssh._tcp.local", "LAN SSH", "Local SSH server discovery", "terminal"),
            ("_sftp-ssh._tcp.local", "LAN SSH", "Local SSH server discovery", "terminal"),
        ]

        for item in cases {
            let annotation = try #require(LocalDiscoveryNameClassifier.classify(item.host, bundle: en.bundle))
            #expect(annotation.kind == .bonjourService)
            #expect(annotation.badgeTitle == item.badge)
            #expect(annotation.detailTitle == item.detail)
            #expect(annotation.symbolName == item.symbol)
        }

        // Subtype syntax does not treat `_sub` as an instance name.
        let subtype = try #require(
            LocalDiscoveryNameClassifier.classify("_universal._sub._ipp._tcp.local", bundle: en.bundle)
        )
        #expect(subtype.badgeTitle == "AirPrint")
        #expect(subtype.detailTitle == "LAN printer & AirPrint discovery")

        // Instance prefixes preserve original casing and append ` (<instance>)`.
        let airplayInstance = try #require(
            LocalDiscoveryNameClassifier.classify("LivingRoom._airplay._tcp.local", bundle: en.bundle)
        )
        #expect(airplayInstance.kind == .bonjourService)
        #expect(airplayInstance.badgeTitle == "AirPlay Video")
        #expect(airplayInstance.detailTitle == "AirPlay video & screen mirroring (LivingRoom)")
        #expect(
            airplayInstance.tooltip ==
                "LivingRoom._airplay._tcp.local — AirPlay video & screen mirroring (LivingRoom) (local LAN discovery only, not public internet)"
        )

        let raopInstance = try #require(
            LocalDiscoveryNameClassifier.classify("AA11BB@Studio._raop._tcp.local.", bundle: en.bundle)
        )
        #expect(raopInstance.badgeTitle == "AirPlay Audio")
        #expect(raopInstance.detailTitle == "AirPlay remote audio streaming (RAOP) (AA11BB@Studio)")
    }

    // MARK: - 4. Unknown Bonjour Service Fallback & `.local` Device Hostname

    @Test("Falls back cleanly for unknown Bonjour services and pure .local device hostnames")
    func classifiesUnknownBonjourAndDeviceHosts() throws {
        let en = try makeBundle(language: "en", strings: [:])
        defer { en.teardown() }

        let unknownTCP = try #require(
            LocalDiscoveryNameClassifier.classify("_custom-telemetry._tcp.local", bundle: en.bundle)
        )
        #expect(unknownTCP.kind == .bonjourService)
        #expect(unknownTCP.badgeTitle == "Bonjour Service")
        #expect(unknownTCP.detailTitle == "Bonjour LAN service (custom-telemetry · TCP)")
        #expect(unknownTCP.symbolName == "bonjour")

        let unknownWithInstance = try #require(
            LocalDiscoveryNameClassifier.classify("Studio-Node._custom-mesh._udp.local", bundle: en.bundle)
        )
        #expect(unknownWithInstance.kind == .bonjourService)
        #expect(unknownWithInstance.detailTitle == "Bonjour LAN service (custom-mesh · UDP) (Studio-Node)")

        let device = try #require(
            LocalDiscoveryNameClassifier.classify("Office-Phone.local.", bundle: en.bundle)
        )
        #expect(device.kind == .localDeviceHost)
        #expect(device.badgeTitle == "LAN Device")
        #expect(device.detailTitle == "Local network device hostname (mDNS)")
        #expect(device.symbolName == "desktopcomputer")
        #expect(
            device.tooltip ==
                "Office-Phone.local — Local network device hostname (mDNS) (local LAN discovery only, not public internet)"
        )

        let macDevice = try #require(
            LocalDiscoveryNameClassifier.classify("Studio-Mac.local", bundle: en.bundle)
        )
        #expect(macDevice.kind == .localDeviceHost)
    }

    // MARK: - 5. Special System DNS Names (`.arpa`)

    @Test("Classifies special .arpa DNS probes with non-LAN-only tooltips")
    func classifiesSpecialSystemDNS() throws {
        let en = try makeBundle(language: "en", strings: [:])
        defer { en.teardown() }

        let ddr = try #require(LocalDiscoveryNameClassifier.classify("_dns.resolver.arpa", bundle: en.bundle))
        #expect(ddr.kind == .specialSystemDNS)
        #expect(ddr.badgeTitle == "Encrypted DNS Probe")
        #expect(ddr.detailTitle == "Discovery of Designated Resolvers (DDR)")
        #expect(ddr.symbolName == "lock.shield")
        #expect(ddr.tooltip == "_dns.resolver.arpa — Discovery of Designated Resolvers (DDR)")

        let ptrV4 = try #require(LocalDiscoveryNameClassifier.classify("1.0.168.192.in-addr.arpa", bundle: en.bundle))
        #expect(ptrV4.kind == .specialSystemDNS)
        #expect(ptrV4.badgeTitle == "Reverse DNS")
        #expect(ptrV4.detailTitle == "Reverse IP-to-hostname lookup (PTR)")
        #expect(ptrV4.symbolName == "arrow.uturn.backward")
        #expect(ptrV4.tooltip == "1.0.168.192.in-addr.arpa — Reverse IP-to-hostname lookup (PTR)")

        let ptrV6 = try #require(LocalDiscoveryNameClassifier.classify("1.0.0.0.ip6.arpa.", bundle: en.bundle))
        #expect(ptrV6.kind == .specialSystemDNS)
        #expect(ptrV6.badgeTitle == "Reverse DNS")

        let nat64 = try #require(LocalDiscoveryNameClassifier.classify("ipv4only.arpa", bundle: en.bundle))
        #expect(nat64.kind == .specialSystemDNS)
        #expect(nat64.badgeTitle == "IPv4 Synthesis Probe")
        #expect(nat64.detailTitle == "NAT64 / DNS64 prefix discovery (RFC 7050)")
        #expect(nat64.symbolName == "network")
        #expect(nat64.tooltip == "ipv4only.arpa — NAT64 / DNS64 prefix discovery (RFC 7050)")

        let homeApex = try #require(LocalDiscoveryNameClassifier.classify("home.arpa.", bundle: en.bundle))
        #expect(homeApex.kind == .specialSystemDNS)
        #expect(homeApex.badgeTitle == "Home LAN")
        #expect(homeApex.detailTitle == "Residential home network domain (RFC 8375)")
        #expect(homeApex.symbolName == "house")
        #expect(homeApex.tooltip == "home.arpa — Residential home network domain (RFC 8375)")
        #expect(!LocalDiscoveryNameClassifier.isPublicOrUnicastDomainName("home.arpa"))

        let homeDevice = try #require(LocalDiscoveryNameClassifier.classify("nas.home.arpa", bundle: en.bundle))
        #expect(homeDevice.kind == .localDeviceHost)
        #expect(homeDevice.badgeTitle == "Home LAN")
        #expect(homeDevice.detailTitle == "Home network device hostname (RFC 8375)")
        #expect(homeDevice.symbolName == "house")
        #expect(
            homeDevice.tooltip ==
                "nas.home.arpa — Home network device hostname (RFC 8375) (local LAN discovery only, not public internet)"
        )
        #expect(!LocalDiscoveryNameClassifier.isPublicOrUnicastDomainName("nas.home.arpa"))
    }

    // MARK: - 6. Custom Bundle Localization & Search Haystack

    @Test("Resolves custom bundle translations and includes semantic annotations in search haystacks")
    func supportsLocalizedBundlesAndSearchHaystack() throws {
        let zh = try makeBundle(
            language: "zh-Hans",
            strings: [
                "Apple Continuity": "Apple 连续互通",
                "Apple Continuity & Companion Link": "Apple 连续互通与设备协同",
                "%@ — %@ (local LAN discovery only, not public internet)": "%@ — %@（仅限本地局域网发现，不访问公网）",
                "Bonjour Service": "Bonjour 服务",
                "Bonjour LAN service (%@ · %@)": "Bonjour 局域网服务 (%@ · %@)",
            ]
        )
        defer { zh.teardown() }

        let zhContinuity = try #require(
            LocalDiscoveryNameClassifier.classify("_companion-link._tcp.local", bundle: zh.bundle)
        )
        #expect(zhContinuity.badgeTitle == "Apple 连续互通")
        #expect(zhContinuity.detailTitle == "Apple 连续互通与设备协同")
        #expect(
            zhContinuity.tooltip ==
                "_companion-link._tcp.local — Apple 连续互通与设备协同（仅限本地局域网发现，不访问公网）"
        )

        let zhFallback = try #require(
            LocalDiscoveryNameClassifier.classify("_custom._udp.local", bundle: zh.bundle)
        )
        #expect(zhFallback.badgeTitle == "Bonjour 服务")
        #expect(zhFallback.detailTitle == "Bonjour 局域网服务 (custom · UDP)")

        let session = makeSession(
            host: "_companion-link._tcp.local",
            src: ("192.168.1.10", 5_353),
            dst: ("224.0.0.251", 5_353),
            protos: [.udp, .mdns]
        )
        #expect(SessionSearchField.host.haystack(in: session, bundle: zh.bundle).contains("连续互通"))
        #expect(SessionSearchField.allFields.haystack(in: session, bundle: zh.bundle).contains("设备协同"))
        #expect(!SessionSearchField.client.haystack(in: session, bundle: zh.bundle).contains("连续互通"))

        let en = try makeBundle(language: "en", strings: [:])
        defer { en.teardown() }
        #expect(SessionSearchField.host.haystack(in: session, bundle: en.bundle).contains("continuity"))
        #expect(SessionSearchField.allFields.haystack(in: session, bundle: en.bundle).contains("companion link"))
    }

    // MARK: - 7. Coordinator Grouping, Multicast Filtering, IP Strictness, and Hidden-Local-Name Persistence

    @MainActor
    @Test("Separates public domains, local discovery groups, and strict IP hosts while persisting hidden local names")
    func coordinatorSeparationAndVisibilityPersistence() throws {
        let suiteAName = "tracexy.test.bonjour.projectA.\(UUID().uuidString)"
        let suiteBName = "tracexy.test.bonjour.projectB.\(UUID().uuidString)"
        let defaultsA = try #require(UserDefaults(suiteName: suiteAName))
        let defaultsB = try #require(UserDefaults(suiteName: suiteBName))
        defer {
            defaultsA.removePersistentDomain(forName: suiteAName)
            defaultsB.removePersistentDomain(forName: suiteBName)
        }

        let coordinator = MainContentCoordinator(settingsDefaults: defaultsA)
        coordinator.sessions = [
            makeSession(
                processName: "Safari",
                host: "api.example.com",
                src: ("192.168.1.10", 51_000),
                dst: ("93.184.216.34", 443),
                protos: [.tcp, .tls, .http2],
                dnsAnswers: ["93.184.216.34"]
            ),
            makeSession(
                processName: "mDNSResponder",
                host: "_companion-link._tcp.local",
                src: ("192.168.1.10", 5_353),
                dst: ("224.0.0.251", 5_353),
                protos: [.udp, .mdns]
            ),
            makeSession(
                processName: "mDNSResponder",
                host: "_companion-link._tcp.local",
                src: ("192.168.1.11", 5_353),
                dst: ("224.0.0.251", 5_353),
                protos: [.udp, .mdns]
            ),
            makeSession(
                processName: "mDNSResponder",
                host: "Office-Phone.local",
                src: ("fe80::10", 5_353),
                dst: ("ff02::fb", 5_353),
                protos: [.udp, .mdns],
                dnsAnswers: ["192.168.1.42", "CNAME alias.local"]
            ),
            makeSession(
                processName: "mDNSResponder",
                host: "_dns.resolver.arpa",
                src: ("192.168.1.10", 52_000),
                dst: ("192.168.1.1", 53),
                protos: [.udp, .dns],
                dnsAnswers: ["1.1.1.1"]
            ),
            makeSession(
                processName: "curl",
                host: "203.0.113.10",
                src: ("192.168.1.10", 53_000),
                dst: ("203.0.113.10", 443),
                protos: [.tcp]
            ),
            makeSession(
                processName: "curl",
                host: "2001:db8::5",
                src: ("fe80::10", 53_001),
                dst: ("2001:db8::5", 443),
                protos: [.tcp]
            ),
            makeSession(
                processName: nil,
                host: "—",
                src: ("—", 0),
                dst: ("—", 0),
                protos: [.arp]
            ),
        ]

        // 1. Public Domains excludes `.local`, `.arpa`, IPs, and `"—"`.
        #expect(coordinator.domainGroups.map(\.domain) == ["api.example.com"])

        // 2. Source summary counts ONLY public domains.
        let summary = MainContentCoordinator.sourceSummary(of: coordinator.sessions)
        #expect(summary.domains == 1)

        // 3. IP Hosts accepts ONLY valid IPv4/IPv6 literals (never `"—"`, `.local`, or `.arpa`).
        #expect(Set(coordinator.ipHosts.map(\.name)) == ["203.0.113.10", "2001:db8::5"])

        // 4. Local discovery groups sort by count desc then name asc, and strip multicast + CNAME.
        let localGroups = coordinator.localDiscoveryGroups
        #expect(localGroups.map(\.name) == [
            "_companion-link._tcp.local",
            "Office-Phone.local",
            "_dns.resolver.arpa",
        ])
        #expect(localGroups[0].count == 2)
        #expect(localGroups[0].ips == ["192.168.1.10", "192.168.1.11"])
        #expect(!localGroups[0].ips.contains("224.0.0.251"))

        #expect(localGroups[1].count == 1)
        #expect(localGroups[1].ips == ["192.168.1.42", "fe80::10"])
        #expect(!localGroups[1].ips.contains("ff02::fb"))
        #expect(!localGroups[1].ips.contains("CNAME alias.local"))

        #expect(localGroups[2].count == 1)
        #expect(localGroups[2].ips == ["1.1.1.1", "192.168.1.1"])

        // 5. Hiding local names routes via `hideSourceHost`/`isSourceHostHidden` and persists per Project.
        coordinator.hideSourceHost("Office-Phone.local")
        #expect(coordinator.isSourceLocalNameHidden("Office-Phone.local"))
        #expect(coordinator.isSourceHostHidden("Office-Phone.local"))
        #expect(!coordinator.isSourceDomainHidden("Office-Phone.local"))
        #expect(!coordinator.isSourceIPHidden("Office-Phone.local"))
        #expect(SourceVisibilityPreferences.loadLocalNames(defaults: defaultsA) == ["Office-Phone.local"])

        // Backward-compatible 4-argument `persist` leaves persisted local names untouched.
        SourceVisibilityPreferences.persist(
            apps: [],
            domains: ["api.example.com"],
            ips: [],
            defaults: defaultsA
        )
        #expect(SourceVisibilityPreferences.loadLocalNames(defaults: defaultsA) == ["Office-Phone.local"])

        // Switching `activeProjectDefaults` reloads hidden local names for the new Project.
        coordinator.activeProjectDefaults = defaultsB
        #expect(coordinator.hiddenSourceLocalNames.isEmpty)
        coordinator.hideSourceLocalName("_dns.resolver.arpa")
        #expect(SourceVisibilityPreferences.loadLocalNames(defaults: defaultsB) == ["_dns.resolver.arpa"])

        // Switching back to Project A restores Project A's hidden local names.
        coordinator.activeProjectDefaults = defaultsA
        #expect(coordinator.hiddenSourceLocalNames == ["Office-Phone.local"])

        coordinator.restoreHiddenSourceLocalNames()
        #expect(coordinator.hiddenSourceLocalNames.isEmpty)
        #expect(SourceVisibilityPreferences.loadLocalNames(defaults: defaultsA).isEmpty)
    }

    // MARK: - 8. Round 3 — FrameAddressNames IPv6 Normalization, Project Runtime Isolation, and IPv6 Deduplication

    @MainActor
    @Test("FrameAddressNames.resolver normalizes uncompressed and compressed IPv6 addresses across sessions and capture records")
    func frameAddressNamesNormalizesIPv6Keys() {
        let book = AddressNameBook()
        let uncompressed = "fd00:0060:0000:0000:0000:0000:0000:0001"
        let compressed = "fd00:60::1"

        let dnsSession = makeSession(
            processName: "mDNSResponder",
            host: "nas.home.arpa",
            src: ("192.0.2.10", 53_000),
            dst: ("192.0.2.1", 53),
            protos: [.udp, .dns],
            dnsAnswers: [compressed]
        )
        var sessionWithBindings = dnsSession
        sessionWithBindings.dnsResolvedBindings = [
            DNSAddressBinding(ip: compressed, hostname: "nas.home.arpa"),
        ]

        let resolverFromSession = FrameAddressNames.resolver(sessions: [sessionWithBindings], book: book)
        #expect(resolverFromSession(compressed) == "nas.home.arpa")
        #expect(resolverFromSession(uncompressed) == "nas.home.arpa")
        #expect(resolverFromSession(uncompressed.uppercased()) == "nas.home.arpa")

        let nrbName = CaptureBoundedText(bytes: Array("TestPhone.local".utf8), declaredLength: "TestPhone.local".utf8.count)
        let resolverFromCaptureRecord = FrameAddressNames.resolver(
            sessions: [],
            book: book,
            captureFileRecords: [
                CaptureNameResolutionRecord(address: uncompressed, name: nrbName),
            ]
        )
        #expect(resolverFromCaptureRecord(compressed) == "TestPhone.local")
        #expect(resolverFromCaptureRecord(uncompressed) == "TestPhone.local")
    }

    @MainActor
    @Test("hiddenSourceLocalNames parks and restores independently across Project runtimes and seeds default keys")
    func hiddenSourceLocalNamesProjectRuntimeIsolation() throws {
        // 1. Safe default allowlist includes hiddenSourceLocalNames so new Projects never fall through to .standard.
        let safeDefaults = ProjectSettingsSeeding.safeDefaultValues()
        let seededLocalNames = try #require(safeDefaults[ProjectScopedSettingsKeys.hiddenSourceLocalNames] as? [String])
        #expect(seededLocalNames.isEmpty)

        // 2. Two independent ProjectRuntimeStates park and adopt hiddenSourceLocalNames symmetrically.
        let suiteAName = "tracexy.test.r3.runtimeA.\(UUID().uuidString)"
        let suiteBName = "tracexy.test.r3.runtimeB.\(UUID().uuidString)"
        let defaultsA = try #require(UserDefaults(suiteName: suiteAName))
        let defaultsB = try #require(UserDefaults(suiteName: suiteBName))
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("tracexy-r3-runtime-test-\(UUID().uuidString)", isDirectory: true)
        defer {
            defaultsA.removePersistentDomain(forName: suiteAName)
            defaultsB.removePersistentDomain(forName: suiteBName)
            try? FileManager.default.removeItem(at: tempDir)
        }

        let coordinator = MainContentCoordinator(settingsDefaults: defaultsA)
        let projectA = UUID()
        let projectB = UUID()
        let layoutA = WorkspaceLayoutPreferences(defaults: defaultsA)
        let layoutB = WorkspaceLayoutPreferences(defaults: defaultsB)

        let runtimeA = ProjectRuntimeState(
            projectID: projectA,
            location: nil,
            settingsDefaults: defaultsA,
            layoutPreferences: layoutA,
            workspaces: WorkspaceStore(maxWorkspaces: 4, layoutPreferences: layoutA, defaults: defaultsA),
            sessionStore: nil,
            liveCaptureSpool: LiveCaptureSpool(directory: tempDir.appendingPathComponent("spoolA", isDirectory: true)),
            capturesDirectory: nil,
            captureInterface: "en0"
        )
        runtimeA.loadPreferenceBackedState()

        let runtimeB = ProjectRuntimeState(
            projectID: projectB,
            location: nil,
            settingsDefaults: defaultsB,
            layoutPreferences: layoutB,
            workspaces: WorkspaceStore(maxWorkspaces: 4, layoutPreferences: layoutB, defaults: defaultsB),
            sessionStore: nil,
            liveCaptureSpool: LiveCaptureSpool(directory: tempDir.appendingPathComponent("spoolB", isDirectory: true)),
            capturesDirectory: nil,
            captureInterface: "en0"
        )
        runtimeB.loadPreferenceBackedState()

        coordinator.adoptProjectRuntime(runtimeA)
        coordinator.hideSourceLocalName("TestPhone.local")
        #expect(coordinator.hiddenSourceLocalNames == ["TestPhone.local"])

        coordinator.parkActiveProjectRuntime()
        #expect(runtimeA.hiddenSourceLocalNames == ["TestPhone.local"])

        coordinator.adoptProjectRuntime(runtimeB)
        #expect(coordinator.hiddenSourceLocalNames.isEmpty)
        coordinator.hideSourceLocalName("nas.home.arpa")
        #expect(coordinator.hiddenSourceLocalNames == ["nas.home.arpa"])

        coordinator.parkActiveProjectRuntime()
        #expect(runtimeB.hiddenSourceLocalNames == ["nas.home.arpa"])

        coordinator.adoptProjectRuntime(runtimeA)
        #expect(coordinator.hiddenSourceLocalNames == ["TestPhone.local"])
        #expect(SourceVisibilityPreferences.loadLocalNames(defaults: defaultsA) == ["TestPhone.local"])
        #expect(SourceVisibilityPreferences.loadLocalNames(defaults: defaultsB) == ["nas.home.arpa"])
    }

    @MainActor
    @Test("localDiscoveryGroups deduplicates compressed and uncompressed IPv6 addresses and includes RFC 8375 home.arpa")
    func localDiscoveryGroupsIPv6DedupAndHomeArpa() throws {
        let suiteName = "tracexy.test.r3.ipv6dedup.\(UUID().uuidString)"
        let defaults = try #require(UserDefaults(suiteName: suiteName))
        defer { defaults.removePersistentDomain(forName: suiteName) }

        let coordinator = MainContentCoordinator(settingsDefaults: defaults)
        coordinator.sessions = [
            makeSession(
                processName: "mDNSResponder",
                host: "TestPhone.local",
                src: ("fd00:0060:0000:0000:0000:0000:0000:0001", 5_353),
                dst: ("ff02::fb", 5_353),
                protos: [.udp, .mdns],
                dnsAnswers: ["fd00:0060:0000:0000:0000:0000:0000:0001", "fd00:60::1"]
            ),
            makeSession(
                processName: "mDNSResponder",
                host: "TestPhone.local",
                src: ("fd00:60::1", 5_353),
                dst: ("ff02::fb", 5_353),
                protos: [.udp, .mdns]
            ),
            makeSession(
                processName: "mDNSResponder",
                host: "nas.home.arpa",
                src: ("192.0.2.10", 53_100),
                dst: ("fd00:0060:0000:0000:0000:0000:0000:0002", 443),
                protos: [.tcp],
                dnsAnswers: ["fd00:60::2"]
            ),
            makeSession(
                processName: "mDNSResponder",
                host: "home.arpa",
                src: ("192.0.2.10", 53_101),
                dst: ("192.0.2.1", 53),
                protos: [.udp, .dns]
            ),
        ]

        let groups = coordinator.localDiscoveryGroups
        #expect(Set(groups.map(\.name)) == ["TestPhone.local", "nas.home.arpa", "home.arpa"])

        let phoneGroup = try #require(groups.first { $0.name == "TestPhone.local" })
        #expect(phoneGroup.count == 2)
        #expect(phoneGroup.ips == ["fd00:60::1"])

        let nasGroup = try #require(groups.first { $0.name == "nas.home.arpa" })
        #expect(nasGroup.count == 1)
        #expect(nasGroup.ips == ["fd00:60::2"])
        #expect(nasGroup.symbolName == "house")

        let homeApexGroup = try #require(groups.first { $0.name == "home.arpa" })
        #expect(homeApexGroup.count == 1)
        #expect(homeApexGroup.ips == ["192.0.2.1"])
        #expect(homeApexGroup.symbolName == "house")

        #expect(coordinator.domainGroups.isEmpty)
    }

    // MARK: - Helpers

    private struct TempBundle {
        let bundle: Bundle
        let teardown: () -> Void
    }

    private func makeBundle(language: String, strings: [String: String]) throws -> TempBundle {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("tracexy-local-discovery-lproj-\(UUID().uuidString)", isDirectory: true)
        let lprojDir = tempDir.appendingPathComponent("\(language).lproj", isDirectory: true)
        try FileManager.default.createDirectory(at: lprojDir, withIntermediateDirectories: true)
        let plist = try PropertyListSerialization.data(
            fromPropertyList: strings,
            format: .binary,
            options: 0
        )
        try plist.write(to: lprojDir.appendingPathComponent("Localizable.strings"))
        guard let bundle = Bundle(url: lprojDir) else {
            try? FileManager.default.removeItem(at: tempDir)
            throw NSError(domain: "LocalDiscoveryNameClassifierTests", code: 1)
        }
        return TempBundle(bundle: bundle) {
            try? FileManager.default.removeItem(at: tempDir)
        }
    }

    private func makeSession(
        processName: String? = "mDNSResponder",
        host: String,
        src: (String, Int) = ("192.168.1.10", 5_353),
        dst: (String, Int) = ("224.0.0.251", 5_353),
        protos: [ProtocolKind] = [.udp, .mdns],
        dnsAnswers: [String] = []
    )
        -> SessionSummary
    {
        let srcEndpoint = src.0 == "—" ? "—" : "\(src.0):\(src.1)"
        let dstEndpoint = dst.0 == "—" ? "—" : "\(dst.0):\(dst.1)"
        return SessionSummary(
            id: UUID(),
            startTime: Date(timeIntervalSince1970: 1_700_000_000),
            duration: 0.01,
            processName: processName,
            host: host,
            sourceEndpoint: srcEndpoint,
            destinationEndpoint: dstEndpoint,
            sourceEndpointValue: src.0 == "—" ? nil : IPEndpoint(ip: src.0, port: UInt16(src.1)),
            destinationEndpointValue: dst.0 == "—" ? nil : IPEndpoint(ip: dst.0, port: UInt16(dst.1)),
            protocolStack: protos,
            status: .ok,
            latencyMilliseconds: nil,
            bytesUp: 64,
            bytesDown: 64,
            dnsAnswers: dnsAnswers
        )
    }
}
