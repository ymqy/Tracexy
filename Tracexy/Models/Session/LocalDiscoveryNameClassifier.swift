import Foundation

// MARK: - LocalDiscoveryKind

/// Broad semantic category of a local-network discovery name or special-use
/// system DNS probe (RFC 6762 mDNS, RFC 6763 DNS-SD, RFC 7050 / RFC 9462 `.arpa`).
nonisolated enum LocalDiscoveryKind: String, Equatable, Hashable, Sendable {
    case dnsSDMeta
    case bonjourService
    case localDeviceHost
    case specialSystemDNS
}

// MARK: - LocalDiscoveryAnnotation

/// Human-readable semantic annotation attached to a local discovery name or
/// special-use system DNS host so the UI can explain what it means without
/// polluting public Internet domain lists.
nonisolated struct LocalDiscoveryAnnotation: Equatable, Hashable, Sendable {
    let kind: LocalDiscoveryKind
    let badgeTitle: String
    let detailTitle: String
    let symbolName: String
    let tooltip: String
}

// MARK: - LocalDiscoveryNameClassifier

/// Pure classifier for mDNS (`.local`), DNS-SD (`_service._tcp.local`,
/// `lb._dns-sd._udp.*`), and special-use `.arpa` system DNS names.
nonisolated enum LocalDiscoveryNameClassifier {
    // MARK: Internal

    /// Classifies a raw host string if it is a local-discovery or special system
    /// DNS name; returns `nil` for public domains, IP literals, empty strings,
    /// and the missing-host placeholder `"—"`.
    static func classify(_ rawHost: String, bundle: Bundle = .main) -> LocalDiscoveryAnnotation? {
        let cleanHost = normalizedHost(rawHost)
        guard !cleanHost.isEmpty, cleanHost != "—" else {
            return nil
        }
        guard IPAddressValue(parsing: cleanHost) == nil else {
            return nil
        }

        let lower = cleanHost.lowercased()

        // Tier A — DNS-SD meta queries (checked before `.arpa` so
        // `lb._dns-sd._udp.0.1.168.192.in-addr.arpa` classifies as DNS-SD).
        if let meta = classifyDNSSDMeta(lower: lower, cleanHost: cleanHost, bundle: bundle) {
            return meta
        }

        // Tier B & C — Bonjour services (`_<svc>._(tcp|udp).local`, subtypes,
        // and `<Instance>._<svc>._(tcp|udp).local`).
        if let service = classifyBonjourService(cleanHost: cleanHost, bundle: bundle) {
            return service
        }

        // Pure `.local` device hostname (excluding underscore-prefixed or
        // `._tcp.local` / `._udp.local` names).
        if let device = classifyLocalDeviceHost(lower: lower, cleanHost: cleanHost, bundle: bundle) {
            return device
        }

        // Special-use system DNS names under `.arpa`.
        if let special = classifySpecialSystemDNS(lower: lower, cleanHost: cleanHost, bundle: bundle) {
            return special
        }

        return nil
    }

    /// True when `rawHost` is an mDNS / DNS-SD local discovery name or a
    /// special-use system `.arpa` DNS name.
    static func isLocalOrSpecialDiscoveryName(_ rawHost: String) -> Bool {
        classify(rawHost) != nil
    }

    /// True when `rawHost` is a domain name that belongs in the public / unicast
    /// Domains list (i.e. a domain name that is NOT local discovery or `.arpa`).
    static func isPublicOrUnicastDomainName(_ rawHost: String) -> Bool {
        MainContentCoordinator.isDomainName(rawHost) && !isLocalOrSpecialDiscoveryName(rawHost)
    }

    // MARK: Private

    private static func normalizedHost(_ rawHost: String) -> String {
        var trimmed = rawHost.trimmingCharacters(in: .whitespacesAndNewlines)
        while trimmed.hasSuffix(".") {
            trimmed.removeLast()
        }
        return trimmed
    }

    private static func makeAnnotation(
        kind: LocalDiscoveryKind,
        cleanHost: String,
        badgeTitle: String,
        detailTitle: String,
        symbolName: String,
        bundle: Bundle
    )
        -> LocalDiscoveryAnnotation
    {
        let tooltip: String = switch kind {
        case .dnsSDMeta,
             .bonjourService,
             .localDeviceHost:
            String(
                format: String(
                    localized: "%@ — %@ (local LAN discovery only, not public internet)",
                    bundle: bundle
                ),
                cleanHost,
                detailTitle
            )
        case .specialSystemDNS:
            String(
                format: String(localized: "%@ — %@", bundle: bundle),
                cleanHost,
                detailTitle
            )
        }

        return LocalDiscoveryAnnotation(
            kind: kind,
            badgeTitle: badgeTitle,
            detailTitle: detailTitle,
            symbolName: symbolName,
            tooltip: tooltip
        )
    }

    private static func classifyDNSSDMeta(
        lower: String,
        cleanHost: String,
        bundle: Bundle
    )
        -> LocalDiscoveryAnnotation?
    {
        if hasNonEmptySuffix(lower, afterPrefix: "lb._dns-sd._udp.") {
            return makeAnnotation(
                kind: .dnsSDMeta,
                cleanHost: cleanHost,
                badgeTitle: String(localized: "Browse Domain Probe", bundle: bundle),
                detailTitle: String(localized: "DNS-SD legacy browse domain enumeration", bundle: bundle),
                symbolName: "bonjour",
                bundle: bundle
            )
        }
        if hasNonEmptySuffix(lower, afterPrefix: "b._dns-sd._udp.")
            || hasNonEmptySuffix(lower, afterPrefix: "db._dns-sd._udp.")
        {
            return makeAnnotation(
                kind: .dnsSDMeta,
                cleanHost: cleanHost,
                badgeTitle: String(localized: "Browse Domain Query", bundle: bundle),
                detailTitle: String(localized: "DNS-SD browse domain discovery", bundle: bundle),
                symbolName: "bonjour",
                bundle: bundle
            )
        }
        if hasNonEmptySuffix(lower, afterPrefix: "r._dns-sd._udp.")
            || hasNonEmptySuffix(lower, afterPrefix: "dr._dns-sd._udp.")
        {
            return makeAnnotation(
                kind: .dnsSDMeta,
                cleanHost: cleanHost,
                badgeTitle: String(localized: "Registration Domain", bundle: bundle),
                detailTitle: String(localized: "DNS-SD registration domain discovery", bundle: bundle),
                symbolName: "bonjour",
                bundle: bundle
            )
        }
        if hasNonEmptySuffix(lower, afterPrefix: "_services._dns-sd._udp.") {
            return makeAnnotation(
                kind: .dnsSDMeta,
                cleanHost: cleanHost,
                badgeTitle: String(localized: "Service Enumeration", bundle: bundle),
                detailTitle: String(localized: "All local Bonjour service types query", bundle: bundle),
                symbolName: "bonjour",
                bundle: bundle
            )
        }
        return nil
    }

    private static func classifyBonjourService(
        cleanHost: String,
        bundle: Bundle
    )
        -> LocalDiscoveryAnnotation?
    {
        let beforeTransport: Substring
        let protoUpper: String
        if let prefix = stripASCIICaseInsensitiveSuffix(cleanHost, suffix: "._tcp.local") {
            beforeTransport = prefix
            protoUpper = "TCP"
        } else if let prefix = stripASCIICaseInsensitiveSuffix(cleanHost, suffix: "._udp.local") {
            beforeTransport = prefix
            protoUpper = "UDP"
        } else {
            return nil
        }

        guard !beforeTransport.isEmpty else {
            return nil
        }

        let serviceLabel: Substring
        let instancePrefix: String?
        if let dotIndex = beforeTransport.lastIndex(of: ".") {
            serviceLabel = beforeTransport[beforeTransport.index(after: dotIndex)...]
            let leading = beforeTransport[..<dotIndex]
            let leadingLower = leading.lowercased()
            if leading.isEmpty || leadingLower == "_sub" || leadingLower.hasSuffix("._sub") {
                instancePrefix = nil
            } else {
                instancePrefix = String(leading)
            }
        } else {
            serviceLabel = beforeTransport
            instancePrefix = nil
        }

        guard serviceLabel.hasPrefix("_"), serviceLabel.count > 1 else {
            return nil
        }

        let serviceKey = serviceLabel.lowercased()
        let badgeTitle: String
        var detailTitle: String
        let symbolName: String

        if let curated = curatedBonjourService(for: serviceKey, bundle: bundle) {
            badgeTitle = curated.badgeTitle
            detailTitle = curated.detailTitle
            symbolName = curated.symbolName
        } else {
            let serviceName = String(serviceKey.dropFirst())
            badgeTitle = String(localized: "Bonjour Service", bundle: bundle)
            detailTitle = String(
                format: String(localized: "Bonjour LAN service (%@ · %@)", bundle: bundle),
                serviceName,
                protoUpper
            )
            symbolName = "bonjour"
        }

        if let instancePrefix {
            detailTitle += " (\(instancePrefix))"
        }

        return makeAnnotation(
            kind: .bonjourService,
            cleanHost: cleanHost,
            badgeTitle: badgeTitle,
            detailTitle: detailTitle,
            symbolName: symbolName,
            bundle: bundle
        )
    }

    private static func curatedBonjourService(
        for serviceKey: String,
        bundle: Bundle
    )
        -> (badgeTitle: String, detailTitle: String, symbolName: String)?
    {
        switch serviceKey {
        case "_companion-link":
            (
                String(localized: "Apple Continuity", bundle: bundle),
                String(localized: "Apple Continuity & Companion Link", bundle: bundle),
                "laptopcomputer.and.iphone"
            )
        case "_airplay":
            (
                String(localized: "AirPlay Video", bundle: bundle),
                String(localized: "AirPlay video & screen mirroring", bundle: bundle),
                "airplayvideo"
            )
        case "_raop":
            (
                String(localized: "AirPlay Audio", bundle: bundle),
                String(localized: "AirPlay remote audio streaming (RAOP)", bundle: bundle),
                "airplayaudio"
            )
        case "_airdrop":
            (
                String(localized: "AirDrop", bundle: bundle),
                String(localized: "AirDrop peer discovery", bundle: bundle),
                "airplayaudio"
            )
        case "_rdlink",
             "_remoted",
             "_remote-pairing":
            (
                String(localized: "Remote Dev Link", bundle: bundle),
                String(localized: "Apple remote device development link", bundle: bundle),
                "iphone"
            )
        case "_apple-mobdev2",
             "_apple-mobdev":
            (
                String(localized: "iOS Wireless Sync", bundle: bundle),
                String(localized: "iPhone & iPad wireless sync and debug", bundle: bundle),
                "iphone"
            )
        case "_hap",
             "_homekit":
            (
                String(localized: "HomeKit", bundle: bundle),
                String(localized: "Apple HomeKit smart home accessory", bundle: bundle),
                "homekit"
            )
        case "_matter",
             "_matterc",
             "_matterd",
             "_meshcop":
            (
                String(localized: "Matter / Thread", bundle: bundle),
                String(localized: "Matter & Thread smart home mesh", bundle: bundle),
                "homekit"
            )
        case "_sleep-proxy":
            (
                String(localized: "Sleep Proxy", bundle: bundle),
                String(localized: "Bonjour Wake-on-LAN sleep proxy", bundle: bundle),
                "moon.zzz"
            )
        case "_adisk":
            (
                String(localized: "Time Machine", bundle: bundle),
                String(localized: "Time Machine wireless backup disk", bundle: bundle),
                "externaldrive.badge.timemachine"
            )
        case "_smb",
             "_afpovertcp",
             "_nfs",
             "_webdav":
            (
                String(localized: "LAN File Sharing", bundle: bundle),
                String(localized: "SMB / AFP local network file sharing", bundle: bundle),
                "folder.badge.person.crop"
            )
        case "_rfb":
            (
                String(localized: "Screen Sharing", bundle: bundle),
                String(localized: "VNC / macOS screen sharing discovery", bundle: bundle),
                "rectangle.on.rectangle"
            )
        case "_eppc":
            (
                String(localized: "Remote Apple Events", bundle: bundle),
                String(localized: "macOS Remote Apple Events (EPPC)", bundle: bundle),
                "macwindow"
            )
        case "_ipp",
             "_ipps",
             "_printer",
             "_pdl-datastream",
             "_riousbprint":
            (
                String(localized: "AirPrint", bundle: bundle),
                String(localized: "LAN printer & AirPrint discovery", bundle: bundle),
                "printer"
            )
        case "_uscan",
             "_uscans",
             "_scanner":
            (
                String(localized: "AirScan", bundle: bundle),
                String(localized: "LAN scanner & AirScan discovery", bundle: bundle),
                "scanner"
            )
        case "_googlecast":
            (
                String(localized: "Google Cast", bundle: bundle),
                String(localized: "Chromecast media device discovery", bundle: bundle),
                "tv"
            )
        case "_spotify-connect":
            (
                String(localized: "Spotify Connect", bundle: bundle),
                String(localized: "Spotify Connect speaker discovery", bundle: bundle),
                "hifispeaker"
            )
        case "_sonos":
            (
                String(localized: "Sonos", bundle: bundle),
                String(localized: "Sonos speaker system discovery", bundle: bundle),
                "hifispeaker.2"
            )
        case "_esphomelib",
             "_home-assistant",
             "_miio",
             "_aqara":
            (
                String(localized: "Smart Home", bundle: bundle),
                String(localized: "Smart home LAN device discovery", bundle: bundle),
                "lightbulb"
            )
        case "_http",
             "_https":
            (
                String(localized: "LAN Web Service", bundle: bundle),
                String(localized: "Local HTTP web interface discovery", bundle: bundle),
                "globe"
            )
        case "_ssh",
             "_sftp-ssh":
            (
                String(localized: "LAN SSH", bundle: bundle),
                String(localized: "Local SSH server discovery", bundle: bundle),
                "terminal"
            )
        default:
            nil
        }
    }

    private static func classifyLocalDeviceHost(
        lower: String,
        cleanHost: String,
        bundle: Bundle
    )
        -> LocalDiscoveryAnnotation?
    {
        guard lower.hasSuffix(".local"),
              !lower.hasPrefix("_"),
              !lower.hasSuffix("._tcp.local"),
              !lower.hasSuffix("._udp.local") else
        {
            return nil
        }
        let hostPrefix = lower.dropLast(".local".count)
        guard !hostPrefix.isEmpty, !hostPrefix.hasSuffix(".") else {
            return nil
        }
        return makeAnnotation(
            kind: .localDeviceHost,
            cleanHost: cleanHost,
            badgeTitle: String(localized: "LAN Device", bundle: bundle),
            detailTitle: String(localized: "Local network device hostname (mDNS)", bundle: bundle),
            symbolName: "desktopcomputer",
            bundle: bundle
        )
    }

    private static func classifySpecialSystemDNS(
        lower: String,
        cleanHost: String,
        bundle: Bundle
    )
        -> LocalDiscoveryAnnotation?
    {
        if lower == "_dns.resolver.arpa"
            || hasNonEmptyPrefix(lower, beforeSuffix: ".resolver.arpa")
        {
            return makeAnnotation(
                kind: .specialSystemDNS,
                cleanHost: cleanHost,
                badgeTitle: String(localized: "Encrypted DNS Probe", bundle: bundle),
                detailTitle: String(localized: "Discovery of Designated Resolvers (DDR)", bundle: bundle),
                symbolName: "lock.shield",
                bundle: bundle
            )
        }
        if hasNonEmptyPrefix(lower, beforeSuffix: ".in-addr.arpa")
            || hasNonEmptyPrefix(lower, beforeSuffix: ".ip6.arpa")
        {
            return makeAnnotation(
                kind: .specialSystemDNS,
                cleanHost: cleanHost,
                badgeTitle: String(localized: "Reverse DNS", bundle: bundle),
                detailTitle: String(localized: "Reverse IP-to-hostname lookup (PTR)", bundle: bundle),
                symbolName: "arrow.uturn.backward",
                bundle: bundle
            )
        }
        if lower == "ipv4only.arpa" {
            return makeAnnotation(
                kind: .specialSystemDNS,
                cleanHost: cleanHost,
                badgeTitle: String(localized: "IPv4 Synthesis Probe", bundle: bundle),
                detailTitle: String(localized: "NAT64 / DNS64 prefix discovery (RFC 7050)", bundle: bundle),
                symbolName: "network",
                bundle: bundle
            )
        }
        return nil
    }

    private static func hasNonEmptySuffix(_ value: String, afterPrefix prefix: String) -> Bool {
        guard value.hasPrefix(prefix) else {
            return false
        }
        let remainder = value.dropFirst(prefix.count)
        return !remainder.isEmpty && !remainder.hasPrefix(".")
    }

    private static func hasNonEmptyPrefix(_ value: String, beforeSuffix suffix: String) -> Bool {
        guard value.hasSuffix(suffix) else {
            return false
        }
        let prefix = value.dropLast(suffix.count)
        return !prefix.isEmpty && !prefix.hasSuffix(".")
    }

    /// Strips an ASCII-only suffix case-insensitively while preserving the exact
    /// original casing and UTF-8 indices of the leading substring.
    private static func stripASCIICaseInsensitiveSuffix(_ value: String, suffix: String) -> Substring? {
        let valueUTF8 = value.utf8
        let suffixUTF8 = suffix.utf8
        guard valueUTF8.count >= suffixUTF8.count else {
            return nil
        }
        let splitIndex = valueUTF8.index(valueUTF8.endIndex, offsetBy: -suffixUTF8.count)
        var vIdx = splitIndex
        var sIdx = suffixUTF8.startIndex
        while sIdx < suffixUTF8.endIndex {
            var vb = valueUTF8[vIdx]
            if vb >= 65, vb <= 90 { // ASCII 'A'...'Z'
                vb += 32
            }
            var sb = suffixUTF8[sIdx]
            if sb >= 65, sb <= 90 {
                sb += 32
            }
            guard vb == sb else {
                return nil
            }
            vIdx = valueUTF8.index(after: vIdx)
            sIdx = suffixUTF8.index(after: sIdx)
        }
        return value[..<splitIndex]
    }
}
