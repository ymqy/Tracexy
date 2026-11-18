import Foundation

// MARK: - TrafficSourceCategory

/// Seven-dimension semantic classification of where a captured network session originated.
nonisolated enum TrafficSourceCategory: String, CaseIterable, Identifiable, Hashable, Sendable {
    case app
    case cli
    case thirdPartyService
    case systemService
    case lanDiscovery
    case kernelAndLink
    case unattributed

    // MARK: Internal

    nonisolated var id: String { rawValue }

    nonisolated var title: String {
        switch self {
        case .app: String(localized: "Apps")
        case .cli: String(localized: "CLI Tools")
        case .thirdPartyService: String(localized: "Third-Party Services")
        case .systemService: String(localized: "System Services")
        case .lanDiscovery: String(localized: "LAN & Discovery")
        case .kernelAndLink: String(localized: "Kernel & Link")
        case .unattributed: String(localized: "Unattributed")
        }
    }

    nonisolated var systemImage: String {
        switch self {
        case .app: "app.badge"
        case .cli: "apple.terminal"
        case .thirdPartyService: "gearshape.2"
        case .systemService: "cpu"
        case .lanDiscovery: "dot.radiowaves.left.and.right"
        case .kernelAndLink: "network"
        case .unattributed: "questionmark.app.dashed"
        }
    }

    nonisolated var opensOnCaptureStart: Bool {
        switch self {
        case .app, .cli, .thirdPartyService: true
        case .systemService, .lanDiscovery, .kernelAndLink, .unattributed: false
        }
    }

    nonisolated var hidesWhenEmpty: Bool {
        switch self {
        case .unattributed: true
        case .app, .cli, .thirdPartyService, .systemService, .lanDiscovery, .kernelAndLink: false
        }
    }
}

// MARK: - SessionProcessContext

/// Process-level provenance captured from `pktap` or `ProcessResolver` (`<libproc.h>` / `sysctl`).
nonisolated struct SessionProcessContext: Equatable, Hashable, Sendable, Codable {
    // MARK: Lifecycle

    init(
        executablePath: String? = nil,
        bundleIdentifier: String? = nil,
        viaProcessName: String? = nil,
        parentProcessName: String? = nil,
        hasControllingTTY: Bool = false,
        isRootUser: Bool = false,
        isKernelTask: Bool = false
    ) {
        self.executablePath = executablePath
        self.bundleIdentifier = bundleIdentifier
        self.viaProcessName = viaProcessName
        self.parentProcessName = parentProcessName
        self.hasControllingTTY = hasControllingTTY
        self.isRootUser = isRootUser
        self.isKernelTask = isKernelTask
    }

    // MARK: Internal

    var executablePath: String?
    var bundleIdentifier: String?
    var viaProcessName: String?
    var parentProcessName: String?
    var hasControllingTTY: Bool
    var isRootUser: Bool
    var isKernelTask: Bool
}

// MARK: - SourceChildTarget

/// Expandable sidebar child under a classified traffic source: either a remote host or a LAN peer IP.
nonisolated struct SourceChildTarget: Equatable, Hashable, Sendable, Identifiable {
    enum Kind: String, Equatable, Hashable, Sendable {
        case host
        case peerIP
    }

    let kind: Kind
    let value: String
    let label: String

    var id: String { "\(kind.rawValue):\(value)" }
}

// MARK: - ClassifiedSessionSource

/// Complete per-session classification, role annotation, and table/sidebar presentation metadata.
nonisolated struct ClassifiedSessionSource: Equatable, Hashable, Sendable {
    let category: TrafficSourceCategory
    let filterKey: String
    let title: String
    let subtitle: String?
    let tableLabel: String
    let tableDetail: String?
    let symbolName: String?
    let childTarget: SourceChildTarget?
}

// MARK: - SourceItemGroup

/// Aggregated sidebar source row across all sessions sharing the same `filterKey`.
nonisolated struct SourceItemGroup: Identifiable, Equatable, Hashable, Sendable {
    let filterKey: String
    let category: TrafficSourceCategory
    let title: String
    let subtitle: String?
    let symbolName: String?
    let children: [SourceChildTarget]
    let count: Int

    var id: String { filterKey }
}

// MARK: - SourceCategoryGroup

/// Aggregated sidebar category section containing sorted `SourceItemGroup` rows.
nonisolated struct SourceCategoryGroup: Identifiable, Equatable, Hashable, Sendable {
    let category: TrafficSourceCategory
    let items: [SourceItemGroup]
    let totalSessions: Int

    var id: String { category.rawValue }
}

// MARK: - Internal Subkind & Aggregation Helpers

nonisolated private enum LanSubkind {
    case mdns, ssdp, dhcp, naming, arp, multicast

    init?(filterKey: String) {
        switch filterKey {
        case "lan:mdns": self = .mdns
        case "lan:ssdp": self = .ssdp
        case "lan:dhcp": self = .dhcp
        case "lan:naming": self = .naming
        case "lan:arp": self = .arp
        case "lan:multicast": self = .multicast
        default: return nil
        }
    }

    var filterKey: String {
        switch self {
        case .mdns: "lan:mdns"
        case .ssdp: "lan:ssdp"
        case .dhcp: "lan:dhcp"
        case .naming: "lan:naming"
        case .arp: "lan:arp"
        case .multicast: "lan:multicast"
        }
    }

    var title: String {
        switch self {
        case .mdns: String(localized: "Bonjour / mDNS")
        case .ssdp: String(localized: "SSDP / UPnP")
        case .dhcp: String(localized: "DHCP Lease Broadcast")
        case .naming: String(localized: "NetBIOS / LLMNR")
        case .arp: String(localized: "Peer ARP Resolution")
        case .multicast: String(localized: "LAN Broadcast / Multicast")
        }
    }

    var subtitle: String {
        switch self {
        case .mdns: String(localized: "Local network service discovery (UDP 5353)")
        case .ssdp: String(localized: "Media, smart-device & router discovery (UDP 1900)")
        case .dhcp: String(localized: "Dynamic IP address configuration broadcast")
        case .naming: String(localized: "Windows & NAS local name broadcast")
        case .arp: String(localized: "Layer-2 MAC lookup between other LAN devices")
        case .multicast: String(localized: "Broadcast or multicast from nearby LAN devices")
        }
    }

    var tableLabel: String {
        switch self {
        case .mdns: String(localized: "LAN · Bonjour")
        case .ssdp: String(localized: "LAN · SSDP")
        case .dhcp: String(localized: "LAN · DHCP")
        case .naming: String(localized: "LAN · Naming")
        case .arp: String(localized: "LAN · Peer ARP")
        case .multicast: String(localized: "LAN · Multicast")
        }
    }
}

nonisolated private enum KernelSubkind {
    case arp, ndp, igmp, icmp, tcpTeardown, inbound

    init?(filterKey: String) {
        switch filterKey {
        case "kernel:arp": self = .arp
        case "kernel:ndp": self = .ndp
        case "kernel:igmp": self = .igmp
        case "kernel:icmp": self = .icmp
        case "kernel:tcp-teardown": self = .tcpTeardown
        case "kernel:inbound": self = .inbound
        default: return nil
        }
    }

    var filterKey: String {
        switch self {
        case .arp: "kernel:arp"
        case .ndp: "kernel:ndp"
        case .igmp: "kernel:igmp"
        case .icmp: "kernel:icmp"
        case .tcpTeardown: "kernel:tcp-teardown"
        case .inbound: "kernel:inbound"
        }
    }

    var title: String {
        switch self {
        case .arp: String(localized: "ARP Resolution")
        case .ndp: String(localized: "IPv6 Neighbor & Router Discovery")
        case .igmp: String(localized: "IGMP / MLD Multicast Control")
        case .icmp: String(localized: "ICMP Probe & Diagnostics")
        case .tcpTeardown: String(localized: "Kernel TCP Teardown / Reset")
        case .inbound: String(localized: "Inbound Unanswered Port")
        }
    }

    var subtitle: String {
        switch self {
        case .arp: String(localized: "Local Mac & gateway Layer-2 MAC resolution")
        case .ndp: String(localized: "ICMPv6 router advertisements & neighbor solicitation")
        case .igmp: String(localized: "Kernel multicast group membership reports")
        case .icmp: String(localized: "Echo ping & unreachable / TTL network diagnostics")
        case .tcpTeardown: String(localized: "Late RST, FIN-ACK or TIME_WAIT handled by macOS kernel")
        case .inbound: String(localized: "Unsolicited packet to a closed local port")
        }
    }

    var tableLabel: String {
        switch self {
        case .arp: String(localized: "Kernel · ARP")
        case .ndp: String(localized: "Kernel · IPv6 NDP")
        case .igmp: String(localized: "Kernel · Multicast")
        case .icmp: String(localized: "Kernel · ICMP")
        case .tcpTeardown: String(localized: "Kernel · TCP Reset")
        case .inbound: String(localized: "Kernel · Closed Port")
        }
    }
}

nonisolated private struct ParsedEndpoints {
    let protos: Set<ProtocolKind>
    let srcIP: IPAddressValue?
    let dstIP: IPAddressValue?
    let srcPort: UInt16?
    let dstPort: UInt16?
    let hasReliableLocalIPs: Bool
    let srcIsLocal: Bool
    let dstIsLocal: Bool
    let dstIsMulticastOrBroadcast: Bool

    var involvesLocal: Bool { srcIsLocal || dstIsLocal }

    func hasPort(_ target: UInt16) -> Bool {
        srcPort == target || dstPort == target
    }

    func hasAnyPort(_ targets: Set<UInt16>) -> Bool {
        if let srcPort, targets.contains(srcPort) { return true }
        if let dstPort, targets.contains(dstPort) { return true }
        return false
    }
}

nonisolated private struct ItemAccumulator {
    var category: TrafficSourceCategory
    let filterKey: String
    var title: String
    var baseSubtitle: String?
    var symbolName: String?
    var bestContextRichness: Int
    var viaProcessNames: [String] = []
    var childrenByID: [String: SourceChildTarget] = [:]
    var count = 1

    init(classified: ClassifiedSessionSource, viaProcessName: String?, contextRichness: Int) {
        category = classified.category
        filterKey = classified.filterKey
        title = classified.title
        baseSubtitle = classified.subtitle
        symbolName = classified.symbolName
        bestContextRichness = contextRichness
        if let viaProcessName {
            viaProcessNames.append(viaProcessName)
        }
        if let child = classified.childTarget {
            childrenByID[child.id] = child
        }
    }

    mutating func merge(classified: ClassifiedSessionSource, viaProcessName: String?, contextRichness: Int) {
        count += 1
        if contextRichness > bestContextRichness {
            bestContextRichness = contextRichness
            category = classified.category
            title = classified.title
            baseSubtitle = classified.subtitle
            symbolName = classified.symbolName
        } else if baseSubtitle == nil, let subtitle = classified.subtitle {
            baseSubtitle = subtitle
        }
        if let viaProcessName, !viaProcessNames.contains(viaProcessName) {
            viaProcessNames.append(viaProcessName)
        }
        if let child = classified.childTarget {
            if let existing = childrenByID[child.id] {
                if existing.label == existing.value, child.label != child.value {
                    childrenByID[child.id] = child
                }
            } else {
                childrenByID[child.id] = child
            }
        }
    }

    func buildItemGroup() -> SourceItemGroup {
        let mergedSubtitle: String? = if category == .app {
            viaProcessNames.isEmpty
                ? nil
                : String(format: String(localized: "via %@"), viaProcessNames.prefix(2).joined(separator: ", "))
        } else {
            baseSubtitle
        }
        let sortedChildren = childrenByID.values.sorted { lhs, rhs in
            lhs.value != rhs.value ? lhs.value < rhs.value : lhs.kind.rawValue < rhs.kind.rawValue
        }
        return SourceItemGroup(
            filterKey: filterKey,
            category: category,
            title: title,
            subtitle: mergedSubtitle,
            symbolName: symbolName,
            children: sortedChildren,
            count: count
        )
    }
}

// MARK: - SessionSourceClassifier

/// Pure, deterministic 7-dimension traffic source classifier and semantic role annotator.
nonisolated enum SessionSourceClassifier {
    // MARK: Internal

    /// Classifies a single `SessionSummary` into one of the 7 traffic source dimensions.
    static func classify(
        _ session: SessionSummary,
        context: SessionProcessContext? = nil,
        localIPs: Set<String> = [],
        isViewingSavedCapture: Bool = false,
        resolvedNames: [String: String] = [:],
        homeDirectoryPath: String = FileManager.default.homeDirectoryForCurrentUser.path,
        appBundleExistsLookup: (String) -> Bool = defaultAppBundleExists(_:)
    )
        -> ClassifiedSessionSource
    {
        classifyNormalized(
            session,
            context: context,
            normalizedLocalIPs: normalizeIPSet(localIPs),
            isViewingSavedCapture: isViewingSavedCapture,
            normalizedResolvedNames: normalizeResolvedNames(resolvedNames),
            homeDirectoryPath: homeDirectoryPath,
            appBundleExistsLookup: appBundleExistsLookup
        )
    }

    /// Aggregates sessions into ordered `SourceCategoryGroup` sections and sorted `SourceItemGroup` rows.
    static func group(
        sessions: [SessionSummary],
        contextsBySessionID: [UUID: SessionProcessContext] = [:],
        localIPs: Set<String> = [],
        isViewingSavedCapture: Bool = false,
        resolvedNames: [String: String] = [:],
        includeEmptyCategories: Bool = false,
        homeDirectoryPath: String = FileManager.default.homeDirectoryForCurrentUser.path,
        appBundleExistsLookup: (String) -> Bool = defaultAppBundleExists(_:)
    )
        -> [SourceCategoryGroup]
    {
        group(
            sessions: sessions,
            contextProvider: { contextsBySessionID[$0.id] },
            localIPs: localIPs,
            isViewingSavedCapture: isViewingSavedCapture,
            resolvedNames: resolvedNames,
            includeEmptyCategories: includeEmptyCategories,
            homeDirectoryPath: homeDirectoryPath,
            appBundleExistsLookup: appBundleExistsLookup
        )
    }

    /// Aggregates sessions using a custom per-session `SessionProcessContext` lookup closure.
    static func group(
        sessions: [SessionSummary],
        contextProvider: (SessionSummary) -> SessionProcessContext?,
        localIPs: Set<String> = [],
        isViewingSavedCapture: Bool = false,
        resolvedNames: [String: String] = [:],
        includeEmptyCategories: Bool = false,
        homeDirectoryPath: String = FileManager.default.homeDirectoryForCurrentUser.path,
        appBundleExistsLookup: (String) -> Bool = defaultAppBundleExists(_:)
    )
        -> [SourceCategoryGroup]
    {
        let normalizedLocal = normalizeIPSet(localIPs)
        let normalizedNames = normalizeResolvedNames(resolvedNames)

        // Pre-index richest known provenance per processName so sticky-attributed
        // sessions whose per-session context was nil still inherit their process provenance.
        var fallbackContextByProcessName: [String: SessionProcessContext] = [:]
        for session in sessions {
            guard let name = normalizedProcessName(session.processName),
                  name != "kernel_task",
                  let ctx = contextProvider(session) else
            {
                continue
            }
            if let existing = fallbackContextByProcessName[name] {
                if contextRichness(ctx) > contextRichness(existing) {
                    fallbackContextByProcessName[name] = ctx
                }
            } else {
                fallbackContextByProcessName[name] = ctx
            }
        }

        var accumulatorsByKey: [String: ItemAccumulator] = [:]
        for session in sessions {
            let directContext = contextProvider(session)
            let effectiveContext: SessionProcessContext? = if let directContext {
                directContext
            } else if let name = normalizedProcessName(session.processName) {
                fallbackContextByProcessName[name]
            } else {
                nil
            }

            let classified = classifyNormalized(
                session,
                context: effectiveContext,
                normalizedLocalIPs: normalizedLocal,
                isViewingSavedCapture: isViewingSavedCapture,
                normalizedResolvedNames: normalizedNames,
                homeDirectoryPath: homeDirectoryPath,
                appBundleExistsLookup: appBundleExistsLookup
            )

            let richness = contextRichness(effectiveContext)
            let viaCandidate = normalizedViaProcessName(
                directContext?.viaProcessName ?? effectiveContext?.viaProcessName,
                excludingProcessName: classified.title
            )
            if var existing = accumulatorsByKey[classified.filterKey] {
                existing.merge(classified: classified, viaProcessName: viaCandidate, contextRichness: richness)
                accumulatorsByKey[classified.filterKey] = existing
            } else {
                accumulatorsByKey[classified.filterKey] = ItemAccumulator(
                    classified: classified,
                    viaProcessName: viaCandidate,
                    contextRichness: richness
                )
            }
        }

        var itemsByCategory: [TrafficSourceCategory: [SourceItemGroup]] = [:]
        for accumulator in accumulatorsByKey.values {
            let item = accumulator.buildItemGroup()
            itemsByCategory[item.category, default: []].append(item)
        }

        var categoryGroups: [SourceCategoryGroup] = []
        for category in TrafficSourceCategory.allCases {
            let sortedItems = (itemsByCategory[category] ?? []).sorted { lhs, rhs in
                if lhs.count != rhs.count { return lhs.count > rhs.count }
                if lhs.title != rhs.title { return lhs.title < rhs.title }
                return lhs.filterKey < rhs.filterKey
            }
            if sortedItems.isEmpty, !includeEmptyCategories {
                continue
            }
            let totalSessions = sortedItems.reduce(0) { $0 + $1.count }
            categoryGroups.append(SourceCategoryGroup(
                category: category,
                items: sortedItems,
                totalSessions: totalSessions
            ))
        }
        return categoryGroups
    }

    /// Human-readable localized title for any `filterKey` (e.g. `"lan:mdns"` -> `"Bonjour / mDNS"`).
    static func displayTitle(forFilterKey key: String) -> String {
        if let lanKind = LanSubkind(filterKey: key) {
            return lanKind.title
        }
        if let kernelKind = KernelSubkind(filterKey: key) {
            return kernelKind.title
        }
        let trimmed = key.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty || trimmed == "—" {
            return String(localized: "Unattributed")
        }
        return key
    }

    /// Whether `key` is a synthetic non-process `filterKey` (`lan:*`, `kernel:*`, or `"—"`).
    static func isSyntheticFilterKey(_ key: String) -> Bool {
        key == "—" || key.hasPrefix("lan:") || key.hasPrefix("kernel:")
    }

    /// Evaluates whether `session` belongs to `filterKey`, preserving 100% compatibility
    /// with named process filters (`"Safari"`, `"curl"`) and synthetic LAN/Kernel/Unattributed keys.
    static func matchesFilterKey(
        _ filterKey: String,
        session: SessionSummary,
        context: SessionProcessContext? = nil,
        localIPs: Set<String> = [],
        isViewingSavedCapture: Bool = false
    )
        -> Bool
    {
        let rawName = normalizedProcessName(session.processName)
        let isKernel = isKernelTaskSession(rawName: rawName, context: context)
        if !isSyntheticFilterKey(filterKey) {
            return !isKernel && rawName == filterKey
        }
        if rawName != nil, !isKernel {
            return false
        }
        let classified = classify(
            session,
            context: context,
            localIPs: localIPs,
            isViewingSavedCapture: isViewingSavedCapture
        )
        return classified.filterKey == filterKey
    }

    /// Default `.app` bundle existence lookup used when `executablePath` is unavailable.
    static func defaultAppBundleExists(_ rawName: String) -> Bool {
        if wellKnownAppNames.contains(rawName) {
            return true
        }
        let homeApps = (FileManager.default.homeDirectoryForCurrentUser.path as NSString)
            .appendingPathComponent("Applications/\(rawName).app")
        let candidatePaths = [
            "/Applications/\(rawName).app",
            "/System/Applications/\(rawName).app",
            "/System/Applications/Utilities/\(rawName).app",
            homeApps,
        ]
        return candidatePaths.contains { FileManager.default.fileExists(atPath: $0) }
    }

    // MARK: Private

    private static let wellKnownAppNames: Set<String> = [
        "Safari", "Mail", "Music", "Messages", "Maps", "Photos", "Calendar", "Notes", "Reminders",
        "FaceTime", "Finder", "Preview", "Terminal", "App Store", "System Settings", "Xcode",
        "Google Chrome", "Chrome", "Firefox", "Slack", "Discord", "Arc", "Brave Browser",
        "Microsoft Edge", "Spotify", "Figma", "Postman",
    ]

    private static let knownSystemDaemonNames: Set<String> = [
        "mDNSResponder", "_mdnsresponder", "usbmuxd", "remoted", "remotepairingd",
        "AMPDeviceDiscoveryAgent", "rapportd", "sharingd", "apsd", "trustd", "ocspd",
        "cloudd", "bird", "nsurlsessiond", "amsengagementd", "amsondevicestoraged",
        "appstoreagent", "appstored", "softwareupdated", "configd", "symptomsd",
        "WiFiAgent", "airportd", "nesessionmanager", "nehelper", "networkserviceproxy",
        "identityservicesd", "imagent", "timed", "locationd", "geod", "parsecd",
        "siriknowledged", "Control Center", "ControlCenter", "WindowServer", "loginwindow",
        "launchd", "UserEventAgent", "dasd", "lsd", "pkd", "secinitd", "syspolicyd",
        "tccd", "analyticsd", "biomesyncd", "chronod", "weatherd",
        "CalendarWidgetExtension", "PhotosReliveWidget", "WallpaperAerialsExtension",
    ]

    private static let knownCLICommands: Set<String> = [
        "curl", "wget", "ssh", "git", "node", "python", "python3", "codex", "go", "ruby",
        "java", "nc", "dig", "ping", "rsync", "scp", "brew", "npm", "pnpm", "bun", "deno",
        "cargo", "rustc", "swift", "swiftc", "clang", "lldb", "openssl", "sftp", "gh",
        "pip", "pip3", "uv",
    ]

    private static let ignoredParentLauncherNames: Set<String> = [
        "launchd", "zsh", "bash", "fish", "sh", "login", "sudo", "-zsh", "-bash", "-fish", "-sh",
    ]

    private static let cliToolchainPathFragments: [String] = [
        "/.cargo/", "/.nvm/", "/.bun/", "/.pyenv/", "/.asdf/", "/.volta/", "/.local/", "/go/bin/",
    ]

    private static let dhcpPorts: Set<UInt16> = [67, 68, 546, 547]
    private static let namingPorts: Set<UInt16> = [137, 138, 5_355]

    // MARK: Core classification

    private static func classifyNormalized(
        _ session: SessionSummary,
        context: SessionProcessContext?,
        normalizedLocalIPs: Set<IPAddressValue>,
        isViewingSavedCapture: Bool,
        normalizedResolvedNames: [String: String],
        homeDirectoryPath: String,
        appBundleExistsLookup: (String) -> Bool
    )
        -> ClassifiedSessionSource
    {
        let rawName = normalizedProcessName(session.processName)
        let endpoints = parseEndpoints(
            of: session,
            normalizedLocalIPs: normalizedLocalIPs,
            isViewingSavedCapture: isViewingSavedCapture
        )

        if isKernelTaskSession(rawName: rawName, context: context) {
            let subkind = classifyKernelSubkind(session, endpoints: endpoints, forceFallbackToTeardown: true)
                ?? .tcpTeardown
            return makeKernelSource(subkind: subkind, session: session)
        }

        if let rawName {
            return classifyNamedProcess(
                rawName: rawName,
                session: session,
                context: context,
                homeDirectoryPath: homeDirectoryPath,
                appBundleExistsLookup: appBundleExistsLookup
            )
        }

        return classifyUnattributedSession(
            session,
            endpoints: endpoints,
            normalizedResolvedNames: normalizedResolvedNames
        )
    }

    private static func isKernelTaskSession(rawName: String?, context: SessionProcessContext?) -> Bool {
        if context?.isKernelTask == true, rawName == nil || rawName == "kernel_task" {
            return true
        }
        return rawName == "kernel_task"
    }

    // MARK: Named process classification (Rule B)

    private static func classifyNamedProcess(
        rawName: String,
        session: SessionSummary,
        context: SessionProcessContext?,
        homeDirectoryPath: String,
        appBundleExistsLookup: (String) -> Bool
    )
        -> ClassifiedSessionSource
    {
        let path = normalizedNonEmpty(context?.executablePath)
        let bundleID = normalizedNonEmpty(context?.bundleIdentifier)
        let via = normalizedViaProcessName(context?.viaProcessName, excludingProcessName: rawName)
        let child = hostChildTarget(for: session)

        if isSystemService(
            rawName: rawName,
            executablePath: path,
            bundleIdentifier: bundleID,
            appBundleExistsLookup: appBundleExistsLookup
        ) {
            let subtitle = systemServiceSubtitle(rawName: rawName, executablePath: path)
            return ClassifiedSessionSource(
                category: .systemService,
                filterKey: rawName,
                title: rawName,
                subtitle: subtitle,
                tableLabel: rawName,
                tableDetail: subtitle,
                symbolName: TrafficSourceCategory.systemService.systemImage,
                childTarget: child
            )
        }

        if isGUIApp(
            rawName: rawName,
            executablePath: path,
            homeDirectoryPath: homeDirectoryPath,
            appBundleExistsLookup: appBundleExistsLookup
        ) {
            let subtitle = via.map { String(format: String(localized: "via %@"), $0) }
            return ClassifiedSessionSource(
                category: .app,
                filterKey: rawName,
                title: rawName,
                subtitle: subtitle,
                tableLabel: rawName,
                tableDetail: subtitle,
                symbolName: nil,
                childTarget: child
            )
        }

        if isCLITool(rawName: rawName, executablePath: path, context: context) {
            let subtitle = cliSubtitle(rawName: rawName, executablePath: path, context: context)
            return ClassifiedSessionSource(
                category: .cli,
                filterKey: rawName,
                title: rawName,
                subtitle: subtitle,
                tableLabel: rawName,
                tableDetail: subtitle,
                symbolName: TrafficSourceCategory.cli.systemImage,
                childTarget: child
            )
        }

        let subtitle = thirdPartyServiceSubtitle(executablePath: path, context: context)
        return ClassifiedSessionSource(
            category: .thirdPartyService,
            filterKey: rawName,
            title: rawName,
            subtitle: subtitle,
            tableLabel: rawName,
            tableDetail: subtitle,
            symbolName: TrafficSourceCategory.thirdPartyService.systemImage,
            childTarget: child
        )
    }

    private static func isSystemService(
        rawName: String,
        executablePath: String?,
        bundleIdentifier: String?,
        appBundleExistsLookup: (String) -> Bool
    )
        -> Bool
    {
        if let path = executablePath {
            if path.hasPrefix("/System/Library/")
                || path.hasPrefix("/usr/libexec/")
                || path.hasPrefix("/usr/sbin/")
                || path.hasPrefix("/sbin/")
            {
                return true
            }
            if bundleIdentifier?.hasPrefix("com.apple.") == true {
                let isSystemAppsApp = (path.hasPrefix("/System/Applications/")
                    || path.contains("/System/Applications/")) && path.contains(".app/")
                let isMainAppsApp = path.hasPrefix("/Applications/") && path.contains(".app/")
                if !isSystemAppsApp, !isMainAppsApp {
                    return true
                }
            }
            return false
        }
        if knownSystemDaemonNames.contains(rawName) {
            return true
        }
        return bundleIdentifier?.hasPrefix("com.apple.") == true && !appBundleExistsLookup(rawName)
    }

    private static func isGUIApp(
        rawName: String,
        executablePath: String?,
        homeDirectoryPath: String,
        appBundleExistsLookup: (String) -> Bool
    )
        -> Bool
    {
        if let path = executablePath {
            guard path.contains(".app/"), !path.hasPrefix("/System/Library/") else {
                return false
            }
            if path.hasPrefix("/Applications/")
                || path.hasPrefix("/System/Applications/")
                || path.contains("/System/Applications/")
            {
                return true
            }
            let normalizedHome = normalizeDirectoryPrefix(homeDirectoryPath)
            if !normalizedHome.isEmpty, path.hasPrefix(normalizedHome) {
                return true
            }
            return path.contains("/Applications/") && !path.hasPrefix("/Library/")
        }
        return appBundleExistsLookup(rawName)
    }

    private static func isCLITool(rawName: String, executablePath: String?, context: SessionProcessContext?) -> Bool {
        if context?.hasControllingTTY == true {
            return true
        }
        if let path = executablePath {
            if path.hasPrefix("/opt/homebrew/")
                || path.hasPrefix("/usr/local/")
                || path.hasPrefix("/Library/Developer/")
                || path.hasPrefix("/usr/bin/")
                || path.hasPrefix("/bin/")
            {
                return true
            }
            return cliToolchainPathFragments.contains { path.contains($0) }
        }
        return knownCLICommands.contains(rawName)
    }

    private static func systemServiceSubtitle(rawName: String, executablePath: String?) -> String {
        if let curated = curatedSystemDaemonSubtitle(for: rawName) {
            return curated
        }
        if let path = executablePath {
            let basename = (path as NSString).lastPathComponent
            if let curatedByBasename = curatedSystemDaemonSubtitle(for: basename) {
                return curatedByBasename
            }
            if let frameworkName = extractFrameworkName(from: path) {
                return String(format: String(localized: "macOS %@ service"), frameworkName)
            }
        }
        return String(localized: "macOS System Service")
    }

    private static func curatedSystemDaemonSubtitle(for name: String) -> String? {
        switch name {
        case "mDNSResponder", "_mdnsresponder": String(localized: "System DNS & Bonjour resolver")
        case "usbmuxd", "remoted", "remotepairingd": String(localized: "iOS device wireless & USB mux")
        case "AMPDeviceDiscoveryAgent": String(localized: "Apple device discovery service")
        case "rapportd", "sharingd": String(localized: "AirDrop, Handoff & Continuity")
        case "apsd": String(localized: "Apple Push Notification service")
        case "trustd", "ocspd": String(localized: "TLS certificate trust & revocation")
        case "cloudd", "bird", "nsurlsessiond": String(localized: "iCloud sync & background transfer")
        case "amsengagementd", "amsondevicestoraged", "appstoreagent", "appstored":
            String(localized: "App Store & media account service")
        case "softwareupdated": String(localized: "macOS Software Update service")
        case "configd", "symptomsd", "WiFiAgent", "airportd",
             "nesessionmanager", "nehelper", "networkserviceproxy":
            String(localized: "Network configuration & diagnostics")
        case "identityservicesd", "imagent": String(localized: "iMessage & FaceTime identity")
        case "timed": String(localized: "Network time synchronization")
        case "locationd", "geod": String(localized: "Location & Maps service")
        case "parsecd", "siriknowledged": String(localized: "Spotlight & Siri suggestions")
        case "Control Center", "ControlCenter": String(localized: "macOS Control Center")
        case "WindowServer", "loginwindow": String(localized: "macOS Window & Login session")
        case "chronod", "weatherd", "pkd",
             "CalendarWidgetExtension", "PhotosReliveWidget", "WallpaperAerialsExtension":
            String(localized: "Widget & System Extension")
        default: nil
        }
    }

    private static func extractFrameworkName(from executablePath: String) -> String? {
        let suffix = ".framework"
        guard let component = executablePath.split(separator: "/").last(where: { $0.hasSuffix(suffix) }) else {
            return nil
        }
        let name = String(component.dropLast(suffix.count))
        return name.isEmpty ? nil : name
    }

    private static func cliSubtitle(
        rawName: String,
        executablePath: String?,
        context: SessionProcessContext?
    )
        -> String
    {
        var parts: [String] = []
        if let path = executablePath {
            if path.hasPrefix("/opt/homebrew/") || path.hasPrefix("/usr/local/") {
                parts.append(String(localized: "Homebrew CLI"))
            } else if path.hasPrefix("/usr/bin/") || path.hasPrefix("/bin/") {
                parts.append(String(localized: "System CLI"))
            } else if path.hasPrefix("/Library/Developer/")
                || cliToolchainPathFragments.contains(where: { path.contains($0) })
            {
                parts.append(String(localized: "Developer Toolchain"))
            } else if context?.hasControllingTTY == true {
                parts.append(String(localized: "Terminal CLI"))
            }
        } else if context?.hasControllingTTY == true {
            parts.append(String(localized: "Terminal CLI"))
        }

        if let parent = normalizedNonEmpty(context?.parentProcessName),
           !ignoredParentLauncherNames.contains(parent),
           parent != rawName
        {
            parts.append(String(format: String(localized: "Launched by %@"), parent))
        }
        return parts.isEmpty ? String(localized: "Terminal CLI") : parts.joined(separator: " · ")
    }

    private static func thirdPartyServiceSubtitle(executablePath: String?, context: SessionProcessContext?) -> String {
        if executablePath?.contains("/Library/SystemExtensions/") == true {
            return String(localized: "System Network Extension")
        }
        if context?.isRootUser == true
            || executablePath?.hasPrefix("/Library/LaunchDaemons/") == true
            || executablePath?.hasPrefix("/Library/PrivilegedHelperTools/") == true
        {
            return String(localized: "Root Background Daemon")
        }
        return String(localized: "Background Agent")
    }

    // MARK: Unattributed wire classification (Rule C)

    private static func classifyUnattributedSession(
        _ session: SessionSummary,
        endpoints: ParsedEndpoints,
        normalizedResolvedNames: [String: String]
    )
        -> ClassifiedSessionSource
    {
        let protos = endpoints.protos

        if protos.contains(.arp) {
            if endpoints.hasReliableLocalIPs, !endpoints.involvesLocal {
                return makeLanSource(.arp, session: session, endpoints: endpoints, names: normalizedResolvedNames)
            }
            return makeKernelSource(subkind: .arp, session: session)
        }

        if protos.contains(.icmpv6) {
            return makeKernelSource(subkind: classifyICMPv6Subkind(session, endpoints: endpoints), session: session)
        }
        if protos.contains(.icmp) {
            return makeKernelSource(subkind: .icmp, session: session)
        }
        if isIPv4IGMP(session, endpoints: endpoints) {
            return makeKernelSource(subkind: .igmp, session: session)
        }

        if endpoints.hasReliableLocalIPs {
            let isDHCPTraffic = protos.contains(.dhcp) || endpoints.hasAnyPort(dhcpPorts)
            if isDHCPTraffic, !endpoints.srcIsLocal || endpoints.dstIsMulticastOrBroadcast {
                return makeLanSource(.dhcp, session: session, endpoints: endpoints, names: normalizedResolvedNames)
            }
            if (!endpoints.srcIsLocal && !endpoints.dstIsLocal)
                || (!endpoints.srcIsLocal && endpoints.dstIsMulticastOrBroadcast)
            {
                let subkind = classifyLiveLanSubkind(endpoints: endpoints)
                return makeLanSource(subkind, session: session, endpoints: endpoints, names: normalizedResolvedNames)
            }
            if endpoints.srcIsLocal, isDHCPTraffic {
                return makeLanSource(.dhcp, session: session, endpoints: endpoints, names: normalizedResolvedNames)
            }
        } else if let savedLan = classifySavedCaptureLanSubkind(endpoints: endpoints) {
            return makeLanSource(savedLan, session: session, endpoints: endpoints, names: normalizedResolvedNames)
        }

        if let kernelSubkind = classifyKernelSubkind(session, endpoints: endpoints, forceFallbackToTeardown: false) {
            return makeKernelSource(subkind: kernelSubkind, session: session)
        }

        return ClassifiedSessionSource(
            category: .unattributed,
            filterKey: "—",
            title: String(localized: "Unattributed"),
            subtitle: nil,
            tableLabel: "—",
            tableDetail: nil,
            symbolName: TrafficSourceCategory.unattributed.systemImage,
            childTarget: hostChildTarget(for: session)
        )
    }

    private static func classifyLiveLanSubkind(endpoints: ParsedEndpoints) -> LanSubkind {
        let protos = endpoints.protos
        if protos.contains(.mdns) || endpoints.hasPort(5_353) { return .mdns }
        if protos.contains(.ssdp) || endpoints.hasPort(1_900) { return .ssdp }
        if protos.contains(.dhcp) || endpoints.hasAnyPort(dhcpPorts) { return .dhcp }
        if protos.contains(.nbns) || protos.contains(.llmnr) || endpoints.hasAnyPort(namingPorts) { return .naming }
        if protos.contains(.arp) { return .arp }
        return .multicast
    }

    private static func classifySavedCaptureLanSubkind(endpoints: ParsedEndpoints) -> LanSubkind? {
        let protos = endpoints.protos
        if protos.contains(.mdns) || (endpoints.dstIsMulticastOrBroadcast && endpoints.hasPort(5_353)) {
            return .mdns
        }
        if protos.contains(.ssdp) || (endpoints.dstIsMulticastOrBroadcast && endpoints.hasPort(1_900)) {
            return .ssdp
        }
        if protos.contains(.dhcp) || endpoints.hasAnyPort(dhcpPorts) {
            return .dhcp
        }
        if protos.contains(.nbns)
            || protos.contains(.llmnr)
            || (endpoints.dstIsMulticastOrBroadcast && endpoints.hasAnyPort(namingPorts))
        {
            return .naming
        }
        return nil
    }

    private static func classifyKernelSubkind(
        _ session: SessionSummary,
        endpoints: ParsedEndpoints,
        forceFallbackToTeardown: Bool
    )
        -> KernelSubkind?
    {
        let protos = endpoints.protos
        if protos.contains(.arp) { return .arp }
        if protos.contains(.icmpv6) { return classifyICMPv6Subkind(session, endpoints: endpoints) }
        if protos.contains(.icmp) { return .icmp }
        if isIPv4IGMP(session, endpoints: endpoints) { return .igmp }

        if endpoints.hasReliableLocalIPs, endpoints.involvesLocal {
            if protos.contains(.tcp), !session.tcpCompleteness.contains(.data) {
                if !endpoints.srcIsLocal, endpoints.dstIsLocal {
                    let remoteSYNRejectedOrUnanswered = session.tcpCompleteness.contains(.syn)
                        && !session.tcpCompleteness.contains(.synAck)
                    if session.packetsUp == 0
                        || session.packetsDown == 0
                        || session.bytesDown == 0
                        || remoteSYNRejectedOrUnanswered
                    {
                        return .inbound
                    }
                }
                return .tcpTeardown
            }
            if !endpoints.srcIsLocal, endpoints.dstIsLocal, session.bytesUp == 0 || session.bytesDown == 0 {
                return .inbound
            }
        }
        return forceFallbackToTeardown ? .tcpTeardown : nil
    }

    private static func classifyICMPv6Subkind(_ session: SessionSummary, endpoints: ParsedEndpoints) -> KernelSubkind {
        if isICMPv6MLD(session, dstIP: endpoints.dstIP) { return .igmp }
        if isICMPv6NDP(session, srcIP: endpoints.srcIP, dstIP: endpoints.dstIP) { return .ndp }
        return .icmp
    }

    private static func isICMPv6MLD(_ session: SessionSummary, dstIP: IPAddressValue?) -> Bool {
        if let dstIP, dstIP.compressedText.lowercased() == "ff02::16" {
            return true
        }
        let texts = icmpInspectionStrings(session)
        let mldTokens = [
            "Type 130", "(130)", "Type 131", "(131)", "Type 132", "(132)", "Type 143", "(143)", "Multicast Listener",
        ]
        return texts.contains { text in mldTokens.contains { text.contains($0) } }
    }

    private static func isICMPv6NDP(
        _ session: SessionSummary,
        srcIP: IPAddressValue?,
        dstIP: IPAddressValue?
    )
        -> Bool
    {
        let texts = icmpInspectionStrings(session)
        let ndpTokens = [
            "Neighbor", "Router", "Type 133", "(133)", "Type 134", "(134)", "Type 135", "(135)", "Type 136", "(136)",
        ]
        if texts.contains(where: { text in ndpTokens.contains { text.contains($0) } }) {
            return true
        }
        let isEchoOrError = texts.contains { text in
            text.contains("Echo") || text.contains("Unreachable") || text.contains("Packet Too Big")
                || text.contains("Time Exceeded") || text.contains("(128)") || text.contains("(129)")
        }
        guard !isEchoOrError else {
            return false
        }
        if let dstIP, isNDPTargetAddress(dstIP) { return true }
        if let srcIP, isIPv6LinkLocal(srcIP) { return true }
        return false
    }

    private static func icmpInspectionStrings(_ session: SessionSummary) -> [String] {
        var strings = [session.infoSummary]
        for layer in session.decodedLayers where layer.proto == .icmpv6 || layer.proto == .icmp {
            if !layer.summary.isEmpty {
                strings.append(layer.summary)
            }
            for field in layer.fields where field.name == "Type" {
                strings.append(field.value)
            }
        }
        return strings
    }

    private static func isNDPTargetAddress(_ ip: IPAddressValue) -> Bool {
        if isIPv6LinkLocal(ip) { return true }
        let lower = ip.compressedText.lowercased()
        if lower == "ff02::1" || lower == "ff02::2" { return true }
        guard ip.family == .v6, ip.bytes.count == 16 else { return false }
        return ip.bytes[0] == 0xFF && ip.bytes[1] == 0x02
            && ip.bytes[2 ..< 11].allSatisfy { $0 == 0 }
            && ip.bytes[11] == 0x01 && ip.bytes[12] == 0xFF
    }

    private static func isIPv6LinkLocal(_ ip: IPAddressValue) -> Bool {
        ip.family == .v6 && ip.bytes.count == 16 && ip.bytes[0] == 0xFE && (ip.bytes[1] & 0xC0) == 0x80
    }

    private static func isIPv4IGMP(_ session: SessionSummary, endpoints: ParsedEndpoints) -> Bool {
        let protos = endpoints.protos
        guard !protos.contains(.udp), !protos.contains(.tcp),
              !protos.contains(.icmp), !protos.contains(.icmpv6), !protos.contains(.arp),
              let dstIP = endpoints.dstIP, dstIP.family == .v4 else
        {
            return false
        }
        let text = dstIP.compressedText
        if text == "224.0.0.22" || text == "224.0.0.1" || text == "224.0.0.2" {
            return true
        }
        guard dstIP.bytes[0] >= 224, dstIP.bytes[0] <= 239 else {
            return false
        }
        for layer in session.decodedLayers where layer.proto == .ipv4 {
            for field in layer.fields where field.name == "Protocol" {
                if field.value == "2" || field.value.contains("IGMP") {
                    return true
                }
            }
        }
        return false
    }

    // MARK: Source & child builders

    private static func makeLanSource(
        _ subkind: LanSubkind,
        session: SessionSummary,
        endpoints: ParsedEndpoints,
        names: [String: String]
    )
        -> ClassifiedSessionSource
    {
        ClassifiedSessionSource(
            category: .lanDiscovery,
            filterKey: subkind.filterKey,
            title: subkind.title,
            subtitle: subkind.subtitle,
            tableLabel: subkind.tableLabel,
            tableDetail: subkind.subtitle,
            symbolName: TrafficSourceCategory.lanDiscovery.systemImage,
            childTarget: peerChildTarget(session: session, endpoints: endpoints, normalizedResolvedNames: names)
        )
    }

    private static func makeKernelSource(subkind: KernelSubkind, session: SessionSummary) -> ClassifiedSessionSource {
        ClassifiedSessionSource(
            category: .kernelAndLink,
            filterKey: subkind.filterKey,
            title: subkind.title,
            subtitle: subkind.subtitle,
            tableLabel: subkind.tableLabel,
            tableDetail: subkind.subtitle,
            symbolName: TrafficSourceCategory.kernelAndLink.systemImage,
            childTarget: hostChildTarget(for: session)
        )
    }

    private static func hostChildTarget(for session: SessionSummary) -> SourceChildTarget? {
        let trimmed = session.host.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, trimmed != "—" else {
            return nil
        }
        return SourceChildTarget(kind: .host, value: trimmed, label: trimmed)
    }

    private static func peerChildTarget(
        session: SessionSummary,
        endpoints: ParsedEndpoints,
        normalizedResolvedNames: [String: String]
    )
        -> SourceChildTarget?
    {
        let candidatePeer: IPAddressValue? = if let src = endpoints.srcIP,
                                                !isUnspecified(src), !isMulticastOrBroadcast(src), !endpoints.srcIsLocal
        {
            src
        } else if let dst = endpoints.dstIP,
                  !isUnspecified(dst), !isMulticastOrBroadcast(dst), !endpoints.dstIsLocal
        {
            dst
        } else {
            nil
        }

        guard let peerIP = candidatePeer else {
            return nil
        }
        let peerText = peerIP.compressedText
        if let resolved = normalizedResolvedNames[peerText.lowercased()] {
            return SourceChildTarget(kind: .peerIP, value: peerText, label: "\(peerText) · \(resolved)")
        }
        if let localQueryName = mdnsPeerNameHint(for: peerIP, in: session) {
            return SourceChildTarget(kind: .peerIP, value: peerText, label: "\(peerText) · \(localQueryName)")
        }
        if isPrivateGatewayAddress(peerIP) {
            return SourceChildTarget(
                kind: .peerIP,
                value: peerText,
                label: "\(peerText) · \(String(localized: "LAN Gateway"))"
            )
        }
        return SourceChildTarget(kind: .peerIP, value: peerText, label: peerText)
    }

    private static func mdnsPeerNameHint(for peerIP: IPAddressValue, in session: SessionSummary) -> String? {
        guard var query = normalizedNonEmpty(session.dnsQuery) else {
            return nil
        }
        if query.hasSuffix(".") {
            query.removeLast()
        }
        guard query.lowercased().hasSuffix(".local"), IPAddressValue(parsing: query) == nil else {
            return nil
        }
        return session.dnsAnswers.contains { parseBareIP($0) == peerIP } ? query : nil
    }

    // MARK: Endpoint & IP helpers

    private static func parseEndpoints(
        of session: SessionSummary,
        normalizedLocalIPs: Set<IPAddressValue>,
        isViewingSavedCapture: Bool
    )
        -> ParsedEndpoints
    {
        let srcParsed = parseSessionEndpoint(session.sourceEndpointValue, fallback: session.sourceEndpoint)
        let dstParsed = parseSessionEndpoint(session.destinationEndpointValue, fallback: session.destinationEndpoint)
        let srcIP = srcParsed?.ip
        let dstIP = dstParsed?.ip
        let hasReliableLocalIPs = !isViewingSavedCapture && !normalizedLocalIPs.isEmpty
        return ParsedEndpoints(
            protos: Set(session.protocolStack),
            srcIP: srcIP,
            dstIP: dstIP,
            srcPort: srcParsed?.port,
            dstPort: dstParsed?.port,
            hasReliableLocalIPs: hasReliableLocalIPs,
            srcIsLocal: hasReliableLocalIPs && (srcIP.map(normalizedLocalIPs.contains) == true),
            dstIsLocal: hasReliableLocalIPs && (dstIP.map(normalizedLocalIPs.contains) == true),
            dstIsMulticastOrBroadcast: dstIP.map(isMulticastOrBroadcast) == true
        )
    }

    private static func parseSessionEndpoint(
        _ typed: IPEndpoint?,
        fallback raw: String
    )
        -> (ip: IPAddressValue, port: UInt16?)?
    {
        if let typed, let ip = parseBareIP(typed.ip) {
            return (ip, typed.port > 0 ? typed.port : nil)
        }
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, trimmed != "—" else {
            return nil
        }
        if trimmed.hasPrefix("[") {
            guard let closeIndex = trimmed.firstIndex(of: "]") else {
                return nil
            }
            let hostPart = String(trimmed[trimmed.index(after: trimmed.startIndex) ..< closeIndex])
            guard let ip = parseBareIP(hostPart) else {
                return nil
            }
            let remainder = trimmed[trimmed.index(after: closeIndex)...]
            if remainder.isEmpty {
                return (ip, nil)
            }
            if remainder.first == ":", let port = parsePort(remainder.dropFirst()) {
                return (ip, port > 0 ? port : nil)
            }
            return nil
        }
        if trimmed.contains(".") {
            if let lastColon = trimmed.lastIndex(of: ":") {
                let hostPart = String(trimmed[..<lastColon])
                let portSlice = trimmed[trimmed.index(after: lastColon)...]
                if let ip = parseBareIP(hostPart), let port = parsePort(portSlice) {
                    return (ip, port > 0 ? port : nil)
                }
            }
            return parseBareIP(trimmed).map { ($0, nil) }
        }
        if let ip = parseBareIP(trimmed) {
            return (ip, nil)
        }
        if let lastColon = trimmed.lastIndex(of: ":") {
            let hostPart = String(trimmed[..<lastColon])
            let portSlice = trimmed[trimmed.index(after: lastColon)...]
            if let port = parsePort(portSlice), let ip = parseBareIP(hostPart) {
                return (ip, port > 0 ? port : nil)
            }
        }
        return nil
    }

    private static func parsePort(_ slice: Substring) -> UInt16? {
        guard !slice.isEmpty, slice.allSatisfy({ $0 >= "0" && $0 <= "9" }) else {
            return nil
        }
        return UInt16(slice)
    }

    private static func parseBareIP(_ raw: String) -> IPAddressValue? {
        var candidate = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if candidate.hasPrefix("["), candidate.hasSuffix("]"), candidate.count >= 2 {
            candidate.removeFirst()
            candidate.removeLast()
        }
        if let zoneIndex = candidate.firstIndex(of: "%") {
            candidate = String(candidate[..<zoneIndex])
        }
        return IPAddressValue(parsing: candidate)
    }

    private static func normalizeIPSet(_ rawIPs: Set<String>) -> Set<IPAddressValue> {
        var result: Set<IPAddressValue> = []
        result.reserveCapacity(rawIPs.count)
        for raw in rawIPs {
            if let parsed = parseBareIP(raw) {
                result.insert(parsed)
            }
        }
        return result
    }

    private static func normalizeResolvedNames(_ resolvedNames: [String: String]) -> [String: String] {
        var result: [String: String] = [:]
        result.reserveCapacity(resolvedNames.count)
        for key in resolvedNames.keys.sorted() {
            guard let rawName = normalizedNonEmpty(resolvedNames[key]),
                  parseBareIP(rawName) == nil,
                  let ip = parseBareIP(key) else
            {
                continue
            }
            result[ip.compressedText.lowercased()] = rawName
        }
        return result
    }

    private static func isUnspecified(_ ip: IPAddressValue) -> Bool {
        ip.bytes.allSatisfy { $0 == 0 }
    }

    private static func isMulticastOrBroadcast(_ ip: IPAddressValue) -> Bool {
        switch ip.family {
        case .v4:
            guard ip.bytes.count == 4 else { return false }
            let (b0, b1, b2, b3) = (ip.bytes[0], ip.bytes[1], ip.bytes[2], ip.bytes[3])
            if b0 >= 224, b0 <= 239 { return true }
            if b0 == 255, b1 == 255, b2 == 255, b3 == 255 { return true }
            if b3 == 255 {
                return b0 == 10 || (b0 == 172 && (b1 & 0xF0) == 16)
                    || (b0 == 192 && b1 == 168) || (b0 == 169 && b1 == 254)
            }
            return false
        case .v6:
            return ip.bytes.count == 16 && ip.bytes[0] == 0xFF
        }
    }

    private static func isPrivateGatewayAddress(_ ip: IPAddressValue) -> Bool {
        guard ip.family == .v4, ip.bytes.count == 4, ip.bytes[3] == 1 else {
            return false
        }
        let (b0, b1) = (ip.bytes[0], ip.bytes[1])
        return b0 == 10 || (b0 == 192 && b1 == 168) || (b0 == 172 && (b1 & 0xF0) == 16)
    }

    // MARK: String & context normalization helpers

    private static func normalizedProcessName(_ raw: String?) -> String? {
        guard let trimmed = normalizedNonEmpty(raw), trimmed != "—" else {
            return nil
        }
        return trimmed
    }

    private static func normalizedViaProcessName(_ raw: String?, excludingProcessName primary: String) -> String? {
        guard let trimmed = normalizedNonEmpty(raw), trimmed != "—", trimmed != primary else {
            return nil
        }
        return trimmed
    }

    private static func normalizedNonEmpty(_ raw: String?) -> String? {
        guard let trimmed = raw?.trimmingCharacters(in: .whitespacesAndNewlines), !trimmed.isEmpty else {
            return nil
        }
        return trimmed
    }

    private static func normalizeDirectoryPrefix(_ path: String) -> String {
        let trimmed = path.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, trimmed != "/" else {
            return ""
        }
        return trimmed.hasSuffix("/") ? trimmed : trimmed + "/"
    }

    private static func contextRichness(_ context: SessionProcessContext?) -> Int {
        guard let context else { return 0 }
        var score = 1
        if normalizedNonEmpty(context.executablePath) != nil { score += 4 }
        if normalizedNonEmpty(context.bundleIdentifier) != nil { score += 2 }
        if normalizedNonEmpty(context.parentProcessName) != nil { score += 2 }
        if context.hasControllingTTY { score += 1 }
        if context.isRootUser { score += 1 }
        return score
    }
}
