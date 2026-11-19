import AppKit
import Foundation
import os
import SwiftUI

// MARK: - SettingsKeys

/// Namespaced `UserDefaults` keys for every persisted preference. Never hardcode
/// a defaults key — everything derives from the family namespace via
/// `TracexyIdentity.defaultsKey` (see the identity abstraction rule).
enum SettingsKeys {
    // MARK: Internal

    static let selectedSettingsTab = key("settings.selectedTab")
    static let appearance = key("settings.appearance")
    static let language = key("settings.language")
    static let defaultView = key("settings.defaultView")
    static let byteUnits = key("settings.byteUnits")
    static let confirmQuitWhileCapturing = key("settings.confirmQuitWhileCapturing")
    static let restoreWorkspace = key("settings.restoreWorkspace")

    static let defaultInterface = key("settings.defaultInterface")
    /// Capture ▸ Manage Interfaces: hidden interfaces, friendly names and comments
    /// (JSON `InterfaceSettings`). App-wide: an interface belongs to this Mac.
    static let interfaceSettings = key("settings.interfaces")
    static let autoStartCapture = key("settings.autoStartCapture")
    static let captureFilterMode = key("settings.captureFilterMode")
    static let bpfExpression = key("settings.bpfExpression")
    /// Named capture filters saved in this Project (JSON `[SavedCaptureFilter]`).
    static let savedCaptureFilters = key("settings.savedCaptureFilters")
    static let snapLength = key("settings.snapLength")
    static let promiscuous = key("settings.promiscuous")
    /// Stop a live capture after this many minutes (0 = never).
    static let autoStopMinutes = key("settings.autoStopMinutes")
    /// Stop a live capture after this many accepted packets (0 = never).
    static let autoStopPackets = key("settings.autoStopPackets")
    /// Save a live capture as a file set: a new file after this many MB (0 = off).
    static let fileSetMegabytes = key("settings.fileSetMegabytes")
    /// Save a live capture as a file set: a new file after this many minutes (0 = off).
    static let fileSetMinutes = key("settings.fileSetMinutes")
    /// Keep only this many newest file-set files (0 = keep every file).
    static let fileSetKeep = key("settings.fileSetKeep")
    static let retainPackets = key("settings.retainPackets")

    static let redactBodies = key("settings.redactBodies")
    static let stripCredentials = key("settings.stripCredentials")
    static let maskIPs = key("settings.maskIPs")
    static let autoClear = key("settings.autoClear")

    /// The validated loopback base address of the local model endpoint, and the
    /// model chosen from what that endpoint advertised. Application-scoped: a
    /// local daemon belongs to this Mac, not to one Project.
    static let assistantEndpoint = key("settings.assistantEndpoint")
    static let assistantModel = key("settings.assistantModel")

    /// The AI Assistant's disclosure opt-ins, one per sensitive field family, all
    /// off by default — the same minimum-disclosure posture the History
    /// automation boundary starts from.
    static let assistantDisclosureProcess = key("settings.assistantDisclosureProcess")
    static let assistantDisclosureHost = key("settings.assistantDisclosureHost")
    static let assistantDisclosureEndpoints = key("settings.assistantDisclosureEndpoints")

    /// Preference keys written by builds before the MCP boundary and the local
    /// Assistant existed. Nothing reads them; they described a listener, a port
    /// and a provider that were never implemented, so leaving them behind would
    /// misrepresent what this build does. They are removed once, at launch.
    static let retiredKeys = [
        key("settings.mcpEnabled"),
        key("settings.mcpPort"),
        key("settings.mcpExposeSessions"),
        key("settings.aiInsights"),
        key("settings.aiProvider"),
    ]

    /// Remove every retired key from one defaults domain. Idempotent, and safe to
    /// run on a domain that never had them.
    static func removeRetiredKeys(from defaults: UserDefaults) {
        for key in retiredKeys where defaults.object(forKey: key) != nil {
            defaults.removeObject(forKey: key)
        }
    }

    // MARK: Private

    private static func key(_ suffix: String) -> String {
        TracexyIdentity.current.defaultsKey(suffix)
    }
}

// MARK: - ProjectScopedSettingsKeys

/// Preference keys that are *not* surfaced in the Settings window but are still
/// owned independently by each Project (pins, Focus Sets, muted noise, hidden
/// sources, remembered panel layout). Centralized here so the per-Project suite
/// seeding and the readers below can never drift apart.
enum ProjectScopedSettingsKeys {
    // MARK: Internal

    static let pinnedHosts = key("pinnedHosts")
    static let focusSets = key("focusSets")
    /// Investigation notes on sessions and findings, keyed by capture content.
    static let investigationNotes = key("investigation.notes")
    static let sessionTags = key("investigation.sessionTags")
    static let recentSessionExpressions = key("investigation.recentExpressions")
    static let savedSessionExpressions = key("investigation.savedExpressions")
    /// One-click filter buttons shown under the toolbar (JSON `[FilterButton]`).
    static let filterButtons = key("investigation.filterButtons.v1")
    /// Named expression macros (JSON `[ExpressionMacro]`).
    static let expressionMacros = key("investigation.expressionMacros.v1")
    /// Named, versioned Tracexy Frame Expressions, isolated to the active Project.
    static let savedFrameFilters = key("investigation.frameFilters.v1")
    /// Ordered, named packet coloring rules (JSON `FrameColorRuleEnvelope`).
    static let savedFrameColorRules = key("investigation.frameColorRules.v1")
    /// Bookmarks of the GeoIP/ASN database files the Project uses, in lookup order.
    static let geoIPDatabases = key("enrichment.geoipDatabases.v1")
    /// The Sessions table's shown/hidden columns and their order (JSON `TableColumnCustomization`).
    static let sessionTableColumns = key("workspace.sessionTableColumns")
    /// Overview ▸ Activity: whether the traffic chart plots bytes, packets or bit rate.
    static let overviewTrafficMeasure = key("overview.trafficMeasure")
    /// Overview: whether the small time chart shows sessions started or retransmissions.
    static let overviewTimeSeries = key("overview.timeSeries")
    /// Names the investigator gave to addresses (JSON `[address: name]`).
    static let addressNames = key("names.addresses")
    /// Address-to-domain mappings passively learned in this Project (JSON).
    static let learnedAddressNames = key("names.learnedAddresses.v1")
    /// Names the investigator gave to IPv4 blocks (JSON `[cidr: name]`).
    static let subnetNames = key("names.subnets")
    /// Where each capture file was left: selection and session expression (JSON).
    static let investigationViewStates = key("investigation.viewStates")
    /// View ▸ Session Time: how the Sessions table shows start times.
    static let sessionTimeFormat = key("workspace.sessionTimeFormat")
    /// View ▸ Frame Time: how frame lists show each frame's time.
    static let frameTimeFormat = key("workspace.frameTimeFormat")
    static let frameTimePrecision = key("workspace.frameTimePrecision")
    /// View ▸ Validate Checksums: note each header checksum's status in the decode tree.
    static let validateChecksums = key("packetDetail.validateChecksums")
    /// View ▸ Zoom In / Out: points added to packet text (hex, decode tree, streams).
    static let packetTextZoom = key("packetDetail.textZoom")
    /// The bytes pane's Show as: `hex` or `bits`.
    static let byteDumpStyle = key("packetDetail.byteDumpStyle")
    /// View ▸ Name Resolution ▸ Resolve Network Addresses in frame lists.
    static let resolveNetworkAddresses = key("packetDetail.resolveNetworkAddresses")
    /// Apply as Column: the decode-tree fields View ▸ All Frames shows as columns.
    static let frameColumns = key("packetDetail.frameColumns")
    /// Capture ▸ Decode As…: port → protocol rules (JSON `[DecodeAsRule]`).
    static let decodeAsRules = key("decode.asRules")
    /// Analyze ▸ Enabled Protocols: the protocols switched off (`ProtocolKind` raw values).
    static let disabledProtocols = key("decode.disabledProtocols")
    static let mutedHosts = key("noise.mutedHosts")
    static let mutedProtocols = key("noise.mutedProtocols")
    static let hiddenSourceApps = key("sources.hiddenApps")
    static let hiddenSourceDomains = key("sources.hiddenDomains")
    static let hiddenSourceLocalNames = key("sources.hiddenLocalNames")
    static let hiddenSourceIPs = key("sources.hiddenIPs")
    static let inspectorLayout = key("workspace.inspectorLayout")
    static let contextDockVisible = key("workspace.contextDockVisible")
    static let allowsAutomaticInspectorReveal = key("workspace.allowsAutomaticInspectorReveal")
    /// Whether Open… copies the chosen capture into the Library (default: open in place).
    static let copiesOpenedCapturesIntoLibrary = key("library.copiesOpenedCaptures")

    // MARK: Private

    private static func key(_ suffix: String) -> String {
        TracexyIdentity.current.defaultsKey(suffix)
    }
}

// MARK: - SettingsTab

enum SettingsTab: String, CaseIterable, Identifiable, Hashable {
    case general
    case capture
    case helper
    case privacy
    case mcp
    case updates

    // MARK: Internal

    var id: String {
        rawValue
    }

    var title: String {
        let bundle = AppLanguage.currentLocalizedBundle()
        return switch self {
        case .general: String(localized: "General", bundle: bundle)
        case .capture: String(localized: "Capture", bundle: bundle)
        case .helper: String(localized: "Helper", bundle: bundle)
        case .privacy: String(localized: "Privacy", bundle: bundle)
        case .mcp: String(localized: "MCP & Assistant", bundle: bundle)
        case .updates: String(localized: "Updates", bundle: bundle)
        }
    }

    var systemImage: String {
        switch self {
        case .general: "gearshape"
        case .capture: "antenna.radiowaves.left.and.right"
        case .helper: "shield.lefthalf.filled"
        case .privacy: "hand.raised"
        case .mcp: "sparkles"
        case .updates: "arrow.down.circle"
        }
    }
}

// MARK: - AppAppearance

/// The user's appearance preference, applied app-wide via `.preferredColorScheme`.
enum AppAppearance: String, CaseIterable, Identifiable {
    case system
    case light
    case dark

    // MARK: Internal

    var id: String {
        rawValue
    }

    var title: String {
        let bundle = AppLanguage.currentLocalizedBundle()
        return switch self {
        case .system: String(localized: "System", bundle: bundle)
        case .light: String(localized: "Light", bundle: bundle)
        case .dark: String(localized: "Dark", bundle: bundle)
        }
    }

    var systemImage: String {
        switch self {
        case .system: "circle.lefthalf.filled"
        case .light: "sun.max.fill"
        case .dark: "moon.fill"
        }
    }

    var detail: String {
        let bundle = AppLanguage.currentLocalizedBundle()
        return switch self {
        case .system: String(localized: "Matches macOS", bundle: bundle)
        case .light: String(localized: "Always light", bundle: bundle)
        case .dark: String(localized: "Always dark", bundle: bundle)
        }
    }

    /// `nil` follows the system; otherwise forces light/dark.
    var colorScheme: ColorScheme? {
        switch self {
        case .system: nil
        case .light: .light
        case .dark: .dark
        }
    }
}

// MARK: - AppLanguage

/// Application display language preference. Updates SwiftUI's `\.locale` live
/// and writes `AppleLanguages` so AppKit menus and `String(localized:)` match on launch.
enum AppLanguage: String, CaseIterable, Identifiable {
    case system
    case simplifiedChinese = "zh-Hans"
    case english = "en"
    case vietnamese = "vi"

    // MARK: Internal

    nonisolated static let launchRawValue: String = {
        guard !TracexyIdentity.isRunningTests else {
            return AppLanguage.system.rawValue
        }
        return UserDefaults.standard.string(forKey: SettingsKeys.language) ?? AppLanguage.system.rawValue
    }()

    var id: String {
        rawValue
    }

    var title: String {
        switch self {
        case .system: String(localized: "System Default", bundle: AppLanguage.currentLocalizedBundle())
        case .simplifiedChinese: "简体中文"
        case .english: "English"
        case .vietnamese: "Tiếng Việt"
        }
    }

    nonisolated var localeOverride: Locale? {
        switch self {
        case .system:
            _ = Self.localeObserver
            let now = ProcessInfo.processInfo.systemUptime
            let lookup = Self.languageStateLock.withLock {
                state -> (resolved: Bool, locale: Locale?, base: Bundle, testingSys: [String]?) in
                if let testingSys = state.testingSystemLanguages {
                    return (false, nil, state.testingBaseBundle ?? .main, testingSys)
                }
                if Self.isRunningTests {
                    return (true, nil, .main, nil)
                }
                // When the process launched with a custom language override (e.g. "en"),
                // SwiftUI's default environment Locale is pinned to that launch override;
                // supply the true host system localization so switching back to `.system`
                // updates all SwiftUI `Text(...)` views immediately without restarting.
                guard Self.launchRawValue != AppLanguage.system.rawValue else {
                    return (true, nil, .main, nil)
                }
                let effectiveBase = state.testingBaseBundle ?? .main
                if state.cachedSystemLocaleBasePath == effectiveBase.bundlePath,
                   now - state.cachedSystemLocaleResolvedAt < LanguageBundleState.systemLocalizationTTL
                {
                    return (true, state.cachedSystemLocalization.map(Locale.init(identifier:)), effectiveBase, nil)
                }
                return (false, nil, effectiveBase, nil)
            }
            if lookup.resolved {
                return lookup.locale
            }
            let sysLang = Self.resolvedSystemLocalization(
                in: lookup.base,
                preferredLanguages: lookup.testingSys
            )
            if lookup.testingSys == nil {
                let basePath = lookup.base.bundlePath
                Self.languageStateLock.withLock { state in
                    state.cachedSystemLocaleBasePath = basePath
                    state.cachedSystemLocalization = sysLang
                    state.cachedSystemLocaleResolvedAt = now
                }
            }
            return sysLang.map(Locale.init(identifier:))
        case .simplifiedChinese,
             .english,
             .vietnamese:
            return Locale(identifier: rawValue)
        }
    }

    nonisolated static func hostSystemPreferredLanguages() -> [String] {
        if let global = CFPreferencesCopyValue(
            "AppleLanguages" as CFString,
            kCFPreferencesAnyApplication,
            kCFPreferencesCurrentUser,
            kCFPreferencesAnyHost
        ) as? [String], !global.isEmpty {
            return global
        }
        return Locale.preferredLanguages
    }

    nonisolated static func resolvedSystemLocalization(
        in base: Bundle = .main,
        preferredLanguages: [String]? = nil
    ) -> String? {
        let prefs = preferredLanguages ?? hostSystemPreferredLanguages()
        let candidates = base.localizations.filter { $0 != "Base" }
        guard !candidates.isEmpty, !prefs.isEmpty else {
            return nil
        }
        return Bundle.preferredLocalizations(from: candidates, forPreferences: prefs).first
    }

    nonisolated static func localizedBundle(for rawValue: String, in base: Bundle = .main) -> Bundle {
        let lang = AppLanguage(rawValue: rawValue) ?? .system
        if lang == .system {
            _ = localeObserver
            let now = ProcessInfo.processInfo.systemUptime
            let basePath = base.bundlePath
            let lookup: (hit: Bundle?, testingSys: [String]?) = languageStateLock.withLock { state in
                if let testingSys = state.testingSystemLanguages {
                    return (nil, testingSys)
                }
                if Self.isRunningTests {
                    return (base, nil)
                }
                if state.cachedSystemBundleBasePath == basePath,
                   let cached = state.cachedSystemBundle,
                   now - state.cachedSystemBundleResolvedAt < LanguageBundleState.systemLocalizationTTL
                {
                    return (cached, nil)
                }
                return (nil, nil)
            }
            if let hit = lookup.hit {
                return hit
            }
            let testingSys = lookup.testingSys
            guard let sysLang = resolvedSystemLocalization(in: base, preferredLanguages: testingSys) else {
                if testingSys == nil {
                    languageStateLock.withLock { state in
                        state.cachedSystemBundleBasePath = basePath
                        state.cachedSystemBundle = base
                        state.cachedSystemBundleResolvedAt = now
                    }
                }
                return base
            }
            let cacheKey = "\(basePath)|system|\(sysLang)"
            return languageStateLock.withLock { state in
                let resolved: Bundle
                if let cached = state.cachedBundles[cacheKey] {
                    resolved = cached
                } else {
                    resolved = base.path(forResource: sysLang, ofType: "lproj")
                        .flatMap(Bundle.init(path:)) ?? base
                    state.cachedBundles[cacheKey] = resolved
                }
                if testingSys == nil {
                    state.cachedSystemBundleBasePath = basePath
                    state.cachedSystemBundle = resolved
                    state.cachedSystemBundleResolvedAt = now
                }
                return resolved
            }
        }
        let cacheKey = "\(base.bundlePath)|\(lang.rawValue)"
        return languageStateLock.withLock { state in
            if let cached = state.cachedBundles[cacheKey] {
                return cached
            }
            let resolved = base.path(forResource: lang.rawValue, ofType: "lproj")
                .flatMap(Bundle.init(path:)) ?? base
            state.cachedBundles[cacheKey] = resolved
            return resolved
        }
    }

    nonisolated static func currentLocalizedBundle(in base: Bundle? = nil) -> Bundle {
        let (currentRawValue, testingBaseBundle) = languageStateLock.withLock {
            ($0.currentRawValue, $0.testingBaseBundle)
        }
        let effectiveBase = base ?? testingBaseBundle ?? .main
        return localizedBundle(for: currentRawValue, in: effectiveBase)
    }

    nonisolated static func currentLocaleOverride() -> Locale? {
        let currentRawValue = languageStateLock.withLock(\.currentRawValue)
        return AppLanguage(rawValue: currentRawValue)?.localeOverride
    }

    nonisolated static func syncCurrentLanguage(_ rawValue: String) {
        guard !Self.isRunningTests else {
            return
        }
        let resolved = (AppLanguage(rawValue: rawValue) ?? .system).rawValue
        languageStateLock.withLock { state in
            state.currentRawValue = resolved
        }
    }

    nonisolated static func withTemporaryLanguageForTesting<T>(
        _ rawValue: String,
        baseBundle: Bundle? = nil,
        systemLanguages: [String]? = nil,
        perform body: () throws -> T
    ) rethrows -> T {
        let resolved = (AppLanguage(rawValue: rawValue) ?? .system).rawValue
        let previous = languageStateLock.withLock { state -> (String, Bundle?, [String]?) in
            let old = (state.currentRawValue, state.testingBaseBundle, state.testingSystemLanguages)
            state.currentRawValue = resolved
            state.testingBaseBundle = baseBundle
            state.testingSystemLanguages = systemLanguages
            return old
        }
        defer {
            languageStateLock.withLock { state in
                state.currentRawValue = previous.0
                state.testingBaseBundle = previous.1
                state.testingSystemLanguages = previous.2
                if let baseBundle, previous.1?.bundlePath != baseBundle.bundlePath {
                    let prefix = "\(baseBundle.bundlePath)|"
                    state.cachedBundles = state.cachedBundles.filter { !$0.key.hasPrefix(prefix) }
                    if state.cachedSystemBundleBasePath == baseBundle.bundlePath {
                        state.cachedSystemBundleBasePath = nil
                        state.cachedSystemBundle = nil
                        state.cachedSystemBundleResolvedAt = -100
                    }
                    if state.cachedSystemLocaleBasePath == baseBundle.bundlePath {
                        state.cachedSystemLocaleBasePath = nil
                        state.cachedSystemLocalization = nil
                        state.cachedSystemLocaleResolvedAt = -100
                    }
                }
            }
        }
        return try body()
    }

    nonisolated static func applyToAppleLanguages(
        _ rawValue: String,
        defaults: UserDefaults = TracexyIdentity.applicationDefaults
    ) {
        let resolved = AppLanguage(rawValue: rawValue) ?? .system
        if !Self.isRunningTests {
            languageStateLock.withLock { state in
                state.currentRawValue = resolved.rawValue
            }
        }
        switch resolved {
        case .system:
            defaults.removeObject(forKey: "AppleLanguages")
        case .simplifiedChinese,
             .english,
             .vietnamese:
            defaults.set([resolved.rawValue], forKey: "AppleLanguages")
        }
        defaults.synchronize()
    }

    @MainActor
    static func relaunchApplication() {
        let configuration = NSWorkspace.OpenConfiguration()
        configuration.createsNewApplicationInstance = true
        NSWorkspace.shared.openApplication(at: Bundle.main.bundleURL, configuration: configuration) { _, error in
            guard error == nil else {
                return
            }
            Task { @MainActor in
                NSApplication.shared.terminate(nil)
            }
        }
    }

    // MARK: Private

    private nonisolated struct LanguageBundleState: @unchecked Sendable {
        static let systemLocalizationTTL: TimeInterval = 5.0

        var currentRawValue: String
        var cachedBundles: [String: Bundle] = [:]
        var testingBaseBundle: Bundle?
        var testingSystemLanguages: [String]?
        var cachedSystemBundleBasePath: String?
        var cachedSystemBundle: Bundle?
        var cachedSystemBundleResolvedAt: TimeInterval = -100
        var cachedSystemLocaleBasePath: String?
        var cachedSystemLocalization: String?
        var cachedSystemLocaleResolvedAt: TimeInterval = -100
    }

    private nonisolated struct LocaleObserverBox: @unchecked Sendable {
        let token: NSObjectProtocol
    }

    private nonisolated static let isRunningTests = TracexyIdentity.isRunningTests

    private nonisolated static let languageStateLock = OSAllocatedUnfairLock(
        initialState: LanguageBundleState(currentRawValue: launchRawValue)
    )

    private nonisolated static let localeObserver = LocaleObserverBox(
        token: NotificationCenter.default.addObserver(
            forName: NSLocale.currentLocaleDidChangeNotification,
            object: nil,
            queue: nil
        ) { _ in
            languageStateLock.withLock { state in
                state.cachedSystemBundleBasePath = nil
                state.cachedSystemBundle = nil
                state.cachedSystemBundleResolvedAt = -100
                state.cachedSystemLocaleBasePath = nil
                state.cachedSystemLocalization = nil
                state.cachedSystemLocaleResolvedAt = -100
            }
        }
    )
}

// MARK: - DefaultView

/// Which surface a fresh workspace lands on. Backs the General → "Default view" pref.
enum DefaultView: String, CaseIterable, Identifiable {
    case sessions
    case overview

    // MARK: Internal

    var id: String {
        rawValue
    }

    var title: String {
        let bundle = AppLanguage.currentLocalizedBundle()
        return switch self {
        case .sessions: String(localized: "Sessions", bundle: bundle)
        case .overview: String(localized: "Overview", bundle: bundle)
        }
    }

    var sidebarItem: SidebarItem {
        switch self {
        case .sessions: .sessions
        case .overview: .overview
        }
    }
}

// MARK: - ByteUnits

/// Binary (KiB) vs decimal (KB) byte formatting preference.
enum ByteUnits: String, CaseIterable, Identifiable {
    case binary
    case decimal

    // MARK: Internal

    var id: String {
        rawValue
    }

    var title: String {
        let bundle = AppLanguage.currentLocalizedBundle()
        return switch self {
        case .binary: String(localized: "Binary — KiB", bundle: bundle)
        case .decimal: String(localized: "Decimal — KB", bundle: bundle)
        }
    }

    var countStyle: ByteCountFormatter.CountStyle {
        switch self {
        case .binary: .binary
        case .decimal: .decimal
        }
    }

    /// The app-wide Units preference. Read from the application defaults on each
    /// use so every byte figure in the app follows the General → Units setting.
    nonisolated static func current(defaults: UserDefaults = .standard) -> ByteUnits {
        let isStandard = defaults === UserDefaults.standard
        let isApplication = !isStandard && defaults === TracexyIdentity.applicationDefaults
        guard isStandard || isApplication else {
            return defaults.string(forKey: SettingsKeys.byteUnits)
                .flatMap(ByteUnits.init(rawValue:)) ?? .binary
        }
        _ = defaultsObserver
        let (generation, cached) = byteFormatLock.withLock { state in
            (
                state.defaultsGeneration,
                isStandard ? state.cachedStandardUnits : state.cachedApplicationUnits
            )
        }
        if let cached {
            return cached
        }
        let resolved = defaults.string(forKey: SettingsKeys.byteUnits)
            .flatMap(ByteUnits.init(rawValue:)) ?? .binary
        byteFormatLock.withLock { state in
            if state.defaultsGeneration == generation {
                if isStandard {
                    state.cachedStandardUnits = resolved
                } else {
                    state.cachedApplicationUnits = resolved
                }
            }
        }
        return resolved
    }

    /// Formats a byte count in the preferred units — the single formatter every
    /// byte figure in the UI goes through.
    nonisolated static func string(_ bytes: Int64, defaults: UserDefaults = .standard) -> String {
        let units = current(defaults: defaults)
        let isDecimal = units == .decimal
        if let locale = AppLanguage.currentLocaleOverride() {
            let key = ByteFormatCacheKey(
                bytes: bytes,
                isDecimal: isDecimal,
                localeID: "override:\(locale.identifier)"
            )
            if let cached = byteFormatLock.withLock({ $0.entries[key] }) {
                return cached
            }
            let style: ByteCountFormatStyle.Style = isDecimal ? .decimal : .binary
            let formatted = bytes.formatted(.byteCount(style: style).locale(locale))
            byteFormatLock.withLock { state in
                if state.entries.count >= ByteFormatCacheState.maxEntries {
                    state.entries.removeAll(keepingCapacity: true)
                }
                state.entries[key] = formatted
            }
            return formatted
        }

        let systemLocaleID = Locale.current.identifier
        let key = ByteFormatCacheKey(
            bytes: bytes,
            isDecimal: isDecimal,
            localeID: "system:\(systemLocaleID)"
        )
        return byteFormatLock.withLock { state in
            if state.systemLocaleIdentifier != systemLocaleID {
                state.systemLocaleIdentifier = systemLocaleID
                state.binaryFormatter = ByteFormatCacheState.makeFormatter(countStyle: .binary)
                state.decimalFormatter = ByteFormatCacheState.makeFormatter(countStyle: .decimal)
                state.entries.removeAll(keepingCapacity: true)
            }
            if let cached = state.entries[key] {
                return cached
            }
            let formatter = isDecimal ? state.decimalFormatter : state.binaryFormatter
            let formatted = formatter.string(fromByteCount: bytes)
            if state.entries.count >= ByteFormatCacheState.maxEntries {
                state.entries.removeAll(keepingCapacity: true)
            }
            state.entries[key] = formatted
            return formatted
        }
    }

    // MARK: Private

    private nonisolated struct ByteFormatCacheKey: Hashable, Sendable {
        let bytes: Int64
        let isDecimal: Bool
        let localeID: String
    }

    private nonisolated struct ByteFormatCacheState: @unchecked Sendable {
        static let maxEntries = 4_096

        var defaultsGeneration: UInt64 = 0
        var cachedStandardUnits: ByteUnits?
        var cachedApplicationUnits: ByteUnits?
        var systemLocaleIdentifier: String
        var binaryFormatter: ByteCountFormatter
        var decimalFormatter: ByteCountFormatter
        var entries: [ByteFormatCacheKey: String] = [:]

        init() {
            systemLocaleIdentifier = Locale.current.identifier
            binaryFormatter = Self.makeFormatter(countStyle: .binary)
            decimalFormatter = Self.makeFormatter(countStyle: .decimal)
        }

        static func makeFormatter(countStyle: ByteCountFormatter.CountStyle) -> ByteCountFormatter {
            let formatter = ByteCountFormatter()
            formatter.countStyle = countStyle
            return formatter
        }
    }

    private nonisolated struct DefaultsObserverBox: @unchecked Sendable {
        let token: NSObjectProtocol
    }

    private nonisolated static let byteFormatLock = OSAllocatedUnfairLock(
        initialState: ByteFormatCacheState()
    )

    private nonisolated static let defaultsObserver = DefaultsObserverBox(
        token: NotificationCenter.default.addObserver(
            forName: UserDefaults.didChangeNotification,
            object: nil,
            queue: nil
        ) { _ in
            byteFormatLock.withLock { state in
                state.defaultsGeneration &+= 1
                state.cachedStandardUnits = nil
                state.cachedApplicationUnits = nil
            }
        }
    )
}

// MARK: - CaptureFilterMode

enum CaptureFilterMode: String, CaseIterable, Identifiable {
    case all
    case custom

    // MARK: Internal

    var id: String {
        rawValue
    }

    var title: String {
        let bundle = AppLanguage.currentLocalizedBundle()
        return switch self {
        case .all: String(localized: "All traffic", bundle: bundle)
        case .custom: String(localized: "Custom (BPF)", bundle: bundle)
        }
    }
}

// MARK: - CaptureSettingsResolver

/// Turns persisted Capture-Settings preferences into validated, bounded capture
/// inputs, read fresh at each capture start. Pure and deterministic so the
/// mapping (and the clamping of invalid persisted values to a safe default) is
/// unit-testable without a live capture or `UserDefaults`.
enum CaptureSettingsResolver {
    /// The retention-window sizes the UI offers, and the safe fallback used when a
    /// persisted value is none of them. These make the existing 8k/20k/50k picker
    /// behavioral: the chosen value becomes the in-memory save/export capacity.
    static let retainPacketsChoices = [8_000, 20_000, 50_000]
    static let defaultRetainPackets = 8_000

    /// Clamp a persisted snap length into the supported range (delegating to the
    /// shared bound), so a corrupt or out-of-range value can never open an
    /// oversized or too-small capture buffer.
    static func resolvedSnapLength(_ raw: Int) -> Int {
        CaptureConfiguration.clampedSnapLength(raw)
    }

    /// Map a persisted retention choice to an allowed capacity; anything not in the
    /// offered set clamps to the safe default rather than sizing the window blindly.
    static func resolvedRetainPackets(_ raw: Int) -> Int {
        retainPacketsChoices.contains(raw) ? raw : defaultRetainPackets
    }

    /// Map the persisted filter mode + expression to a BPF string: `.all` → no
    /// filter (`nil`); `.custom` → the trimmed expression, or `nil` when it is
    /// blank so an empty custom filter is never sent as a (meaningless) expression.
    static func resolvedBPF(filterMode: String, expression: String) -> String? {
        guard filterMode == CaptureFilterMode.custom.rawValue else {
            return nil
        }
        let trimmed = expression.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }

    /// Assemble a capture configuration from the current preferences. Reads the
    /// snap length, promiscuous flag, filter mode, and BPF expression fresh, so a
    /// settings change since the last capture takes effect at the next start.
    /// `defaults` is injectable so the whole mapping is testable without touching
    /// the shared store.
    static func configuration(
        interface: String,
        defaults: UserDefaults = .standard,
        optimizeBPF: Bool = true
    )
        -> CaptureConfiguration
    {
        CaptureConfiguration(
            interface: interface,
            snapLength: resolvedSnapLength(defaults.integer(forKey: SettingsKeys.snapLength)),
            promiscuous: defaults.bool(forKey: SettingsKeys.promiscuous),
            bpf: resolvedBPF(
                filterMode: defaults.string(forKey: SettingsKeys.captureFilterMode) ?? CaptureFilterMode.all.rawValue,
                expression: defaults.string(forKey: SettingsKeys.bpfExpression) ?? ""
            ),
            optimizeBPF: optimizeBPF
        )
    }

    /// Resolve the configured retention-window capacity from the current
    /// preferences, clamping an invalid persisted value to the safe default.
    static func retainCapacity(defaults: UserDefaults = .standard) -> Int {
        resolvedRetainPackets(defaults.integer(forKey: SettingsKeys.retainPackets))
    }
}

// MARK: - PrivacySettingsResolver

/// Resolves export protections from persisted preferences without treating an
/// unset `UserDefaults` key as `false`. The Privacy pane's shipped defaults are
/// protective, so a fresh install must apply them before the user has opened
/// Settings or caused `@AppStorage` to materialize the keys.
enum PrivacySettingsResolver {
    // MARK: Internal

    static func exportPolicy(defaults: UserDefaults = .standard) -> SessionExportPrivacyPolicy {
        SessionExportPrivacyPolicy(
            redactPayloadBodies: resolvedBool(
                forKey: SettingsKeys.redactBodies,
                defaultValue: true,
                defaults: defaults
            ),
            stripCredentials: resolvedBool(
                forKey: SettingsKeys.stripCredentials,
                defaultValue: true,
                defaults: defaults
            ),
            maskIPAddresses: resolvedBool(
                forKey: SettingsKeys.maskIPs,
                defaultValue: false,
                defaults: defaults
            )
        )
    }

    // MARK: Private

    private static func resolvedBool(
        forKey key: String,
        defaultValue: Bool,
        defaults: UserDefaults
    )
        -> Bool
    {
        (defaults.object(forKey: key) as? Bool) ?? defaultValue
    }
}

// MARK: - AutoClear

enum AutoClear: String, CaseIterable, Identifiable {
    case never
    case minutes15
    case hour1
    case hours24

    // MARK: Internal

    var id: String {
        rawValue
    }

    var title: String {
        let bundle = AppLanguage.currentLocalizedBundle()
        return switch self {
        case .never: String(localized: "Never", bundle: bundle)
        case .minutes15: String(localized: "After 15 minutes", bundle: bundle)
        case .hour1: String(localized: "After 1 hour", bundle: bundle)
        case .hours24: String(localized: "After 24 hours", bundle: bundle)
        }
    }

    /// The retention window this choice represents, or `nil` for `.never` (no
    /// automatic clearing). The coordinator — never this type or the store — turns
    /// a non-`nil` interval into a `HistoryRetentionPolicy`.
    var retentionInterval: TimeInterval? {
        switch self {
        case .never: nil
        case .minutes15: 900
        case .hour1: 3_600
        case .hours24: 86_400
        }
    }
}

// MARK: - HistoryRetentionSettingsResolver

/// Resolves the persisted History Auto-clear choice from injected `UserDefaults`.
/// An absent key (fresh install, before the picker has been touched) or an unknown
/// persisted value fails closed to `.never`, so corrupt or stale defaults can never
/// trigger deletion. Pure and deterministic, so the mapping is unit-testable without
/// the shared store.
enum HistoryRetentionSettingsResolver {
    static func autoClear(defaults: UserDefaults = .standard) -> AutoClear {
        guard let raw = defaults.string(forKey: SettingsKeys.autoClear) else {
            return .never
        }
        return AutoClear(rawValue: raw) ?? .never
    }
}

// MARK: - AppInfo

/// Read-only app identity for the Updates pane. Real values from the bundle —
/// never invented.
enum AppInfo {
    static var versionString: String {
        let short = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "1.0"
        let build = Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "1"
        return "\(short) (build \(build))"
    }
}
