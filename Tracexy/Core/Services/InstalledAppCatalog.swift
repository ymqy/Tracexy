import Foundation
import os

/// Thread-safe, lazily refreshed catalog of installed macOS host `.app` bundles.
///
/// Indexes folder stems, `Info.plist` display/bundle names, bundle identifiers,
/// and localized `InfoPlist.strings` / `InfoPlist.loctable` display names so
/// apps whose user-facing name differs from their `.app` folder stem (such as
/// localized names) can be classified and resolved to icons even when not running.
nonisolated final class InstalledAppCatalog: Sendable {
    // MARK: Lifecycle

    init(
        searchRootURLs: [URL] = InstalledAppCatalog.defaultSearchRootURLs,
        refreshInterval: TimeInterval = 30
    ) {
        self.searchRootURLs = searchRootURLs
        self.refreshInterval = max(0, refreshInterval)
    }

    // MARK: Internal

    static let shared = InstalledAppCatalog()

    static var defaultSearchRootURLs: [URL] {
        [
            URL(fileURLWithPath: "/Applications", isDirectory: true),
            URL(fileURLWithPath: "/System/Applications", isDirectory: true),
            URL(fileURLWithPath: "/System/Applications/Utilities", isDirectory: true),
            FileManager.default.homeDirectoryForCurrentUser
                .appendingPathComponent("Applications", isDirectory: true),
        ]
    }

    func appBundlePath(forName name: String) -> String? {
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            return nil
        }
        let snapshot = currentSnapshot()
        return snapshot.exactNames[trimmed] ?? snapshot.lowercasedNames[trimmed.lowercased()]
    }

    func appBundlePath(forBundleIdentifier bundleID: String) -> String? {
        let normalized = bundleID.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !normalized.isEmpty else {
            return nil
        }
        return currentSnapshot().bundleIdentifiers[normalized]
    }

    func containsApp(named name: String) -> Bool {
        appBundlePath(forName: name) != nil
    }

    // MARK: Private

    private struct Snapshot: Sendable {
        var exactNames: [String: String] = [:]
        var lowercasedNames: [String: String] = [:]
        var bundleIdentifiers: [String: String] = [:]
        var rootModificationDates: [String: Date?] = [:]
        var lastCheckedAt: Date?
        var hasLoaded = false
    }

    private static let candidateLocalizationDirectories: [String] = [
        "zh-Hans.lproj",
        "zh_CN.lproj",
        "zh-Hant.lproj",
        "zh_TW.lproj",
        "zh_HK.lproj",
        "en.lproj",
        "Base.lproj",
        "vi.lproj",
    ]

    private static let candidateLoctableLocales: [String] = [
        "zh-Hans",
        "zh_CN",
        "zh-Hant",
        "zh_TW",
        "zh_HK",
        "en",
        "Base",
        "vi",
    ]

    private static let skippedPackageExtensions: Set<String> = [
        "app",
        "appex",
        "bundle",
        "framework",
        "kext",
        "plugin",
        "prefpane",
        "xpc",
    ]

    private let searchRootURLs: [URL]
    private let refreshInterval: TimeInterval
    private let state = OSAllocatedUnfairLock(initialState: Snapshot())

    private func currentSnapshot(now: Date = Date()) -> Snapshot {
        let cached = state.withLock { $0 }
        if cached.hasLoaded,
           let lastCheckedAt = cached.lastCheckedAt,
           now.timeIntervalSince(lastCheckedAt) <= refreshInterval
        {
            return cached
        }

        let currentModDates = Self.rootModificationDates(for: searchRootURLs)
        if cached.hasLoaded, currentModDates == cached.rootModificationDates {
            return state.withLock { snapshot in
                snapshot.lastCheckedAt = now
                return snapshot
            }
        }

        let rebuilt = Self.scanRoots(
            searchRootURLs,
            modificationDates: currentModDates,
            checkedAt: now
        )
        return state.withLock { snapshot in
            snapshot = rebuilt
            return snapshot
        }
    }

    private static func rootModificationDates(for roots: [URL]) -> [String: Date?] {
        var result: [String: Date?] = [:]
        for root in roots {
            let key = normalizedDirectoryPath(root.path)
            let values = try? root.resourceValues(forKeys: [.contentModificationDateKey])
            result[key] = values?.contentModificationDate
        }
        return result
    }

    private static func scanRoots(
        _ roots: [URL],
        modificationDates: [String: Date?],
        checkedAt: Date
    )
        -> Snapshot
    {
        var snapshot = Snapshot(
            rootModificationDates: modificationDates,
            lastCheckedAt: checkedAt,
            hasLoaded: true
        )

        let fileManager = FileManager.default
        for root in roots {
            let depth1Entries = sortedDirectoryChildren(at: root, fileManager: fileManager)
            var depth1Apps: [URL] = []
            var depth1Subdirectories: [URL] = []

            for entry in depth1Entries {
                let ext = entry.pathExtension.lowercased()
                if ext == "app" {
                    if isDirectoryFollowingSymlinks(entry, fileManager: fileManager) {
                        depth1Apps.append(entry)
                    }
                    continue
                }
                if !skippedPackageExtensions.contains(ext),
                   isNonSymlinkDirectory(entry)
                {
                    depth1Subdirectories.append(entry)
                }
            }

            for appURL in depth1Apps {
                indexAppBundle(at: appURL, into: &snapshot, fileManager: fileManager)
            }

            for subdir in depth1Subdirectories {
                let depth2Entries = sortedDirectoryChildren(at: subdir, fileManager: fileManager)
                for entry in depth2Entries where entry.pathExtension.lowercased() == "app" {
                    if isDirectoryFollowingSymlinks(entry, fileManager: fileManager) {
                        indexAppBundle(at: entry, into: &snapshot, fileManager: fileManager)
                    }
                }
            }
        }

        return snapshot
    }

    private static func sortedDirectoryChildren(at directoryURL: URL, fileManager: FileManager) -> [URL] {
        // Do not pass `.skipsHiddenFiles`: macOS marks Cryptex-backed symlinks such as
        // `/Applications/Safari.app` with `UF_HIDDEN`. Filter dot-prefixed entries instead.
        guard let entries = try? fileManager.contentsOfDirectory(
            at: directoryURL,
            includingPropertiesForKeys: [.isDirectoryKey, .isSymbolicLinkKey],
            options: []
        ) else {
            return []
        }
        return entries
            .filter { !$0.lastPathComponent.hasPrefix(".") }
            .sorted { lhs, rhs in
                lhs.lastPathComponent.localizedStandardCompare(rhs.lastPathComponent) == .orderedAscending
            }
    }

    private static func isDirectoryFollowingSymlinks(_ url: URL, fileManager: FileManager) -> Bool {
        var isDirectory: ObjCBool = false
        return fileManager.fileExists(atPath: url.path, isDirectory: &isDirectory) && isDirectory.boolValue
    }

    private static func isNonSymlinkDirectory(_ url: URL) -> Bool {
        guard let values = try? url.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey]) else {
            return false
        }
        return values.isDirectory == true && values.isSymbolicLink != true
    }

    private static func indexAppBundle(
        at appURL: URL,
        into snapshot: inout Snapshot,
        fileManager: FileManager
    ) {
        let bundlePath = normalizedDirectoryPath(appURL.path)
        guard PktapHeader.isHostAppBundlePath(bundlePath) else {
            return
        }

        var names: [String] = []
        let folderStem = trimmedNonEmpty(appURL.deletingPathExtension().lastPathComponent)
        if let folderStem {
            names.append(folderStem)
        }

        var bundleIdentifier: String?
        let contentsURL = appURL.appendingPathComponent("Contents", isDirectory: true)
        let infoPlistURL = contentsURL.appendingPathComponent("Info.plist", isDirectory: false)
        if let info = readPropertyListDictionary(at: infoPlistURL) {
            if let displayName = trimmedNonEmpty(info["CFBundleDisplayName"] as? String) {
                names.append(displayName)
            }
            if let bundleName = trimmedNonEmpty(info["CFBundleName"] as? String) {
                names.append(bundleName)
            }
            bundleIdentifier = trimmedNonEmpty(info["CFBundleIdentifier"] as? String)
        }

        let resourcesURL = contentsURL.appendingPathComponent("Resources", isDirectory: true)
        for localization in candidateLocalizationDirectories {
            let stringsURL = resourcesURL
                .appendingPathComponent(localization, isDirectory: true)
                .appendingPathComponent("InfoPlist.strings", isDirectory: false)
            guard fileManager.fileExists(atPath: stringsURL.path),
                  let strings = readPropertyListDictionary(at: stringsURL) else
            {
                continue
            }
            if let displayName = trimmedNonEmpty(strings["CFBundleDisplayName"] as? String) {
                names.append(displayName)
            }
            if let bundleName = trimmedNonEmpty(strings["CFBundleName"] as? String) {
                names.append(bundleName)
            }
        }

        let loctableURL = resourcesURL.appendingPathComponent("InfoPlist.loctable", isDirectory: false)
        if fileManager.fileExists(atPath: loctableURL.path),
           let loctable = readPropertyListDictionary(at: loctableURL)
        {
            for locale in candidateLoctableLocales {
                guard let entries = loctable[locale] as? [String: Any] else {
                    continue
                }
                if let displayName = trimmedNonEmpty(entries["CFBundleDisplayName"] as? String) {
                    names.append(displayName)
                }
                if let bundleName = trimmedNonEmpty(entries["CFBundleName"] as? String) {
                    names.append(bundleName)
                }
            }
        }

        for name in names {
            if snapshot.exactNames[name] == nil {
                snapshot.exactNames[name] = bundlePath
            }
            let lowercased = name.lowercased()
            if snapshot.lowercasedNames[lowercased] == nil {
                snapshot.lowercasedNames[lowercased] = bundlePath
            }
        }

        if let bundleIdentifier {
            let lowercasedID = bundleIdentifier.lowercased()
            if snapshot.bundleIdentifiers[lowercasedID] == nil {
                snapshot.bundleIdentifiers[lowercasedID] = bundlePath
            }
        }
    }

    private static func readPropertyListDictionary(at url: URL) -> [String: Any]? {
        NSDictionary(contentsOf: url) as? [String: Any]
    }

    private static func normalizedDirectoryPath(_ rawPath: String) -> String {
        var path = rawPath
        while path.count > 1, path.hasSuffix("/") {
            path.removeLast()
        }
        return path
    }

    private static func trimmedNonEmpty(_ value: String?) -> String? {
        guard let trimmed = value?.trimmingCharacters(in: .whitespacesAndNewlines),
              !trimmed.isEmpty else
        {
            return nil
        }
        return trimmed
    }
}
