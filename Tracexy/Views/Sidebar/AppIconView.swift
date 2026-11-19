import AppKit
import SwiftUI

/// Renders an app icon: a neutral placeholder symbol for unattributed traffic,
/// the real NSWorkspace icon when the app can be resolved by name, or a
/// gradient monogram fallback otherwise.
struct AppIconView: View {
    // MARK: Internal

    let name: String
    var size: CGFloat = 16

    var body: some View {
        let badgeSize = (size * 0.86).rounded()
        let cornerRadius = (badgeSize * 0.26 * 2).rounded() / 2
        if Self.isUnattributedPlaceholder(name) {
            RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
                .fill(.quaternary)
                .frame(width: badgeSize, height: badgeSize)
                .overlay {
                    Image(systemName: "questionmark")
                        .font(.system(size: max(8, badgeSize * 0.62), weight: .semibold))
                        .foregroundStyle(.secondary)
                }
                .frame(width: size, height: size)
        } else if let icon = Self.resolvedIcon(for: name, size: size) {
            Image(nsImage: icon)
                .resizable()
                .interpolation(.high)
                .frame(width: size, height: size)
        } else {
            RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
                .fill(gradient)
                .frame(width: badgeSize, height: badgeSize)
                .overlay {
                    Text(letter)
                        .font(.system(size: max(9, badgeSize * 0.58), weight: .bold, design: .rounded))
                        .foregroundStyle(.white)
                }
                .frame(width: size, height: size)
        }
    }

    nonisolated static func isUnattributedPlaceholder(_ name: String) -> Bool {
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty || trimmed == "—"
    }

    nonisolated static func candidateApplicationPaths(
        for name: String,
        homeDirectoryURL: URL = FileManager.default.homeDirectoryForCurrentUser
    ) -> [String] {
        let userAppPath = homeDirectoryURL
            .appendingPathComponent("Applications", isDirectory: true)
            .appendingPathComponent("\(name).app", isDirectory: true)
            .path
        return [
            "/Applications/\(name).app",
            "/System/Applications/\(name).app",
            "/System/Applications/Utilities/\(name).app",
            "/System/Library/CoreServices/\(name).app",
            userAppPath,
        ]
    }

    nonisolated static func outermostAppBundlePath(for bundleURL: URL) -> String? {
        var path = bundleURL.standardizedFileURL.path
        while path.count > 1, path.hasSuffix("/") {
            path.removeLast()
        }
        guard let range = path.range(of: ".app/", options: [.caseInsensitive]) else {
            return nil
        }
        let slashIndex = path.index(before: range.upperBound)
        let outerBundlePath = String(path[..<slashIndex])
        guard (outerBundlePath as NSString).lastPathComponent.count > 4 else {
            return nil
        }
        return outerBundlePath
    }

    nonisolated static func matchesRunningApplication(
        localizedName: String?,
        bundleURL: URL?,
        query name: String
    ) -> Bool {
        localizedName == name || bundleURL?.deletingPathExtension().lastPathComponent == name
    }

    nonisolated static func resolvedApplicationBundlePath(
        for name: String,
        catalog: InstalledAppCatalog = .shared,
        homeDirectoryURL: URL = FileManager.default.homeDirectoryForCurrentUser
    ) -> String? {
        if let catalogPath = catalog.appBundlePath(forName: name),
           FileManager.default.fileExists(atPath: catalogPath)
        {
            return catalogPath
        }
        for path in candidateApplicationPaths(for: name, homeDirectoryURL: homeDirectoryURL) {
            if FileManager.default.fileExists(atPath: path) {
                return path
            }
        }
        return nil
    }

    static func resolvedIcon(for name: String, size: CGFloat) -> NSImage? {
        guard !isUnattributedPlaceholder(name) else {
            return nil
        }
        let cacheKey = IconCacheKey(name: name, size: Int(size.rounded()))
        if let cached = resizedIconCache[cacheKey] {
            return cached
        }
        guard let source = resolveIconSource(for: name),
              let icon = source.copy() as? NSImage else
        {
            return nil
        }
        icon.size = NSSize(width: size, height: size)
        resizedIconCache[cacheKey] = icon
        return icon
    }

    static func resolveIconSource(for name: String) -> NSImage? {
        guard !isUnattributedPlaceholder(name), !missingIconNames.contains(name) else {
            return nil
        }
        if let cached = iconCache[name] {
            return cached
        }

        if let bundleID = bundleIDMap[name],
           let appURL = NSWorkspace.shared.urlForApplication(withBundleIdentifier: bundleID)
        {
            let icon = NSWorkspace.shared.icon(forFile: appURL.path)
            iconCache[name] = icon
            return icon
        }

        if let bundlePath = resolvedApplicationBundlePath(for: name) {
            let icon = NSWorkspace.shared.icon(forFile: bundlePath)
            iconCache[name] = icon
            return icon
        }

        for app in NSWorkspace.shared.runningApplications
            where matchesRunningApplication(
                localizedName: app.localizedName,
                bundleURL: app.bundleURL,
                query: name
            )
        {
            if let bundleURL = app.bundleURL,
               let outerBundlePath = outermostAppBundlePath(for: bundleURL),
               FileManager.default.fileExists(atPath: outerBundlePath)
            {
                let icon = NSWorkspace.shared.icon(forFile: outerBundlePath)
                iconCache[name] = icon
                return icon
            }
            if let icon = app.icon {
                iconCache[name] = icon
                return icon
            }
        }

        missingIconNames.insert(name)
        return nil
    }

    // MARK: Private

    private struct IconCacheKey: Hashable {
        let name: String
        let size: Int
    }

    private static var iconCache: [String: NSImage] = [:]
    private static var resizedIconCache: [IconCacheKey: NSImage] = [:]
    private static var missingIconNames: Set<String> = []

    private static let bundleIDMap: [String: String] = [
        "Chrome": "com.google.Chrome",
        "Google Chrome": "com.google.Chrome",
        "Safari": "com.apple.Safari",
        "Firefox": "org.mozilla.firefox",
        "Slack": "com.tinyspeck.slackmacgap",
        "Xcode": "com.apple.dt.Xcode",
        "Spotify": "com.spotify.client",
        "Discord": "com.hnc.Discord",
        "Arc": "company.thebrowser.Browser",
        "Brave Browser": "com.brave.Browser",
        "Microsoft Edge": "com.microsoft.edgemac",
        "Figma": "com.figma.Desktop",
        "Postman": "com.postmanlabs.mac",
    ]

    private var letter: String {
        String(name.prefix(1)).uppercased()
    }

    private var gradient: LinearGradient {
        // Deterministic per-name hue so the same process keeps the same color.
        let hue = Double(abs(name.hashValue) % 360) / 360.0
        return LinearGradient(
            colors: [
                Color(hue: hue, saturation: 0.55, brightness: 0.85),
                Color(hue: hue, saturation: 0.65, brightness: 0.60),
            ],
            startPoint: .topLeading,
            endPoint: .bottomTrailing
        )
    }
}
