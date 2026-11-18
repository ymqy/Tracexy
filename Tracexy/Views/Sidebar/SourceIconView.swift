import AppKit
import SwiftUI

/// Unified squircle icon badge for the 7-dimension traffic source system.
///
/// macOS `.app` bundle icons include a ~7.5% transparent outer margin inside their
/// `size × size` image canvas (leaving an ~85% visible squircle). `SourceIconView`
/// renders non-app sources inside an optically matched continuous squircle tile
/// (`0.86 × size`) centered in the same `size × size` layout slot, so `.app` icons,
/// CLI tools, daemons, LAN broadcasts, and kernel protocol rows align on one exact
/// vertical axis in both `SidebarView` and `SessionCenterView`.
struct SourceIconView: View {
    // MARK: Internal

    let category: TrafficSourceCategory
    let filterKey: String
    let title: String
    var subtitle: String?
    var fallbackSymbol: String?
    var isActive = false
    var size: CGFloat = 18

    var body: some View {
        if category == .app {
            AppIconView(name: title, size: size)
        } else if category == .systemService,
                  Self.systemProcessesWithBundleIcons.contains(title),
                  let icon = AppIconView.resolvedIcon(for: Self.canonicalBundleLookupName(for: title), size: size)
        {
            Image(nsImage: icon)
                .resizable()
                .interpolation(.high)
                .frame(width: size, height: size)
        } else {
            symbolSquircleBadge
                .frame(width: size, height: size)
        }
    }

    nonisolated static func resolvedSymbolName(
        category: TrafficSourceCategory,
        filterKey: String,
        title: String,
        subtitle: String? = nil,
        fallbackSymbol: String? = nil
    ) -> String {
        switch category {
        case .app:
            return fallbackSymbol ?? "app.badge"
        case .cli:
            return cliSymbol(for: filterKey.isEmpty ? title : filterKey)
        case .thirdPartyService:
            if subtitle == String(localized: "System Network Extension") {
                return "puzzlepiece.extension"
            }
            if subtitle == String(localized: "Root Background Daemon") {
                return "server.rack"
            }
            return "gearshape"
        case .systemService:
            return systemServiceSymbol(for: filterKey.isEmpty ? title : filterKey)
        case .lanDiscovery:
            return lanSymbol(for: filterKey)
        case .kernelAndLink:
            return kernelSymbol(for: filterKey)
        case .unattributed:
            return "questionmark"
        }
    }

    // MARK: Private

    private static let systemProcessesWithBundleIcons: Set<String> = [
        "Finder",
        "Safari",
        "Dock",
        "ControlCenter",
        "Control Center",
        "NotificationCenter",
        "SystemUIServer",
        "Spotlight",
    ]

    @Environment(\.colorScheme) private var colorScheme

    private var badgeSize: CGFloat {
        max(12, size - 2)
    }

    private var cornerRadius: CGFloat {
        (badgeSize * 0.26 * 2).rounded() / 2
    }

    private var symbolName: String {
        Self.resolvedSymbolName(
            category: category,
            filterKey: filterKey,
            title: title,
            subtitle: subtitle,
            fallbackSymbol: fallbackSymbol
        )
    }

    private var tint: Color {
        if isActive {
            return .accentColor
        }
        return switch category {
        case .app: .accentColor
        case .cli: .indigo
        case .thirdPartyService: .purple
        case .systemService: .cyan
        case .lanDiscovery: .teal
        case .kernelAndLink: .orange
        case .unattributed: .secondary
        }
    }

    private var fillOpacity: Double {
        if category == .unattributed, !isActive {
            return colorScheme == .dark ? 0.14 : 0.10
        }
        if isActive {
            return colorScheme == .dark ? 0.28 : 0.20
        }
        return colorScheme == .dark ? 0.18 : 0.13
    }

    private var strokeOpacity: Double {
        if category == .unattributed, !isActive {
            return colorScheme == .dark ? 0.22 : 0.16
        }
        if isActive {
            return 0.50
        }
        return colorScheme == .dark ? 0.34 : 0.24
    }

    private var symbolSquircleBadge: some View {
        let shape = RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
        return shape
            .fill(tint.opacity(fillOpacity))
            .frame(width: badgeSize, height: badgeSize)
            .overlay {
                shape.strokeBorder(tint.opacity(strokeOpacity), lineWidth: 0.75)
            }
            .overlay {
                Image(systemName: symbolName)
                    .font(.system(size: Theme.Icon.small, weight: .semibold))
                    .imageScale(.small)
                    .foregroundStyle(category == .unattributed && !isActive ? AnyShapeStyle(.secondary) : AnyShapeStyle(tint))
            }
    }

    nonisolated private static func canonicalBundleLookupName(for name: String) -> String {
        if name == "Control Center" {
            return "ControlCenter"
        }
        return name
    }

    nonisolated private static func cliSymbol(for command: String) -> String {
        let lower = command.lowercased()
        switch lower {
        case "zsh", "bash", "fish", "sh", "-zsh", "-bash", "-fish", "-sh":
            return "terminal"
        case "curl", "wget", "nc", "telnet", "ftp", "tftp":
            return "arrow.up.arrow.down"
        case "ping", "ping6", "traceroute", "traceroute6", "networkquality", "tcpdump", "netstat", "lsof":
            return "waveform.path.ecg"
        case "dig", "nslookup", "host", "whois", "dns-sd", "dscacheutil", "scutil", "arp", "ndp", "ifconfig", "route", "networksetup":
            return "magnifyingglass"
        case "git", "gh":
            return "arrow.triangle.branch"
        case "ssh", "scp", "sftp", "rsync", "openssl":
            return "lock.shield"
        case "brew", "npm", "pnpm", "pip", "pip3", "uv", "cargo":
            return "shippingbox"
        case "python", "python3", "node", "bun", "deno", "go", "ruby", "rustc", "swift", "swiftc", "clang", "lldb", "java", "codex":
            return "curlybraces"
        default:
            return "terminal"
        }
    }

    nonisolated private static func systemServiceSymbol(for daemon: String) -> String {
        switch daemon {
        case "mDNSResponder", "_mdnsresponder":
            return "bonjour"
        case "apsd":
            return "bell"
        case "usbmuxd", "remoted", "remotepairingd", "AMPDeviceDiscoveryAgent":
            return "iphone"
        case "rapportd", "sharingd":
            return "airplayaudio"
        case "cloudd", "bird", "nsurlsessiond", "appleaccountd":
            return "icloud"
        case "trustd", "ocspd", "secinitd", "syspolicyd", "tccd":
            return "checkmark.shield"
        case "amsengagementd", "amsondevicestoraged", "appstoreagent", "appstored", "softwareupdated":
            return "arrow.down.circle"
        case "configd", "symptomsd", "WiFiAgent", "airportd", "nesessionmanager", "nehelper", "networkserviceproxy":
            return "wifi"
        case "identityservicesd", "imagent":
            return "message"
        case "timed":
            return "clock"
        case "locationd", "geod":
            return "location"
        case "parsecd", "siriknowledged":
            return "magnifyingglass"
        case "WindowServer", "loginwindow", "ControlCenter", "Control Center":
            return "macwindow"
        default:
            if daemon.hasPrefix("com.apple.appkit.") {
                return "macwindow"
            }
            if daemon.hasSuffix("Extension") || daemon == "chronod" || daemon == "weatherd" || daemon == "pkd" {
                return "square.grid.2x2"
            }
            return "gearshape"
        }
    }

    nonisolated private static func lanSymbol(for filterKey: String) -> String {
        switch filterKey {
        case "lan:mdns": "bonjour"
        case "lan:ssdp": "tv"
        case "lan:dhcp": "arrow.triangle.2.circlepath"
        case "lan:naming": "tag"
        case "lan:arp": "point.3.connected.trianglepath.dotted"
        default: "dot.radiowaves.right"
        }
    }

    nonisolated private static func kernelSymbol(for filterKey: String) -> String {
        switch filterKey {
        case "kernel:arp": "link"
        case "kernel:ndp": "network"
        case "kernel:igmp": "dot.radiowaves.up.forward"
        case "kernel:icmp": "waveform.path.ecg"
        case "kernel:tcp-teardown": "arrow.uturn.backward"
        case "kernel:inbound": "shield.lefthalf.filled"
        default: "network"
        }
    }
}
