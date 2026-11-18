import AppKit
import CoreGraphics
import Foundation
import SwiftUI
import Testing
@testable import Tracexy

@Suite("Sidebar app icon view")
struct AppIconViewTests {
    // MARK: Internal

    @Test("Identifies empty, whitespace-only, and em-dash names as unattributed placeholders")
    func unattributedPlaceholderClassification() {
        #expect(AppIconView.isUnattributedPlaceholder(""))
        #expect(AppIconView.isUnattributedPlaceholder("  "))
        #expect(AppIconView.isUnattributedPlaceholder("\t\n "))
        #expect(AppIconView.isUnattributedPlaceholder("—"))

        #expect(!AppIconView.isUnattributedPlaceholder("Finder"))
        #expect(!AppIconView.isUnattributedPlaceholder("Safari"))
        #expect(!AppIconView.isUnattributedPlaceholder("Google Chrome"))
        #expect(!AppIconView.isUnattributedPlaceholder("Terminal"))
        #expect(!AppIconView.isUnattributedPlaceholder("curl"))
        #expect(!AppIconView.isUnattributedPlaceholder("-"))
    }

    @Test("Unattributed placeholders resolve nil icon source without crashing")
    @MainActor
    func placeholderIconSourceReturnsNil() {
        #expect(AppIconView.resolveIconSource(for: "") == nil)
        #expect(AppIconView.resolveIconSource(for: "  ") == nil)
        #expect(AppIconView.resolveIconSource(for: "—") == nil)
        #expect(AppIconView.resolvedIcon(for: "—", size: 16) == nil)
    }

    @Test("Resolves real icons for macOS system applications across lookup directories")
    @MainActor
    func resolvesSystemApplicationIcons() throws {
        let finderSource = try #require(AppIconView.resolveIconSource(for: "Finder"))
        #expect(finderSource.size.width > 0)
        #expect(finderSource.size.height > 0)

        let safariSource = try #require(AppIconView.resolveIconSource(for: "Safari"))
        #expect(safariSource.size.width > 0)

        let calculatorSource = try #require(AppIconView.resolveIconSource(for: "Calculator"))
        #expect(calculatorSource.size.width > 0)

        let terminalSource = try #require(AppIconView.resolveIconSource(for: "Terminal"))
        #expect(terminalSource.size.width > 0)

        let resizedFirst = try #require(AppIconView.resolvedIcon(for: "Finder", size: 16))
        let resizedSecond = try #require(AppIconView.resolvedIcon(for: "Finder", size: 16))
        #expect(resizedFirst.size == NSSize(width: 16, height: 16))
        #expect(resizedFirst === resizedSecond)
    }

    @Test("Caches missing process icon lookups safely")
    @MainActor
    func unknownProcessReturnsNilOnRepeatLookups() {
        let unknownName = "com.tracexy.tests.nonexistent-app-icon-target"
        #expect(AppIconView.resolveIconSource(for: unknownName) == nil)
        #expect(AppIconView.resolveIconSource(for: unknownName) == nil)
        #expect(AppIconView.resolvedIcon(for: unknownName, size: 16) == nil)
    }

    @Test("Enumerates standard system, CoreServices, Utilities, and user Applications bundle paths")
    func candidateApplicationPathsCoverExpectedLocations() {
        let homeURL = URL(fileURLWithPath: "/tmp/example-home", isDirectory: true)
        let paths = AppIconView.candidateApplicationPaths(for: "SampleApp", homeDirectoryURL: homeURL)

        #expect(paths == [
            "/Applications/SampleApp.app",
            "/System/Applications/SampleApp.app",
            "/System/Applications/Utilities/SampleApp.app",
            "/System/Library/CoreServices/SampleApp.app",
            "/tmp/example-home/Applications/SampleApp.app",
        ])
    }

    @Test("Extracts outermost .app bundle path only when bundle URL is nested inside another .app")
    func outermostAppBundlePathResolution() {
        let topLevel = URL(fileURLWithPath: "/Applications/Safari.app", isDirectory: true)
        #expect(AppIconView.outermostAppBundlePath(for: topLevel) == nil)

        let topLevelNoSlash = URL(fileURLWithPath: "/Applications/Safari.app")
        #expect(AppIconView.outermostAppBundlePath(for: topLevelNoSlash) == nil)

        let nestedHelper = URL(
            fileURLWithPath: "/Applications/Example.app/Contents/Frameworks/Example Helper.app",
            isDirectory: true
        )
        #expect(AppIconView.outermostAppBundlePath(for: nestedHelper) == "/Applications/Example.app")

        let doublyNested = URL(
            fileURLWithPath: "/tmp/example-home/Apps/Outer.app/Contents/Helpers/Middle.app/Contents/XPCServices/Inner.app"
        )
        #expect(AppIconView.outermostAppBundlePath(for: doublyNested) == "/tmp/example-home/Apps/Outer.app")
    }

    @Test("Matches running applications by either localizedName or bundle basename")
    func runningApplicationMatching() {
        let bundleURL = URL(fileURLWithPath: "/Applications/WeChat.app", isDirectory: true)

        #expect(AppIconView.matchesRunningApplication(
            localizedName: "微信",
            bundleURL: bundleURL,
            query: "微信"
        ))
        #expect(AppIconView.matchesRunningApplication(
            localizedName: "微信",
            bundleURL: bundleURL,
            query: "WeChat"
        ))
        #expect(!AppIconView.matchesRunningApplication(
            localizedName: "微信",
            bundleURL: bundleURL,
            query: "Safari"
        ))
    }

    @Test("Renders neutral placeholder badge for unattributed traffic instead of colored monogram")
    @MainActor
    func rendersNeutralPlaceholderInsteadOfColoredMonogram() throws {
        let dashMaxChroma = try Self.maximumPixelChroma(
            of: AppIconView(name: "—", size: 32).environment(\.colorScheme, .light)
        )
        let emptyMaxChroma = try Self.maximumPixelChroma(
            of: AppIconView(name: "", size: 32).environment(\.colorScheme, .light)
        )
        let monogramMaxChroma = try Self.maximumPixelChroma(
            of: AppIconView(name: "TracexyUnresolvedDaemon", size: 32).environment(\.colorScheme, .light)
        )

        #expect(dashMaxChroma <= 8)
        #expect(emptyMaxChroma <= 8)
        #expect(monogramMaxChroma >= 60)
    }

    @Test("SourceIconView resolves distinct valid SF Symbols across CLI, daemon, LAN, and kernel sources")
    @MainActor
    func sourceIconViewResolvesDistinctValidSymbols() {
        let cases: [(TrafficSourceCategory, String, String, String)] = [
            (.cli, "curl", "curl", "arrow.up.arrow.down"),
            (.cli, "ping", "ping", "waveform.path.ecg"),
            (.cli, "git", "git", "arrow.triangle.branch"),
            (.cli, "python3", "python3", "curlybraces"),
            (.cli, "zsh", "zsh", "terminal"),
            (.systemService, "mDNSResponder", "mDNSResponder", "bonjour"),
            (.systemService, "apsd", "apsd", "bell"),
            (.systemService, "usbmuxd", "usbmuxd", "iphone"),
            (.systemService, "rapportd", "rapportd", "airplayaudio"),
            (.systemService, "appleaccountd", "appleaccountd", "icloud"),
            (.systemService, "trustd", "trustd", "checkmark.shield"),
            (.systemService, "configd", "configd", "wifi"),
            (.systemService, "com.apple.appkit.xpc.openAndSavePanelService", "com.apple.appkit.xpc.openAndSavePanelService", "macwindow"),
            (.systemService, "unknownsysd", "unknownsysd", "gearshape"),
            (.lanDiscovery, "lan:mdns", "Bonjour / mDNS", "bonjour"),
            (.lanDiscovery, "lan:ssdp", "SSDP / UPnP", "tv"),
            (.lanDiscovery, "lan:dhcp", "DHCP Lease Broadcast", "arrow.triangle.2.circlepath"),
            (.lanDiscovery, "lan:arp", "Peer ARP Resolution", "point.3.connected.trianglepath.dotted"),
            (.kernelAndLink, "kernel:arp", "ARP Resolution", "link"),
            (.kernelAndLink, "kernel:ndp", "IPv6 Neighbor & Router Discovery", "network"),
            (.kernelAndLink, "kernel:icmp", "ICMP Probe & Diagnostics", "waveform.path.ecg"),
            (.kernelAndLink, "kernel:tcp-teardown", "Kernel TCP Teardown / Reset", "arrow.uturn.backward"),
            (.kernelAndLink, "kernel:inbound", "Inbound Unanswered Port", "shield.lefthalf.filled"),
            (.unattributed, "—", "Unattributed", "questionmark"),
        ]

        for (category, filterKey, title, expectedSymbol) in cases {
            let resolved = SourceIconView.resolvedSymbolName(
                category: category,
                filterKey: filterKey,
                title: title
            )
            #expect(resolved == expectedSymbol)
            #expect(NSImage(systemSymbolName: resolved, accessibilityDescription: nil) != nil)
        }
    }

    // MARK: Private

    @MainActor
    private static func maximumPixelChroma(of view: some View) throws -> Int {
        let renderer = ImageRenderer(content: view)
        renderer.scale = 2
        let cgImage = try #require(renderer.cgImage)

        let width = cgImage.width
        let height = cgImage.height
        let bytesPerRow = width * 4
        var pixels = [UInt8](repeating: 0, count: height * bytesPerRow)
        let colorSpace = CGColorSpaceCreateDeviceRGB()
        let bitmapInfo = CGImageAlphaInfo.premultipliedLast.rawValue

        let drawn = pixels.withUnsafeMutableBytes { rawBuffer -> Bool in
            guard let baseAddress = rawBuffer.baseAddress,
                  let context = CGContext(
                      data: baseAddress,
                      width: width,
                      height: height,
                      bitsPerComponent: 8,
                      bytesPerRow: bytesPerRow,
                      space: colorSpace,
                      bitmapInfo: bitmapInfo
                  ) else
            {
                return false
            }
            context.draw(cgImage, in: CGRect(x: 0, y: 0, width: width, height: height))
            return true
        }
        #expect(drawn)

        var maxChroma = 0
        for index in stride(from: 0, to: pixels.count, by: 4) {
            let alpha = Int(pixels[index + 3])
            guard alpha > 16 else {
                continue
            }
            let red = Int(pixels[index])
            let green = Int(pixels[index + 1])
            let blue = Int(pixels[index + 2])
            let chroma = max(red, green, blue) - min(red, green, blue)
            if chroma > maxChroma {
                maxChroma = chroma
            }
        }
        return maxChroma
    }
}
