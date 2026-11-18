import Darwin
import Foundation
import os
import Testing
@testable import Tracexy

@Suite("ProcessResolver netstat socket lookup & bundle resolution")
struct ProcessResolverTests {
    @Test
    func parsesRealNetstatTCPAndUDPRowsIncludingMultiWordProcesses() {
        let lines = [
            "Active Internet connections (including servers)",
            "Proto Recv-Q Send-Q Local Address Foreign Address (state)"
                + " rxbytes txbytes rhiwat shiwat process:pid state options gencnt flags flags1 usecnt rtncnt fltrs",
            "tcp4 0 0 192.168.0.130.52881 47.57.244.14.81 ESTABLISHED"
                + " 46862 15389 131072 131072 OrbStack Helper:94285"
                + " 00102 00000008 00fc6329 00000080 04000900 2 0 000000",
            "tcp4 0 0 127.0.0.1.57009 127.0.0.1.56683 ESTABLISHED"
                + " 338556 1688763 503104 146988 Antigravity Help:85092"
                + " 00102 00000104 00fd0f49 00000081 01000800 2 0 000000",
            "tcp4 0 0 192.168.0.130.55718 142.251.10.188.443 ESTABLISHED"
                + " 12040 3412 131072 131072 Google Chrome He:1234"
                + " 00102 00000008 00fc1001 00000080 04000900 2 0 000000",
            "tcp4 0 0 192.168.0.130.55719 142.251.10.188.443 ESTABLISHED"
                + " 1024 512 131072 131072 Microsoft Teams :12345"
                + " 00102 00000008 00fc1002 00000080 04000900 2 0 000000",
            "tcp6 0 0 fe80::1%en0.1024 fe80::2%en0.1025 ESTABLISHED"
                + " 2332 1017 131264 132108 UURemoteDaemon:512"
                + " 00102 00000204 00a29e6f 00100001 04080900 2 0 000000",
            "tcp6 0 0 ::1.8080 *.* LISTEN"
                + " 0 0 131072 131072 usbmuxd:402 00100 00000006 002a7cc5 00000000 00000800 1 0 000000",
            "tcp46 0 0 *.8443 *.* LISTEN"
                + " 0 0 131072 131072 nsurlsessiond:501 00100 00000006 00199ca1 00000000 00000800 1 0 000000",
            "udp4 0 0 *.5353 *.*"
                + " 701513134 175454162 786896 9216 _mdnsresponder:456"
                + " 00100 00050200 000008fb 10000000 04000800 1 0 000002",
            "udp46 0 0 *.546 *.*"
                + " 0 560 786896 9216 configd:369 00180 00000000 00fb450d 00008000 00000800 1 0 000002",
            "udp6 0 0 fe80::185c:d75f:a2bc:7c15%en0.50569 *.*"
                + " 1200 800 786896 9216 apsd:311 00100 00000204 00f75ab6 00080083 01000800 2 0 000000",
            "udp4 0 0 *.* *.*"
                + " 0 0 786896 9216 airportd:492 00080 00000000 00000aea 00000000 00000800 1 0 000000",
            "udp4 0 0 127.0.0.1.0 *.*"
                + " 0 0 786896 9216 airportd:492 00080 00000000 00000aeb 00000000 00000800 1 0 000000",
        ]
        let output = lines.joined(separator: "\n")
        let table = ProcessResolver.parseNetstat(output)

        #expect(
            table.specific[ProcessResolver.SocketEndpoint(ip: "192.168.0.130", port: 52_881)]
                == ProcessResolver.ResolvedProcess(pid: 94_285, command: "OrbStack Helper")
        )
        #expect(
            table.specific[ProcessResolver.SocketEndpoint(ip: "127.0.0.1", port: 57_009)]
                == ProcessResolver.ResolvedProcess(pid: 85_092, command: "Antigravity Help")
        )
        #expect(
            table.specific[ProcessResolver.SocketEndpoint(ip: "192.168.0.130", port: 55_718)]
                == ProcessResolver.ResolvedProcess(pid: 1_234, command: "Google Chrome He")
        )
        #expect(
            table.specific[ProcessResolver.SocketEndpoint(ip: "192.168.0.130", port: 55_719)]
                == ProcessResolver.ResolvedProcess(pid: 12_345, command: "Microsoft Teams")
        )
        #expect(
            table.specific[ProcessResolver.SocketEndpoint(ip: "fe80::1", port: 1_024)]
                == ProcessResolver.ResolvedProcess(pid: 512, command: "UURemoteDaemon")
        )
        #expect(
            table.specific[ProcessResolver.SocketEndpoint(ip: "::1", port: 8_080)]
                == ProcessResolver.ResolvedProcess(pid: 402, command: "usbmuxd")
        )
        #expect(
            table.specific[ProcessResolver.SocketEndpoint(ip: "fe80::185c:d75f:a2bc:7c15", port: 50_569)]
                == ProcessResolver.ResolvedProcess(pid: 311, command: "apsd")
        )
        #expect(
            table.wildcard[8_443]
                == ProcessResolver.ResolvedProcess(pid: 501, command: "nsurlsessiond")
        )
        #expect(
            table.wildcard[5_353]
                == ProcessResolver.ResolvedProcess(pid: 456, command: "_mdnsresponder")
        )
        #expect(
            table.wildcard[546]
                == ProcessResolver.ResolvedProcess(pid: 369, command: "configd")
        )
        #expect(table.wildcard[0] == nil)
        #expect(table.specific[ProcessResolver.SocketEndpoint(ip: "127.0.0.1", port: 0)] == nil)
    }

    @Test
    func prefersActiveSocketOverTimeWaitOnSameEndpoint() {
        let lines = [
            "tcp4 0 0 127.0.0.1.57009 127.0.0.1.56001 TIME_WAIT"
                + " 512 256 131072 131072 oldproc:111 02131 00000008 00fd1ea1 00000080 04000900 0 0 000000",
            "tcp4 0 0 127.0.0.1.57009 *.* LISTEN"
                + " 0 0 131072 131072 Antigravity Help:85092 00100 00000106 00f3e42c 00000001 00000800 1 0 000000",
            "tcp6 0 0 fd00:60::1c48:ce1e:9d20:3f4.56769 fd00:60::14d4:8335:8095:8306.62078 TIME_WAIT"
                + " 1620 712 131520 132060 usbmuxd:402 02031 00000000 00fd13aa 00000081 04000900 0 0 000000",
        ]
        let table = ProcessResolver.parseNetstat(lines.joined(separator: "\n"))

        #expect(
            table.specific[ProcessResolver.SocketEndpoint(ip: "127.0.0.1", port: 57_009)]
                == ProcessResolver.ResolvedProcess(pid: 85_092, command: "Antigravity Help")
        )
        #expect(
            table.specific[ProcessResolver.SocketEndpoint(ip: "fd00:60::1c48:ce1e:9d20:3f4", port: 56_769)]
                == ProcessResolver.ResolvedProcess(pid: 402, command: "usbmuxd")
        )
    }

    @Test
    func specificEndpointBeatsWildcardAndRejectsForeignIPCollisions() {
        var resolved = ProcessResolver.ResolvedSocketTable()
        resolved.specific[ProcessResolver.SocketEndpoint(ip: "127.0.0.1", port: 8_080)] = "LocalDevProxy"
        resolved.wildcard[8_080] = "WildcardServer"
        resolved.wildcard[5_353] = "mDNSResponder"
        resolved.wildcard[5_000] = "ControlCenter"
        resolved.specific[ProcessResolver.SocketEndpoint(ip: "fe80::1", port: 1_024)] = "UURemoteDaemon"

        let localIPs: Set<String> = ["192.168.0.130", "127.0.0.1", "::1", "fe80::1%en0"]

        // 1. Exact `(ip, port)` match takes precedence over `*.port` wildcard.
        #expect(
            resolved.appName(
                forEndpoints: "127.0.0.1:8080",
                "127.0.0.1:59100",
                localIPs: localIPs
            ) == "LocalDevProxy"
        )

        // 2. Wildcard `*.port` matches when the endpoint IP is a verified local IP and no specific entry exists.
        #expect(
            resolved.appName(
                forEndpoints: "192.168.0.130:8080",
                "198.51.100.10:52341",
                localIPs: localIPs
            ) == "WildcardServer"
        )
        #expect(
            resolved.appName(
                forEndpoints: "192.168.0.130:5353",
                "224.0.0.251:5353",
                localIPs: localIPs
            ) == "mDNSResponder"
        )

        // 3. Inbound session where `destination` is the local endpoint.
        #expect(
            resolved.appName(
                forEndpoints: "198.51.100.42:60123",
                "192.168.0.130:5000",
                localIPs: localIPs
            ) == "ControlCenter"
        )

        // 4. Foreign LAN IP whose port happens to equal a local wildcard port MUST NOT match.
        #expect(
            resolved.appName(
                forEndpoints: "192.168.0.50:5000",
                "198.51.100.42:443",
                localIPs: localIPs
            ) == nil
        )
        #expect(
            resolved.appName(
                forEndpoints: "192.168.0.50:5353",
                "224.0.0.251:5353",
                localIPs: localIPs
            ) == nil
        )

        // 5. IPv6 endpoints match in both bracketed (`[fe80::1]:1024`) and PacketDecoder uncompressed forms.
        #expect(
            resolved.appName(
                forEndpoints: "[fe80::1]:1024",
                "[fe80::99]:1024",
                localIPs: localIPs
            ) == "UURemoteDaemon"
        )
        #expect(
            resolved.appName(
                forEndpoints: "fe80:0:0:0:0:0:0:1:1024",
                "fe80:0:0:0:0:0:0:99:1024",
                localIPs: localIPs
            ) == "UURemoteDaemon"
        )
    }

    @Test
    func extractsOutermostAppBundleAndResolvesDisplayName() {
        let helperExec = "/Applications/Antigravity.app/Contents/Frameworks/"
            + "Antigravity Helper (Plugin).app/Contents/MacOS/Antigravity Helper (Plugin)"
        #expect(
            ProcessResolver.outermostAppBundlePath(fromExecutablePath: helperExec)
                == "/Applications/Antigravity.app"
        )

        let appexExec = "/Applications/Tailscale.app/Contents/PlugIns/"
            + "IPNExtension.appex/Contents/MacOS/IPNExtension"
        #expect(
            ProcessResolver.outermostAppBundlePath(fromExecutablePath: appexExec)
                == "/Applications/Tailscale.app"
        )

        let xpcExec = "/Applications/Safari.app/Contents/XPCServices/"
            + "com.apple.WebKit.Networking.xpc/Contents/MacOS/com.apple.WebKit.Networking"
        #expect(
            ProcessResolver.outermostAppBundlePath(fromExecutablePath: xpcExec)
                == "/Applications/Safari.app"
        )

        #expect(ProcessResolver.outermostAppBundlePath(fromExecutablePath: "/usr/sbin/mDNSResponder") == nil)

        // Outermost `.app` prefers Bundle display name and ignores NSRunningApplication helper name.
        let orbHelperPath = "/Applications/OrbStack.app/Contents/Frameworks/"
            + "OrbStack Helper.app/Contents/MacOS/OrbStack Helper"
        let resolvedFromBundle = ProcessResolver.resolveAppName(
            pid: 94_285,
            command: "OrbStack Helper",
            executablePathProvider: { _ in orbHelperPath },
            bundleNameLookup: { path in path == "/Applications/OrbStack.app" ? "OrbStack" : nil },
            runningAppNameLookup: { _ in "OrbStack Helper" }
        )
        #expect(resolvedFromBundle == "OrbStack")

        // Falls back to outermost `.app` folder basename (preserving inner dots) when Bundle lookup returns nil.
        let nodeHelperPath = "/Applications/Node.js.app/Contents/Frameworks/"
            + "Node.js Helper.app/Contents/MacOS/Node.js Helper"
        let resolvedFromFolder = ProcessResolver.resolveAppName(
            pid: 777,
            command: "Node.js Helper",
            executablePathProvider: { _ in nodeHelperPath },
            bundleNameLookup: { _ in nil },
            runningAppNameLookup: { _ in "Node.js Helper" }
        )
        #expect(resolvedFromFolder == "Node.js")

        // When executable has no `.app/`, falls back to NSRunningApplication, basename, then command.
        let systemXPCPath = "/System/Library/Frameworks/WebKit.framework/XPCServices/"
            + "com.apple.WebKit.Networking.xpc/Contents/MacOS/com.apple.WebKit.Networking"
        let resolvedRunningXPC = ProcessResolver.resolveAppName(
            pid: 94_326,
            command: "com.apple.WebKit",
            executablePathProvider: { _ in systemXPCPath },
            bundleNameLookup: { _ in nil },
            runningAppNameLookup: { _ in "Safari Networking" }
        )
        #expect(resolvedRunningXPC == "Safari Networking")

        let ampPath = "/System/Library/PrivateFrameworks/AMPDevices.framework/"
            + "Versions/A/Support/AMPDeviceDiscoveryAgent"
        let resolvedDaemonBasename = ProcessResolver.resolveAppName(
            pid: 717,
            command: "AMPDeviceDiscove",
            executablePathProvider: { _ in ampPath },
            bundleNameLookup: { _ in nil },
            runningAppNameLookup: { _ in nil }
        )
        #expect(resolvedDaemonBasename == "AMPDeviceDiscoveryAgent")

        let resolvedExitedFallback = ProcessResolver.resolveAppName(
            pid: 402,
            command: "usbmuxd",
            executablePathProvider: { _ in nil },
            bundleNameLookup: { _ in nil },
            runningAppNameLookup: { _ in nil }
        )
        #expect(resolvedExitedFallback == "usbmuxd")
    }

    @Test
    func extractsPortAndDiscoversLocalLoopbackIPs() {
        #expect(ProcessResolver.port(from: "10.0.0.2:50467") == 50_467)
        #expect(ProcessResolver.port(from: "[fe80::1]:443") == 443)
        #expect(ProcessResolver.port(from: "::1:8080") == 8_080)
        #expect(ProcessResolver.port(from: "*:5353") == 5_353)
        #expect(ProcessResolver.port(from: "[fe80::1]") == nil)
        #expect(ProcessResolver.port(from: "no-port") == nil)

        let localIPs = ProcessResolver.discoverLocalIPs()
        #expect(localIPs.contains("127.0.0.1"))
        #expect(localIPs.contains("::1"))
        #expect(localIPs.allSatisfy { !$0.contains("%") })
    }

    @Test
    @MainActor
    func refreshesThrottledAt400msAndResolvesEndpointsOnMainActor() async throws {
        #expect(ProcessResolver.refreshThrottleInterval == 0.4)

        let callCount = OSAllocatedUnfairLock(initialState: 0)
        let netstatFixture = [
            "tcp4 0 0 192.168.0.130.55718 142.251.10.188.443 ESTABLISHED"
                + " 12040 3412 131072 131072 Antigravity Help:85092"
                + " 00102 00000008 00fc1001 00000080 04000900 2 0 000000",
            "udp4 0 0 *.5353 *.*"
                + " 1024 512 786896 9216 mDNSResponder:503 00100 00050200 000008fb 10000000 04000800 1 0 000002",
        ].joined(separator: "\n")

        let resolver = ProcessResolver(
            netstatRunner: {
                callCount.withLock { count in
                    count += 1
                }
                return netstatFixture
            },
            localIPsProvider: { ["192.168.0.130", "127.0.0.1", "::1"] },
            appNameResolver: { pid, command in
                pid == 85_092 ? "Antigravity" : command
            }
        )

        resolver.refresh()
        for _ in 0 ..< 40 {
            if resolver.appName(forEndpoints: "192.168.0.130:55718", "142.251.10.188:443") != nil {
                break
            }
            try await Task.sleep(nanoseconds: 10_000_000)
        }

        #expect(resolver.appName(forEndpoints: "192.168.0.130:55718", "142.251.10.188:443") == "Antigravity")
        #expect(resolver.appName(forEndpoints: "192.168.0.130:5353", "224.0.0.251:5353") == "mDNSResponder")
        #expect(resolver.appName(forEndpoints: "192.168.0.99:5353", "224.0.0.251:5353") == nil)
        #expect(callCount.withLock { $0 } == 1)

        // Immediate unforced refresh within 0.4s throttle window must be suppressed.
        resolver.refresh()
        try await Task.sleep(nanoseconds: 30_000_000)
        #expect(callCount.withLock { $0 } == 1)

        // Forced refresh bypasses throttle immediately.
        resolver.refresh(force: true)
        for _ in 0 ..< 40 {
            if callCount.withLock({ $0 }) == 2 {
                break
            }
            try await Task.sleep(nanoseconds: 10_000_000)
        }
        #expect(callCount.withLock { $0 } == 2)
    }

    @Test
    @MainActor
    func collectsLiveLibprocSocketsAndPopulatesDefaultResolverSynchronously() throws {
        let tcpFD = socket(AF_INET, SOCK_STREAM, 0)
        try #require(tcpFD >= 0)
        defer { close(tcpFD) }

        var loopbackAddr = sockaddr_in()
        loopbackAddr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        loopbackAddr.sin_family = sa_family_t(AF_INET)
        loopbackAddr.sin_port = 0
        loopbackAddr.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))
        let bindResult = withUnsafePointer(to: &loopbackAddr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { saPtr in
                bind(tcpFD, saPtr, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        try #require(bindResult == 0)
        try #require(listen(tcpFD, 1) == 0)

        var boundAddr = sockaddr_in()
        var boundLen = socklen_t(MemoryLayout<sockaddr_in>.size)
        let nameResult = withUnsafeMutablePointer(to: &boundAddr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { saPtr in
                getsockname(tcpFD, saPtr, &boundLen)
            }
        }
        try #require(nameResult == 0)
        let tcpPort = UInt16(bigEndian: boundAddr.sin_port)
        try #require(tcpPort > 0)

        let udpFD = socket(AF_INET, SOCK_DGRAM, 0)
        try #require(udpFD >= 0)
        defer { close(udpFD) }

        var wildcardAddr = sockaddr_in()
        wildcardAddr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        wildcardAddr.sin_family = sa_family_t(AF_INET)
        wildcardAddr.sin_port = 0
        wildcardAddr.sin_addr = in_addr(s_addr: INADDR_ANY)
        let udpBind = withUnsafePointer(to: &wildcardAddr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { saPtr in
                bind(udpFD, saPtr, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        try #require(udpBind == 0)

        var udpBoundAddr = sockaddr_in()
        var udpBoundLen = socklen_t(MemoryLayout<sockaddr_in>.size)
        let udpNameResult = withUnsafeMutablePointer(to: &udpBoundAddr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { saPtr in
                getsockname(udpFD, saPtr, &udpBoundLen)
            }
        }
        try #require(udpNameResult == 0)
        let udpPort = UInt16(bigEndian: udpBoundAddr.sin_port)
        try #require(udpPort > 0)

        let currentPID = ProcessInfo.processInfo.processIdentifier
        let table = ProcessResolver.collectLibprocSockets()
        let specificOwner = table.specific[ProcessResolver.SocketEndpoint(ip: "127.0.0.1", port: tcpPort)]
        #expect(specificOwner?.pid == currentPID)
        #expect(specificOwner?.command.isEmpty == false)
        #expect(table.wildcard[udpPort]?.pid == currentPID)

        // Default `ProcessResolver()` populates synchronously at init (`t = 0ms`)
        // without needing any async `refresh()` round-trip.
        let liveResolver = ProcessResolver()
        let expectedName = ProcessResolver.resolveAppName(
            pid: currentPID,
            command: specificOwner?.command ?? ""
        )
        #expect(
            liveResolver.appName(forEndpoints: "127.0.0.1:\(tcpPort)", "127.0.0.1:59999")
                == expectedName
        )
        #expect(
            liveResolver.appName(forEndpoints: "127.0.0.1:\(udpPort)", "198.51.100.1:53")
                == expectedName
        )
    }
}
