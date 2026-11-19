import Foundation
import os
import Testing
@testable import Tracexy

@Suite("Inbound & Ephemeral Socket Attribution")
struct InboundEphemeralAttributionTests {
    // MARK: - PktapHeader.InboundSocketResolver

    @Test
    func inboundSocketResolverRefreshesAt25msCatchesBackToBackDNSPortsRetainsFor2sAndYieldsOnPortReuse() throws {
        #expect(PktapHeader.InboundSocketResolver.defaultMissRefreshIntervalNanoseconds == 25_000_000)
        #expect(PktapHeader.InboundSocketResolver.defaultRecentTTLNanoseconds == 2_000_000_000)
        #expect(PktapHeader.InboundSocketResolver.defaultMaxRecentEntries == 512)

        let localIP = PktapHeader.InboundIPKey.v4(0xC0A8_0082) // 192.168.0.130
        let key62774 = PktapHeader.InboundSocketPortMap.SpecificKey(proto: .udp, ip: localIP, port: 62_774)
        let key51060 = PktapHeader.InboundSocketPortMap.SpecificKey(proto: .udp, ip: localIP, port: 51_060)
        let keyOther = PktapHeader.InboundSocketPortMap.SpecificKey(proto: .udp, ip: localIP, port: 59_999)

        let target62774 = PktapHeader.InboundPacketTarget(proto: .udp, destinationIP: localIP, destinationPort: 62_774)
        let target51060 = PktapHeader.InboundPacketTarget(proto: .udp, destinationIP: localIP, destinationPort: 51_060)
        let targetOther = PktapHeader.InboundPacketTarget(proto: .udp, destinationIP: localIP, destinationPort: 59_999)

        var nowNs: UInt64 = 1_000_000_000 // t = 0ms baseline
        var scanCount = 0
        var activeMap = PktapHeader.InboundSocketPortMap(
            localIPs: [localIP],
            specific: [key62774: 94_285],
            wildcard: [:],
            commandByPID: [94_285: "OrbStack Helper"]
        )

        var resolver = PktapHeader.InboundSocketResolver(
            nowNanoseconds: { nowNs },
            portMapProvider: {
                scanCount += 1
                return activeMap
            }
        )

        // t = 0ms: first inbound DNS response on :62774 triggers initial scan and caches hit.
        let rawHit1 = resolver.resolveOwner(target: target62774)
        let hit1 = try #require(rawHit1)
        #expect(hit1.pid == 94_285)
        #expect(hit1.command == "OrbStack Helper")
        #expect(scanCount == 1)

        // Second concurrent ephemeral DNS socket :51060 opens while :62774 closes.
        activeMap = PktapHeader.InboundSocketPortMap(
            localIPs: [localIP],
            specific: [key51060: 94_285],
            wildcard: [:],
            commandByPID: [94_285: "OrbStack Helper"]
        )

        // t = 10ms (< 25ms throttle): miss on :51060 MUST respect the 25ms guard (0 extra scans).
        nowNs += 10_000_000
        let guardedMiss = resolver.resolveOwner(target: target51060)
        #expect(guardedMiss == nil)
        #expect(scanCount == 1)

        // t = 30ms (>= 25ms throttle, whereas old 500ms throttle missed it): refreshes and catches :51060!
        nowNs += 20_000_000
        let rawHit2 = resolver.resolveOwner(target: target51060)
        let hit2 = try #require(rawHit2)
        #expect(hit2.pid == 94_285)
        #expect(hit2.command == "OrbStack Helper")
        #expect(scanCount == 2)

        // t = 500ms (< 2s TTL): :62774 is no longer in live `portMap`, but resolves from
        // `recentResolved` in O(1) with ZERO extra scans.
        nowNs = 1_500_000_000
        let rawRetained = resolver.resolveOwner(target: target62774)
        let retained = try #require(rawRetained)
        #expect(retained.pid == 94_285)
        #expect(retained.command == "OrbStack Helper")
        #expect(scanCount == 2)

        // t = 1_600ms: another process (`curl`, PID 42_001) reuses :51060 and an unrelated miss
        // refreshes `portMap`. Live `portMap` MUST override `recentResolved` immediately.
        activeMap = PktapHeader.InboundSocketPortMap(
            localIPs: [localIP],
            specific: [key51060: 42_001, keyOther: 42_001],
            wildcard: [:],
            commandByPID: [42_001: "curl"]
        )
        nowNs = 2_600_000_000
        let rawOtherHit = resolver.resolveOwner(target: targetOther)
        let otherHit = try #require(rawOtherHit)
        #expect(otherHit.pid == 42_001)
        #expect(scanCount == 3)

        let rawReusedHit = resolver.resolveOwner(target: target51060)
        let reusedHit = try #require(rawReusedHit)
        #expect(reusedHit.pid == 42_001)
        #expect(reusedHit.command == "curl")
        #expect(scanCount == 3)

        // t = 3_001ms (> 2s since :62774 was last verified at 1_000_000_000): :62774 expires cleanly.
        activeMap = PktapHeader.InboundSocketPortMap(
            localIPs: [localIP],
            specific: [:],
            wildcard: [:],
            commandByPID: [:]
        )
        nowNs = 3_001_000_000
        let expiredHit = resolver.resolveOwner(target: target62774)
        #expect(expiredHit == nil)
        #expect(scanCount == 4)

        // Meanwhile :51060 (re-verified at 2_600_000_000 with PID 42_001) is still within 2s and
        // retains the NEW owner (`curl`), never reverting to `OrbStack Helper`.
        let rawRetainedReused = resolver.resolveOwner(target: target51060)
        let retainedReused = try #require(rawRetainedReused)
        #expect(retainedReused.pid == 42_001)
        #expect(retainedReused.command == "curl")
        #expect(scanCount == 4)
    }

    @Test
    func inboundSocketResolverSkipsPrivilegedPortsMulticastAndBoundsRecentCache() throws {
        let localIP = PktapHeader.InboundIPKey.v4(0xC0A8_0082) // 192.168.0.130
        let multicastIP = PktapHeader.InboundIPKey.v4(0xE000_00FB) // 224.0.0.251

        var nowNs: UInt64 = 1_000_000_000
        var scanCount = 0
        var activeMap = PktapHeader.InboundSocketPortMap(
            localIPs: [localIP],
            specific: [
                .init(proto: .udp, ip: localIP, port: 53): 500,
                .init(proto: .udp, ip: localIP, port: 50_001): 501,
                .init(proto: .udp, ip: localIP, port: 50_002): 502,
                .init(proto: .udp, ip: localIP, port: 50_003): 503,
            ],
            wildcard: [:],
            commandByPID: [500: "dnsd", 501: "app1", 502: "app2", 503: "app3"]
        )

        var resolver = PktapHeader.InboundSocketResolver(
            nowNanoseconds: { nowNs },
            portMapProvider: {
                scanCount += 1
                return activeMap
            },
            maxRecentEntries: 2
        )

        // Multicast destination returns nil immediately with 0 scans.
        let mcastHit = resolver.resolveOwner(
            target: .init(proto: .udp, destinationIP: multicastIP, destinationPort: 5_353)
        )
        #expect(mcastHit == nil)
        #expect(scanCount == 0)

        // Privileged port :53 resolves while live, but MUST NOT enter `recentResolved`.
        let rawDNSHit = resolver.resolveOwner(
            target: .init(proto: .udp, destinationIP: localIP, destinationPort: 53)
        )
        let dnsHit = try #require(rawDNSHit)
        #expect(dnsHit.pid == 500)
        #expect(resolver.recentCacheCount == 0)

        // Resolve 3 ephemeral ports across distinct refresh timestamps; maxRecentEntries = 2
        // keeps only the 2 newest entries.
        let hit50001 = resolver.resolveOwner(
            target: .init(proto: .udp, destinationIP: localIP, destinationPort: 50_001)
        )
        #expect(hit50001?.pid == 501)
        #expect(resolver.recentCacheCount == 1)

        // Force a second refresh at t + 30ms so :50002 gets a newer `verifiedAt`.
        nowNs += 30_000_000
        let miss1 = resolver.resolveOwner(
            target: .init(proto: .udp, destinationIP: localIP, destinationPort: 59_000)
        )
        #expect(miss1 == nil)
        let hit50002 = resolver.resolveOwner(
            target: .init(proto: .udp, destinationIP: localIP, destinationPort: 50_002)
        )
        #expect(hit50002?.pid == 502)
        #expect(resolver.recentCacheCount == 2)

        // Force a third refresh at t + 60ms so :50003 gets an even newer `verifiedAt`, evicting :50001.
        nowNs += 30_000_000
        activeMap.specific.removeValue(forKey: .init(proto: .udp, ip: localIP, port: 50_001))
        activeMap.specific.removeValue(forKey: .init(proto: .udp, ip: localIP, port: 53))
        let miss2 = resolver.resolveOwner(
            target: .init(proto: .udp, destinationIP: localIP, destinationPort: 59_001)
        )
        #expect(miss2 == nil)
        let hit50003 = resolver.resolveOwner(
            target: .init(proto: .udp, destinationIP: localIP, destinationPort: 50_003)
        )
        #expect(hit50003?.pid == 503)
        #expect(resolver.recentCacheCount == 2)

        // :53 was never cached in recentResolved and is now closed.
        nowNs += 30_000_000
        let closedDNS = resolver.resolveOwner(
            target: .init(proto: .udp, destinationIP: localIP, destinationPort: 53)
        )
        #expect(closedDNS == nil)

        // :50001 was evicted as oldest; :50002 and :50003 remain cached after closing.
        activeMap.specific.removeAll()
        nowNs += 30_000_000
        let evicted50001 = resolver.resolveOwner(
            target: .init(proto: .udp, destinationIP: localIP, destinationPort: 50_001)
        )
        let cached50002 = resolver.resolveOwner(
            target: .init(proto: .udp, destinationIP: localIP, destinationPort: 50_002)
        )
        let cached50003 = resolver.resolveOwner(
            target: .init(proto: .udp, destinationIP: localIP, destinationPort: 50_003)
        )
        #expect(evicted50001 == nil)
        #expect(cached50002?.pid == 502)
        #expect(cached50003?.pid == 503)
    }

    @Test
    func inboundSocketResolverParsesRawEthernetIPv4UDPInboundFrame() throws {
        let localIP = PktapHeader.InboundIPKey.v4(0xC0A8_0082) // 192.168.0.130
        let frame = makeEthernetIPv4UDPFrame(
            srcIP: [192, 168, 0, 1],
            dstIP: [192, 168, 0, 130],
            srcPort: 53,
            dstPort: 51_060
        )

        var resolver = PktapHeader.InboundSocketResolver(
            nowNanoseconds: { 1_000_000_000 },
            portMapProvider: {
                PktapHeader.InboundSocketPortMap(
                    localIPs: [localIP],
                    specific: [.init(proto: .udp, ip: localIP, port: 51_060): 94_285],
                    wildcard: [:],
                    commandByPID: [94_285: "OrbStack Helper"]
                )
            }
        )

        let rawOwner = resolver.resolveOwner(innerBytes: frame, innerDLT: 1)
        let owner = try #require(rawOwner)
        #expect(owner.pid == 94_285)
        #expect(owner.command == "OrbStack Helper")
    }

    // MARK: - ProcessResolver Rolling Ephemeral Socket History

    @Test
    @MainActor
    func processResolverRetainsClosedEphemeralSocketFor5sExcludesServerPortsAndYieldsOnPortReuse() async throws {
        #expect(ProcessResolver.refreshThrottleInterval == 0.15)
        #expect(ProcessResolver.ephemeralRetentionInterval == 5.0)
        #expect(ProcessResolver.maxRecentEphemeralEntries == 1_024)
        #expect(ProcessResolver.isCacheableEphemeralPort(51_060))
        #expect(!ProcessResolver.isCacheableEphemeralPort(53))
        #expect(!ProcessResolver.isCacheableEphemeralPort(80))
        #expect(!ProcessResolver.isCacheableEphemeralPort(443))
        #expect(!ProcessResolver.isCacheableEphemeralPort(8_080))

        let baseTime = Date(timeIntervalSince1970: 1_700_000_000)
        let state = OSAllocatedUnfairLock(initialState: (
            now: baseTime,
            table: ProcessResolver.SocketTable(
                specific: [
                    .init(ip: "192.168.0.130", port: 51_060): .init(pid: 94_285, command: "OrbStack Helper"),
                    .init(ip: "192.168.0.130", port: 53): .init(pid: 500, command: "mDNSResponder"),
                    .init(ip: "192.168.0.130", port: 80): .init(pid: 501, command: "httpd"),
                    .init(ip: "192.168.0.130", port: 443): .init(pid: 502, command: "nginx"),
                    .init(ip: "192.168.0.130", port: 8_080): .init(pid: 503, command: "proxy"),
                ],
                wildcard: [:]
            ),
            refreshCount: 0
        ))

        let orbProvenance = ProcessProvenance(
            executablePath: "/Applications/OrbStack.app/Contents/Frameworks/OrbStack Helper.app/Contents/MacOS/OrbStack Helper",
            bundleIdentifier: "dev.kdrag0n.MacVirt",
            viaProcessName: "OrbStack Helper",
            originProcessName: "OrbStack Helper"
        )
        let curlProvenance = ProcessProvenance(
            executablePath: "/usr/bin/curl",
            originProcessName: "curl"
        )

        let resolver = ProcessResolver(
            socketTableProvider: {
                state.withLock { s in
                    s.refreshCount += 1
                    return s.table
                }
            },
            populateImmediately: false,
            localIPsProvider: { ["192.168.0.130", "127.0.0.1", "::1"] },
            appNameResolver: { pid, command in
                switch pid {
                case 94_285: "OrbStack"
                case 77_001: "curl"
                default: command
                }
            },
            provenanceResolver: { pid, _, _ in
                switch pid {
                case 94_285: orbProvenance
                case 77_001: curlProvenance
                default: ProcessProvenance()
                }
            },
            nowProvider: { state.withLock(\.now) }
        )

        // 1. Early refresh at t = 0.0s observes ephemeral UDP DNS socket :51060 + server ports.
        resolver.refresh()
        try await waitUntil { state.withLock(\.refreshCount) == 1 && resolver.recentEphemeralAttributionCount == 1 }

        // Only :51060 is cached in rolling ephemeral history (server ports :53, :80, :443, :8080 excluded).
        #expect(resolver.recentEphemeralAttributionCount == 1)

        // Unforced refresh inside the 150ms throttle window (t = 0.05s) is suppressed.
        state.withLock { $0.now = baseTime.addingTimeInterval(0.05) }
        resolver.refresh()
        try await Task.sleep(nanoseconds: 25_000_000)
        #expect(state.withLock(\.refreshCount) == 1)

        // 2. Socket :51060 (and server sockets) close before the next refresh 300ms later (t = 0.3s).
        state.withLock { s in
            s.now = baseTime.addingTimeInterval(0.3)
            s.table = ProcessResolver.SocketTable()
        }
        resolver.refresh()
        try await waitUntil {
            state.withLock(\.refreshCount) == 2
                && resolver.appName(forEndpoints: "192.168.0.130:443", "93.184.216.34:54000") == nil
        }

        // Closed ephemeral DNS socket STILL resolves within 5.0s (e.g. when 800ms live snapshot runs).
        state.withLock { $0.now = baseTime.addingTimeInterval(0.8) }
        let retained = try #require(
            resolver.attribution(forEndpoints: "192.168.0.130:51060", "192.168.0.1:53")
        )
        #expect(retained.appName == "OrbStack")
        #expect(retained.provenance == orbProvenance)
        #expect(resolver.appName(forEndpoints: "192.168.0.130:51060", "192.168.0.1:53") == "OrbStack")

        // Foreign LAN IP sharing port :51060 MUST NOT match!
        #expect(resolver.attribution(forEndpoints: "192.168.0.99:51060", "192.168.0.1:53") == nil)

        // Closed server ports (:53, :80, :443, :8080) MUST NOT resolve from rolling ephemeral cache!
        #expect(resolver.attribution(forEndpoints: "192.168.0.130:53", "192.168.0.50:52000") == nil)
        #expect(resolver.attribution(forEndpoints: "192.168.0.130:80", "192.168.0.50:52001") == nil)
        #expect(resolver.attribution(forEndpoints: "192.168.0.130:443", "192.168.0.50:52002") == nil)
        #expect(resolver.attribution(forEndpoints: "192.168.0.130:8080", "192.168.0.50:52003") == nil)

        // 3. Port reuse: a new process (`curl`, PID 77_001) rebinds 192.168.0.130:51060 at t = 1.0s.
        //    Live `resolvedTable` MUST win immediately and update recent history.
        state.withLock { s in
            s.now = baseTime.addingTimeInterval(1.0)
            s.table = ProcessResolver.SocketTable(
                specific: [
                    .init(ip: "192.168.0.130", port: 51_060): .init(pid: 77_001, command: "curl"),
                ],
                wildcard: [:]
            )
        }
        resolver.refresh()
        try await waitUntil {
            state.withLock(\.refreshCount) == 3
                && resolver.appName(forEndpoints: "192.168.0.130:51060", "192.168.0.1:53") == "curl"
        }

        let reused = try #require(
            resolver.attribution(forEndpoints: "192.168.0.130:51060", "192.168.0.1:53")
        )
        #expect(reused.appName == "curl")
        #expect(reused.provenance == curlProvenance)

        // Even after `curl` closes :51060 at t = 1.5s, rolling cache reflects `curl` (observed at t = 1.0s).
        state.withLock { s in
            s.now = baseTime.addingTimeInterval(1.5)
            s.table = ProcessResolver.SocketTable()
        }
        resolver.refresh()
        try await waitUntil { state.withLock(\.refreshCount) == 4 }
        try await Task.sleep(nanoseconds: 25_000_000)

        let afterClose = try #require(
            resolver.attribution(forEndpoints: "192.168.0.130:51060", "192.168.0.1:53")
        )
        #expect(afterClose.appName == "curl")

        // 4. Expiry: after > 5.0s since last observation (t = 1.0s + 5.1s = 6.1s), it expires cleanly.
        state.withLock { $0.now = baseTime.addingTimeInterval(6.1) }
        #expect(resolver.attribution(forEndpoints: "192.168.0.130:51060", "192.168.0.1:53") == nil)
        #expect(resolver.appName(forEndpoints: "192.168.0.130:51060", "192.168.0.1:53") == nil)
        #expect(resolver.recentEphemeralAttributionCount == 0)
    }

    @Test
    @MainActor
    func processResolverBoundsRollingEphemeralCacheAndSupportsExplicitClear() {
        let baseTime = Date(timeIntervalSince1970: 1_700_000_000)
        var initialSpecific: [ProcessResolver.SocketEndpoint: ProcessResolver.ResolvedProcess] = [:]
        // Populate 1,100 distinct ephemeral ports (> maxRecentEphemeralEntries = 1,024).
        for offset in 0 ..< 1_100 {
            let port = UInt16(30_000 + offset)
            initialSpecific[.init(ip: "192.168.0.130", port: port)] = .init(pid: 1_000, command: "OrbStack Helper")
        }
        let snapshotSpecific = initialSpecific

        let resolver = ProcessResolver(
            socketTableProvider: {
                ProcessResolver.SocketTable(specific: snapshotSpecific, wildcard: [:])
            },
            populateImmediately: true,
            localIPsProvider: { ["192.168.0.130"] },
            appNameResolver: { _, _ in "OrbStack" },
            provenanceResolver: { _, _, _ in ProcessProvenance() },
            nowProvider: { baseTime }
        )

        #expect(resolver.recentEphemeralAttributionCount == ProcessResolver.maxRecentEphemeralEntries)

        resolver.clearRecentEphemeralAttributions()
        #expect(resolver.recentEphemeralAttributionCount == 0)
    }

    // MARK: - Helpers

    private func makeEthernetIPv4UDPFrame(
        srcIP: [UInt8],
        dstIP: [UInt8],
        srcPort: UInt16,
        dstPort: UInt16
    ) -> [UInt8] {
        var bytes: [UInt8] = []
        // Ethernet header (14 bytes): dst MAC + src MAC + EtherType IPv4 (0x0800)
        bytes += [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]
        bytes += [0x11, 0x22, 0x33, 0x44, 0x55, 0x66]
        bytes += [0x08, 0x00]
        // IPv4 header (20 bytes): IHL=5, proto=UDP (17), total len=28
        bytes += [0x45, 0x00, 0x00, 0x1C]
        bytes += [0x12, 0x34, 0x00, 0x00]
        bytes += [0x40, 17, 0x00, 0x00]
        bytes += srcIP
        bytes += dstIP
        // UDP header (8 bytes): srcPort, dstPort, length=8, checksum=0
        bytes += [UInt8(srcPort >> 8), UInt8(srcPort & 0xFF)]
        bytes += [UInt8(dstPort >> 8), UInt8(dstPort & 0xFF)]
        bytes += [0x00, 0x08, 0x00, 0x00]
        return bytes
    }

    @MainActor
    private func waitUntil(
        timeoutIterations: Int = 60,
        condition: @MainActor () -> Bool
    ) async throws {
        for _ in 0 ..< timeoutIterations {
            if condition() {
                return
            }
            try await Task.sleep(nanoseconds: 10_000_000)
        }
    }
}
