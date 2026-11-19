import Foundation
import Observation
import os
import Testing
@testable import Tracexy

// MARK: - LiveScrollCoalescingTests

@MainActor
@Suite("Live scroll coalescing, batched attribution, and visibility memoization")
struct LiveScrollCoalescingTests {
    // MARK: Internal

    @Test("beginUserLiveScroll buffers & coalesces live snapshots and endUserLiveScroll flushes immediately")
    func liveScrollBuffersCoalescesAndFlushesOnEnd() async {
        let environment = ProjectIsolationEnvironment(name: "live-scroll-coalesce")
        defer { environment.tearDown() }
        let coordinator = environment.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()

        coordinator.isCapturing = true
        let generation = coordinator.startGeneration

        let s1 = UUID()
        let s2 = UUID()
        let s3 = UUID()
        let s4 = UUID()
        let safariProvenance = ProcessProvenance(
            executablePath: "/Applications/Safari.app/Contents/MacOS/Safari",
            bundleIdentifier: "com.apple.Safari",
            viaProcessName: "Safari Networking"
        )

        // Initial live publication while NOT scrolling adopts immediately.
        await coordinator.publishLiveDetailed(
            Self.snapshot([Self.summary(id: s1, host: "one.example", processName: "Safari", provenance: safariProvenance)]),
            expectedGeneration: generation,
            isCapturing: true
        ).value
        #expect(coordinator.sessions.map(\.id) == [s1])

        // Begin live scroll -> subsequent live snapshots buffer without mutating observable sessions.
        coordinator.beginUserLiveScroll()
        #expect(coordinator.isUserLiveScrolling)

        let observedMutation = OSAllocatedUnfairLock(initialState: false)
        withObservationTracking {
            _ = coordinator.sessions.count
            _ = coordinator.attributedProcessesBySessionID.count
            _ = coordinator.attributedProvenancesBySessionID.count
        } onChange: {
            observedMutation.withLock { $0 = true }
        }

        let curlProvenance = ProcessProvenance(
            executablePath: "/usr/bin/curl",
            hasControllingTTY: true
        )

        // Tick 1 while scrolling introduces s2 with sticky attribution.
        await coordinator.publishLiveDetailed(
            Self.snapshot([
                Self.summary(id: s1, host: "one.example", processName: nil),
                Self.summary(id: s2, host: "two.example", processName: "curl", provenance: curlProvenance),
            ]),
            expectedGeneration: generation,
            isCapturing: true
        ).value
        #expect(coordinator.sessions.map(\.id) == [s1])

        // Tick 2 while scrolling adds s3 and drops s2's live processName (closed socket).
        await coordinator.publishLiveDetailed(
            Self.snapshot([
                Self.summary(id: s1, host: "one.example", processName: nil),
                Self.summary(id: s2, host: "two.example", processName: nil),
                Self.summary(id: s3, host: "three.example", processName: "Mail"),
            ]),
            expectedGeneration: generation,
            isCapturing: true
        ).value
        #expect(coordinator.sessions.map(\.id) == [s1])

        // Tick 3 while scrolling adds s4 — overwrites older deferred snapshot (latest wins).
        await coordinator.publishLiveDetailed(
            Self.snapshot([
                Self.summary(id: s1, host: "one.example", processName: nil),
                Self.summary(id: s2, host: "two.example", processName: nil),
                Self.summary(id: s3, host: "three.example", processName: nil),
                Self.summary(id: s4, host: "four.example", processName: "Notes"),
            ]),
            expectedGeneration: generation,
            isCapturing: true
        ).value
        #expect(coordinator.sessions.map(\.id) == [s1])
        #expect(!observedMutation.withLock { $0 })

        // End live scroll -> flushes latest coalesced snapshot immediately and preserves sticky attribution!
        coordinator.endUserLiveScroll()
        #expect(!coordinator.isUserLiveScrolling)
        #expect(coordinator.sessions.map(\.id) == [s1, s2, s3, s4])
        #expect(coordinator.sessions.map(\.processName) == ["Safari", "curl", "Mail", "Notes"])
        #expect(coordinator.attributedProcessesBySessionID[s2] == "curl")
        #expect(coordinator.attributedProvenancesBySessionID[s2] == curlProvenance)
        #expect(coordinator.investigationSnapshot.sessions.map(\.id) == [s1, s2, s3, s4])
    }

    @Test("Terminal stop and clearSessions are never blocked by live scroll and discard stale buffered publications")
    func terminalStopAndClearDiscardStaleBufferedLiveSnapshots() async {
        let environment = ProjectIsolationEnvironment(name: "live-scroll-boundaries")
        defer { environment.tearDown() }
        let coordinator = environment.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()

        // Part A: Terminal stop (`isCapturing: false`) must NEVER defer and must discard buffered live ticks.
        coordinator.isCapturing = true
        let liveGen = coordinator.startGeneration
        let liveOnlyID = UUID()
        let terminalID = UUID()

        coordinator.beginUserLiveScroll()
        await coordinator.publishLiveDetailed(
            Self.snapshot([Self.summary(id: liveOnlyID, host: "stale-live.example", processName: "Safari")]),
            expectedGeneration: liveGen,
            isCapturing: true
        ).value
        #expect(coordinator.sessions.isEmpty)

        coordinator.isCapturing = false
        coordinator.startGeneration &+= 1
        let stoppedGen = coordinator.startGeneration

        await coordinator.publishLiveDetailed(
            Self.snapshot([Self.summary(id: terminalID, host: "final-stop.example", processName: "Mail")]),
            expectedGeneration: stoppedGen,
            isCapturing: false,
            terminalHistoryCompleteness: .complete
        ).value

        #expect(!coordinator.isUserLiveScrolling)
        #expect(coordinator.sessions.map(\.id) == [terminalID])

        // Calling endUserLiveScroll() afterward must NOT overwrite the stopped capture.
        coordinator.endUserLiveScroll()
        #expect(coordinator.sessions.map(\.id) == [terminalID])

        // Part B: clearSessions() while live-scrolling clears state and drops stale buffered live snapshots.
        coordinator.isCapturing = true
        let nextLiveGen = coordinator.startGeneration
        coordinator.beginUserLiveScroll()
        await coordinator.publishLiveDetailed(
            Self.snapshot([Self.summary(id: UUID(), host: "pre-clear.example", processName: "curl")]),
            expectedGeneration: nextLiveGen,
            isCapturing: true
        ).value
        #expect(coordinator.isUserLiveScrolling)

        coordinator.clearSessions()
        await coordinator.ingestChain?.value
        #expect(!coordinator.isUserLiveScrolling)
        #expect(coordinator.sessions.isEmpty)

        coordinator.endUserLiveScroll()
        #expect(coordinator.sessions.isEmpty)
    }

    @Test("Max deferral safety valve and auto-end watchdog bound continuous live-scroll deferral")
    func maxDeferralSafetyValveAndAutoEndWatchdogFlush() async throws {
        let environment = ProjectIsolationEnvironment(name: "live-scroll-safety-valve")
        defer { environment.tearDown() }
        let coordinator = environment.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()

        coordinator.isCapturing = true
        let generation = coordinator.startGeneration
        coordinator.maxLiveScrollDeferralDuration = .milliseconds(40)
        coordinator.liveScrollAutoEndWatchdogDuration = .seconds(10)

        let bufferedID = UUID()
        let flushedID = UUID()

        coordinator.beginUserLiveScroll()
        await coordinator.publishLiveDetailed(
            Self.snapshot([Self.summary(id: bufferedID, host: "buffered.example", processName: "Safari")]),
            expectedGeneration: generation,
            isCapturing: true
        ).value
        #expect(coordinator.sessions.isEmpty)

        try await Task.sleep(for: .milliseconds(60))

        // Next tick exceeds `maxLiveScrollDeferralDuration` and flushes immediately even while scrolling.
        await coordinator.publishLiveDetailed(
            Self.snapshot([Self.summary(id: flushedID, host: "flushed.example", processName: "Safari")]),
            expectedGeneration: generation,
            isCapturing: true
        ).value
        #expect(coordinator.isUserLiveScrolling)
        #expect(coordinator.sessions.map(\.id) == [flushedID])
        coordinator.endUserLiveScroll()

        // Watchdog test: if `endUserLiveScroll()` is never delivered, watchdog ends scroll and flushes.
        coordinator.maxLiveScrollDeferralDuration = .seconds(10)
        coordinator.liveScrollAutoEndWatchdogDuration = .milliseconds(60)
        let watchdogID = UUID()

        coordinator.beginUserLiveScroll()
        await coordinator.publishLiveDetailed(
            Self.snapshot([Self.summary(id: watchdogID, host: "watchdog.example", processName: "curl")]),
            expectedGeneration: generation,
            isCapturing: true
        ).value
        #expect(coordinator.sessions.map(\.id) == [flushedID])

        try await Task.sleep(for: .milliseconds(140))
        #expect(!coordinator.isUserLiveScrolling)
        #expect(coordinator.sessions.map(\.id) == [watchdogID])
    }

    @Test("Batched attribution bumps processContextGeneration minimally and adopts off-main ActivityBuilder correlation")
    func batchedAttributionAndOffMainCorrelation() async {
        let environment = ProjectIsolationEnvironment(name: "batched-attribution")
        defer { environment.tearDown() }
        let coordinator = environment.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()

        coordinator.isCapturing = true
        let generation = coordinator.startGeneration

        // Build > 64 sessions with provenances AND a correlated DNS -> TLS pair to exercise off-main correlation.
        let baseDate = Date(timeIntervalSince1970: 1_700_000_000)
        var initialSessions: [SessionSummary] = []
        initialSessions.reserveCapacity(120)

        let dnsID = UUID()
        let tlsID = UUID()
        let safariProv = ProcessProvenance(
            executablePath: "/Applications/Safari.app/Contents/MacOS/Safari",
            bundleIdentifier: "com.apple.Safari",
            viaProcessName: "Safari Networking"
        )
        initialSessions.append(
            SessionSummary(
                id: dnsID,
                startTime: baseDate,
                duration: 0.02,
                processName: "Safari",
                processProvenance: safariProv,
                host: "api.correlated.example",
                sourceEndpoint: "198.51.100.10:53000",
                destinationEndpoint: "203.0.113.53:53",
                protocolStack: [.udp, .dns],
                status: .ok,
                latencyMilliseconds: 8,
                bytesUp: 64,
                bytesDown: 128,
                dnsQuery: "api.correlated.example",
                dnsAnswers: ["203.0.113.99"]
            )
        )
        initialSessions.append(
            SessionSummary(
                id: tlsID,
                startTime: baseDate.addingTimeInterval(0.05),
                duration: 0.3,
                processName: "Safari",
                processProvenance: safariProv,
                host: "api.correlated.example",
                sourceEndpoint: "198.51.100.10:54000",
                destinationEndpoint: "203.0.113.99:443",
                protocolStack: [.tcp, .tls],
                status: .ok,
                latencyMilliseconds: 22,
                bytesUp: 512,
                bytesDown: 4_096,
                sni: "api.correlated.example"
            )
        )

        for idx in 2 ..< 120 {
            let prov = ProcessProvenance(
                executablePath: "/Applications/App\(idx).app/Contents/MacOS/App\(idx)",
                bundleIdentifier: "com.example.app\(idx)"
            )
            initialSessions.append(
                Self.summary(
                    id: UUID(),
                    host: "service-\(idx).example",
                    processName: "App\(idx)",
                    provenance: prov,
                    startTime: baseDate.addingTimeInterval(Double(idx) * 10)
                )
            )
        }

        let genBeforeFirst = coordinator.processContextGeneration
        let adoptionsBefore = coordinator.precomputedActivitiesAdoptionCount

        await coordinator.publishLiveDetailed(
            Self.snapshot(initialSessions),
            expectedGeneration: generation,
            isCapturing: true
        ).value

        let genDeltaFirst = coordinator.processContextGeneration - genBeforeFirst
        // At most 2 bumps (1 batched provenance dictionary assignment + 1 sessions assignment), never N (~120).
        #expect(genDeltaFirst <= 2)
        #expect(coordinator.attributedProcessesBySessionID.count == 120)
        #expect(coordinator.attributedProvenancesBySessionID.count == 120)
        #expect(coordinator.precomputedActivitiesAdoptionCount == adoptionsBefore + 1)
        #expect(coordinator.activityIndex[dnsID] != nil)
        #expect(coordinator.activityIndex[tlsID]?.id == coordinator.activityIndex[dnsID]?.id)

        // Second snapshot drops live process names/provenances -> sticky maps preserve all 120 with 0 provenance rewrites!
        let stripped = initialSessions.map { session in
            var copy = session
            copy.processName = nil
            copy.processProvenance = nil
            copy.bytesDown += 128
            return copy
        }
        let genBeforeSecond = coordinator.processContextGeneration
        await coordinator.publishLiveDetailed(
            Self.snapshot(stripped),
            expectedGeneration: generation,
            isCapturing: true
        ).value

        // Provenance dictionary did NOT change, so only `sessions.didSet` bumps `processContextGeneration` once.
        #expect(coordinator.processContextGeneration - genBeforeSecond == 1)
        #expect(coordinator.sessions.allSatisfy { ($0.processName ?? "").isEmpty == false })
        #expect(coordinator.sessions.allSatisfy { $0.processProvenance != nil })

        // Mutating removedSessionIDs still keeps action grouping consistent with visible survivors.
        coordinator.activeWorkspace.sessionGrouping = .action
        let actionRowsBeforeRemove = coordinator.sessionRows
        #expect(actionRowsBeforeRemove.contains {
            if case let .action(activity) = $0 {
                return activity.sessions.contains { $0.id == dnsID } && activity.sessions.contains { $0.id == tlsID }
            }
            return false
        })
        coordinator.removeSessionsFromView([dnsID])
        let actionRowsAfterRemove = coordinator.sessionRows
        #expect(!actionRowsAfterRemove.contains {
            if case let .action(activity) = $0 {
                return activity.sessions.contains { $0.id == dnsID }
            }
            return false
        })
        #expect(actionRowsAfterRemove.contains {
            if case let .session(session) = $0 {
                return session.id == tlsID
            }
            return false
        })
    }

    @Test("Memoized visibleSessions, visibleProtocolCounts, and sessionRows invalidate immediately and hit < 5ms over 1,000 sessions")
    func memoizedVisibilityInvalidatesAndMeetsLatencyBudget() async {
        let environment = ProjectIsolationEnvironment(name: "visibility-memo")
        defer { environment.tearDown() }
        let coordinator = environment.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()

        let baseDate = Date(timeIntervalSince1970: 1_700_100_000)
        var bulk: [SessionSummary] = []
        bulk.reserveCapacity(1_000)
        for index in 0 ..< 1_000 {
            let isHTTP = index.isMultiple(of: 2)
            let protoStack: [ProtocolKind] = isHTTP ? [.tcp, .tls, .http] : [.udp, .dns]
            let host = "host-\(index % 25).example"
            let process = index.isMultiple(of: 3) ? "Safari" : "curl"
            bulk.append(
                SessionSummary(
                    id: UUID(),
                    startTime: baseDate.addingTimeInterval(Double(index) * 0.5),
                    duration: 0.1,
                    processName: process,
                    host: host,
                    sourceEndpoint: "198.51.100.10:\(20_000 + index)",
                    destinationEndpoint: "203.0.113.\((index % 200) + 1):\(isHTTP ? 443 : 53)",
                    protocolStack: protoStack,
                    status: index.isMultiple(of: 50) ? .error : .ok,
                    latencyMilliseconds: Double(5 + (index % 40)),
                    bytesUp: 128,
                    bytesDown: 1_024 + index
                )
            )
        }
        coordinator.sessions = bulk

        // Warm caches once.
        let initialVisible = coordinator.visibleSessions
        let initialCounts = coordinator.visibleProtocolCounts
        let initialRows = coordinator.sessionRows
        #expect(initialVisible.count == 1_000)
        #expect(initialCounts[.http] == 500)
        #expect(initialCounts[.dns] == 500)
        #expect(initialRows.count == 1_000)

        // Benchmark 20 repeated reads across all 3 cached surfaces over 1,000 sessions.
        let clock = ContinuousClock()
        let elapsed = clock.measure {
            for _ in 0 ..< 20 {
                #expect(coordinator.visibleSessions.count == 1_000)
                #expect(coordinator.visibleProtocolCounts[.http] == 500)
                #expect(coordinator.sessionRows.count == 1_000)
            }
        }
        #expect(elapsed < .milliseconds(5))

        // Verify `@Observable` tracking fires even after cache hits!
        let invalidatedOnHostFilter = OSAllocatedUnfairLock(initialState: false)
        withObservationTracking {
            _ = coordinator.visibleSessions
        } onChange: {
            invalidatedOnHostFilter.withLock { $0 = true }
        }
        coordinator.activeWorkspace.hostFilter = "host-0.example"
        #expect(invalidatedOnHostFilter.withLock { $0 })
        #expect(coordinator.visibleSessions.count == 40)
        #expect(coordinator.visibleProtocolCounts[.tcp] == 20)
        #expect(coordinator.sessionRows.count == 40)

        let invalidatedOnGrouping = OSAllocatedUnfairLock(initialState: false)
        withObservationTracking {
            _ = coordinator.sessionRows
        } onChange: {
            invalidatedOnGrouping.withLock { $0 = true }
        }
        coordinator.activeWorkspace.sessionGrouping = .host
        #expect(invalidatedOnGrouping.withLock { $0 })
        #expect(coordinator.sessionRows.count == 1)
        if case let .group(group) = coordinator.sessionRows.first {
            #expect(group.kind == .host)
            #expect(group.sessions.count == 40)
        } else {
            Issue.record("Expected single .host group row after switching sessionGrouping")
        }

        // Mute host invalidates immediately.
        coordinator.activeWorkspace.hostFilter = nil
        coordinator.activeWorkspace.sessionGrouping = .none
        #expect(coordinator.visibleSessions.count == 1_000)

        let invalidatedOnMute = OSAllocatedUnfairLock(initialState: false)
        withObservationTracking {
            _ = coordinator.visibleProtocolCounts
        } onChange: {
            invalidatedOnMute.withLock { $0 = true }
        }
        coordinator.mutedHosts.insert("host-0.example")
        #expect(invalidatedOnMute.withLock { $0 })
        #expect(coordinator.visibleSessions.count == 960)
        #expect(coordinator.visibleProtocolCounts[.http] == 480)

        // Mute protocol invalidates immediately.
        coordinator.mutedProtocols.insert(.dns)
        #expect(coordinator.visibleSessions.count == 480)
        #expect(coordinator.visibleProtocolCounts[.dns] == nil)

        // Search text invalidates immediately.
        coordinator.mutedHosts.removeAll()
        coordinator.mutedProtocols.removeAll()
        coordinator.activeWorkspace.filterText = "host-7.example"
        #expect(coordinator.visibleSessions.count == 40)

        // Category filter invalidates immediately.
        coordinator.activeWorkspace.filterText = ""
        coordinator.activeWorkspace.categoryFilters = [.errors]
        #expect(coordinator.visibleSessions.count == 20)
    }

    @Test("AddressNameBook.learn fast-skips public HTTPS sessions while preserving DNS and Fake-IP SNI learning")
    func addressNameBookLearnFastPathAndCorrectness() {
        let book = AddressNameBook()
        let suiteName = "com.tracexy.test.address-book-fast-path.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)!
        defer { defaults.removePersistentDomain(forName: suiteName) }
        book.bind(to: defaults)

        // 1,000 normal public HTTPS sessions with SNI (non-Fake-IP) + a few DNS / Fake-IP sessions.
        var sessions: [SessionSummary] = []
        sessions.reserveCapacity(1_005)
        for index in 0 ..< 1_000 {
            sessions.append(
                SessionSummary(
                    id: UUID(),
                    startTime: Date(timeIntervalSince1970: 1_700_000_000 + Double(index)),
                    duration: 0.1,
                    processName: "Safari",
                    host: "www.public-\(index).example",
                    sourceEndpoint: "192.168.1.50:\(40_000 + index)",
                    destinationEndpoint: "142.250.190.\((index % 200) + 1):443",
                    sourceEndpointValue: IPEndpoint(ip: "192.168.1.50", port: UInt16(40_000 + index)),
                    destinationEndpointValue: IPEndpoint(ip: "142.250.190.\((index % 200) + 1)", port: 443),
                    protocolStack: [.tcp, .tls],
                    status: .ok,
                    bytesUp: 256,
                    bytesDown: 1_024,
                    sni: "www.public-\(index).example"
                )
            )
        }

        // Verify pure non-Fake-IP HTTPS scan is ultra-fast and learns nothing spurious.
        let clock = ContinuousClock()
        let publicElapsed = clock.measure {
            book.learn(from: sessions)
        }
        #expect(book.learnedNames.isEmpty)
        #expect(publicElapsed < .milliseconds(5))

        // Now append DNS + IPv4 Fake-IP (198.18 & 100.64) + IPv6 Fake-IP (fc00:: & fdfe:dcba:9876::).
        let mixed: [SessionSummary] = [
            SessionSummary(
                id: UUID(),
                host: "dns.example",
                sourceEndpoint: "192.168.1.50:53001",
                destinationEndpoint: "1.1.1.1:53",
                protocolStack: [.udp, .dns],
                status: .ok,
                bytesUp: 64,
                bytesDown: 128,
                dnsQuery: "api.dns.example",
                dnsAnswers: ["203.0.113.10"]
            ),
            SessionSummary(
                id: UUID(),
                host: "198.18.0.42",
                sourceEndpoint: "192.168.1.50:53002",
                destinationEndpoint: "198.18.0.42:443",
                sourceEndpointValue: IPEndpoint(ip: "192.168.1.50", port: 53_002),
                destinationEndpointValue: IPEndpoint(ip: "198.18.0.42", port: 443),
                protocolStack: [.tcp, .tls],
                status: .ok,
                bytesUp: 256,
                bytesDown: 512,
                sni: "fake-v4.example"
            ),
            SessionSummary(
                id: UUID(),
                host: "100.64.0.9",
                sourceEndpoint: "192.168.1.50:53003",
                destinationEndpoint: "100.64.0.9:443",
                sourceEndpointValue: IPEndpoint(ip: "192.168.1.50", port: 53_003),
                destinationEndpointValue: IPEndpoint(ip: "100.64.0.9", port: 443),
                protocolStack: [.tcp, .tls],
                status: .ok,
                bytesUp: 256,
                bytesDown: 512,
                sni: "cgnat-v4.example"
            ),
            SessionSummary(
                id: UUID(),
                host: "fc00::42",
                sourceEndpoint: "[fe80::1]:53004",
                destinationEndpoint: "[fc00::42]:443",
                sourceEndpointValue: IPEndpoint(ip: "fe80::1", port: 53_004),
                destinationEndpointValue: IPEndpoint(ip: "fc00::42", port: 443),
                protocolStack: [.tcp, .tls],
                status: .ok,
                bytesUp: 256,
                bytesDown: 512,
                sni: "singbox-v6.example"
            ),
            SessionSummary(
                id: UUID(),
                host: "fdfe:dcba:9876::5",
                sourceEndpoint: "[fe80::1]:53005",
                destinationEndpoint: "[fdfe:dcba:9876::5]:443",
                sourceEndpointValue: IPEndpoint(ip: "fe80::1", port: 53_005),
                destinationEndpointValue: IPEndpoint(ip: "fdfe:dcba:9876::5", port: 443),
                protocolStack: [.tcp, .tls],
                status: .ok,
                bytesUp: 256,
                bytesDown: 512,
                sni: "clash-v6.example"
            ),
        ]
        book.learn(from: mixed)

        #expect(book.learnedName(for: "203.0.113.10") == "api.dns.example")
        #expect(book.learnedName(for: "198.18.0.42") == "fake-v4.example")
        #expect(book.learnedName(for: "100.64.0.9") == "cgnat-v4.example")
        #expect(book.learnedName(for: "fc00::42") == "singbox-v6.example")
        #expect(book.learnedName(for: "fdfe:dcba:9876::5") == "clash-v6.example")
    }

    @Test("Out-of-order publication sequences cannot overwrite newer deferred/flushed snapshots or clear newer staged attributions")
    func outOfOrderPublicationSequenceGuards() async throws {
        let environment = ProjectIsolationEnvironment(name: "live-scroll-seq-ordering")
        defer { environment.tearDown() }
        let coordinator = environment.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()

        coordinator.isCapturing = true
        let generation = coordinator.startGeneration

        let olderID = UUID()
        let newerID = UUID()
        let olderSession = Self.summary(id: olderID, host: "older.example", processName: "Mail")
        let newerSession = Self.summary(id: newerID, host: "newer.example", processName: "Safari")
        let olderSnap = Self.snapshot([olderSession])
        let newerSnap = Self.snapshot([olderSession, newerSession])

        // 1. Stash newer seq 20 first while scrolling, then deliver older seq 10 -> newer stays stashed.
        coordinator.beginUserLiveScroll()
        coordinator.deliverOrDeferLiveDetailedPublication(
            applied: [olderSession, newerSession],
            publishedSnapshot: newerSnap,
            expectedGeneration: generation,
            isCapturing: true,
            stoppedSourceHasFrames: false,
            terminalHistoryCompleteness: nil,
            precomputedActivities: nil,
            nextProcesses: [olderID: "Mail", newerID: "Safari"],
            nextProvenances: nil,
            publicationSequence: 20
        )
        coordinator.deliverOrDeferLiveDetailedPublication(
            applied: [olderSession],
            publishedSnapshot: olderSnap,
            expectedGeneration: generation,
            isCapturing: true,
            stoppedSourceHasFrames: false,
            terminalHistoryCompleteness: nil,
            precomputedActivities: nil,
            nextProcesses: [olderID: "Mail"],
            nextProvenances: nil,
            publicationSequence: 10
        )
        #expect(coordinator.deferredLiveScrollPublication?.publicationSequence == 20)
        #expect(coordinator.deferredLiveScrollPublication?.applied.map(\.id) == [olderID, newerID])

        // 2. endUserLiveScroll() flushes seq 20 and advances `lastAdoptedLivePublicationSequence`;
        //    a late seq 15 arriving right after MUST be ignored rather than regressing `sessions`.
        coordinator.endUserLiveScroll()
        #expect(coordinator.sessions.map(\.id) == [olderID, newerID])
        #expect(coordinator.lastAdoptedLivePublicationSequence == 20)

        coordinator.deliverOrDeferLiveDetailedPublication(
            applied: [olderSession],
            publishedSnapshot: olderSnap,
            expectedGeneration: generation,
            isCapturing: true,
            stoppedSourceHasFrames: false,
            terminalHistoryCompleteness: nil,
            precomputedActivities: nil,
            nextProcesses: [olderID: "Mail"],
            nextProvenances: nil,
            publicationSequence: 15
        )
        #expect(coordinator.sessions.map(\.id) == [olderID, newerID])

        // 3. Safety-valve flush: stash seq 40, wait past `maxLiveScrollDeferralDuration`, then let
        //    older seq 30 trigger the safety valve -> newer seq 40 wins over older seq 30!
        let safetyNewerID = UUID()
        let safetyNewerSession = Self.summary(id: safetyNewerID, host: "safety-newer.example", processName: "Notes")
        coordinator.maxLiveScrollDeferralDuration = .milliseconds(30)
        coordinator.beginUserLiveScroll()
        coordinator.deliverOrDeferLiveDetailedPublication(
            applied: [safetyNewerSession],
            publishedSnapshot: Self.snapshot([safetyNewerSession]),
            expectedGeneration: generation,
            isCapturing: true,
            stoppedSourceHasFrames: false,
            terminalHistoryCompleteness: nil,
            precomputedActivities: nil,
            nextProcesses: [safetyNewerID: "Notes"],
            nextProvenances: nil,
            publicationSequence: 40
        )
        try await Task.sleep(for: .milliseconds(50))
        coordinator.deliverOrDeferLiveDetailedPublication(
            applied: [olderSession],
            publishedSnapshot: olderSnap,
            expectedGeneration: generation,
            isCapturing: true,
            stoppedSourceHasFrames: false,
            terminalHistoryCompleteness: nil,
            precomputedActivities: nil,
            nextProcesses: [olderID: "Mail"],
            nextProvenances: nil,
            publicationSequence: 30
        )
        #expect(coordinator.sessions.map(\.id) == [safetyNewerID])
        #expect(coordinator.lastAdoptedLivePublicationSequence == 40)
        coordinator.endUserLiveScroll()

        // 4. Staged attribution sequence guard: adopting seq 50 must NOT clear staged map from seq 60!
        let stagedID = UUID()
        let stagedProv = ProcessProvenance(executablePath: "/usr/bin/curl", hasControllingTTY: true)
        coordinator.stagedAttributedProcesses = (
            generation: generation,
            sequence: 60,
            map: [stagedID: "curl"]
        )
        coordinator.stagedAttributedProvenances = (
            generation: generation,
            sequence: 60,
            map: [stagedID: stagedProv]
        )
        coordinator.deliverOrDeferLiveDetailedPublication(
            applied: [olderSession],
            publishedSnapshot: olderSnap,
            expectedGeneration: generation,
            isCapturing: true,
            stoppedSourceHasFrames: false,
            terminalHistoryCompleteness: nil,
            precomputedActivities: nil,
            nextProcesses: nil,
            nextProvenances: nil,
            publicationSequence: 50
        )
        #expect(coordinator.stagedAttributedProcesses?.sequence == 60)
        #expect(coordinator.stagedAttributedProcesses?.map[stagedID] == "curl")
        #expect(coordinator.stagedAttributedProvenances?.sequence == 60)
        #expect(coordinator.stagedAttributedProvenances?.map[stagedID] == stagedProv)

        // Adopting seq 60 DOES clear the matching staged map cleanly.
        coordinator.deliverOrDeferLiveDetailedPublication(
            applied: [olderSession],
            publishedSnapshot: olderSnap,
            expectedGeneration: generation,
            isCapturing: true,
            stoppedSourceHasFrames: false,
            terminalHistoryCompleteness: nil,
            precomputedActivities: nil,
            nextProcesses: [stagedID: "curl"],
            nextProvenances: [stagedID: stagedProv],
            publicationSequence: 60
        )
        #expect(coordinator.stagedAttributedProcesses == nil)
        #expect(coordinator.stagedAttributedProvenances == nil)
        #expect(coordinator.attributedProcessesBySessionID[stagedID] == "curl")
        #expect(coordinator.attributedProvenancesBySessionID[stagedID] == stagedProv)
    }

    // MARK: Private

    private static func snapshot(_ sessions: [SessionSummary]) -> InvestigationSnapshot {
        InvestigationSnapshot.empty.replacingSessions(with: sessions)
    }

    private static func summary(
        id: UUID,
        host: String,
        processName: String?,
        provenance: ProcessProvenance? = nil,
        startTime: Date = Date(timeIntervalSince1970: 1_700_000_000),
        bytesDown: Int = 512
    )
        -> SessionSummary
    {
        SessionSummary(
            id: id,
            startTime: startTime,
            duration: 0.25,
            processName: processName,
            processProvenance: provenance,
            host: host,
            sourceEndpoint: "198.51.100.10:0",
            destinationEndpoint: "203.0.113.20:0",
            protocolStack: [.tcp, .tls],
            status: .ok,
            latencyMilliseconds: 15,
            bytesUp: 256,
            bytesDown: bytesDown
        )
    }
}
