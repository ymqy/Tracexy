import Foundation
import Testing
@testable import Tracexy

// MARK: - StickyProcessAttributionTests

@MainActor
@Suite("Sticky session process attribution")
struct StickyProcessAttributionTests {
    // MARK: Internal

    @Test("Sticky attribution retains resolved app names when later snapshots report nil")
    func retainsResolvedAppNamesAcrossSnapshotsAndStop() async throws {
        let environment = ProjectIsolationEnvironment(name: "sticky-retention")
        defer { environment.tearDown() }
        let coordinator = environment.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()

        let pktapSessionID = UUID()
        let resolverCachedSessionID = UUID()
        let unattributedSessionID = UUID()

        coordinator.isCapturing = true
        let liveGeneration = coordinator.startGeneration
        // Pre-seed one entry as if an earlier ProcessResolver lookup resolved an open socket.
        coordinator.attributedProcessesBySessionID[resolverCachedSessionID] = "curl"

        let initialSnapshot = Self.snapshot([
            Self.summary(id: pktapSessionID, host: "apple.example", processName: "Safari", bytesDown: 1_024),
            Self.summary(id: resolverCachedSessionID, host: "api.example", processName: nil, bytesDown: 512),
        ])
        await coordinator.publishLiveDetailed(
            initialSnapshot,
            expectedGeneration: liveGeneration,
            isCapturing: true
        ).value

        #expect(coordinator.attributedProcessesBySessionID[pktapSessionID] == "Safari")
        #expect(coordinator.attributedProcessesBySessionID[resolverCachedSessionID] == "curl")
        #expect(coordinator.sessions.map(\.processName) == ["Safari", "curl"])
        #expect(coordinator.investigationSnapshot.sessions.map(\.processName) == ["Safari", "curl"])

        // Later live snapshot after connections closed: engine emits processName == nil.
        let laterSnapshot = Self.snapshot([
            Self.summary(id: pktapSessionID, host: "apple.example", processName: nil, bytesDown: 4_096),
            Self.summary(id: resolverCachedSessionID, host: "api.example", processName: nil, bytesDown: 2_048),
            Self.summary(id: unattributedSessionID, host: "unknown.example", processName: nil, bytesDown: 256),
        ])
        await coordinator.publishLiveDetailed(
            laterSnapshot,
            expectedGeneration: liveGeneration,
            isCapturing: true
        ).value

        #expect(coordinator.sessions.map(\.processName) == ["Safari", "curl", nil])
        #expect(coordinator.investigationSnapshot.sessions.map(\.processName) == ["Safari", "curl", nil])
        #expect(coordinator.attributedProcessesBySessionID[unattributedSessionID] == nil)

        // Post-stop terminal snapshot also retains sticky attributions.
        coordinator.isCapturing = false
        coordinator.startGeneration &+= 1
        let stoppedGeneration = coordinator.startGeneration
        await coordinator.publishLiveDetailed(
            laterSnapshot,
            expectedGeneration: stoppedGeneration,
            isCapturing: false,
            terminalHistoryCompleteness: .complete
        ).value

        #expect(coordinator.sessions.map(\.processName) == ["Safari", "curl", nil])
        #expect(coordinator.investigationSnapshot.sessions.map(\.processName) == ["Safari", "curl", nil])
    }

    @Test("Non-empty pktap attribution updates cache while empty string falls back to cached app")
    func nonEmptyUpdatesCacheAndEmptyFallsBack() async {
        let environment = ProjectIsolationEnvironment(name: "sticky-empty")
        defer { environment.tearDown() }
        let coordinator = environment.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()

        let sessionID = UUID()
        coordinator.attributedProcessesBySessionID[sessionID] = "HelperDaemon"

        let updatedSnapshot = Self.snapshot([
            Self.summary(id: sessionID, host: "cdn.example", processName: "Safari"),
        ])
        await coordinator.publishLiveDetailed(
            updatedSnapshot,
            expectedGeneration: coordinator.startGeneration,
            isCapturing: false
        ).value
        #expect(coordinator.attributedProcessesBySessionID[sessionID] == "Safari")
        #expect(coordinator.sessions.first?.processName == "Safari")

        let emptyNameSnapshot = Self.snapshot([
            Self.summary(id: sessionID, host: "cdn.example", processName: ""),
        ])
        await coordinator.publishLiveDetailed(
            emptyNameSnapshot,
            expectedGeneration: coordinator.startGeneration,
            isCapturing: false
        ).value
        #expect(coordinator.attributedProcessesBySessionID[sessionID] == "Safari")
        #expect(coordinator.sessions.first?.processName == "Safari")
    }

    @Test("Stale generation or mismatched capture state does not mutate attribution cache")
    func staleOrMismatchedPublicationLeavesCacheUntouched() async {
        let environment = ProjectIsolationEnvironment(name: "sticky-guards")
        defer { environment.tearDown() }
        let coordinator = environment.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()

        let sessionID = UUID()
        let snapshot = Self.snapshot([
            Self.summary(id: sessionID, host: "stale.example", processName: "Safari"),
        ])

        await coordinator.publishLiveDetailed(
            snapshot,
            expectedGeneration: coordinator.startGeneration + 1,
            isCapturing: coordinator.isCapturing
        ).value
        #expect(coordinator.attributedProcessesBySessionID.isEmpty)
        #expect(coordinator.sessions.isEmpty)

        await coordinator.publishLiveDetailed(
            snapshot,
            expectedGeneration: coordinator.startGeneration,
            isCapturing: !coordinator.isCapturing
        ).value
        #expect(coordinator.attributedProcessesBySessionID.isEmpty)
        #expect(coordinator.sessions.isEmpty)
    }

    @Test("History demo mode leaves demo fixtures untouched and skips ProcessResolver")
    func historyDemoModeLeavesFixturesUntouched() async {
        let environment = ProjectIsolationEnvironment(name: "sticky-demo")
        defer { environment.tearDown() }
        let defaults = UserDefaults(suiteName: "\(environment.suitePrefix).demo")
        defer { TestPreferences.remove("\(environment.suitePrefix).demo") }
        let coordinator = MainContentCoordinator(
            projectDataProvider: environment.provider,
            isHistoryDemoMode: true,
            settingsDefaults: defaults
        )
        await coordinator.hydrateProjectsOnLaunch()

        let attributedID = UUID()
        let unattributedID = UUID()
        let demoSnapshot = Self.snapshot([
            Self.summary(id: attributedID, host: "demo-a.example", processName: "Safari"),
            Self.summary(id: unattributedID, host: "demo-b.example", processName: nil),
        ])
        await coordinator.publishLiveDetailed(
            demoSnapshot,
            expectedGeneration: coordinator.startGeneration,
            isCapturing: false
        ).value

        #expect(coordinator.attributedProcessesBySessionID.isEmpty)
        #expect(coordinator.sessions.map(\.processName) == ["Safari", nil])
    }

    @Test("Clear, engine reset, and opening a saved capture clear sticky attributions")
    func captureBoundariesClearStickyAttributions() async throws {
        let environment = ProjectIsolationEnvironment(name: "sticky-reset")
        defer { environment.tearDown() }
        let coordinator = environment.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()

        let sessionID = UUID()
        await coordinator.publishLiveDetailed(
            Self.snapshot([Self.summary(id: sessionID, host: "first.example", processName: "Safari")]),
            expectedGeneration: coordinator.startGeneration,
            isCapturing: false
        ).value
        #expect(coordinator.attributedProcessesBySessionID[sessionID] == "Safari")

        // 1. clearSessions wipes cached attributions so an identical UUID in a later capture does not inherit it.
        coordinator.clearSessions()
        await coordinator.ingestChain?.value
        #expect(coordinator.attributedProcessesBySessionID.isEmpty)

        await coordinator.publishLiveDetailed(
            Self.snapshot([Self.summary(id: sessionID, host: "first.example", processName: nil)]),
            expectedGeneration: coordinator.startGeneration,
            isCapturing: false
        ).value
        #expect(coordinator.sessions.first?.processName == nil)

        // 2. Direct resetSessionEngine wipes cached attributions.
        coordinator.attributedProcessesBySessionID[sessionID] = "Mail"
        coordinator.startGeneration &+= 1
        coordinator.resetSessionEngine(token: coordinator.startGeneration)
        await coordinator.ingestChain?.value
        #expect(coordinator.attributedProcessesBySessionID.isEmpty)

        // 3. Opening a saved capture wipes cached attributions.
        coordinator.attributedProcessesBySessionID[sessionID] = "Terminal"
        let pcapURL = environment.root.appendingPathComponent("sample.pcap")
        try FileManager.default.createDirectory(at: environment.root, withIntermediateDirectories: true)
        let frames = SampleCapture.frames(now: Date(timeIntervalSince1970: 1_700_000_000))
        try PcapWriter.write(linkType: LinkType.ethernet, frames: frames, to: pcapURL)
        coordinator.openSavedCapture(
            SavedCapture(url: pcapURL, name: "sample", date: Date(), byteCount: frames.count)
        )
        await coordinator.waitForSavedCaptureOpen()
        #expect(coordinator.attributedProcessesBySessionID.isEmpty)
    }

    @Test("Project switches park and restore sticky attributions without cross-project bleed")
    func projectSwitchesParkAndRestoreWithoutBleed() async throws {
        let environment = ProjectIsolationEnvironment(name: "sticky-projects")
        defer { environment.tearDown() }
        let coordinator = environment.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()

        let projectA = coordinator.projectStore.activeProjectID
        let sharedSessionID = UUID()
        let projectAOnlyID = UUID()
        let projectBOnlyID = UUID()

        await coordinator.publishLiveDetailed(
            Self.snapshot([
                Self.summary(id: sharedSessionID, host: "shared.example", processName: "Safari"),
                Self.summary(id: projectAOnlyID, host: "mail.example", processName: "Mail"),
            ]),
            expectedGeneration: coordinator.startGeneration,
            isCapturing: false
        ).value
        #expect(coordinator.attributedProcessesBySessionID == [
            sharedSessionID: "Safari",
            projectAOnlyID: "Mail",
        ])

        // Switch to newly created Project B: starts clean with no bleed from Project A.
        let projectB = try #require(coordinator.createProject(named: "Second"))
        #expect(await coordinator.waitForProjectTransition())
        #expect(coordinator.attributedProcessesBySessionID.isEmpty)

        await coordinator.publishLiveDetailed(
            Self.snapshot([
                Self.summary(id: sharedSessionID, host: "shared.example", processName: nil),
                Self.summary(id: projectBOnlyID, host: "shell.example", processName: "Terminal"),
            ]),
            expectedGeneration: coordinator.startGeneration,
            isCapturing: false
        ).value
        #expect(coordinator.sessions.map(\.processName) == [nil, "Terminal"])
        #expect(coordinator.attributedProcessesBySessionID == [projectBOnlyID: "Terminal"])

        // Switch back to Project A: restores Project A's attributions and excludes Project B's.
        #expect(coordinator.switchToProject(id: projectA))
        #expect(await coordinator.waitForProjectTransition())
        #expect(coordinator.attributedProcessesBySessionID == [
            sharedSessionID: "Safari",
            projectAOnlyID: "Mail",
        ])

        await coordinator.publishLiveDetailed(
            Self.snapshot([
                Self.summary(id: sharedSessionID, host: "shared.example", processName: nil),
                Self.summary(id: projectAOnlyID, host: "mail.example", processName: nil),
                Self.summary(id: projectBOnlyID, host: "shell.example", processName: nil),
            ]),
            expectedGeneration: coordinator.startGeneration,
            isCapturing: false
        ).value
        #expect(coordinator.sessions.map(\.processName) == ["Safari", "Mail", nil])

        // Clearing Project B leaves Project A's parked sticky attributions intact.
        #expect(coordinator.switchToProject(id: projectB.id))
        #expect(await coordinator.waitForProjectTransition())
        #expect(coordinator.attributedProcessesBySessionID == [projectBOnlyID: "Terminal"])
        coordinator.clearSessions()
        await coordinator.ingestChain?.value
        #expect(coordinator.attributedProcessesBySessionID.isEmpty)

        #expect(coordinator.switchToProject(id: projectA))
        #expect(await coordinator.waitForProjectTransition())
        #expect(coordinator.attributedProcessesBySessionID == [
            sharedSessionID: "Safari",
            projectAOnlyID: "Mail",
        ])
    }

    // MARK: Private

    private static func snapshot(_ sessions: [SessionSummary]) -> InvestigationSnapshot {
        InvestigationSnapshot.empty.replacingSessions(with: sessions)
    }

    /// Uses RFC 5737 documentation endpoints with port `0` so live host socket tables
    /// never accidentally match an unattributed test session.
    private static func summary(
        id: UUID,
        host: String,
        processName: String?,
        bytesDown: Int = 512
    )
        -> SessionSummary
    {
        SessionSummary(
            id: id,
            startTime: Date(timeIntervalSince1970: 1_700_000_000),
            duration: 0.25,
            processName: processName,
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
