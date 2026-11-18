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

    @Test("Provenance flows from CapturedFrame to SessionSummary, sticks across snapshots, and drives synthetic filters")
    func provenancePlumbingAndSyntheticSourceFiltering() async throws {
        let environment = ProjectIsolationEnvironment(name: "sticky-provenance")
        defer { environment.tearDown() }
        let coordinator = environment.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()

        let safariProvenance = ProcessProvenance(
            executablePath: "/Applications/Safari.app"
                + "/Contents/XPCServices/com.apple.WebKit.Networking.xpc/Contents/MacOS/com.apple.WebKit.Networking",
            bundleIdentifier: "com.apple.Safari",
            viaProcessName: "Safari Networking"
        )
        let sampleFrames = SampleCapture.frames(now: Date(timeIntervalSince1970: 1_700_000_000))
        var taggedFrame = try #require(sampleFrames.first)
        taggedFrame.processName = "Safari"
        taggedFrame.processProvenance = safariProvenance
        let builtFromFrames = SessionBuilder.build(from: [taggedFrame], linkType: LinkType.ethernet)
        let decodedSession = try #require(builtFromFrames.first)
        #expect(decodedSession.processName == "Safari")
        #expect(decodedSession.processProvenance == safariProvenance)

        let mdnsID = UUID()
        let ndpID = UUID()
        let unattributedID = UUID()
        let mdnsSession = SessionSummary(
            id: mdnsID,
            startTime: Date(timeIntervalSince1970: 1_700_000_001),
            duration: 0.01,
            processName: nil,
            host: "224.0.0.251",
            sourceEndpoint: "198.51.100.78:5353",
            destinationEndpoint: "224.0.0.251:5353",
            sourceEndpointValue: IPEndpoint(ip: "198.51.100.78", port: 5_353),
            destinationEndpointValue: IPEndpoint(ip: "224.0.0.251", port: 5_353),
            protocolStack: [.udp, .mdns],
            status: .ok,
            bytesUp: 120,
            bytesDown: 0
        )
        let ndpSession = SessionSummary(
            id: ndpID,
            startTime: Date(timeIntervalSince1970: 1_700_000_002),
            duration: 0,
            processName: "kernel_task",
            processProvenance: ProcessProvenance(isRootUser: true, isKernelTask: true),
            host: "ff02::1",
            sourceEndpoint: "[fe80::1]:0",
            destinationEndpoint: "[ff02::1]:0",
            sourceEndpointValue: IPEndpoint(ip: "fe80::1", port: 0),
            destinationEndpointValue: IPEndpoint(ip: "ff02::1", port: 0),
            protocolStack: [.icmpv6],
            status: .ok,
            bytesUp: 64,
            bytesDown: 0
        )
        let unattributedSession = SessionSummary(
            id: unattributedID,
            startTime: Date(timeIntervalSince1970: 1_700_000_003),
            duration: 0.25,
            processName: nil,
            host: "mystery.example",
            sourceEndpoint: "127.0.0.1:59999",
            destinationEndpoint: "203.0.113.20:443",
            sourceEndpointValue: IPEndpoint(ip: "127.0.0.1", port: 59_999),
            destinationEndpointValue: IPEndpoint(ip: "203.0.113.20", port: 443),
            protocolStack: [.udp, .quic],
            status: .ok,
            bytesUp: 512,
            bytesDown: 512,
            packetsUp: 2,
            packetsDown: 2
        )

        await coordinator.publishLiveDetailed(
            Self.snapshot([decodedSession, mdnsSession, ndpSession, unattributedSession]),
            expectedGeneration: coordinator.startGeneration,
            isCapturing: false
        ).value

        #expect(coordinator.attributedProvenancesBySessionID[decodedSession.id] == safariProvenance)
        let strippedSafari = SessionSummary(
            id: decodedSession.id,
            startTime: decodedSession.startTime,
            duration: decodedSession.duration,
            processName: nil,
            processProvenance: nil,
            host: decodedSession.host,
            sourceEndpoint: decodedSession.sourceEndpoint,
            destinationEndpoint: decodedSession.destinationEndpoint,
            sourceEndpointValue: decodedSession.sourceEndpointValue,
            destinationEndpointValue: decodedSession.destinationEndpointValue,
            protocolStack: decodedSession.protocolStack,
            status: decodedSession.status,
            bytesUp: decodedSession.bytesUp,
            bytesDown: decodedSession.bytesDown
        )
        await coordinator.publishLiveDetailed(
            Self.snapshot([strippedSafari, mdnsSession, ndpSession, unattributedSession]),
            expectedGeneration: coordinator.startGeneration,
            isCapturing: false
        ).value

        let classifiedSafari = coordinator.classifiedSource(for: coordinator.sessions[0])
        #expect(classifiedSafari.category == .app)
        #expect(classifiedSafari.subtitle == String(format: String(localized: "via %@"), "Safari Networking"))

        let categories = coordinator.sourceCategoryGroups.map(\.category)
        #expect(categories == [.app, .lanDiscovery, .kernelAndLink, .unattributed])

        coordinator.selectProcess("lan:mdns")
        #expect(coordinator.visibleSessions.map(\.id) == [mdnsID])

        coordinator.selectProcess("kernel:ndp")
        #expect(coordinator.visibleSessions.map(\.id) == [ndpID])

        coordinator.selectProcess("—")
        #expect(coordinator.visibleSessions.map(\.id) == [unattributedID])

        coordinator.clearSessions()
        await coordinator.ingestChain?.value
        #expect(coordinator.attributedProvenancesBySessionID.isEmpty)
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
