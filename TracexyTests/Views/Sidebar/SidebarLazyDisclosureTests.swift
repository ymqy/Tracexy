import Foundation
import Testing
@testable import Tracexy

@Suite("Sidebar lazy disclosure and value-scoped filter state")
struct SidebarLazyDisclosureTests {
    // MARK: Internal

    @Test("SidebarActiveScope matches host, process, IP, and child targets only in .sessions scope")
    func activeScopeMatchesOnlyInSessionsSelection() {
        let hostChild = SourceChildTarget(kind: .host, value: "api.example.com", label: "api.example.com")
        let otherHostChild = SourceChildTarget(kind: .host, value: "cdn.example.com", label: "cdn.example.com")
        let peerChild = SourceChildTarget(kind: .peerIP, value: "192.0.2.10", label: "192.0.2.10")
        let otherPeerChild = SourceChildTarget(kind: .peerIP, value: "192.0.2.20", label: "192.0.2.20")

        let workspace = WorkspaceState(title: "Capture", sidebarSelection: .sessions)
        workspace.hostFilter = "api.example.com"
        workspace.processFilter = "app:com.example.browser"
        workspace.ipFilter = "192.0.2.10"

        let sessionsScope = SidebarActiveScope(workspace: workspace)
        #expect(sessionsScope.isSessionsScope)
        #expect(sessionsScope.isActiveHost("api.example.com"))
        #expect(!sessionsScope.isActiveHost("cdn.example.com"))
        #expect(sessionsScope.isActiveProcess("app:com.example.browser"))
        #expect(!sessionsScope.isActiveProcess("cli:curl"))
        #expect(sessionsScope.isActiveIP("192.0.2.10"))
        #expect(!sessionsScope.isActiveIP("192.0.2.20"))
        #expect(sessionsScope.isActiveChild(hostChild))
        #expect(!sessionsScope.isActiveChild(otherHostChild))
        #expect(sessionsScope.isActiveChild(peerChild))
        #expect(!sessionsScope.isActiveChild(otherPeerChild))

        let nonSessionSelections: [SidebarItem] = [.overview, .flow, .history, .http, .dns]
        for selection in nonSessionSelections {
            workspace.sidebarSelection = selection
            let scope = SidebarActiveScope(workspace: workspace)
            #expect(!scope.isSessionsScope)
            #expect(!scope.isActiveHost("api.example.com"))
            #expect(!scope.isActiveProcess("app:com.example.browser"))
            #expect(!scope.isActiveIP("192.0.2.10"))
            #expect(!scope.isActiveChild(hostChild))
            #expect(!scope.isActiveChild(peerChild))
        }
    }

    @Test("SidebarActiveScope equality tracks every filter field")
    func activeScopeEquatableSemantics() {
        let base = SidebarActiveScope(
            isSessionsScope: true,
            hostFilter: "example.com",
            processFilter: "cli:curl",
            ipFilter: "203.0.113.5"
        )
        let same = SidebarActiveScope(
            isSessionsScope: true,
            hostFilter: "example.com",
            processFilter: "cli:curl",
            ipFilter: "203.0.113.5"
        )
        let diffScope = SidebarActiveScope(
            isSessionsScope: false,
            hostFilter: "example.com",
            processFilter: "cli:curl",
            ipFilter: "203.0.113.5"
        )
        let diffHost = SidebarActiveScope(
            isSessionsScope: true,
            hostFilter: "other.example.com",
            processFilter: "cli:curl",
            ipFilter: "203.0.113.5"
        )
        let diffProcess = SidebarActiveScope(
            isSessionsScope: true,
            hostFilter: "example.com",
            processFilter: "cli:dig",
            ipFilter: "203.0.113.5"
        )
        let diffIP = SidebarActiveScope(
            isSessionsScope: true,
            hostFilter: "example.com",
            processFilter: "cli:curl",
            ipFilter: "203.0.113.6"
        )

        #expect(base == same)
        #expect(base != diffScope)
        #expect(base != diffHost)
        #expect(base != diffProcess)
        #expect(base != diffIP)
    }

    @Test("SidebarChildSlice caps unsearched lists at 60 and expands on showAll or search")
    func childSliceCapAndExpansionModes() {
        #expect(SidebarChildSlice<String>.defaultLimit == 60)

        let emptySlice = SidebarChildSlice([String](), showAll: false, isSearching: false)
        #expect(emptySlice.visible.isEmpty)
        #expect(emptySlice.remainingCount == 0)
        #expect(!emptySlice.isTruncated)

        let exactBoundary = (1 ... 60).map { "198.51.100.\($0)" }
        let boundarySlice = SidebarChildSlice(exactBoundary, showAll: false, isSearching: false)
        #expect(boundarySlice.visible.count == 60)
        #expect(boundarySlice.remainingCount == 0)
        #expect(!boundarySlice.isTruncated)

        let oversizedIPs = (1 ... 145).map { "198.51.100.\($0)" }
        let cappedSlice = SidebarChildSlice(oversizedIPs, showAll: false, isSearching: false)
        #expect(cappedSlice.visible.count == 60)
        #expect(Array(cappedSlice.visible) == Array(oversizedIPs.prefix(60)))
        #expect(cappedSlice.remainingCount == 85)
        #expect(cappedSlice.isTruncated)

        let showAllSlice = SidebarChildSlice(oversizedIPs, showAll: true, isSearching: false)
        #expect(showAllSlice.visible.count == 145)
        #expect(showAllSlice.remainingCount == 0)
        #expect(!showAllSlice.isTruncated)

        let searchSlice = SidebarChildSlice(oversizedIPs, showAll: false, isSearching: true)
        #expect(searchSlice.visible.count == 145)
        #expect(searchSlice.remainingCount == 0)
        #expect(!searchSlice.isTruncated)

        let targets = (1 ... 75).map {
            SourceChildTarget(kind: .host, value: "host-\($0).example.com", label: "host-\($0).example.com")
        }
        let targetCapped = SidebarChildSlice(targets, showAll: false, isSearching: false)
        #expect(targetCapped.visible.count == 60)
        #expect(targetCapped.remainingCount == 15)
        #expect(targetCapped.isTruncated)

        let zeroCap = SidebarChildSlice(targets, showAll: false, isSearching: false, limit: -5)
        #expect(zeroCap.visible.isEmpty)
        #expect(zeroCap.remainingCount == 75)
        #expect(zeroCap.isTruncated)
    }

    @Test("SidebarView enforces lazy disclosure guards and single activeWorkspace read")
    func sidebarViewLazyDisclosureAndScopeInvariants() throws {
        let sidebar = try readProjectFile("Tracexy/Views/Sidebar/SidebarView.swift")

        // Only SidebarView.body reads coordinator.activeWorkspace; rows consume SidebarActiveScope.
        let workspaceReads = sidebar.components(separatedBy: "coordinator.activeWorkspace").count - 1
        #expect(workspaceReads == 1)

        // Top-level DisclosureGroups guard inner body construction when collapsed.
        #expect(sidebar.contains("if isSearching || protocolsExpanded {"))
        #expect(sidebar.contains("if isSearching || expanded.wrappedValue {"))
        #expect(sidebar.contains("if isSearching || domainsExpanded {"))
        #expect(sidebar.contains("if isSearching || localDiscoveryExpanded {"))
        #expect(sidebar.contains("if isSearching || ipsExpanded {"))
        #expect(sidebar.contains("if isSearching || pinnedExpanded {"))
        #expect(sidebar.contains("if isSearching || savedExpanded {"))

        // All 4 nested row types guard DisclosureGroup child content with `if isExpanded {`.
        let nestedExpansionChecks = sidebar.components(separatedBy: "let isExpanded = forceExpanded || expanded").count - 1
        #expect(nestedExpansionChecks == 4)
        let lazyRowGuards = sidebar.components(separatedBy: "if isExpanded {").count - 1
        #expect(lazyRowGuards == 5)

        // Child overflow row uses shared caption typography and exact "+ N more…" copy.
        #expect(sidebar.contains("Text(\"+ \\(remainingCount) more…\")"))
        #expect(sidebar.contains("SidebarChildSlice("))
    }

    // MARK: Private

    private enum ResolveError: Error {
        case rootNotFound
    }

    private func readProjectFile(_ relativePath: String) throws -> String {
        let root = try resolveProjectRoot()
        return try String(contentsOf: root.appendingPathComponent(relativePath), encoding: .utf8)
    }

    private func resolveProjectRoot() throws -> URL {
        var url = URL(fileURLWithPath: #filePath)
        while url.lastPathComponent != "TracexyTests", url.path != "/" {
            url.deleteLastPathComponent()
        }
        guard url.lastPathComponent == "TracexyTests" else {
            throw ResolveError.rootNotFound
        }
        url.deleteLastPathComponent()
        return url
    }
}
