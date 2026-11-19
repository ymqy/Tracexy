import Foundation
import Testing
@testable import Tracexy

@Suite("Sidebar & surface local discovery presentation contract")
struct SidebarLocalDiscoveryContractTests {
    // MARK: Internal

    @Test("Sidebar Local Services & Devices defaults collapsed and never auto-expands on capture")
    func localDiscoveryGroupDefaultsCollapsedAndNeverAutoExpands() throws {
        let sidebar = try readProjectFile("Tracexy/Views/Sidebar/SidebarView.swift")

        #expect(sidebar.contains("@State private var localDiscoveryExpanded = false"))
        #expect(!sidebar.contains("localDiscoveryExpanded = true"))
        #expect(sidebar.contains("DisclosureGroup(isExpanded: searchExpansion($localDiscoveryExpanded))"))
        #expect(sidebar.contains("title: String(localized: \"Local Services & Devices\")"))
        #expect(sidebar.contains("systemImage: \"bonjour\""))
        #expect(sidebar.contains("Text(\"No visible local names\")"))
        #expect(sidebar.contains("copyLabel: \"Copy Local Names\""))
        #expect(sidebar.contains("restoreLabel: \"Restore Hidden Local Names\""))
        #expect(sidebar.contains("hiddenCount: coordinator.hiddenSourceLocalNames.count"))
        #expect(sidebar.contains("onRestore: coordinator.restoreHiddenSourceLocalNames"))
    }

    @Test("Sidebar places Local Services & Devices strictly between Domains and IP Addresses")
    func localDiscoveryPlacedBetweenDomainsAndIPAddresses() throws {
        let sidebar = try readProjectFile("Tracexy/Views/Sidebar/SidebarView.swift")

        let sectionMarker = try #require(sidebar.range(of: "Section(String(localized: \"Sources\"))"))
        let sourcesSection = sidebar[sectionMarker.lowerBound...]
        let domainsRange = try #require(sourcesSection.range(of: "if showsDomainsCategory {\n                        domainsDisclosure"))
        let localRange = try #require(sourcesSection.range(of: "if showsLocalDiscoveryCategory {\n                        localDiscoveryDisclosure"))
        let ipsRange = try #require(sourcesSection.range(of: "if showsIPAddressesCategory {\n                        ipAddressesDisclosure"))

        #expect(domainsRange.upperBound < localRange.lowerBound)
        #expect(localRange.upperBound < ipsRange.lowerBound)
        #expect(sidebar.contains("|| showsLocalDiscoveryCategory"))
        #expect(sidebar.contains("|| !filteredLocalDiscoveryGroups.isEmpty"))
    }

    @Test("Sidebar local discovery search and row interactions follow source-list contracts")
    func localDiscoverySearchAndRowContract() throws {
        let sidebar = try readProjectFile("Tracexy/Views/Sidebar/SidebarView.swift")

        #expect(sidebar.contains("matches(\"Local Services & Devices\")"))
        #expect(sidebar.contains("matches(\"本地服务与设备名\")"))
        #expect(sidebar.contains("matches(\"bonjour\")"))
        #expect(sidebar.contains("matches(\"local\")"))
        #expect(sidebar.contains("matches(group.name) || matches(group.subtitle) || matches(group.badgeTitle)"))
        #expect(sidebar.contains("private struct LocalDiscoveryRow: View"))
        #expect(sidebar.contains("if group.ips.isEmpty {\n            rowLabel\n        } else {\n            DisclosureGroup"))
        #expect(sidebar.contains("copyLabel: \"Copy Local Name\""))
        #expect(sidebar.contains("coordinator.selectHost(group.name)"))
        #expect(sidebar.contains("coordinator.hideSourceLocalName(group.name)"))
        #expect(sidebar.contains(".help(group.tooltip)"))
    }

    @Test("SessionCenterView annotates local discovery hosts in both flat and grouped tables")
    func sessionCenterAnnotatesLocalDiscoveryHosts() throws {
        let sessions = try readProjectFile("Tracexy/Views/Sessions/SessionCenterView.swift")

        let classifyCount = sessions.components(separatedBy: "LocalDiscoveryNameClassifier.classify(displayHost)").count - 1
        #expect(classifyCount == 2)
        #expect(sessions.contains("private func localDiscoveryBadge(_ discovery: LocalDiscoveryAnnotation)"))
        #expect(sessions.contains("Text(discovery.badgeTitle)"))
        #expect(sessions.contains(".help(discovery?.tooltip ?? displayHost)"))
        #expect(sessions.contains(".help(discovery.tooltip)"))
        #expect(sessions.contains(".width(min: 130, ideal: 215)"))
    }

    @Test("InspectorView and ContextDockView display local discovery detail titles and tooltips")
    func inspectorAndContextDockDisplayLocalDiscoveryDetails() throws {
        let inspector = try readProjectFile("Tracexy/Views/Inspector/InspectorView.swift")
        let dock = try readProjectFile("Tracexy/Views/Inspector/ContextDockView.swift")

        #expect(inspector.contains("let identity = selectedIdentity(for: session)"))
        #expect(inspector.contains("let discovery = LocalDiscoveryNameClassifier.classify(identity)"))
        #expect(inspector.contains("Text(\"(\\(discovery.detailTitle))\")"))
        #expect(inspector.contains(".help(discovery?.tooltip ?? identity)"))

        #expect(dock.contains("LocalDiscoveryNameClassifier.classify(session.host)"))
        #expect(dock.contains("Text(discovery.detailTitle)"))
        #expect(dock.contains("discovery?.tooltip"))
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
