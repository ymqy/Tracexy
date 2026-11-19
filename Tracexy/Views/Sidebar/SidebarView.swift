import AppKit
import SwiftUI

// MARK: - SidebarView

/// Source-list sidebar: a Browse / Focus / Library navigator segmented control
/// swaps the whole body so each kind of work stands alone, instead of stacking
/// Monitor + Protocols + Sources + Favorites into one crowded list.
///
/// - Browse  — Monitor destinations (Overview/Sessions/Flow Map), the Protocols
///             lens group, and Sources (Apps/Domains/IPs). Protocols is a single
///             disclosure group. Protocols, Apps, and Domains begin collapsed,
///             then open once when the current capture first publishes a decoded
///             session. A later manual collapse remains under user control.
/// - Focus   — saved Focus Sets (named filters) + Noise Control (mute hosts /
///             protocols so a chatty capture stops flooding the list).
/// - Library — Favorites (Pinned hosts / Saved captures).
struct SidebarView: View {
    // MARK: Internal

    @Bindable var coordinator: MainContentCoordinator

    var body: some View {
        let workspace = coordinator.activeWorkspace
        navigatorChrome(workspace)
            .onChange(of: coordinator.sessions.isEmpty, initial: true) { _, sessionsAreEmpty in
                observeCaptureData(hasCaptureData: !sessionsAreEmpty)
            }
            .confirmationDialog(
                capturePendingRemoval.map { "Move “\($0.name)” to Trash?" } ?? "Move Capture to Trash?",
                isPresented: captureRemovalConfirmation,
                titleVisibility: .visible
            ) {
                if let capture = capturePendingRemoval {
                    Button("Move to Trash", role: .destructive) {
                        moveCaptureToTrash(capture)
                    }
                }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text("The capture will disappear from Saved and can be recovered from the Trash.")
            }
            .alert("Couldn’t Remove Capture", isPresented: captureRemovalErrorPresentation) {
                Button("OK", role: .cancel) { captureRemovalError = nil }
            } message: {
                Text(captureRemovalError ?? "The capture could not be moved to the Trash.")
            }
    }

    // MARK: Private

    private static let fileSetMenuLimit = 24

    @Environment(\.openWindow) private var openWindow

    /// Live sidebar-search text. Deliberately *local* to the sidebar: it scopes
    /// the navigator's own rows and never touches `WorkspaceState.filterText` or
    /// the session list, which have their own filter controls.
    @State private var sidebarSearch = ""

    /// Context-menu removal is staged through a confirmation because a saved
    /// capture is user data, not merely sidebar presentation state. The actual
    /// operation is recoverable (move to Trash), matching native macOS library
    /// behavior while still removing the row immediately after success.
    @State private var capturePendingRemoval: SavedCapture?
    @State private var captureRemovalError: String?

    @State private var protocolsExpanded = false
    @State private var captureAutoExpansion = SidebarCaptureAutoExpansionState()
    @State private var savedExpanded = false
    @State private var pinnedExpanded = true
    // Large, dynamic source lists start collapsed so the idle sidebar stays
    // scannable. The first decoded session opens the useful capture groups once;
    // after that, user disclosure choices and search remain authoritative.
    // Separate @State Bools keep NSOutlineView's structural branch identity stable
    // as sibling categories dynamically enter and leave during live capture.
    @State private var appsExpanded = false
    @State private var cliExpanded = false
    @State private var thirdPartyServicesExpanded = false
    @State private var systemServicesExpanded = false
    @State private var lanExpanded = false
    @State private var kernelAndLinkExpanded = false
    @State private var unattributedExpanded = false
    @State private var domainsExpanded = false
    @State private var localDiscoveryExpanded = false
    @State private var ipsExpanded = false

    // MARK: Sidebar search

    /// Normalized query. Empty means "not searching" — every list shows its full
    /// contents and honors the user's own disclosure state.
    private var query: String {
        sidebarSearch.trimmingCharacters(in: .whitespaces).lowercased()
    }

    private var isSearching: Bool {
        !sidebarSearch.isEmpty && !query.isEmpty
    }

    private var filteredMonitorItems: [SidebarItem] {
        if isSearching, matches("Monitor") {
            return SidebarSection.monitor.items
        }
        return SidebarSection.monitor.items.filter { matches($0.title) }
    }

    private var filteredProtocolItems: [SidebarItem] {
        if isSearching, matches(SidebarSection.protocols.title) {
            return SidebarSection.protocols.items
        }
        return SidebarSection.protocols.items.filter { matches($0.title) }
    }

    private struct SourceCategoryDisplay: Identifiable {
        let category: TrafficSourceCategory
        let visibleCount: Int
        let filteredItems: [SourceItemGroup]

        var id: TrafficSourceCategory { category }
    }

    /// 7-dimension traffic sources filtered against hidden source/host/IP preferences.
    private var visibleItemsBySourceCategory: [TrafficSourceCategory: [SourceItemGroup]] {
        var result: [TrafficSourceCategory: [SourceItemGroup]] = [:]
        for group in coordinator.sourceCategoryGroups {
            let items: [SourceItemGroup] = group.items.compactMap { item in
                guard !coordinator.isSourceAppHidden(item.filterKey) else {
                    return nil
                }
                let subprocesses: [SourceSubprocessGroup] = item.subprocesses.compactMap { sub in
                    guard !coordinator.isSourceAppHidden(sub.filterKey) else {
                        return nil
                    }
                    let subChildren = sub.children.filter { child in
                        switch child.kind {
                        case .host: !coordinator.isSourceHostHidden(child.value)
                        case .peerIP: !coordinator.isSourceIPHidden(child.value)
                        }
                    }
                    return SourceSubprocessGroup(
                        filterKey: sub.filterKey,
                        category: sub.category,
                        title: sub.title,
                        subtitle: sub.subtitle,
                        iconTitle: sub.iconTitle,
                        symbolName: sub.symbolName,
                        children: subChildren,
                        count: sub.count
                    )
                }
                let children = item.children.filter { child in
                    switch child.kind {
                    case .host: !coordinator.isSourceHostHidden(child.value)
                    case .peerIP: !coordinator.isSourceIPHidden(child.value)
                    }
                }
                return SourceItemGroup(
                    filterKey: item.filterKey,
                    category: item.category,
                    title: item.title,
                    subtitle: item.subtitle,
                    symbolName: item.symbolName,
                    subprocesses: subprocesses,
                    children: children,
                    count: item.count
                )
            }
            if !items.isEmpty {
                result[group.category] = items
            }
        }
        return result
    }

    private var displayedSourceCategories: [SourceCategoryDisplay] {
        let byCategory = visibleItemsBySourceCategory
        let bundle = AppLanguage.currentLocalizedBundle()
        let matchesSectionHeader = isSearching
            && (matches(String(localized: "Sources", bundle: bundle)) || matches("Sources"))
        return TrafficSourceCategory.allCases.compactMap { category in
            let visibleItems = byCategory[category] ?? []
            let filteredItems: [SourceItemGroup]
            if !isSearching || matchesSectionHeader || matches(category.title) {
                filteredItems = visibleItems
            } else {
                filteredItems = visibleItems.compactMap { item in
                    if matches(item.title) || (item.subtitle.map(matches) ?? false) {
                        return item
                    }
                    let matchingSubprocesses: [SourceSubprocessGroup] = item.subprocesses.compactMap { sub in
                        if matches(sub.title) || (sub.subtitle.map(matches) ?? false) {
                            return sub
                        }
                        let matchingSubChildren = sub.children.filter {
                            matches($0.label) || matches($0.value)
                        }
                        guard !matchingSubChildren.isEmpty else {
                            return nil
                        }
                        return SourceSubprocessGroup(
                            filterKey: sub.filterKey,
                            category: sub.category,
                            title: sub.title,
                            subtitle: sub.subtitle,
                            iconTitle: sub.iconTitle,
                            symbolName: sub.symbolName,
                            children: matchingSubChildren,
                            count: sub.count
                        )
                    }
                    let matchingChildren = item.children.filter {
                        matches($0.label) || matches($0.value)
                    }
                    guard !matchingSubprocesses.isEmpty || !matchingChildren.isEmpty else {
                        return nil
                    }
                    return SourceItemGroup(
                        filterKey: item.filterKey,
                        category: item.category,
                        title: item.title,
                        subtitle: item.subtitle,
                        symbolName: item.symbolName,
                        subprocesses: matchingSubprocesses,
                        children: matchingChildren,
                        count: item.count
                    )
                }
            }
            let showsHiddenRestoreFallback = category == .app
                && !isSearching
                && !coordinator.hiddenSourceApps.isEmpty
            guard !filteredItems.isEmpty || showsHiddenRestoreFallback else {
                return nil
            }
            return SourceCategoryDisplay(
                category: category,
                visibleCount: visibleItems.count,
                filteredItems: filteredItems
            )
        }
    }

    private var visibleDomainGroups: [DomainGroup] {
        coordinator.domainGroups.compactMap { group in
            guard !coordinator.isSourceDomainHidden(group.domain) else {
                return nil
            }
            let ips = group.ips.filter { !coordinator.isSourceIPHidden($0) }
            return DomainGroup(domain: group.domain, ips: ips, count: group.count)
        }
    }

    private var visibleLocalDiscoveryGroups: [LocalDiscoveryGroup] {
        coordinator.localDiscoveryGroups.compactMap { group in
            guard !coordinator.isSourceLocalNameHidden(group.name) else {
                return nil
            }
            let ips = group.ips.filter { !coordinator.isSourceIPHidden($0) }
            return LocalDiscoveryGroup(
                name: group.name,
                badgeTitle: group.badgeTitle,
                subtitle: group.subtitle,
                symbolName: group.symbolName,
                tooltip: group.tooltip,
                ips: ips,
                count: group.count
            )
        }
    }

    private var visibleIPHosts: [(name: String, count: Int)] {
        coordinator.ipHosts.filter { !coordinator.isSourceIPHidden($0.name) }
    }

    private var filteredPinnedHosts: [String] {
        guard isSearching else {
            return coordinator.pinnedHosts
        }
        if matches("Pinned") || matches("Favorites") {
            return coordinator.pinnedHosts
        }
        return coordinator.pinnedHosts.filter { matches($0) }
    }

    private var filteredSavedCaptures: [SavedCapture] {
        guard isSearching else {
            return coordinator.savedCaptures
        }
        if matches("Saved") || matches("Favorites") {
            return coordinator.savedCaptures
        }
        return coordinator.savedCaptures.filter { matches($0.name) }
    }

    private var filteredFocusSets: [FocusSet] {
        guard isSearching else {
            return coordinator.focusSets
        }
        if matches("Focus Sets") {
            return coordinator.focusSets
        }
        return coordinator.focusSets.filter { matches($0.name) || matches($0.subtitle) }
    }

    /// Noise Control belongs to Focus mode's chrome, so it stays visible while
    /// browsing but bows out of a search unless the query is about muting.
    private var showsNoiseControl: Bool {
        !isSearching || matches("noise control") || matches("muted") || matches("mute")
    }

    private var captureRemovalConfirmation: Binding<Bool> {
        Binding(
            get: { capturePendingRemoval != nil },
            set: {
                if !$0 {
                    capturePendingRemoval = nil
                }
            }
        )
    }

    private var captureRemovalErrorPresentation: Binding<Bool> {
        Binding(
            get: { captureRemovalError != nil },
            set: {
                if !$0 {
                    captureRemovalError = nil
                }
            }
        )
    }

    private var sidebarBottomBar: some View {
        SidebarBottomBar(searchText: $sidebarSearch) {
            Button("Save Current Capture", systemImage: "square.and.arrow.down") {
                coordinator.saveCurrentCapture()
            }
            .disabled(!coordinator.canSaveCapture)
            Button("Import Capture…", systemImage: "tray.and.arrow.down") {
                coordinator.presentCaptureImportPanel()
            }
        }
    }

    /// Honest empty state — shown only while searching, so an idle capture with
    /// nothing to browse doesn't get labelled "No results".
    private var noResultsRow: some View {
        Text("No results for “\(sidebarSearch)”")
            .font(Theme.Typography.caption)
            .foregroundStyle(.tertiary)
    }

    // MARK: Focus mode

    private var focusList: some View {
        let focusSets = filteredFocusSets
        return List {
            Section {
                if focusSets.isEmpty {
                    Text(isSearching ? "No matching focus sets" : "No focus sets yet")
                        .font(Theme.Typography.caption).foregroundStyle(.tertiary)
                } else {
                    ForEach(focusSets) { set in
                        FocusSetRow(set: set, coordinator: coordinator) { openFocusEditor(set) }
                    }
                }
            } header: {
                focusHeader("Focus Sets") {
                    Button { newFocusSet() } label: {
                        Label("New", systemImage: "plus")
                    }
                    .controlSize(.small)
                    .help("Create a focus set")
                }
                // Nudge just this header + its New button down a step; Noise
                // Control below keeps its own baseline.
                .padding(.top, Theme.Metrics.spacingS)
            }

            if showsNoiseControl {
                Section {
                    Button {
                        openWindow(id: TracexyApp.noiseControlWindowID)
                    } label: {
                        HStack {
                            Label(
                                coordinator.isNoiseControlActive
                                    ? "\(coordinator.noiseRuleCount) muted"
                                    : "Nothing muted",
                                systemImage: "speaker.slash"
                            )
                            .foregroundStyle(coordinator.isNoiseControlActive ? Color.accentColor : .secondary)
                            Spacer()
                        }
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                } header: {
                    focusHeader("Noise Control") {
                        Button("Configure…") { openWindow(id: TracexyApp.noiseControlWindowID) }
                            .controlSize(.small)
                    }
                }
            }
        }
        .listStyle(.sidebar)
    }

    // MARK: Library mode

    private func libraryList(_ workspace: WorkspaceState) -> some View {
        let activeScope = SidebarActiveScope(workspace: workspace)
        let pinnedHosts = filteredPinnedHosts
        let savedCaptures = filteredSavedCaptures
        let hasPinned = !isSearching || !pinnedHosts.isEmpty
        let hasSaved = !isSearching || !savedCaptures.isEmpty
        return List {
            Section("Favorites") {
                if hasPinned {
                    pinnedDisclosure(filteredHosts: pinnedHosts, activeScope: activeScope)
                }
                if hasSaved {
                    savedDisclosure(filteredCaptures: savedCaptures)
                }
                if isSearching, !hasPinned, !hasSaved {
                    noResultsRow
                }
            }
        }
        .listStyle(.sidebar)
    }

    private func pinnedDisclosure(filteredHosts: [String], activeScope: SidebarActiveScope) -> some View {
        DisclosureGroup(isExpanded: searchExpansion($pinnedExpanded)) {
            if isSearching || pinnedExpanded {
                if filteredHosts.isEmpty {
                    Text("No pinned hosts")
                        .font(Theme.Typography.caption).foregroundStyle(.tertiary)
                } else {
                    ForEach(filteredHosts, id: \.self) { host in
                        let isActive = activeScope.isActiveHost(host)
                        Label(host, systemImage: "globe")
                            .foregroundStyle(isActive ? Color.accentColor : .secondary)
                            .font(isActive ? Theme.Typography.navigationMedium : Theme.Typography.navigation)
                            .lineLimit(1)
                            .contentShape(Rectangle())
                            .onTapGesture { coordinator.selectHost(host) }
                            .accessibilityAddTraits(.isButton)
                            .accessibilityAddTraits(isActive ? .isSelected : [])
                            .accessibilityAction { coordinator.selectHost(host) }
                            .contextMenu {
                                SidebarSourceContextMenu(
                                    value: host,
                                    copyLabel: "Copy Address",
                                    pinnedHost: host,
                                    coordinator: coordinator,
                                    onShowSessions: { coordinator.selectHost(host) }
                                )
                            }
                    }
                }
            }
        } label: {
            Label("Pinned", systemImage: "pin.fill").badge(coordinator.pinnedHosts.count)
        }
    }

    /// Saved captures, expandable inline like Pinned — the list lives in the
    /// sidebar and a tap opens that capture in the main session view.
    private func savedDisclosure(filteredCaptures: [SavedCapture]) -> some View {
        DisclosureGroup(isExpanded: searchExpansion($savedExpanded)) {
            if isSearching || savedExpanded {
                if filteredCaptures.isEmpty {
                    Text("No saved captures")
                        .font(Theme.Typography.caption).foregroundStyle(.tertiary)
                } else {
                    ForEach(filteredCaptures) { capture in
                        savedCaptureRow(capture)
                    }
                }
                Button { coordinator.presentCaptureOpenPanel() } label: {
                    Label("Open…", systemImage: "folder.badge.plus")
                        .font(Theme.Typography.caption).foregroundStyle(.secondary)
                }
                .buttonStyle(.plain)
                .help("Open a capture where it is (⌘O). Use Import to keep a copy in the Library.")
                Button { coordinator.presentCaptureImportPanel() } label: {
                    Label("Import into Library…", systemImage: "tray.and.arrow.down")
                        .font(Theme.Typography.caption).foregroundStyle(.secondary)
                }
                .buttonStyle(.plain)
            }
        } label: {
            Label("Saved", systemImage: "folder").badge(coordinator.savedCaptures.count)
                .contextMenu {
                    Button("Save Current Capture", systemImage: "square.and.arrow.down") {
                        coordinator.saveCurrentCapture()
                    }
                    .disabled(!coordinator.canSaveCapture)
                    Button("Open…", systemImage: "folder.badge.plus") {
                        coordinator.presentCaptureOpenPanel()
                    }
                    Button("Import into Library…", systemImage: "tray.and.arrow.down") {
                        coordinator.presentCaptureImportPanel()
                    }
                }
        }
    }

    // MARK: Sources (Browse)

    /// One of the 7 semantic traffic source categories (`Apps`, `CLI Tools`,
    /// `Third-Party Services`, `System Services`, `LAN & Discovery`, `Kernel & Link`,
    /// `Unattributed`), expandable to its source rows and their hosts or peer IPs.
    private func sourceCategoryDisclosure(
        _ display: SourceCategoryDisplay,
        expanded: Binding<Bool>,
        activeScope: SidebarActiveScope
    ) -> some View {
        DisclosureGroup(isExpanded: searchExpansion(expanded)) {
            if isSearching || expanded.wrappedValue {
                if display.filteredItems.isEmpty {
                    Text("No visible sources")
                        .font(Theme.Typography.caption).foregroundStyle(.tertiary)
                } else {
                    ForEach(display.filteredItems) { item in
                        SourceItemRow(item: item, coordinator: coordinator, activeScope: activeScope, forceExpanded: isSearching)
                    }
                }
            }
        } label: {
            sourceCategoryLabel(
                title: display.category.title,
                systemImage: display.category.systemImage,
                count: display.visibleCount,
                expanded: expanded,
                copyLabel: "Copy Source Names",
                values: display.filteredItems.map(\.title),
                hiddenCount: coordinator.hiddenSourceApps.count,
                restoreLabel: "Restore Hidden Sources",
                onRestore: coordinator.restoreHiddenSourceApps
            )
        }
    }

    /// Domains, each expandable to the server IPs it resolved to (sub-IPs).
    private func domainsDisclosure(
        visibleCount: Int,
        filteredGroups: [DomainGroup],
        activeScope: SidebarActiveScope
    ) -> some View {
        DisclosureGroup(isExpanded: searchExpansion($domainsExpanded)) {
            if isSearching || domainsExpanded {
                if filteredGroups.isEmpty {
                    Text("No visible domains")
                        .font(Theme.Typography.caption).foregroundStyle(.tertiary)
                } else {
                    ForEach(filteredGroups) { group in
                        DomainRow(group: group, coordinator: coordinator, activeScope: activeScope, forceExpanded: isSearching)
                    }
                }
            }
        } label: {
            sourceCategoryLabel(
                title: String(localized: "Domains", bundle: AppLanguage.currentLocalizedBundle()),
                systemImage: "globe",
                count: visibleCount,
                expanded: $domainsExpanded,
                copyLabel: "Copy Domains",
                values: filteredGroups.map(\.domain),
                hiddenCount: coordinator.hiddenSourceDomains.count,
                restoreLabel: "Restore Hidden Domains",
                onRestore: coordinator.restoreHiddenSourceDomains
            )
        }
    }

    /// Local Bonjour / mDNS services, device hostnames, and special system DNS
    /// discovery names, separated from public Domains and kept collapsed by default.
    private func localDiscoveryDisclosure(
        visibleCount: Int,
        filteredGroups: [LocalDiscoveryGroup],
        activeScope: SidebarActiveScope
    ) -> some View {
        DisclosureGroup(isExpanded: searchExpansion($localDiscoveryExpanded)) {
            if isSearching || localDiscoveryExpanded {
                if filteredGroups.isEmpty {
                    Text("No visible local names")
                        .font(Theme.Typography.caption).foregroundStyle(.tertiary)
                } else {
                    ForEach(filteredGroups) { group in
                        LocalDiscoveryRow(group: group, coordinator: coordinator, activeScope: activeScope, forceExpanded: isSearching)
                    }
                }
            }
        } label: {
            sourceCategoryLabel(
                title: String(localized: "Local Services & Devices", bundle: AppLanguage.currentLocalizedBundle()),
                systemImage: "bonjour",
                count: visibleCount,
                expanded: $localDiscoveryExpanded,
                copyLabel: "Copy Local Names",
                values: filteredGroups.map(\.name),
                hiddenCount: coordinator.hiddenSourceLocalNames.count,
                restoreLabel: "Restore Hidden Local Names",
                onRestore: coordinator.restoreHiddenSourceLocalNames
            )
        }
    }

    /// Hosts seen only as a bare IP (no domain name resolved). Capped while
    /// browsing to stay scannable; a search widens the net to every match.
    private func ipAddressesDisclosure(
        visibleCount: Int,
        filteredHosts: [(name: String, count: Int)],
        activeScope: SidebarActiveScope
    ) -> some View {
        let hosts = isSearching ? filteredHosts : Array(filteredHosts.prefix(20))
        return DisclosureGroup(isExpanded: searchExpansion($ipsExpanded)) {
            if isSearching || ipsExpanded {
                if hosts.isEmpty {
                    Text("No visible IP addresses")
                        .font(Theme.Typography.caption).foregroundStyle(.tertiary)
                } else {
                    ForEach(hosts, id: \.name) { host in
                        SidebarIPRow(ip: host.name, count: host.count, coordinator: coordinator, activeScope: activeScope)
                    }
                }
            }
        } label: {
            sourceCategoryLabel(
                title: String(localized: "IP Addresses", bundle: AppLanguage.currentLocalizedBundle()),
                systemImage: "number",
                count: visibleCount,
                expanded: $ipsExpanded,
                copyLabel: "Copy IP Addresses",
                values: hosts.map(\.name),
                hiddenCount: coordinator.hiddenSourceIPs.count,
                restoreLabel: "Restore Hidden IP Addresses",
                onRestore: coordinator.restoreHiddenSourceIPs
            )
        }
    }

    /// One Library row. A managed copy and an in-place reference share the row
    /// shape; the reference adds a link badge (or a warning badge when its file
    /// is missing or changed) and the Locate… / Copy into Library actions. Every
    /// action a drop or double-click offers is also here, per the HIG's
    /// drag-and-drop guidance.
    private func savedCaptureRow(_ capture: SavedCapture) -> some View {
        HStack(spacing: Theme.Metrics.spacingS) {
            Label(capture.name, systemImage: "doc.text.magnifyingglass")
                .foregroundStyle(capture.isReadable ? .secondary : .tertiary)
                .lineLimit(1)
                .truncationMode(.middle)
            Spacer(minLength: 0)
            if capture.isReferenced {
                Image(systemName: capture.availability == .checking ? "clock" :
                    (capture.isReadable ? "link" : "exclamationmark.triangle"))
                    .font(Theme.Typography.caption)
                    .foregroundStyle(capture.availability == .checking || capture.isReadable
                        ? AnyShapeStyle(.tertiary) : AnyShapeStyle(.orange))
                    .help(Self.availabilityHelp(capture))
                    .accessibilityLabel(Self.availabilityHelp(capture))
            }
        }
        .contentShape(Rectangle())
        .onTapGesture { coordinator.openSavedCapture(capture) }
        // Same assistive contract as every other tappable sidebar row:
        // a tap gesture alone is invisible to VoiceOver and UI automation.
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(.isButton)
        .accessibilityHint(capture.availability == .checking ? "Checks and opens this capture" :
            (capture.isReadable ? "Opens this capture" : "Shows how to locate this capture"))
        .accessibilityAction { coordinator.openSavedCapture(capture) }
        .contextMenu {
            Button("Open", systemImage: "eye") { coordinator.openSavedCapture(capture) }
                .disabled(capture.availability == .missing || capture.availability == .changed)
            Button("Reveal in Finder", systemImage: "folder") {
                NSWorkspace.shared.activateFileViewerSelecting([capture.url])
            }
            .disabled(capture.availability == .missing)
            Button("Copy Path", systemImage: "doc.on.doc") {
                copyToPasteboard(capture.url.path)
            }
            if coordinator.activeSavedCapture?.id == capture.id {
                Button("Export Frames…", systemImage: "square.and.arrow.up") {
                    coordinator.presentFrameExportPanel()
                }
                .disabled(!coordinator.canExportFrames)
            }
            if capture.isReadable, let fileSet = CaptureFileSet(member: capture.url) {
                fileSetMenu(fileSet)
            }
            if capture.isReferenced {
                Divider()
                Button("Locate…", systemImage: "magnifyingglass") {
                    coordinator.locateReferencedCapture(capture)
                }
                Button("Copy into Library", systemImage: "tray.and.arrow.down") {
                    coordinator.copyReferencedCaptureIntoLibrary(capture)
                }
                .disabled(!capture.isReadable)
                Divider()
                // Removing a reference never touches the referenced file and the
                // sidecar goes to the Trash, so no confirmation is asked.
                Button("Remove from Library", systemImage: "trash", role: .destructive) {
                    removeReference(capture)
                }
            } else {
                Divider()
                Button("Move to Trash…", systemImage: "trash", role: .destructive) {
                    capturePendingRemoval = capture
                }
            }
        }
    }

    /// The ring-buffer set a Library item belongs to, listed in sequence order
    /// with the open member checked; every member opens in place. Read from disk
    /// when the menu opens so a set still being written stays current.
    private func fileSetMenu(_ fileSet: CaptureFileSet) -> some View {
        let listed = fileSet.members.prefix(Self.fileSetMenuLimit)
        return Menu("File Set", systemImage: "doc.on.doc") {
            Button("Next File") {
                if let next = fileSet.next {
                    coordinator.openFileSetMember(next)
                }
            }
            .disabled(fileSet.next == nil || !coordinator.canOpenCaptureSource)
            Button("Previous File") {
                if let previous = fileSet.previous {
                    coordinator.openFileSetMember(previous)
                }
            }
            .disabled(fileSet.previous == nil || !coordinator.canOpenCaptureSource)
            Divider()
            Picker(
                "Files in “\(fileSet.prefix)”",
                selection: Binding(
                    get: { fileSet.currentIndex },
                    set: { index in
                        guard index != fileSet.currentIndex, fileSet.members.indices.contains(index) else {
                            return
                        }
                        coordinator.openFileSetMember(fileSet.members[index])
                    }
                )
            ) {
                ForEach(Array(listed.enumerated()), id: \.offset) { index, member in
                    Text(member.url.lastPathComponent).tag(index)
                }
            }
            .pickerStyle(.inline)
            .disabled(!coordinator.canOpenCaptureSource)
            if fileSet.count > listed.count {
                Text("\((fileSet.count - listed.count).formatted()) more files — use Next File")
            }
        }
    }

    // MARK: Native Liquid Glass chrome

    /// macOS 26 seats navigator controls in safe-area bars so the source list
    /// continues behind the sidebar's native Liquid Glass layer. The explicit
    /// fallback preserves the previous stacked structure on older systems.
    private func navigatorChrome(_ workspace: WorkspaceState) -> some View {
        navigatorList(workspace)
            .tracexySoftScrollEdge()
            .tracexySafeAreaBar(edge: .top) {
                navigatorPicker(workspace)
            }
            .tracexySafeAreaBar(edge: .bottom) {
                sidebarBottomBar
            }
    }

    private func navigatorPicker(_ workspace: WorkspaceState) -> some View {
        WorkspaceModeSegmentedControl(
            selection: navigatorBinding(workspace),
            segments: SidebarNavigatorMode.allCases.map { mode in
                WorkspaceModeSegment(
                    value: mode,
                    title: mode.title,
                    systemImage: mode.systemImage
                )
            },
            accessibilityLabel: String(localized: "Navigator", bundle: AppLanguage.currentLocalizedBundle())
        )
        .workspaceModeSwitcherStyle()
    }

    @ViewBuilder
    private func navigatorList(_ workspace: WorkspaceState) -> some View {
        switch workspace.navigatorMode {
        case .browse: browseList(workspace)
        case .focus: focusList
        case .library: libraryList(workspace)
        }
    }

    /// A Sources category is itself an actionable sidebar item, not only a
    /// disclosure triangle. The full-width label makes secondary-clicking the
    /// row reliable, while the menu exposes category-level actions that remain
    /// meaningful even before the user expands it.
    private func sourceCategoryLabel(
        title: String,
        systemImage: String,
        count: Int,
        expanded: Binding<Bool>,
        copyLabel: String,
        values: [String],
        hiddenCount: Int,
        restoreLabel: String,
        onRestore: @escaping () -> Void
    )
        -> some View
    {
        let appearsExpanded = isSearching || expanded.wrappedValue
        return HStack {
            Label(title, systemImage: systemImage)
            Spacer(minLength: 0)
        }
        .badge(count)
        .contentShape(Rectangle())
        .contextMenu {
            Button("Show All Sessions", systemImage: "rectangle.stack") {
                coordinator.selectSidebarItem(.sessions)
            }
            Button(LocalizedStringKey(copyLabel), systemImage: "doc.on.doc") {
                copyToPasteboard(values.joined(separator: "\n"))
            }
            .disabled(values.isEmpty)
            if hiddenCount > 0 {
                Button("\(NSLocalizedString(restoreLabel, comment: "")) (\(hiddenCount))", systemImage: "arrow.uturn.backward") {
                    onRestore()
                }
            }
            Divider()
            Button(
                appearsExpanded ? "Collapse \(title)" : "Expand \(title)",
                systemImage: appearsExpanded ? "chevron.up" : "chevron.down"
            ) {
                expanded.wrappedValue.toggle()
            }
            .disabled(isSearching)
        }
    }

    /// A section header with a trailing native push button (clear, not a faint
    /// label) — the visible "New" / "Configure…" affordances in Focus mode.
    private func focusHeader(_ title: String, @ViewBuilder button: () -> some View) -> some View {
        HStack {
            Text(title)
            Spacer()
            // A modest trailing inset pulls both header buttons ("New" /
            // "Configure…") off the sidebar's trailing edge without shifting the
            // list rows below, which keep the list's own leading/trailing insets.
            button()
                .padding(.trailing, Theme.Metrics.spacingM)
        }
    }

    // MARK: Browse mode

    private func browseList(_ workspace: WorkspaceState) -> some View {
        // One filter pass feeds every badge and disclosure group in this list.
        let selectedItem = workspace.sidebarSelection
        let activeScope = SidebarActiveScope(workspace: workspace)
        let visibleCount = coordinator.visibleSessions.count
        let protocolCounts = coordinator.visibleProtocolCounts
        let monitorItems = filteredMonitorItems
        let protocolItems = filteredProtocolItems
        let sourceCategories = displayedSourceCategories
        let visibleDomains = visibleDomainGroups
        let filteredDomains = filterDomainGroups(visibleDomains)
        let visibleLocalNames = visibleLocalDiscoveryGroups
        let filteredLocalDiscoveryGroups = filterLocalDiscoveryGroups(visibleLocalNames)
        let visibleIPs = visibleIPHosts
        let filteredIPs = filterIPHosts(visibleIPs)
        let showsDomainsCategory = !filteredDomains.isEmpty
            || (!isSearching && !coordinator.hiddenSourceDomains.isEmpty)
        let showsLocalDiscoveryCategory = !filteredLocalDiscoveryGroups.isEmpty
            || (!isSearching && !coordinator.hiddenSourceLocalNames.isEmpty)
        let showsIPAddressesCategory = !filteredIPs.isEmpty
            || (!isSearching && !coordinator.hiddenSourceIPs.isEmpty)
        let hasAnyBrowseResults = !monitorItems.isEmpty
            || !protocolItems.isEmpty
            || !sourceCategories.isEmpty
            || !filteredDomains.isEmpty
            || !filteredLocalDiscoveryGroups.isEmpty
            || !filteredIPs.isEmpty

        return List(selection: selectionBinding(workspace)) {
            if !monitorItems.isEmpty {
                Section("Monitor") {
                    ForEach(monitorItems) { item in
                        navRow(
                            item,
                            selectedItem: selectedItem,
                            visibleCount: visibleCount,
                            protocolCounts: protocolCounts
                        )
                    }
                }
            }

            // Protocol lenses are secondary: they filter the same list rather than
            // navigating anywhere new. They open when the current capture first
            // yields data, while search still forces the group open and prunes it.
            if !protocolItems.isEmpty {
                Section {
                    DisclosureGroup(isExpanded: searchExpansion($protocolsExpanded)) {
                        if isSearching || protocolsExpanded {
                            ForEach(protocolItems) { item in
                                navRow(
                                    item,
                                    selectedItem: selectedItem,
                                    visibleCount: visibleCount,
                                    protocolCounts: protocolCounts
                                )
                            }
                        }
                    } label: {
                        Label(SidebarSection.protocols.title, systemImage: SidebarSection.protocols.systemImage)
                    }
                }
            }

            if !sourceCategories.isEmpty
                || showsDomainsCategory
                || showsLocalDiscoveryCategory
                || showsIPAddressesCategory
            {
                let displaysByCategory = Dictionary(
                    uniqueKeysWithValues: sourceCategories.map { ($0.category, $0) }
                )
                Section(String(localized: "Sources", bundle: AppLanguage.currentLocalizedBundle())) {
                    if let display = displaysByCategory[.app] {
                        sourceCategoryDisclosure(display, expanded: $appsExpanded, activeScope: activeScope)
                    }
                    if let display = displaysByCategory[.cli] {
                        sourceCategoryDisclosure(display, expanded: $cliExpanded, activeScope: activeScope)
                    }
                    if let display = displaysByCategory[.thirdPartyService] {
                        sourceCategoryDisclosure(display, expanded: $thirdPartyServicesExpanded, activeScope: activeScope)
                    }
                    if let display = displaysByCategory[.systemService] {
                        sourceCategoryDisclosure(display, expanded: $systemServicesExpanded, activeScope: activeScope)
                    }
                    if let display = displaysByCategory[.lanDiscovery] {
                        sourceCategoryDisclosure(display, expanded: $lanExpanded, activeScope: activeScope)
                    }
                    if let display = displaysByCategory[.kernelAndLink] {
                        sourceCategoryDisclosure(display, expanded: $kernelAndLinkExpanded, activeScope: activeScope)
                    }
                    if let display = displaysByCategory[.unattributed] {
                        sourceCategoryDisclosure(display, expanded: $unattributedExpanded, activeScope: activeScope)
                    }
                    if showsDomainsCategory {
                        domainsDisclosure(visibleCount: visibleDomains.count, filteredGroups: filteredDomains, activeScope: activeScope)
                    }
                    if showsLocalDiscoveryCategory {
                        localDiscoveryDisclosure(visibleCount: visibleLocalNames.count, filteredGroups: filteredLocalDiscoveryGroups, activeScope: activeScope)
                    }
                    if showsIPAddressesCategory {
                        ipAddressesDisclosure(visibleCount: visibleIPs.count, filteredHosts: filteredIPs, activeScope: activeScope)
                    }
                }
            }

            if isSearching, !hasAnyBrowseResults {
                noResultsRow
            }
        }
        .listStyle(.sidebar)
    }

    // MARK: Rows / helpers

    private func filterDomainGroups(_ visible: [DomainGroup]) -> [DomainGroup] {
        guard isSearching else {
            return visible
        }
        if matches("Domains") || matches("Sources") {
            return visible
        }
        return visible.compactMap { group in
            if matches(group.domain) {
                return group
            }
            let ips = group.ips.filter { matches($0) }
            return ips.isEmpty ? nil : DomainGroup(domain: group.domain, ips: ips, count: group.count)
        }
    }

    private func filterLocalDiscoveryGroups(_ visible: [LocalDiscoveryGroup]) -> [LocalDiscoveryGroup] {
        guard isSearching else {
            return visible
        }
        let bundle = AppLanguage.currentLocalizedBundle()
        if matches(String(localized: "Local Services & Devices", bundle: bundle))
            || matches("Local Services & Devices")
            || matches("本地服务与设备名")
            || matches("bonjour")
            || matches("local")
            || matches(String(localized: "Sources", bundle: bundle))
            || matches("Sources")
        {
            return visible
        }
        return visible.compactMap { group in
            if matches(group.name) || matches(group.subtitle) || matches(group.badgeTitle) {
                return group
            }
            let ips = group.ips.filter { matches($0) }
            return ips.isEmpty ? nil : LocalDiscoveryGroup(
                name: group.name,
                badgeTitle: group.badgeTitle,
                subtitle: group.subtitle,
                symbolName: group.symbolName,
                tooltip: group.tooltip,
                ips: ips,
                count: group.count
            )
        }
    }

    private func filterIPHosts(_ visible: [(name: String, count: Int)]) -> [(name: String, count: Int)] {
        guard isSearching else {
            return visible
        }
        if matches("IP Addresses") || matches("Sources") {
            return visible
        }
        return visible.filter { matches($0.name) }
    }

    private func navRow(
        _ item: SidebarItem,
        selectedItem: SidebarItem,
        visibleCount: Int,
        protocolCounts: [ProtocolKind: Int]
    )
        -> some View
    {
        // No forced foreground on selection: `List(.sidebar)` renders the accent
        // (or graphite, in an inactive window) highlight itself and keeps the
        // label legible against it. A hardcoded white icon broke the inactive
        // case, where the highlight is light grey.
        Label {
            Text(item.title)
        } icon: {
            if selectedItem == item {
                Image(systemName: item.systemImage)
            } else {
                Image(systemName: item.systemImage)
                    .foregroundStyle(tint(item))
            }
        }
        .badge(badge(for: item, visibleCount: visibleCount, protocolCounts: protocolCounts))
        .tag(item)
    }

    private static func availabilityHelp(_ capture: SavedCapture) -> String {
        switch capture.availability {
        case .managed: ""
        case .checking: "Checking the referenced file on this Mac"
        case .available: "Opened in place on this Mac"
        case .missing: "The referenced file on this Mac can’t be found"
        case .changed: "The referenced file changed on disk"
        }
    }

    private func removeReference(_ capture: SavedCapture) {
        do {
            try coordinator.removeReferencedCapture(capture)
        } catch {
            captureRemovalError = error.localizedDescription
        }
    }

    /// Case-insensitive substring match; always true when not searching so call
    /// sites read the same in both modes.
    private func matches(_ text: String) -> Bool {
        guard !sidebarSearch.isEmpty else {
            return true
        }
        let needle = query
        return needle.isEmpty || text.lowercased().contains(needle)
    }

    /// Force a disclosure open while searching so matching children are visible,
    /// but hand control straight back to the user during normal browsing.
    private func searchExpansion(_ state: Binding<Bool>) -> Binding<Bool> {
        Binding(
            get: { isSearching || state.wrappedValue },
            set: { state.wrappedValue = $0 }
        )
    }

    /// Opens capture-derived groups at the first decoded session of each capture
    /// data lifetime. A zero-session boundary re-arms the behavior for the next
    /// live-data publication; increasing counts within one capture never override
    /// a user's later manual collapse.
    private func observeCaptureData(hasCaptureData: Bool) {
        var nextState = captureAutoExpansion
        let shouldExpand = nextState.observe(hasCaptureData: hasCaptureData)
        captureAutoExpansion = nextState

        guard shouldExpand else {
            return
        }
        protocolsExpanded = true
        for category in TrafficSourceCategory.allCases where category.opensOnCaptureStart {
            switch category {
            case .app: appsExpanded = true
            case .cli: cliExpanded = true
            case .thirdPartyService: thirdPartyServicesExpanded = true
            case .systemService: systemServicesExpanded = true
            case .lanDiscovery: lanExpanded = true
            case .kernelAndLink: kernelAndLinkExpanded = true
            case .unattributed: unattributedExpanded = true
            }
        }
        domainsExpanded = true
    }

    /// A section header with a trailing action button (the "+ Add" pattern).
    private func newFocusSet() {
        coordinator.editingFocusSet = coordinator.draftFocusSet()
        openWindow(id: TracexyApp.focusSetEditorWindowID)
    }

    private func openFocusEditor(_ set: FocusSet) {
        coordinator.editingFocusSet = set
        openWindow(id: TracexyApp.focusSetEditorWindowID)
    }

    private func navigatorBinding(_ workspace: WorkspaceState) -> Binding<SidebarNavigatorMode> {
        Binding(
            get: { workspace.navigatorMode },
            set: { workspace.navigatorMode = $0 }
        )
    }

    private func moveCaptureToTrash(_ capture: SavedCapture) {
        capturePendingRemoval = nil
        do {
            try coordinator.moveSavedCaptureToTrash(capture)
        } catch {
            captureRemovalError = error.localizedDescription
        }
    }

    private func copyToPasteboard(_ value: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(value, forType: .string)
    }

    private func selectionBinding(_ workspace: WorkspaceState) -> Binding<SidebarItem?> {
        Binding(
            get: { workspace.sidebarSelection },
            set: { newValue in
                if let newValue {
                    coordinator.selectSidebarItem(newValue)
                }
            }
        )
    }

    /// Protocol-tinted icon color (Finder-style colored source-list icons).
    private func tint(_ item: SidebarItem) -> Color {
        if let proto = item.protocolFilter {
            return Theme.color(for: proto)
        }
        return .secondary
    }

    private func badge(for item: SidebarItem, visibleCount: Int, protocolCounts: [ProtocolKind: Int]) -> Text? {
        let count: Int = switch item {
        case .sessions: visibleCount
        default:
            if let proto = item.protocolFilter {
                protocolCounts[proto] ?? 0
            } else {
                0
            }
        }
        return count > 0 ? Text(count.formatted()) : nil
    }
}

// MARK: - SidebarCaptureAutoExpansionState

/// Small state machine kept outside the view so capture-boundary behavior stays
/// deterministic and independently testable.
struct SidebarCaptureAutoExpansionState: Equatable, Sendable {
    // MARK: Internal

    /// Returns true exactly once after an empty-to-populated data transition.
    mutating func observe(hasCaptureData: Bool) -> Bool {
        guard hasCaptureData else {
            hasExpandedForCurrentCapture = false
            return false
        }
        guard !hasExpandedForCurrentCapture else {
            return false
        }
        hasExpandedForCurrentCapture = true
        return true
    }

    // MARK: Private

    private var hasExpandedForCurrentCapture = false
}

// MARK: - SidebarActiveScope

/// Value-scoped snapshot of the active workspace's sidebar drill-down state.
/// Computed once per `SidebarView` render pass so individual rows never register
/// per-row `@Observable` subscriptions on `WorkspaceState`.
nonisolated struct SidebarActiveScope: Equatable, Sendable {
    let isSessionsScope: Bool
    let hostFilter: String?
    let processFilter: String?
    let ipFilter: String?

    init(isSessionsScope: Bool, hostFilter: String? = nil, processFilter: String? = nil, ipFilter: String? = nil) {
        self.isSessionsScope = isSessionsScope
        self.hostFilter = hostFilter
        self.processFilter = processFilter
        self.ipFilter = ipFilter
    }

    func isActiveHost(_ host: String) -> Bool { isSessionsScope && hostFilter == host }
    func isActiveProcess(_ key: String) -> Bool { isSessionsScope && processFilter == key }
    func isActiveIP(_ ip: String) -> Bool { isSessionsScope && ipFilter == ip }

    func isActiveChild(_ child: SourceChildTarget) -> Bool {
        guard isSessionsScope else { return false }
        return switch child.kind {
        case .host: hostFilter == child.value
        case .peerIP: ipFilter == child.value
        }
    }
}

extension SidebarActiveScope {
    @MainActor
    init(workspace: WorkspaceState) {
        self.init(
            isSessionsScope: workspace.sidebarSelection == .sessions,
            hostFilter: workspace.hostFilter,
            processFilter: workspace.processFilter,
            ipFilter: workspace.ipFilter
        )
    }
}

// MARK: - SidebarChildSlice

/// Bounds unsearched expanded child-target lists (`DomainRow`, `LocalDiscoveryRow`,
/// `SourceItemRow`, `SourceSubprocessRow`) until the user explicitly requests all
/// rows or filters via sidebar search.
nonisolated struct SidebarChildSlice<Element> {
    static var defaultLimit: Int { 60 }

    let visible: ArraySlice<Element>
    let remainingCount: Int

    var isTruncated: Bool { remainingCount > 0 }

    init(_ elements: [Element], showAll: Bool, isSearching: Bool, limit: Int = Self.defaultLimit) {
        let cap = max(0, limit)
        if showAll || isSearching || elements.count <= cap {
            visible = elements[...]
            remainingCount = 0
        } else {
            visible = elements.prefix(cap)
            remainingCount = elements.count - cap
        }
    }
}

extension SidebarChildSlice: Equatable where Element: Equatable {}
extension SidebarChildSlice: Sendable where Element: Sendable {}

// MARK: - SidebarShowMoreChildrenRow

private struct SidebarShowMoreChildrenRow: View {
    let remainingCount: Int
    let onShowAll: () -> Void

    var body: some View {
        Button(action: onShowAll) {
            Text("+ \(remainingCount) more…")
                .font(Theme.Typography.caption)
                .foregroundStyle(.tertiary)
                .frame(maxWidth: .infinity, alignment: .leading)
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityLabel("Show \(remainingCount) more items")
    }
}

// MARK: - SidebarIPRow

private struct SidebarIPRow: View {
    let ip: String
    var count: Int?
    let coordinator: MainContentCoordinator
    let activeScope: SidebarActiveScope

    var body: some View {
        let isActiveIP = activeScope.isActiveIP(ip)
        Label(ip, systemImage: "number")
            .foregroundStyle(isActiveIP ? Color.accentColor : .secondary)
            .font(isActiveIP ? Theme.Typography.navigationMedium : Theme.Typography.navigation)
            .lineLimit(1)
            .frame(maxWidth: .infinity, alignment: .leading)
            .badge(count.map { Text($0.formatted()) })
            .contentShape(Rectangle())
            .onTapGesture { coordinator.selectIP(ip) }
            .accessibilityAddTraits(.isButton)
            .accessibilityAddTraits(isActiveIP ? .isSelected : [])
            .accessibilityAction { coordinator.selectIP(ip) }
            .help("Show sessions for \(ip)")
            .contextMenu {
                SidebarSourceContextMenu(
                    value: ip,
                    copyLabel: "Copy IP Address",
                    pinnedHost: ip,
                    coordinator: coordinator,
                    onShowSessions: { coordinator.selectIP(ip) },
                    onRemove: { coordinator.hideSourceIP(ip) }
                )
            }
    }
}

// MARK: - SidebarChildIPList

private struct SidebarChildIPList: View {
    let ips: [String]
    let coordinator: MainContentCoordinator
    let activeScope: SidebarActiveScope
    let isSearching: Bool
    @Binding var showAllChildren: Bool

    var body: some View {
        let slice = SidebarChildSlice(ips, showAll: showAllChildren, isSearching: isSearching)
        ForEach(slice.visible, id: \.self) { ip in
            SidebarIPRow(ip: ip, coordinator: coordinator, activeScope: activeScope)
        }
        if slice.isTruncated {
            SidebarShowMoreChildrenRow(remainingCount: slice.remainingCount) { showAllChildren = true }
        }
    }
}

// MARK: - SidebarChildTargetList

private struct SidebarChildTargetList: View {
    let children: [SourceChildTarget]
    let coordinator: MainContentCoordinator
    let activeScope: SidebarActiveScope
    let isSearching: Bool
    @Binding var showAllChildren: Bool

    var body: some View {
        let slice = SidebarChildSlice(children, showAll: showAllChildren, isSearching: isSearching)
        ForEach(slice.visible) { child in
            SourceChildTargetRow(child: child, coordinator: coordinator, activeScope: activeScope)
        }
        if slice.isTruncated {
            SidebarShowMoreChildrenRow(remainingCount: slice.remainingCount) { showAllChildren = true }
        }
    }
}

// MARK: - FocusSetRow

/// A saved focus set in the sidebar: tap to apply its rules, context-menu to
/// edit or delete.
private struct FocusSetRow: View {
    let set: FocusSet
    let coordinator: MainContentCoordinator
    let onEdit: () -> Void

    var body: some View {
        HStack(spacing: 6) {
            Image(systemName: set.symbol).foregroundStyle(Color.accentColor)
            VStack(alignment: .leading, spacing: 1) {
                Text(set.name).lineLimit(1)
                Text(set.subtitle)
                    .font(Theme.Typography.micro).foregroundStyle(.tertiary).lineLimit(1)
            }
            Spacer()
        }
        .badge(set.activeRuleCount)
        .contentShape(Rectangle())
        .onTapGesture { coordinator.applyFocusSet(set) }
        .accessibilityAddTraits(.isButton)
        .accessibilityHint("Applies this focus set")
        .accessibilityAction { coordinator.applyFocusSet(set) }
        .help("Click to apply this focus set")
        .contextMenu {
            Button("Apply", systemImage: "scope") { coordinator.applyFocusSet(set) }
            Button("Edit…", systemImage: "pencil") { onEdit() }
            Divider()
            Button("Delete", systemImage: "trash", role: .destructive) {
                coordinator.deleteFocusSet(set)
            }
        }
    }
}

// MARK: - DomainRow

/// A domain in the sidebar that expands to the server IPs it resolved to.
private struct DomainRow: View {
    // MARK: Internal

    let group: DomainGroup
    let coordinator: MainContentCoordinator
    let activeScope: SidebarActiveScope
    var forceExpanded = false

    var body: some View {
        let isExpanded = forceExpanded || expanded
        let isActiveHost = activeScope.isActiveHost(group.domain)
        return DisclosureGroup(isExpanded: expansion) {
            if isExpanded {
                SidebarChildIPList(
                    ips: group.ips,
                    coordinator: coordinator,
                    activeScope: activeScope,
                    isSearching: forceExpanded,
                    showAllChildren: $showAllChildren
                )
            }
        } label: {
            Label(group.domain, systemImage: "globe")
                .foregroundStyle(isActiveHost ? Color.accentColor : .secondary)
                .font(isActiveHost ? Theme.Typography.navigationMedium : Theme.Typography.navigation)
                .lineLimit(1)
                .frame(maxWidth: .infinity, alignment: .leading)
                .badge(group.count)
                .contentShape(Rectangle())
                .onTapGesture { coordinator.selectHost(group.domain) }
                .accessibilityAddTraits(.isButton)
                .accessibilityAddTraits(isActiveHost ? .isSelected : [])
                .accessibilityAction { coordinator.selectHost(group.domain) }
                .help("Show sessions for \(group.domain)")
                .contextMenu {
                    SidebarSourceContextMenu(
                        value: group.domain,
                        copyLabel: "Copy Domain",
                        pinnedHost: group.domain,
                        coordinator: coordinator,
                        onShowSessions: { coordinator.selectHost(group.domain) },
                        onRemove: { coordinator.hideSourceDomain(group.domain) }
                    )
                }
        }
    }

    // MARK: Private

    @State private var expanded = false
    @State private var showAllChildren = false

    private var expansion: Binding<Bool> {
        Binding(
            get: { forceExpanded || expanded },
            set: { newValue in
                expanded = newValue
                if !newValue {
                    showAllChildren = false
                }
            }
        )
    }
}

// MARK: - LocalDiscoveryRow

/// A local Bonjour / mDNS service, device hostname, or special system DNS
/// discovery name in the sidebar, with a semantic subtitle and optional
/// expandable peer or resolved IP rows.
private struct LocalDiscoveryRow: View {
    // MARK: Internal

    let group: LocalDiscoveryGroup
    let coordinator: MainContentCoordinator
    let activeScope: SidebarActiveScope
    var forceExpanded = false

    var body: some View {
        let isExpanded = forceExpanded || expanded
        if group.ips.isEmpty {
            rowLabel
        } else {
            DisclosureGroup(isExpanded: expansion) {
                if isExpanded {
                    SidebarChildIPList(
                        ips: group.ips,
                        coordinator: coordinator,
                        activeScope: activeScope,
                        isSearching: forceExpanded,
                        showAllChildren: $showAllChildren
                    )
                }
            } label: {
                rowLabel
            }
        }
    }

    // MARK: Private

    @Environment(\.colorScheme) private var colorScheme
    @State private var expanded = false
    @State private var showAllChildren = false

    private var expansion: Binding<Bool> {
        Binding(
            get: { forceExpanded || expanded },
            set: { newValue in
                expanded = newValue
                if !newValue {
                    showAllChildren = false
                }
            }
        )
    }

    private var isActiveHost: Bool {
        activeScope.isActiveHost(group.name)
    }

    private var iconBadge: some View {
        let tint: Color = isActiveHost ? .accentColor : .teal
        let fillOpacity: Double = if isActiveHost {
            colorScheme == .dark ? 0.28 : 0.20
        } else {
            colorScheme == .dark ? 0.18 : 0.13
        }
        let strokeOpacity: Double = if isActiveHost {
            0.50
        } else {
            colorScheme == .dark ? 0.34 : 0.24
        }
        let shape = RoundedRectangle(cornerRadius: 4, style: .continuous)
        return shape
            .fill(tint.opacity(fillOpacity))
            .frame(width: 16, height: 16)
            .overlay {
                shape.strokeBorder(tint.opacity(strokeOpacity), lineWidth: 0.75)
            }
            .overlay {
                Image(systemName: group.symbolName)
                    .font(.system(size: Theme.Icon.small, weight: .semibold))
                    .imageScale(.small)
                    .foregroundStyle(tint)
            }
            .frame(width: 18, height: 18)
    }

    private var rowLabel: some View {
        let hasSubtitle = !group.subtitle.isEmpty
        return HStack(alignment: hasSubtitle ? .top : .center, spacing: 7) {
            iconBadge
            VStack(alignment: .leading, spacing: 1.5) {
                Text(group.name)
                    .font(isActiveHost ? Theme.Typography.navigationMedium : Theme.Typography.navigation)
                    .foregroundStyle(isActiveHost ? Color.accentColor : .primary)
                    .lineLimit(1)
                if hasSubtitle {
                    Text(group.subtitle)
                        .font(Theme.Typography.micro)
                        .foregroundStyle(.tertiary)
                        .lineLimit(1)
                }
            }
            Spacer(minLength: 0)
        }
        .padding(.vertical, hasSubtitle ? 1.5 : 0.5)
        .frame(maxWidth: .infinity, alignment: .leading)
        .badge(group.count)
        .contentShape(Rectangle())
        .onTapGesture { coordinator.selectHost(group.name) }
        .accessibilityAddTraits(.isButton)
        .accessibilityAddTraits(isActiveHost ? .isSelected : [])
        .accessibilityAction { coordinator.selectHost(group.name) }
        .help(group.tooltip)
        .contextMenu {
            SidebarSourceContextMenu(
                value: group.name,
                copyLabel: "Copy Local Name",
                pinnedHost: group.name,
                coordinator: coordinator,
                onShowSessions: { coordinator.selectHost(group.name) },
                onRemove: { coordinator.hideSourceLocalName(group.name) }
            )
        }
    }
}

// MARK: - SidebarSourceContextMenu

/// Shared native actions for dynamic source rows. Static navigation groups stay
/// intentionally quiet; rows representing actual apps, hosts,
/// domains, and IPs expose the actions that help an investigation continue.
private struct SidebarSourceContextMenu: View {
    let value: String
    let copyLabel: String
    var pinnedHost: String?
    let coordinator: MainContentCoordinator
    let onShowSessions: () -> Void
    var onRemove: (() -> Void)?

    var body: some View {
        Button("Show Sessions", systemImage: "rectangle.stack") {
            onShowSessions()
        }
        Button(LocalizedStringKey(copyLabel), systemImage: "doc.on.doc") {
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(value, forType: .string)
        }
        if let pinnedHost {
            Divider()
            PinHostButton(host: pinnedHost, coordinator: coordinator)
        }
        if let onRemove {
            Divider()
            Button("Remove from Sources", systemImage: "trash", role: .destructive) {
                onRemove()
            }
        }
    }
}

// MARK: - PinHostButton

/// A reusable Pin/Unpin menu item for a host or IP, used across sidebar rows and
/// the session table's context menu.
struct PinHostButton: View {
    let host: String
    let coordinator: MainContentCoordinator

    var body: some View {
        let pinned = coordinator.isHostPinned(host)
        Button(pinned ? "Unpin" : "Pin", systemImage: pinned ? "pin.slash" : "pin") {
            coordinator.togglePinHost(host)
        }
    }
}

// MARK: - SourceItemRow

/// A classified traffic source in the sidebar (App, CLI Tool, Third-Party Service,
/// System Service, LAN & Discovery, Kernel & Link, or Unattributed) with role/via
/// subtitle and expandable remote hosts or LAN peer IPs.
private struct SourceItemRow: View {
    // MARK: Internal

    let item: SourceItemGroup
    let coordinator: MainContentCoordinator
    let activeScope: SidebarActiveScope
    var forceExpanded = false

    var body: some View {
        let isExpanded = forceExpanded || expanded
        if !item.subprocesses.isEmpty {
            DisclosureGroup(isExpanded: expansion) {
                if isExpanded {
                    ForEach(item.subprocesses) { subprocess in
                        SourceSubprocessRow(
                            subprocess: subprocess,
                            coordinator: coordinator,
                            activeScope: activeScope,
                            forceExpanded: forceExpanded
                        )
                    }
                }
            } label: {
                sourceItemLabel
            }
        } else if item.children.isEmpty {
            sourceItemLabel
        } else {
            DisclosureGroup(isExpanded: expansion) {
                if isExpanded {
                    SidebarChildTargetList(
                        children: item.children,
                        coordinator: coordinator,
                        activeScope: activeScope,
                        isSearching: forceExpanded,
                        showAllChildren: $showAllChildren
                    )
                }
            } label: {
                sourceItemLabel
            }
        }
    }

    // MARK: Private

    @State private var expanded = false
    @State private var showAllChildren = false

    private var expansion: Binding<Bool> {
        Binding(
            get: { forceExpanded || expanded },
            set: { newValue in
                expanded = newValue
                if !newValue {
                    showAllChildren = false
                }
            }
        )
    }

    private var isActiveSource: Bool {
        activeScope.isActiveProcess(item.filterKey)
    }

    private var sourceItemLabel: some View {
        let hasSubtitle = (item.subtitle?.isEmpty == false)
        return HStack(alignment: hasSubtitle ? .top : .center, spacing: 7) {
            SourceIconView(
                category: item.category,
                filterKey: item.filterKey,
                title: item.title,
                subtitle: item.subtitle,
                fallbackSymbol: item.symbolName,
                isActive: isActiveSource,
                size: 18
            )
            VStack(alignment: .leading, spacing: 1.5) {
                Text(item.title)
                    .font(isActiveSource ? Theme.Typography.navigationMedium : Theme.Typography.navigation)
                    .foregroundStyle(isActiveSource ? Color.accentColor : .primary)
                    .lineLimit(1)
                if let subtitle = item.subtitle, !subtitle.isEmpty {
                    Text(subtitle)
                        .font(Theme.Typography.micro)
                        .foregroundStyle(.tertiary)
                        .lineLimit(1)
                }
            }
            Spacer(minLength: 0)
        }
        .padding(.vertical, hasSubtitle ? 1.5 : 0.5)
        .frame(maxWidth: .infinity, alignment: .leading)
        .badge(item.count)
        .contentShape(Rectangle())
        .onTapGesture { coordinator.selectProcess(item.filterKey) }
        .accessibilityAddTraits(.isButton)
        .accessibilityAddTraits(isActiveSource ? .isSelected : [])
        .accessibilityAction { coordinator.selectProcess(item.filterKey) }
        .help(item.subtitle.map { "\(item.title) — \($0)" } ?? item.title)
        .contextMenu {
            SidebarSourceContextMenu(
                value: item.title,
                copyLabel: "Copy Source Name",
                pinnedHost: nil,
                coordinator: coordinator,
                onShowSessions: { coordinator.selectProcess(item.filterKey) },
                onRemove: { coordinator.hideSourceApp(item.filterKey) }
            )
        }
    }
}

// MARK: - SourceSubprocessRow

/// Concrete initiating process nested under an `.app` item (main binary, nested `.app` helper,
/// or embedded CLI command spawned by that app), expandable to the hosts/IPs it contacted.
private struct SourceSubprocessRow: View {
    // MARK: Internal

    let subprocess: SourceSubprocessGroup
    let coordinator: MainContentCoordinator
    let activeScope: SidebarActiveScope
    var forceExpanded = false

    var body: some View {
        let isExpanded = forceExpanded || expanded
        if subprocess.children.isEmpty {
            subprocessLabel
        } else {
            DisclosureGroup(isExpanded: expansion) {
                if isExpanded {
                    SidebarChildTargetList(
                        children: subprocess.children,
                        coordinator: coordinator,
                        activeScope: activeScope,
                        isSearching: forceExpanded,
                        showAllChildren: $showAllChildren
                    )
                }
            } label: {
                subprocessLabel
            }
        }
    }

    // MARK: Private

    @State private var expanded = false
    @State private var showAllChildren = false

    private var expansion: Binding<Bool> {
        Binding(
            get: { forceExpanded || expanded },
            set: { newValue in
                expanded = newValue
                if !newValue {
                    showAllChildren = false
                }
            }
        )
    }

    private var isActiveSubprocess: Bool {
        activeScope.isActiveProcess(subprocess.filterKey)
    }

    private var subprocessLabel: some View {
        let hasSubtitle = (subprocess.subtitle?.isEmpty == false)
        return HStack(alignment: hasSubtitle ? .top : .center, spacing: 7) {
            SourceIconView(
                category: subprocess.category,
                filterKey: subprocess.filterKey,
                title: subprocess.iconTitle,
                subtitle: subprocess.subtitle,
                fallbackSymbol: subprocess.symbolName,
                isActive: isActiveSubprocess,
                size: 17
            )
            VStack(alignment: .leading, spacing: 1.5) {
                Text(subprocess.title)
                    .font(isActiveSubprocess ? Theme.Typography.navigationMedium : Theme.Typography.navigation)
                    .foregroundStyle(isActiveSubprocess ? Color.accentColor : .primary)
                    .lineLimit(1)
                if let subtitle = subprocess.subtitle, !subtitle.isEmpty {
                    Text(subtitle)
                        .font(Theme.Typography.micro)
                        .foregroundStyle(.tertiary)
                        .lineLimit(1)
                }
            }
            Spacer(minLength: 0)
        }
        .padding(.vertical, hasSubtitle ? 1.5 : 0.5)
        .frame(maxWidth: .infinity, alignment: .leading)
        .badge(subprocess.count)
        .contentShape(Rectangle())
        .onTapGesture { coordinator.selectProcess(subprocess.filterKey) }
        .accessibilityAddTraits(.isButton)
        .accessibilityAddTraits(isActiveSubprocess ? .isSelected : [])
        .accessibilityAction { coordinator.selectProcess(subprocess.filterKey) }
        .help(subprocess.subtitle.map { "\(subprocess.title) — \($0)" } ?? subprocess.title)
        .contextMenu {
            SidebarSourceContextMenu(
                value: subprocess.title,
                copyLabel: "Copy Source Name",
                pinnedHost: nil,
                coordinator: coordinator,
                onShowSessions: { coordinator.selectProcess(subprocess.filterKey) },
                onRemove: { coordinator.hideSourceApp(subprocess.filterKey) }
            )
        }
    }
}

// MARK: - SourceChildTargetRow

private struct SourceChildTargetRow: View {
    let child: SourceChildTarget
    let coordinator: MainContentCoordinator
    let activeScope: SidebarActiveScope

    var body: some View {
        let isActive = activeScope.isActiveChild(child)
        let selectAction: () -> Void = switch child.kind {
        case .host: { coordinator.selectHost(child.value) }
        case .peerIP: { coordinator.selectIP(child.value) }
        }
        let removeAction: () -> Void = switch child.kind {
        case .host: { coordinator.hideSourceHost(child.value) }
        case .peerIP: { coordinator.hideSourceIP(child.value) }
        }
        let copyLabel = child.kind == .host ? "Copy Address" : "Copy IP Address"
        let childSymbol = child.kind == .host ? "globe" : "point.3.connected.trianglepath.dotted"
        return Label(child.label, systemImage: childSymbol)
            .font(isActive ? Theme.Typography.navigationMedium : Theme.Typography.navigation)
            .foregroundStyle(isActive ? Color.accentColor : .secondary)
            .lineLimit(1)
            .frame(maxWidth: .infinity, alignment: .leading)
            .contentShape(Rectangle())
            .onTapGesture(perform: selectAction)
            .accessibilityAddTraits(.isButton)
            .accessibilityAddTraits(isActive ? .isSelected : [])
            .accessibilityAction { selectAction() }
            .help(child.label)
            .contextMenu {
                SidebarSourceContextMenu(
                    value: child.value,
                    copyLabel: copyLabel,
                    pinnedHost: child.value,
                    coordinator: coordinator,
                    onShowSessions: selectAction,
                    onRemove: removeAction
                )
            }
    }
}
