import AppKit
import Foundation
import SwiftUI

// MARK: - SessionCenterView

struct SessionCenterView: View {
    // MARK: Internal

    @Bindable var coordinator: MainContentCoordinator

    let commandDescriptors: [SessionCommandDescriptor]
    let onCommandAction: (SessionCommandKind) -> Void

    var body: some View {
        let workspace = coordinator.activeWorkspace
        let sessions = coordinator.visibleSessions
        sessionContent(sessions: sessions, workspace: workspace)
            .tracexyDenseScrollEdge()
            .tracexySafeAreaBar(edge: .top) {
                sessionControlShelf(
                    workspace,
                    shownCount: sessions.count,
                    shownIDs: coordinator.pinnedSessionIDs.isEmpty ? [] : Set(sessions.map(\.id))
                )
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .onChange(of: visibilityFingerprint(workspace)) { _, _ in
                coordinator.reconcileLiveFollowing(in: workspace)
            }
            .onAppear(perform: loadColumnCustomization)
            .alert(
                "Name \(namingAddress ?? "Address")",
                isPresented: Binding(get: { namingAddress != nil }, set: {
                    if !$0 {
                        namingAddress = nil
                    }
                })
            ) {
                TextField("Name, for example NAS", text: $addressNameDraft)
                Button("Save") {
                    if let address = namingAddress {
                        coordinator.addressNames.setName(addressNameDraft, for: address)
                    }
                    namingAddress = nil
                }
                if let address = namingAddress, coordinator.addressNames.name(for: address) != nil {
                    Button("Remove Name", role: .destructive) {
                        coordinator.addressNames.setName("", for: address)
                        namingAddress = nil
                    }
                }
                Button("Cancel", role: .cancel) { namingAddress = nil }
            } message: {
                Text("Shown in this Project wherever this address is a session’s only name.")
            }
            .onChange(of: coordinator.projectStore.activeProjectID) { _, _ in
                didLoadColumnCustomization = false
                loadColumnCustomization()
            }
            .onChange(of: columnState) { _, updated in
                guard didLoadColumnCustomization else {
                    return
                }
                updated.save(
                    to: coordinator.activeProjectDefaults,
                    key: ProjectScopedSettingsKeys.sessionTableColumns
                )
            }
    }

    /// A compact, counted inventory of what the file actually contained: how many
    /// link types its frames declared, and the two coverage caveats. Nothing here
    /// interprets a link type, a comment or an option — these are counts only.
    nonisolated static func metadataSummary(_ metadata: CaptureMetadataSummary) -> String {
        var parts: [String] = []
        let linkTypes = metadata.linkTypeCounts.count
        if metadata.linkTypeOverflowFrameCount > 0 {
            parts.append("More than \(linkTypes.formatted()) link types")
        } else if linkTypes > 0 {
            parts.append(linkTypes == 1 ? "1 link type" : "\(linkTypes.formatted()) link types")
        }
        if metadata.untimedFrameCount > 0 {
            parts.append("\(metadata.untimedFrameCount.formatted()) untimed")
        }
        if metadata.undecodableLinkLayerFrameCount > 0 {
            parts.append("\(metadata.undecodableLinkLayerFrameCount.formatted()) undecoded link layer")
        }
        return parts.joined(separator: ", ")
    }

    static func waitingForPacketsMessage(interfaceID: String, hasCaptureFilter: Bool) -> String {
        let bundle = AppLanguage.currentLocalizedBundle()
        if NetworkInterfaces.isSpecialPurposeWiFi(interfaceID) {
            return String(
                localized: "This interface carries specialized Wi-Fi traffic. Choose your connected Wi-Fi or Ethernet interface for internet sessions.",
                bundle: bundle
            )
        }
        if hasCaptureFilter {
            return String(localized: "Waiting for packets matching the capture filter…", bundle: bundle)
        }
        return String(localized: "Waiting for packets…", bundle: bundle)
    }

    // MARK: Private

    private struct VisibilityFingerprint: Equatable {
        let sidebarSelection: SidebarItem
        let filterText: String
        let searchField: SessionSearchField
        let isSearchEnabled: Bool
        let categoryFilters: Set<SessionFilterCategory>
        let hostFilter: String?
        let processFilter: String?
        let ipFilter: String?
        let aggregateProtocolFilters: Set<ProtocolKind>
        let aggregateDestinationFilter: String?
        let aggregateRequiresFindings: Bool
        let filterRules: [SessionFilterRule]
    }

    @Environment(\.locale) private var locale

    /// Column sort chosen by clicking a header. Empty keeps the engine's stable
    /// capture order (oldest→newest, rows updating in place), which stays the
    /// default so a live list never reshuffles under the cursor unasked.
    @State private var sortCriteria: [SessionOutlineSortCriterion] = []
    /// Which columns are shown, their widths, and their order; kept per Project.
    @State private var columnState = SessionOutlineColumnState.defaultState
    @State private var didLoadColumnCustomization = false
    /// The address being named from the context menu, and the name being typed.
    @State private var namingAddress: String?
    @State private var addressNameDraft = ""

    private var captureImportNotice: some View {
        HStack(spacing: Theme.Metrics.spacingM) {
            Image(systemName: "tray.and.arrow.down")
                .foregroundStyle(Color.accentColor)
            VStack(alignment: .leading, spacing: 3) {
                Text(coordinator.isCancellingCaptureImport ? "Cancelling import…" : "Importing capture…")
                    .font(Theme.Typography.bodyEmphasis)
                if let name = coordinator.captureImportName {
                    Text(name).font(Theme.Typography.caption).lineLimit(1).truncationMode(.middle)
                }
                if let fraction = coordinator.captureImportFraction {
                    ProgressView(value: fraction)
                        .accessibilityValue(Text(fraction, format: .percent))
                } else {
                    ProgressView().controlSize(.small)
                }
            }
            Spacer(minLength: 0)
            Button("Cancel Import") { coordinator.cancelCaptureImport() }
                .disabled(coordinator.isCancellingCaptureImport)
        }
        .padding(.horizontal, Theme.Metrics.spacingL)
        .padding(.vertical, Theme.Metrics.spacingS)
        .background(Color.accentColor.opacity(0.06))
        .accessibilityIdentifier("capture-import-progress")
    }

    private var savedCaptureSourceNotice: some View {
        HStack(spacing: Theme.Metrics.spacingS) {
            Image(systemName: "doc")
            Text(coordinator.activeSavedCapture?.url.lastPathComponent ?? "Saved capture")
                .lineLimit(1).truncationMode(.middle)
                .help(coordinator.activeSavedCapture?.url.lastPathComponent ?? "Saved capture")
            Spacer(minLength: 0)
            Text("Saved capture")
            if let activity = coordinator.savedCaptureActivity {
                Text("\(activity.totalFrames.formatted()) frames")
                    .monospacedDigit()
            }
            if let metadata = coordinator.savedCaptureMetadata {
                Text(Self.metadataSummary(metadata))
                    .monospacedDigit()
                    .accessibilityIdentifier("saved-capture-metadata")
            }
        }
        .font(Theme.Typography.caption)
        .foregroundStyle(.secondary)
        .padding(.horizontal, Theme.Metrics.spacingL)
        .padding(.vertical, Theme.Metrics.spacingS)
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier("saved-capture-source")
    }

    private var savedCaptureOpeningNotice: some View {
        HStack(spacing: Theme.Metrics.spacingM) {
            Image(systemName: "doc.badge.clock")
                .foregroundStyle(Color.accentColor)
            VStack(alignment: .leading, spacing: 3) {
                Text("Opening capture…")
                    .font(Theme.Typography.bodyEmphasis)
                if let fraction = coordinator.savedCaptureOpenFraction {
                    ProgressView(value: fraction)
                        .accessibilityValue(Text(fraction, format: .percent))
                } else {
                    ProgressView()
                        .controlSize(.small)
                }
            }
        }
        .padding(.horizontal, Theme.Metrics.spacingL)
        .padding(.vertical, Theme.Metrics.spacingS)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.accentColor.opacity(0.06))
    }

    @ViewBuilder private var emptyState: some View {
        let scope = coordinator.sessionScope(shownCount: 0)
        if let error = coordinator.captureError {
            ContentUnavailableView {
                Label("Capture Error", systemImage: "exclamationmark.triangle")
            } description: {
                Text(error)
            }
        } else if scope.emptyClassification == .allSessionsRemoved {
            ContentUnavailableView {
                Label("All Sessions Removed from View", systemImage: "eye.slash")
            } description: {
                Text("The capture evidence is still intact and can be restored.")
            } actions: {
                scopeRecovery(scope)
            }
        } else if scope.emptyClassification == .hiddenByScope {
            ContentUnavailableView {
                Label("No Matching Sessions", systemImage: "line.3.horizontal.decrease.circle")
            } description: {
                Text("Sessions exist in this capture, but none match the current scope.")
            } actions: {
                scopeRecovery(scope)
            }
        } else if coordinator.isCapturing {
            ContentUnavailableView {
                Label("Capturing on \(coordinator.captureSourceName)", systemImage: "dot.radiowaves.left.and.right")
            } description: {
                Text(Self.waitingForPacketsMessage(
                    interfaceID: coordinator.captureInterface,
                    hasCaptureFilter: coordinator.readinessCaptureConfiguration.bpf != nil
                ))
            }
        } else if coordinator.isViewingSavedCapture {
            ContentUnavailableView {
                Label("No Sessions", systemImage: "rectangle.stack")
            } description: {
                Text("This capture contains no sessions.")
            }
        } else {
            firstRunEmptyState
        }
    }

    /// First-run / no-data landing on the Sessions surface: a quiet, actionless
    /// empty state (never a blank table) that points to the toolbar, which
    /// already owns Start/Stop and the interface picker.
    private var firstRunEmptyState: some View {
        ContentUnavailableView {
            Label("No Sessions", systemImage: "network.slash")
        } description: {
            Text("Start a capture from the toolbar to observe network sessions.")
        }
    }

    /// The open saved capture's file changed underneath it. Reload re-reads it;
    /// the sessions shown are from the bytes as they were when opened.
    private var changedOnDiskNotice: some View {
        HStack(spacing: Theme.Metrics.spacingM) {
            Image(systemName: "arrow.clockwise.circle")
                .foregroundStyle(.orange)
            VStack(alignment: .leading, spacing: 3) {
                Text("The capture file changed on disk")
                    .font(Theme.Typography.bodyEmphasis)
                Text("Sessions shown are from the file as it was when it was opened. Reload to read the current file.")
                    .font(Theme.Typography.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer(minLength: 0)
            // Command-R belongs to File > Reload, which carries the
            // canReloadActiveSavedCapture guard this button does not.
            Button("Reload") { coordinator.reloadActiveSavedCapture() }
        }
        .padding(.horizontal, Theme.Metrics.spacingL)
        .padding(.vertical, Theme.Metrics.spacingS)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.orange.opacity(0.06))
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("capture-changed-on-disk")
    }

    @ViewBuilder
    private func scopeRecovery(_ scope: SessionScopeSummary) -> some View {
        if scope.hasClearableFilters {
            Button(SessionScopeAction.resetTitle) { coordinator.resetSessionFilters() }
                .help(SessionScopeAction.resetHelp)
        }
        if coordinator.isNoiseControlActive {
            Button("Reset Noise Control for Project") { coordinator.clearNoiseControl() }
                .help("Removes this Project’s muted host and protocol rules across its workspaces.")
        }
        if scope.removedCount > 0 {
            Button("Restore Removed Sessions") { coordinator.restoreRemovedSessions() }
        }
    }

    private func sessionControlShelf(_ workspace: WorkspaceState, shownCount: Int, shownIDs: Set<UUID>) -> some View {
        VStack(spacing: Theme.Glass.functionalBarVerticalInset) {
            if workspace.isFilterBarVisible {
                SessionFilterBar(
                    coordinator: coordinator,
                    commandDescriptors: commandDescriptors,
                    onCommandAction: onCommandAction
                )
            }
            if coordinator.sessionScope(shownCount: shownCount).isConstrained || coordinator
                .canReturnToPreviousSessionScope
            {
                SessionScopeNotice(
                    coordinator: coordinator,
                    shownCount: shownCount,
                    showsResetAction: !workspace.isFilterBarVisible && shownCount > 0
                )
                .padding(.horizontal, Theme.Metrics.spacingL)
            }
            let pinned = coordinator.pinnedSessions
            if !pinned.isEmpty {
                PinnedSessionsStrip(coordinator: coordinator, pinned: pinned, shownIDs: shownIDs)
                    .padding(.horizontal, Theme.Metrics.spacingL)
            }
            if coordinator.isViewingSavedCapture {
                savedCaptureSourceNotice
            } else {
                LiveTrafficStrip(coordinator: coordinator, isExpanded: liveChartBinding(workspace))
            }
        }
        .padding(.bottom, Theme.Glass.functionalBarVerticalInset)
    }

    private func sessionContent(sessions: [SessionSummary], workspace: WorkspaceState) -> some View {
        VStack(spacing: 0) {
            if coordinator.isImportingCapture {
                captureImportNotice
                Divider()
            } else if coordinator.isOpeningSavedCapture {
                savedCaptureOpeningNotice
                Divider()
            } else if let unavailable = coordinator.unavailableReferencedCapture {
                unavailableSourceNotice(unavailable)
                Divider()
            } else if coordinator.canReloadActiveSavedCapture {
                changedOnDiskNotice
                Divider()
            } else if let warning = coordinator.savedCaptureWarning {
                savedCaptureWarningNotice(warning)
                Divider()
            }
            // List-first (Wireshark/Proxyman): the native NSOutlineView table is
            // the spine and takes the remaining height.
            //
            // When there are no rows, show ONLY the purposeful empty state — not
            // an empty table whose header + ghost separators would show through.
            if sessions.isEmpty {
                emptyState
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                nativeSessionTable(sessions: sessions, workspace: workspace)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    /// A referenced capture whose file is missing or changed. An inline notice
    /// with one recovery action, never an alert (HIG: alerts are not for
    /// information). The Library item and any adopted sessions stay intact.
    private func unavailableSourceNotice(_ capture: SavedCapture) -> some View {
        HStack(spacing: Theme.Metrics.spacingM) {
            Image(systemName: "doc.questionmark")
                .foregroundStyle(.orange)
            VStack(alignment: .leading, spacing: 3) {
                Text(capture
                    .availability == .missing ? "“\(capture.name)” can’t be found" :
                    "“\(capture.name)” changed on disk")
                    .font(Theme.Typography.bodyEmphasis)
                Text(
                    capture.availability == .missing
                        ? "The original file for this Library item is no longer available on this Mac. Locate it to open the capture."
                        : "The original file for this Library item changed on this Mac. Locate the original, or reload to read the current file."
                )
                .font(Theme.Typography.caption)
                .foregroundStyle(.secondary)
                .lineLimit(2)
                .truncationMode(.middle)
            }
            Spacer(minLength: 0)
            if capture.availability == .changed {
                Button("Reload") { coordinator.reloadReferencedCapture(capture) }
            }
            Button("Locate…") { coordinator.locateReferencedCapture(capture) }
        }
        .padding(.horizontal, Theme.Metrics.spacingL)
        .padding(.vertical, Theme.Metrics.spacingS)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.orange.opacity(0.06))
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("capture-source-unavailable")
    }

    private func savedCaptureWarningNotice(_ warning: String) -> some View {
        HStack(spacing: Theme.Metrics.spacingS) {
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundStyle(.yellow)
            Text(warning)
                .font(Theme.Typography.caption)
                .foregroundStyle(.secondary)
        }
        .padding(.horizontal, Theme.Metrics.spacingL)
        .padding(.vertical, Theme.Metrics.spacingS)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.yellow.opacity(0.06))
    }

    private func nativeSessionTable(sessions: [SessionSummary], workspace: WorkspaceState) -> some View {
        let isGrouped = workspace.sessionGrouping != .none
        let timeFormat = coordinator.sessionTimeDisplay.format
        let captureStart = coordinator.trafficTimeline.captureStartFrame
        let languageBundlePath = "\(locale.identifier)|\(AppLanguage.currentLocalizedBundle().bundlePath)"

        let groupedRows: [SessionRow] = isGrouped ? coordinator.sessionRows : []
        let presentationRows: [SessionOutlineRowModel]

        if isGrouped {
            presentationRows = SessionOutlineRowModel.buildGroupedRows(
                rows: groupedRows,
                timeFormat: timeFormat,
                captureStart: captureStart,
                displayHostForSession: { coordinator.addressNames.displayHost(for: $0) },
                classifiedSourceForSession: { coordinator.classifiedSource(for: $0) }
            )
        } else {
            let visibleOptional = columnState.visibleOptionalColumns
            let timelineSpan = visibleOptional.contains(.timeline)
                ? SessionTimelineBar.span(of: sessions)
                : nil
            let investigationNotes = coordinator.investigationNotes
            let noteIDs: Set<UUID> = investigationNotes.notes.isEmpty
                ? []
                : investigationNotes.annotatedSessionIDs
            let tagsBySessionID: [UUID: [SessionTag]]
            if let scope = investigationNotes.scope, !investigationNotes.tagRecords.isEmpty {
                var map: [UUID: [SessionTag]] = [:]
                map.reserveCapacity(investigationNotes.tagRecords.count)
                for record in investigationNotes.tagRecords where record.scope == scope {
                    if map[record.sessionID] == nil {
                        map[record.sessionID] = record.tags
                    }
                }
                tagsBySessionID = map
            } else {
                tagsBySessionID = [:]
            }

            presentationRows = SessionOutlineRowModel.buildFlatRows(
                sessions: sessions,
                sortCriteria: sortCriteria,
                timeFormat: timeFormat,
                captureStart: captureStart,
                timelineSpan: timelineSpan,
                visibleOptionalColumns: visibleOptional,
                noteIDs: noteIDs,
                tagsBySessionID: tagsBySessionID,
                displayHostForSession: { coordinator.addressNames.displayHost(for: $0) },
                classifiedSourceForSession: { coordinator.classifiedSource(for: $0) }
            )
        }

        return NativeSessionOutlineTable(
            rows: presentationRows,
            isGrouped: isGrouped,
            timeFormat: timeFormat,
            languageBundlePath: languageBundlePath,
            selectedSessionID: Binding(
                get: { workspace.selectedSessionID },
                set: { newValue in
                    if workspace.selectedSessionID != newValue {
                        workspace.selectedSessionID = newValue
                    }
                }
            ),
            sortCriteria: $sortCriteria,
            columnState: $columnState,
            revealToken: workspace.sessionRevealToken,
            onLiveScrollStateChange: { isScrolling in
                if isScrolling {
                    coordinator.beginUserLiveScroll()
                } else {
                    coordinator.endUserLiveScroll()
                }
            },
            onUserNavigateHistory: {
                coordinator.userDidNavigateSessionHistory()
            },
            contextMenuBuilder: { rowModel in
                contextMenu(for: rowModel, sessions: sessions, groupedRows: groupedRows)
            }
        )
    }

    private func contextMenu(
        for rowModel: SessionOutlineRowModel,
        sessions: [SessionSummary],
        groupedRows: [SessionRow]
    ) -> NSMenu? {
        let bundle = AppLanguage.currentLocalizedBundle()
        switch rowModel.kind {
        case .session:
            guard let session = resolveSession(id: rowModel.id, sessions: sessions, groupedRows: groupedRows) else {
                return nil
            }
            return makeSessionMenu(for: session, bundle: bundle)

        case .action:
            guard let activity = groupedRows.compactMap({ row -> Activity? in
                if case let .action(item) = row, item.id == rowModel.id {
                    return item
                }
                return nil
            }).first else {
                return nil
            }
            let actions = SessionOutlineContextMenuBuilder.ActionRowActions(
                sessionCount: activity.sessions.count,
                summary: rowModel.summary,
                hasFirstSession: activity.sessions.first != nil,
                onInspectFirst: {
                    if let first = activity.sessions.first {
                        coordinator.select(first)
                    }
                },
                onCopySummary: {
                    copyToPasteboard(rowModel.summary)
                },
                onRemoveAll: {
                    coordinator.removeSessionsFromView(Set(activity.sessions.map(\.id)))
                }
            )
            return SessionOutlineContextMenuBuilder.makeActionRowMenu(actions, bundle: bundle)

        case .group:
            guard let group = groupedRows.compactMap({ row -> SessionGroup? in
                if case let .group(item) = row, item.id == rowModel.id {
                    return item
                }
                return nil
            }).first else {
                return nil
            }
            let host = group.key
            let actions = SessionOutlineContextMenuBuilder.GroupRowActions(
                kind: group.kind == .host ? .host : .process,
                key: group.key,
                sessionCount: group.sessions.count,
                hasFirstSession: group.sessions.first != nil,
                isValidHost: isValidHost(host),
                isHostPinned: coordinator.isHostPinned(host),
                isHostMuted: coordinator.isHostMuted(host),
                onInspectFirst: {
                    if let first = group.sessions.first {
                        coordinator.select(first)
                    }
                },
                onCopyGroupName: {
                    copyToPasteboard(group.key)
                },
                onSelectHost: { coordinator.selectHost($0) },
                onTogglePinHost: { coordinator.togglePinHost($0) },
                onToggleMuteHost: { coordinator.toggleMuteHost($0) },
                onSelectProcess: { coordinator.selectProcess($0) },
                onRemoveAll: {
                    coordinator.removeSessionsFromView(Set(group.sessions.map(\.id)))
                }
            )
            return SessionOutlineContextMenuBuilder.makeGroupRowMenu(actions, bundle: bundle)
        }
    }

    private func makeSessionMenu(for session: SessionSummary, bundle: Bundle) -> NSMenu {
        let host = session.host
        let hostValid = isValidHost(host)
        let proto = session.primaryProtocol
        let classifiedSource = coordinator.classifiedSource(for: session)
        let embeddedCLIHostApp: String? = if classifiedSource.category == .cli {
            coordinator.sessionProcessContext(for: session)?.hostAppName
        } else {
            nil
        }

        let addresses = [session.sourceEndpointValue?.ip, session.destinationEndpointValue?.ip]
            .compactMap(\.self)
            .filter { IPAddressValue(parsing: $0) != nil }
        let nameableAddresses: [(address: String, existingName: String?)] = Array(Set(addresses))
            .sorted()
            .map { address in
                (address: address, existingName: coordinator.addressNames.name(for: address))
            }

        let activeTags = Set(coordinator.investigationNotes.tags(onSession: session.id))
        let actions = SessionOutlineContextMenuBuilder.SessionActions(
            isValidHost: hostValid,
            host: host,
            sourceEndpoint: session.sourceEndpoint,
            destinationEndpoint: session.destinationEndpoint,
            infoSummary: session.infoSummary,
            primaryProtocol: proto,
            canExport: coordinator.canExport(session),
            canExportFrames: coordinator.canExportFrames,
            likeThisTerms: likeThisTerms(session),
            tagScopeAvailable: coordinator.investigationNotes.scope != nil,
            activeTags: activeTags,
            nameableAddresses: nameableAddresses,
            isSessionPinned: coordinator.isSessionPinned(session.id),
            classifiedSource: classifiedSource,
            embeddedCLIHostApp: embeddedCLIHostApp,
            isHostPinned: coordinator.isHostPinned(host),
            isHostMuted: coordinator.isHostMuted(host),
            isProtocolMuted: coordinator.isProtocolMuted(proto),
            onInspect: { coordinator.select(session) },
            onExport: { coordinator.exportSession(session, as: $0) },
            onExportFrames: { coordinator.presentFrameExportPanel(preselectedSessions: [session.id]) },
            onCopy: { copyToPasteboard($0) },
            onInvestigateTerm: { coordinator.investigateSessions(narrowingWith: $0) },
            onToggleTag: { coordinator.toggleTag($0, on: [session.id]) },
            onClearTags: { coordinator.clearTags(on: [session.id]) },
            onNameAddress: { address in
                addressNameDraft = coordinator.addressNames.name(for: address) ?? ""
                namingAddress = address
            },
            onTogglePinSession: { coordinator.togglePinSession(session.id) },
            onSelectHost: { coordinator.selectHost($0) },
            onSelectProcess: { coordinator.selectProcess($0) },
            onTogglePinHost: { coordinator.togglePinHost($0) },
            onToggleMuteHost: { coordinator.toggleMuteHost($0) },
            onToggleMuteProtocol: { coordinator.toggleMuteProtocol($0) },
            onRemoveFromView: { coordinator.removeSessionsFromView(Set([session.id])) }
        )
        return SessionOutlineContextMenuBuilder.makeSessionMenu(actions, bundle: bundle)
    }

    private func resolveSession(
        id: UUID,
        sessions: [SessionSummary],
        groupedRows: [SessionRow]
    ) -> SessionSummary? {
        if let direct = sessions.first(where: { $0.id == id }) {
            return direct
        }
        for row in groupedRows {
            switch row {
            case let .session(session) where session.id == id:
                return session
            case let .action(activity):
                if let match = activity.sessions.first(where: { $0.id == id }) {
                    return match
                }
            case let .group(group):
                if let match = group.sessions.first(where: { $0.id == id }) {
                    return match
                }
            default:
                continue
            }
        }
        return nil
    }

    /// "Investigate Sessions Like This": each item narrows the session expression by
    /// one of this session's own facts and applies it. Only facts the session actually
    /// carries are offered, and each becomes a term the parser accepts.
    private func likeThisTerms(_ session: SessionSummary) -> [(title: String, term: String)] {
        let bundle = AppLanguage.currentLocalizedBundle()
        let terms: [(String, String?)] = [
            (String(localized: "Same Host", bundle: bundle), SessionExpressionTerm.sameHost(session.host)),
            (
                String(localized: "Same Destination Address", bundle: bundle),
                SessionExpressionTerm.sameDestinationIP(session.destinationEndpointValue)
            ),
            (
                String(localized: "Same Destination Port", bundle: bundle),
                SessionExpressionTerm.sameDestinationPort(session.destinationEndpointValue)
            ),
            (
                String(localized: "Same Process", bundle: bundle),
                SessionExpressionTerm.sameProcess(validProcessName(session.processName))
            ),
            (
                String(localized: "Same Protocol", bundle: bundle),
                SessionExpressionTerm.sameProtocol(session.primaryProtocol)
            ),
        ]
        return terms.compactMap { title, term in term.map { (title, $0) } }
    }

    private func loadColumnCustomization() {
        columnState = SessionOutlineColumnState.load(
            from: coordinator.activeProjectDefaults,
            key: ProjectScopedSettingsKeys.sessionTableColumns
        )
        didLoadColumnCustomization = true
    }

    private func visibilityFingerprint(_ workspace: WorkspaceState) -> VisibilityFingerprint {
        VisibilityFingerprint(
            sidebarSelection: workspace.sidebarSelection,
            filterText: workspace.filterText,
            searchField: workspace.searchField,
            isSearchEnabled: workspace.isSearchEnabled,
            categoryFilters: workspace.categoryFilters,
            hostFilter: workspace.hostFilter,
            processFilter: workspace.processFilter,
            ipFilter: workspace.ipFilter,
            aggregateProtocolFilters: workspace.aggregateProtocolFilters,
            aggregateDestinationFilter: workspace.aggregateDestinationFilter,
            aggregateRequiresFindings: workspace.aggregateRequiresFindings,
            filterRules: workspace.filterRules
        )
    }

    /// A host is worth acting on only when it is a real name — a blank host or the
    /// em-dash placeholder must not become a filter, pin, or mute target.
    private func isValidHost(_ host: String) -> Bool {
        let trimmed = host.trimmingCharacters(in: .whitespacesAndNewlines)
        return !trimmed.isEmpty && trimmed != "—"
    }

    private func validProcessName(_ processName: String?) -> String? {
        guard let trimmed = processName?.trimmingCharacters(in: .whitespacesAndNewlines),
              !trimmed.isEmpty,
              trimmed != "—" else
        {
            return nil
        }
        return trimmed
    }

    /// Copies exactly the chosen value to the general pasteboard.
    private func copyToPasteboard(_ value: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(value, forType: .string)
    }

    private func liveChartBinding(_ workspace: WorkspaceState) -> Binding<Bool> {
        Binding(
            get: { workspace.isLiveChartExpanded },
            set: { workspace.isLiveChartExpanded = $0 }
        )
    }
}

// MARK: - LiveTrafficStrip

/// A modest, collapsible live-throughput strip above the session table. Isolated
/// so its per-second updates don't re-render the Table's host body.
private struct LiveTrafficStrip: View {
    // MARK: Internal

    let coordinator: MainContentCoordinator

    @Binding var isExpanded: Bool

    var body: some View {
        VStack(spacing: 0) {
            Button {
                withAnimation(.smooth(duration: 0.2)) { isExpanded.toggle() }
            } label: {
                HStack(spacing: 6) {
                    Image(systemName: "waveform.path.ecg")
                        .font(.system(size: Theme.Icon.small)).foregroundStyle(.secondary)
                    Text("Live Traffic")
                        .font(Theme.Typography.captionEmphasis).foregroundStyle(.secondary)
                    Spacer()
                    Text(currentRate)
                        .font(Theme.Typography.monoSmall)
                        .foregroundStyle(Color.accentColor)
                    Image(systemName: isExpanded ? "chevron.up" : "chevron.down")
                        .font(.system(size: Theme.Icon.small)).foregroundStyle(.tertiary)
                }
                .padding(.horizontal, Theme.Metrics.spacingL)
                .padding(.vertical, 5)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)

            if isExpanded {
                ThroughputChart(samples: coordinator.throughputSamples)
                    .frame(height: 104)
                    .padding(.horizontal, Theme.Metrics.spacingL)
                    .padding(.bottom, Theme.Metrics.spacingS)
            }
        }
        .tracexyContentSurface(
            in: RoundedRectangle(cornerRadius: Theme.Metrics.cornerRadius, style: .continuous)
        )
        .padding(.horizontal, Theme.Glass.functionalBarHorizontalInset)
    }

    // MARK: Private

    private var currentRate: String {
        let bytesPerSecond = coordinator.throughputSamples.last?.bytesPerSecond ?? 0
        return "\(ByteUnits.string(Int64(bytesPerSecond)))/s"
    }
}

// MARK: - ClosureMenuAction

/// Lightweight retained target for dynamically constructed `NSMenuItem`s.
private final class ClosureMenuAction: NSObject {
    let handler: () -> Void

    init(_ handler: @escaping () -> Void) {
        self.handler = handler
    }

    @objc
    func invoke(_: Any?) {
        handler()
    }
}

// MARK: - SessionOutlineContextMenuBuilder

/// Builds native AppKit `NSMenu`s for `.session`, `.action`, and `.group` rows
/// with 100% action parity with the original SwiftUI menus and live localization.
enum SessionOutlineContextMenuBuilder {
    // MARK: Internal

    struct SessionActions {
        let isValidHost: Bool
        let host: String
        let sourceEndpoint: String
        let destinationEndpoint: String
        let infoSummary: String
        let primaryProtocol: ProtocolKind
        let canExport: Bool
        let canExportFrames: Bool
        let likeThisTerms: [(title: String, term: String)]
        let tagScopeAvailable: Bool
        let activeTags: Set<SessionTag>
        let nameableAddresses: [(address: String, existingName: String?)]
        let isSessionPinned: Bool
        let classifiedSource: ClassifiedSessionSource
        let embeddedCLIHostApp: String?
        let isHostPinned: Bool
        let isHostMuted: Bool
        let isProtocolMuted: Bool

        let onInspect: () -> Void
        let onExport: (SessionExportFormat) -> Void
        let onExportFrames: () -> Void
        let onCopy: (String) -> Void
        let onInvestigateTerm: (String) -> Void
        let onToggleTag: (SessionTag) -> Void
        let onClearTags: () -> Void
        let onNameAddress: (String) -> Void
        let onTogglePinSession: () -> Void
        let onSelectHost: (String) -> Void
        let onSelectProcess: (String) -> Void
        let onTogglePinHost: (String) -> Void
        let onToggleMuteHost: (String) -> Void
        let onToggleMuteProtocol: (ProtocolKind) -> Void
        let onRemoveFromView: () -> Void
    }

    struct ActionRowActions {
        let sessionCount: Int
        let summary: String
        let hasFirstSession: Bool
        let onInspectFirst: () -> Void
        let onCopySummary: () -> Void
        let onRemoveAll: () -> Void
    }

    struct GroupRowActions {
        let kind: SessionOutlineGroupKind
        let key: String
        let sessionCount: Int
        let hasFirstSession: Bool
        let isValidHost: Bool
        let isHostPinned: Bool
        let isHostMuted: Bool
        let onInspectFirst: () -> Void
        let onCopyGroupName: () -> Void
        let onSelectHost: (String) -> Void
        let onTogglePinHost: (String) -> Void
        let onToggleMuteHost: (String) -> Void
        let onSelectProcess: (String) -> Void
        let onRemoveAll: () -> Void
    }

    static func makeSessionMenu(
        _ actions: SessionActions,
        bundle: Bundle = AppLanguage.currentLocalizedBundle()
    ) -> NSMenu {
        let menu = NSMenu()
        menu.autoenablesItems = false

        menu.addItem(makeItem(
            title: String(localized: "Inspect Session", bundle: bundle),
            symbol: "sidebar.right",
            handler: actions.onInspect
        ))
        menu.addItem(.separator())

        // Export submenu
        let exportMenu = NSMenu()
        exportMenu.autoenablesItems = false
        for format in SessionExportFormat.allCases {
            exportMenu.addItem(makeItem(
                title: String(localized: String.LocalizationValue(format.title), bundle: bundle),
                handler: { actions.onExport(format) }
            ))
        }
        exportMenu.addItem(.separator())
        let exportFramesItem = makeItem(
            title: String(localized: "Export Frames…", bundle: bundle),
            isEnabled: actions.canExportFrames,
            handler: actions.onExportFrames
        )
        exportMenu.addItem(exportFramesItem)
        let exportRoot = makeSubmenuItem(
            title: String(localized: "Export", bundle: bundle),
            symbol: "square.and.arrow.up",
            submenu: exportMenu,
            isEnabled: actions.canExport || actions.canExportFrames
        )
        menu.addItem(exportRoot)
        menu.addItem(.separator())

        // Copy submenu
        let copyMenu = NSMenu()
        copyMenu.autoenablesItems = false
        if actions.isValidHost {
            copyMenu.addItem(makeItem(
                title: String(localized: "Host", bundle: bundle),
                handler: { actions.onCopy(actions.host) }
            ))
        }
        copyMenu.addItem(makeItem(
            title: String(localized: "Source", bundle: bundle),
            handler: { actions.onCopy(actions.sourceEndpoint) }
        ))
        copyMenu.addItem(makeItem(
            title: String(localized: "Destination", bundle: bundle),
            handler: { actions.onCopy(actions.destinationEndpoint) }
        ))
        copyMenu.addItem(makeItem(
            title: String(localized: "Summary", bundle: bundle),
            handler: { actions.onCopy(actions.infoSummary) }
        ))
        if !actions.likeThisTerms.isEmpty {
            copyMenu.addItem(.separator())
            let exprMenu = NSMenu()
            exprMenu.autoenablesItems = false
            for (title, term) in actions.likeThisTerms {
                let item = makeItem(title: title, handler: { actions.onCopy(term) })
                item.toolTip = term
                exprMenu.addItem(item)
            }
            copyMenu.addItem(makeSubmenuItem(
                title: String(localized: "As Session Expression", bundle: bundle),
                submenu: exprMenu
            ))
        }
        menu.addItem(makeSubmenuItem(
            title: String(localized: "Copy", bundle: bundle),
            symbol: "doc.on.doc",
            submenu: copyMenu
        ))
        menu.addItem(.separator())

        // Investigate Sessions Like This
        if !actions.likeThisTerms.isEmpty {
            let likeMenu = NSMenu()
            likeMenu.autoenablesItems = false
            for (title, term) in actions.likeThisTerms {
                let item = makeItem(title: title, handler: { actions.onInvestigateTerm(term) })
                item.toolTip = term
                likeMenu.addItem(item)
            }
            menu.addItem(makeSubmenuItem(
                title: String(localized: "Investigate Sessions Like This", bundle: bundle),
                symbol: "scope",
                submenu: likeMenu
            ))
        }

        // Tag submenu
        let tagMenu = NSMenu()
        tagMenu.autoenablesItems = false
        for tag in SessionTag.allCases {
            let item = makeItem(
                title: String(localized: String.LocalizationValue(tag.title), bundle: bundle),
                handler: { actions.onToggleTag(tag) }
            )
            item.state = actions.activeTags.contains(tag) ? .on : .off
            item.image = SessionOutlineIconCache.smallSymbol(
                named: "circle.fill",
                color: SessionOutlineStyle.color(for: tag),
                colorKey: "tag-\(tag.rawValue)",
                pointSize: 10
            )
            tagMenu.addItem(item)
        }
        tagMenu.addItem(.separator())
        tagMenu.addItem(makeItem(
            title: String(localized: "Clear Tags", bundle: bundle),
            isEnabled: !actions.activeTags.isEmpty,
            handler: actions.onClearTags
        ))
        menu.addItem(makeSubmenuItem(
            title: String(localized: "Tag", bundle: bundle),
            symbol: "tag",
            submenu: tagMenu,
            isEnabled: actions.tagScopeAvailable
        ))

        // Name Address submenu
        if !actions.nameableAddresses.isEmpty {
            let addrMenu = NSMenu()
            addrMenu.autoenablesItems = false
            for entry in actions.nameableAddresses {
                let title = entry.existingName.map { "\(entry.address) (\($0))…" } ?? "\(entry.address)…"
                addrMenu.addItem(makeItem(title: title, handler: { actions.onNameAddress(entry.address) }))
            }
            menu.addItem(makeSubmenuItem(
                title: String(localized: "Name Address", bundle: bundle),
                symbol: "character.cursor.ibeam",
                submenu: addrMenu
            ))
        }

        // Pin / Unpin Session
        menu.addItem(makeItem(
            title: actions.isSessionPinned
                ? String(localized: "Unpin Session", bundle: bundle)
                : String(localized: "Pin Session", bundle: bundle),
            symbol: actions.isSessionPinned ? "pin.slash" : "pin",
            handler: actions.onTogglePinSession
        ))

        if actions.isValidHost {
            menu.addItem(makeItem(
                title: String(localized: "Show Sessions for \(actions.host)", bundle: bundle),
                symbol: "line.3.horizontal.decrease.circle",
                handler: { actions.onSelectHost(actions.host) }
            ))
        }

        let classified = actions.classifiedSource
        if classified.category != .unattributed {
            menu.addItem(makeItem(
                title: String(localized: "Show Sessions for \(classified.title)", bundle: bundle),
                symbol: classified.symbolName ?? classified.category.systemImage,
                handler: { actions.onSelectProcess(classified.filterKey) }
            ))
            if classified.category == .cli,
               let hostApp = actions.embeddedCLIHostApp,
               !hostApp.isEmpty
            {
                menu.addItem(makeItem(
                    title: String(localized: "Show Sessions for \(hostApp)", bundle: bundle),
                    symbol: "app.badge",
                    handler: { actions.onSelectProcess(hostApp) }
                ))
            }
        }

        if actions.isValidHost || classified.category != .unattributed {
            menu.addItem(.separator())
        }

        if actions.isValidHost {
            menu.addItem(makeItem(
                title: actions.isHostPinned
                    ? String(localized: "Unpin Host", bundle: bundle)
                    : String(localized: "Pin Host", bundle: bundle),
                symbol: actions.isHostPinned ? "pin.slash" : "pin",
                handler: { actions.onTogglePinHost(actions.host) }
            ))
            menu.addItem(makeItem(
                title: actions.isHostMuted
                    ? String(localized: "Unmute Host", bundle: bundle)
                    : String(localized: "Mute Host", bundle: bundle),
                symbol: actions.isHostMuted ? "speaker.wave.2" : "speaker.slash",
                handler: { actions.onToggleMuteHost(actions.host) }
            ))
        }

        let proto = actions.primaryProtocol
        menu.addItem(makeItem(
            title: actions.isProtocolMuted
                ? String(localized: "Unmute \(proto.label)", bundle: bundle)
                : String(localized: "Mute \(proto.label)", bundle: bundle),
            symbol: actions.isProtocolMuted ? "speaker.wave.2" : "speaker.slash",
            handler: { actions.onToggleMuteProtocol(proto) }
        ))

        menu.addItem(.separator())

        menu.addItem(makeItem(
            title: String(localized: "Remove from View", bundle: bundle),
            symbol: "trash",
            handler: actions.onRemoveFromView
        ))

        return menu
    }

    static func makeActionRowMenu(
        _ actions: ActionRowActions,
        bundle: Bundle = AppLanguage.currentLocalizedBundle()
    ) -> NSMenu {
        let menu = NSMenu()
        menu.autoenablesItems = false
        if actions.hasFirstSession {
            menu.addItem(makeItem(
                title: String(localized: "Inspect First Session", bundle: bundle),
                symbol: "sidebar.right",
                handler: actions.onInspectFirst
            ))
        }
        menu.addItem(makeItem(
            title: String(localized: "Copy Summary", bundle: bundle),
            symbol: "doc.on.doc",
            handler: actions.onCopySummary
        ))
        menu.addItem(.separator())
        menu.addItem(makeItem(
            title: String(localized: "Remove \(actions.sessionCount) Sessions from View", bundle: bundle),
            symbol: "trash",
            handler: actions.onRemoveAll
        ))
        return menu
    }

    static func makeGroupRowMenu(
        _ actions: GroupRowActions,
        bundle: Bundle = AppLanguage.currentLocalizedBundle()
    ) -> NSMenu {
        let menu = NSMenu()
        menu.autoenablesItems = false
        if actions.hasFirstSession {
            menu.addItem(makeItem(
                title: String(localized: "Inspect First Session", bundle: bundle),
                symbol: "sidebar.right",
                handler: actions.onInspectFirst
            ))
        }
        menu.addItem(makeItem(
            title: String(localized: "Copy Group Name", bundle: bundle),
            symbol: "doc.on.doc",
            handler: actions.onCopyGroupName
        ))
        menu.addItem(.separator())

        switch actions.kind {
        case .host:
            if actions.isValidHost {
                menu.addItem(makeItem(
                    title: String(localized: "Show Sessions for \(actions.key)", bundle: bundle),
                    symbol: "line.3.horizontal.decrease.circle",
                    handler: { actions.onSelectHost(actions.key) }
                ))
                menu.addItem(.separator())
                menu.addItem(makeItem(
                    title: actions.isHostPinned
                        ? String(localized: "Unpin Host", bundle: bundle)
                        : String(localized: "Pin Host", bundle: bundle),
                    symbol: actions.isHostPinned ? "pin.slash" : "pin",
                    handler: { actions.onTogglePinHost(actions.key) }
                ))
                menu.addItem(makeItem(
                    title: actions.isHostMuted
                        ? String(localized: "Unmute Host", bundle: bundle)
                        : String(localized: "Mute Host", bundle: bundle),
                    symbol: actions.isHostMuted ? "speaker.wave.2" : "speaker.slash",
                    handler: { actions.onToggleMuteHost(actions.key) }
                ))
            }
        case .process:
            menu.addItem(makeItem(
                title: String(localized: "Show Sessions for \(actions.key)", bundle: bundle),
                symbol: "app.badge",
                handler: { actions.onSelectProcess(actions.key) }
            ))
        }

        menu.addItem(.separator())
        menu.addItem(makeItem(
            title: String(localized: "Remove \(actions.sessionCount) Sessions from View", bundle: bundle),
            symbol: "trash",
            handler: actions.onRemoveAll
        ))
        return menu
    }

    // MARK: Private

    static func makeItem(
        title: String,
        symbol: String? = nil,
        isEnabled: Bool = true,
        handler: @escaping () -> Void
    ) -> NSMenuItem {
        let action = ClosureMenuAction(handler)
        let item = NSMenuItem(title: title, action: #selector(ClosureMenuAction.invoke(_:)), keyEquivalent: "")
        item.target = action
        item.representedObject = action
        item.isEnabled = isEnabled
        if let symbol {
            item.image = NSImage(systemSymbolName: symbol, accessibilityDescription: nil)
        }
        return item
    }

    static func makeSubmenuItem(
        title: String,
        symbol: String? = nil,
        submenu: NSMenu,
        isEnabled: Bool = true
    ) -> NSMenuItem {
        let item = NSMenuItem(title: title, action: nil, keyEquivalent: "")
        item.submenu = submenu
        item.isEnabled = isEnabled
        if let symbol {
            item.image = NSImage(systemSymbolName: symbol, accessibilityDescription: nil)
        }
        return item
    }
}

