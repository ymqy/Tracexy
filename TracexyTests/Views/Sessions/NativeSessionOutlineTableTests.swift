import AppKit
import Foundation
import Testing
@testable import Tracexy

@Suite("Native AppKit NSOutlineView session table")
struct NativeSessionOutlineTableTests {
    // MARK: Internal

    @Test("Flat and grouped modes mount in NSWindow, expand/collapse actions, and resolve representative selection without reentrancy")
    func flatAndGroupedMountingAndSelectionSemantics() throws {
        _ = NSApplication.shared

        var selectedIDs: [UUID?] = []
        var navigationEvents = 0
        let coordinator = NativeSessionOutlineTable.Coordinator(
            onSelectSessionID: { selectedIDs.append($0) },
            onSortCriteriaChange: { _ in },
            onColumnStateChange: { _ in },
            onLiveScrollStateChange: nil,
            onUserNavigateHistory: { navigationEvents += 1 },
            contextMenuBuilder: { _ in nil }
        )

        let (window, scrollView, outlineView) = try mountOffscreen(coordinator: coordinator)
        defer { window.orderOut(nil) }

        let s1 = makeSession(host: "api.example.com", bytesUp: 100, bytesDown: 200, offsetSeconds: 0)
        let s2 = makeSession(host: "cdn.example.com", bytesUp: 300, bytesDown: 400, offsetSeconds: 1)
        let s3 = makeSession(host: "printer.local", bytesUp: 50, bytesDown: 60, offsetSeconds: 2)

        // 1. Flat mode
        let flatRows = buildFlat([s1, s2, s3])
        coordinator.apply(
            rows: flatRows,
            isGrouped: false,
            timeFormat: .timeOfDay,
            selectedSessionID: s2.id,
            sortCriteria: [],
            columnState: .defaultState,
            revealToken: 0
        )
        scrollView.layoutSubtreeIfNeeded()
        outlineView.layoutSubtreeIfNeeded()

        #expect(outlineView.numberOfRows == 3)
        #expect(outlineView.selectedRow == 1)
        #expect(navigationEvents == 0, "Programmatic selection sync must never trigger onUserNavigateHistory")
        #expect(selectedIDs.isEmpty, "Programmatic selection sync must not re-enter onSelectSessionID")
        #expect(coordinator.outlineView(outlineView, heightOfRowByItem: coordinator.topLevelNodes[0]) == 24)
        // Local discovery host annotation carries badge & tooltip in flat mode
        if case let .session(hostData) = flatRows[2].kind {
            #expect(hostData.localDiscoveryBadgeTitle != nil)
            #expect(hostData.localDiscoveryTooltip != nil)
        } else {
            Issue.record("Expected .session row kind")
        }

        // 2. Grouped mode with expandable .action, .host group, and .process group
        let activity = Activity(
            sessions: [s1, s2],
            evidence: [.dnsAnswerToConnection(name: "api.example.com", address: "93.184.216.34")]
        )
        let hostGroup = SessionGroup(kind: .host, key: "cdn.example.com", sessions: [s2])
        let procGroup = SessionGroup(kind: .process, key: "Safari", sessions: [s3])
        let groupedRows = buildGrouped([.action(activity), .group(hostGroup), .group(procGroup)])

        coordinator.apply(
            rows: groupedRows,
            isGrouped: true,
            timeFormat: .timeOfDay,
            selectedSessionID: nil,
            sortCriteria: [],
            columnState: .defaultState,
            revealToken: 0
        )
        outlineView.layoutSubtreeIfNeeded()

        #expect(outlineView.numberOfRows == 3)
        let actionNode = coordinator.topLevelNodes[0]
        let hostGroupNode = coordinator.topLevelNodes[1]
        #expect(coordinator.outlineView(outlineView, heightOfRowByItem: actionNode) == 36)
        #expect(coordinator.outlineView(outlineView, heightOfRowByItem: hostGroupNode) == 24)
        #expect(coordinator.outlineView(outlineView, isItemExpandable: actionNode))
        #expect(!coordinator.outlineView(outlineView, isItemExpandable: hostGroupNode))

        // Expand & collapse .action row
        outlineView.expandItem(actionNode)
        #expect(outlineView.numberOfRows == 5)
        outlineView.collapseItem(actionNode)
        #expect(outlineView.numberOfRows == 3)

        // Simulated user selection on .action row resolves to representativeSessionID
        outlineView.selectRowIndexes(IndexSet(integer: 0), byExtendingSelection: false)
        #expect(selectedIDs.last == activity.sessions.first?.id)
        #expect(navigationEvents == 1)

        // Programmatic re-apply with the same selectedSessionID must NOT re-fire delegate callbacks
        let priorNavCount = navigationEvents
        let priorSelectCount = selectedIDs.count
        coordinator.apply(
            rows: groupedRows,
            isGrouped: true,
            timeFormat: .timeOfDay,
            selectedSessionID: activity.sessions.first?.id,
            sortCriteria: [],
            columnState: .defaultState,
            revealToken: 0
        )
        #expect(navigationEvents == priorNavCount)
        #expect(selectedIDs.count == priorSelectCount)
    }

    @Test("Incremental updates on 1,000 rows preserve node identity, skip reloadData, and tail-append without losing scroll or expansion")
    func incrementalVisibleUpdatesAndTailAppend() throws {
        _ = NSApplication.shared

        let coordinator = NativeSessionOutlineTable.Coordinator(
            onSelectSessionID: { _ in },
            onSortCriteriaChange: { _ in },
            onColumnStateChange: { _ in },
            onLiveScrollStateChange: nil,
            onUserNavigateHistory: {},
            contextMenuBuilder: { _ in nil }
        )

        let (window, scrollView, outlineView) = try mountOffscreen(coordinator: coordinator)
        defer { window.orderOut(nil) }

        var sessions = (0 ..< 1_000).map { index in
            makeSession(
                host: "host-\(index).example.com",
                bytesUp: 128 + index,
                bytesDown: 256 + index,
                offsetSeconds: Double(index) * 0.01
            )
        }

        let initialRows = buildFlat(sessions)
        coordinator.apply(
            rows: initialRows,
            isGrouped: false,
            timeFormat: .timeOfDay,
            selectedSessionID: sessions[5].id,
            sortCriteria: [],
            columnState: .defaultState,
            revealToken: 0
        )
        scrollView.layoutSubtreeIfNeeded()
        outlineView.layoutSubtreeIfNeeded()

        #expect(outlineView.numberOfRows == 1_000)
        #expect(coordinator.fullReloadCount == 1)

        let originalNodeIDs = coordinator.topLevelNodes.map(ObjectIdentifier.init)

        // Scroll partway down so we can also assert scroll position is preserved across updates
        outlineView.scroll(NSPoint(x: 0, y: 240))
        scrollView.layoutSubtreeIfNeeded()
        let savedOrigin = scrollView.contentView.bounds.origin

        // Mutate byte counts across all 1,000 rows and measure incremental update latency
        for index in sessions.indices {
            sessions[index].bytesDown += 4_096
        }
        let updatedRows = buildFlat(sessions)

        let clock = ContinuousClock()
        let elapsed = clock.measure {
            coordinator.apply(
                rows: updatedRows,
                isGrouped: false,
                timeFormat: .timeOfDay,
                selectedSessionID: sessions[5].id,
                sortCriteria: [],
                columnState: .defaultState,
                revealToken: 0
            )
        }

        let elapsedMs = Double(elapsed.components.seconds) * 1_000.0
            + Double(elapsed.components.attoseconds) / 1e15

        #expect(coordinator.fullReloadCount == 1, "Same-ID updates must NOT trigger reloadData()")
        #expect(coordinator.incrementalVisibleUpdateCount == 1)
        #expect(coordinator.topLevelNodes.map(ObjectIdentifier.init) == originalNodeIDs)
        #expect(scrollView.contentView.bounds.origin == savedOrigin)
        print(String(format: "[benchmark] 1000-row incremental visible update: %.3f ms", elapsedMs))
        #expect(elapsedMs < 5.0, "1,000-row incremental visible update took \(elapsedMs)ms (budget < 5ms)")

        // Verify visible cell actually reflects the updated byte count
        let visibleRange = outlineView.rows(in: outlineView.visibleRect)
        let lengthColIndex = outlineView.column(
            withIdentifier: NSUserInterfaceItemIdentifier(SessionOutlineColumnID.length.rawValue)
        )
        if visibleRange.length > 0, lengthColIndex >= 0 {
            let sampleRow = visibleRange.location
            if let cell = outlineView.view(atColumn: lengthColIndex, row: sampleRow, makeIfNecessary: false) as? NSTableCellView {
                #expect(cell.textField?.stringValue == updatedRows[sampleRow].lengthText)
            }
        }

        // Append 50 new tail rows -> must use incremental insertItems without reloadData()
        let tailSessions = (1_000 ..< 1_050).map { index in
            makeSession(
                host: "tail-\(index).example.com",
                bytesUp: 64,
                bytesDown: 128,
                offsetSeconds: Double(index) * 0.01
            )
        }
        let appendedRows = buildFlat(sessions + tailSessions)
        coordinator.apply(
            rows: appendedRows,
            isGrouped: false,
            timeFormat: .timeOfDay,
            selectedSessionID: sessions[5].id,
            sortCriteria: [],
            columnState: .defaultState,
            revealToken: 0
        )

        #expect(outlineView.numberOfRows == 1_050)
        #expect(coordinator.fullReloadCount == 1, "Pure tail append must NOT trigger reloadData()")
        #expect(coordinator.incrementalTailInsertCount == 1)
        #expect(Array(coordinator.topLevelNodes.prefix(1_000)).map(ObjectIdentifier.init) == originalNodeIDs)
        #expect(scrollView.contentView.bounds.origin == savedOrigin)

        // Grouped tail append preserves expanded .action state without reloadData()
        let a1 = Activity(
            sessions: [sessions[0], sessions[1]],
            evidence: [.sameProcessAtConnect(process: "Safari")]
        )
        let a2 = Activity(
            sessions: [sessions[2], sessions[3]],
            evidence: [.sameProcessAtConnect(process: "curl")]
        )
        let groupedInitial = buildGrouped([.action(a1)])
        coordinator.apply(
            rows: groupedInitial,
            isGrouped: true,
            timeFormat: .timeOfDay,
            selectedSessionID: nil,
            sortCriteria: [],
            columnState: .defaultState,
            revealToken: 0
        )
        let reloadsBeforeTail = coordinator.fullReloadCount
        let firstActionNode = coordinator.topLevelNodes[0]
        outlineView.expandItem(firstActionNode)
        #expect(outlineView.isItemExpanded(firstActionNode))
        #expect(outlineView.numberOfRows == 3)

        let groupedTail = buildGrouped([.action(a1), .action(a2)])
        coordinator.apply(
            rows: groupedTail,
            isGrouped: true,
            timeFormat: .timeOfDay,
            selectedSessionID: nil,
            sortCriteria: [],
            columnState: .defaultState,
            revealToken: 0
        )
        #expect(coordinator.fullReloadCount == reloadsBeforeTail)
        #expect(outlineView.isItemExpanded(firstActionNode))
        #expect(outlineView.numberOfRows == 4)
    }

    @Test("Column visibility, widths, and legacy SwiftUI customization bytes round-trip cleanly in isolated UserDefaults")
    func columnCustomizationPersistenceAndLegacyFallback() throws {
        let suiteName = "tracexy.tests.nativeOutlineColumns.\(UUID().uuidString)"
        let defaults = try #require(UserDefaults(suiteName: suiteName))
        defer { defaults.removePersistentDomain(forName: suiteName) }

        // 1. Legacy SwiftUI TableColumnCustomization JSON falls back gracefully to defaultState
        let legacyJSON = Data(#"{"columnVisibility":{"latency":"hidden"},"columnOrder":["summary","time"]}"#.utf8)
        defaults.set(legacyJSON, forKey: ProjectScopedSettingsKeys.sessionTableColumns)

        let recovered = SessionOutlineColumnState.load(from: defaults)
        #expect(recovered.isVisible(.latency))
        #expect(recovered.isVisible(.status))
        #expect(!recovered.isVisible(.timeline))
        #expect(!recovered.isVisible(.tcpCompleteness))
        #expect(recovered.columnOrder == SessionOutlineColumnID.allCases)

        // 2. Custom visibility, width, and status-cannot-be-hidden rule round-trip cleanly
        var customized = recovered
        customized.setVisible(true, for: .timeline)
        customized.setVisible(true, for: .bytesUp)
        customized.setVisible(false, for: .source)
        customized.setVisible(false, for: .status) // must be ignored
        customized.setWidth(260, for: .host)
        customized.save(to: defaults)

        let reloaded = SessionOutlineColumnState.load(from: defaults)
        #expect(reloaded.isVisible(.timeline))
        #expect(reloaded.isVisible(.bytesUp))
        #expect(!reloaded.isVisible(.source))
        #expect(reloaded.isVisible(.status))
        #expect(reloaded.width(for: .host) == 260)
        #expect(reloaded.visibleOptionalColumns == [.timeline, .bytesUp])
    }

    @Test("Flat row sorting matches column types and preserves capture order when empty")
    func flatRowSortingSemantics() {
        let s1 = makeSession(host: "zeta.example", bytesUp: 500, bytesDown: 100, latency: 42.0, status: .error, offsetSeconds: 2)
        let s2 = makeSession(host: "alpha.example", bytesUp: 100, bytesDown: 900, latency: 5.0, status: .ok, offsetSeconds: 0)
        let s3 = makeSession(host: "mid.example", bytesUp: 200, bytesDown: 200, latency: nil, status: .warning, offsetSeconds: 1)
        let input = [s1, s2, s3]

        // Empty sort preserves exact capture order
        let unsorted = SessionOutlineRowModel.sortSessions(input, using: [])
        #expect(unsorted.map(\.id) == [s1.id, s2.id, s3.id])

        // Host ascending
        let byHost = SessionOutlineRowModel.sortSessions(
            input,
            using: [SessionOutlineSortCriterion(column: .host, ascending: true)]
        )
        #expect(byHost.map(\.id) == [s2.id, s3.id, s1.id])

        // Length descending (s2=1000, s1=600, s3=400)
        let byLengthDesc = SessionOutlineRowModel.sortSessions(
            input,
            using: [SessionOutlineSortCriterion(column: .length, ascending: false)]
        )
        #expect(byLengthDesc.map(\.id) == [s2.id, s1.id, s3.id])

        // Latency ascending (nil sorts last)
        let byLatency = SessionOutlineRowModel.sortSessions(
            input,
            using: [SessionOutlineSortCriterion(column: .latency, ascending: true)]
        )
        #expect(byLatency.map(\.id) == [s2.id, s1.id, s3.id])

        // Status ascending (ok < warning < error)
        let byStatus = SessionOutlineRowModel.sortSessions(
            input,
            using: [SessionOutlineSortCriterion(column: .status, ascending: true)]
        )
        #expect(byStatus.map(\.id) == [s2.id, s3.id, s1.id])
    }

    @Test("Context menu builder produces full action parity for session, action, and group rows")
    func contextMenuBuilderParity() throws {
        var inspected = false
        var exportedFormat: SessionExportFormat?
        var copiedValue: String?
        var toggledTag: SessionTag?
        var namedAddress: String?
        var removedCount = 0

        let classifiedCLI = ClassifiedSessionSource(
            category: .cli,
            filterKey: "cli:curl",
            title: "curl",
            subtitle: "CLI Tool",
            tableLabel: "curl",
            tableDetail: "CLI Tool",
            symbolName: "terminal",
            childTarget: nil
        )

        let sessionMenu = SessionOutlineContextMenuBuilder.makeSessionMenu(
            .init(
                isValidHost: true,
                host: "api.example.com",
                sourceEndpoint: "10.0.0.2:54321",
                destinationEndpoint: "93.184.216.34:443",
                infoSummary: "TLS to api.example.com",
                primaryProtocol: .tls,
                canExport: true,
                canExportFrames: true,
                likeThisTerms: [("Same Host", "host == \"api.example.com\"")],
                tagScopeAvailable: true,
                activeTags: [.red],
                nameableAddresses: [("93.184.216.34", nil)],
                isSessionPinned: false,
                classifiedSource: classifiedCLI,
                embeddedCLIHostApp: "Terminal",
                isHostPinned: false,
                isHostMuted: false,
                isProtocolMuted: false,
                onInspect: { inspected = true },
                onExport: { exportedFormat = $0 },
                onExportFrames: {},
                onCopy: { copiedValue = $0 },
                onInvestigateTerm: { _ in },
                onToggleTag: { toggledTag = $0 },
                onClearTags: {},
                onNameAddress: { namedAddress = $0 },
                onTogglePinSession: {},
                onSelectHost: { _ in },
                onSelectProcess: { _ in },
                onTogglePinHost: { _ in },
                onToggleMuteHost: { _ in },
                onToggleMuteProtocol: { _ in },
                onRemoveFromView: { removedCount += 1 }
            ),
            bundle: .main
        )

        let titles = sessionMenu.items.filter { !$0.isSeparatorItem }.map(\.title)
        #expect(titles.contains("Inspect Session"))
        #expect(titles.contains("Export"))
        #expect(titles.contains("Copy"))
        #expect(titles.contains("Investigate Sessions Like This"))
        #expect(titles.contains("Tag"))
        #expect(titles.contains("Name Address"))
        #expect(titles.contains("Pin Session"))
        #expect(titles.contains("Show Sessions for api.example.com"))
        #expect(titles.contains("Show Sessions for curl"))
        #expect(titles.contains("Show Sessions for Terminal"))
        #expect(titles.contains("Pin Host"))
        #expect(titles.contains("Mute Host"))
        #expect(titles.contains("Mute TLS"))
        #expect(titles.contains("Remove from View"))

        // Invoke actions via menu item targets to confirm closure wiring works
        let inspectItem = try #require(sessionMenu.item(withTitle: "Inspect Session"))
        invoke(inspectItem)
        #expect(inspected)

        let exportSubmenu = try #require(sessionMenu.item(withTitle: "Export")?.submenu)
        let pcapItem = try #require(exportSubmenu.item(withTitle: "Export as pcap"))
        invoke(pcapItem)
        #expect(exportedFormat == .pcap)

        let copySubmenu = try #require(sessionMenu.item(withTitle: "Copy")?.submenu)
        invoke(try #require(copySubmenu.item(withTitle: "Host")))
        #expect(copiedValue == "api.example.com")

        let tagSubmenu = try #require(sessionMenu.item(withTitle: "Tag")?.submenu)
        let redTagItem = try #require(tagSubmenu.item(withTitle: "Red"))
        #expect(redTagItem.state == .on)
        let blueTagItem = try #require(tagSubmenu.item(withTitle: "Blue"))
        #expect(blueTagItem.state == .off)
        invoke(blueTagItem)
        #expect(toggledTag == .blue)

        let nameAddrSubmenu = try #require(sessionMenu.item(withTitle: "Name Address")?.submenu)
        invoke(try #require(nameAddrSubmenu.items.first))
        #expect(namedAddress == "93.184.216.34")

        invoke(try #require(sessionMenu.item(withTitle: "Remove from View")))
        #expect(removedCount == 1)

        // Action row menu
        let actionMenu = SessionOutlineContextMenuBuilder.makeActionRowMenu(
            .init(
                sessionCount: 4,
                summary: "4 sessions, DNS → TLS",
                hasFirstSession: true,
                onInspectFirst: {},
                onCopySummary: {},
                onRemoveAll: {}
            ),
            bundle: .main
        )
        let actionTitles = actionMenu.items.filter { !$0.isSeparatorItem }.map(\.title)
        #expect(actionTitles == [
            "Inspect First Session",
            "Copy Summary",
            "Remove 4 Sessions from View",
        ])

        // Group row menus (.host and .process)
        let hostGroupMenu = SessionOutlineContextMenuBuilder.makeGroupRowMenu(
            .init(
                kind: .host,
                key: "api.example.com",
                sessionCount: 3,
                hasFirstSession: true,
                isValidHost: true,
                isHostPinned: true,
                isHostMuted: false,
                onInspectFirst: {},
                onCopyGroupName: {},
                onSelectHost: { _ in },
                onTogglePinHost: { _ in },
                onToggleMuteHost: { _ in },
                onSelectProcess: { _ in },
                onRemoveAll: {}
            ),
            bundle: .main
        )
        let hostGroupTitles = hostGroupMenu.items.filter { !$0.isSeparatorItem }.map(\.title)
        #expect(hostGroupTitles.contains("Inspect First Session"))
        #expect(hostGroupTitles.contains("Copy Group Name"))
        #expect(hostGroupTitles.contains("Show Sessions for api.example.com"))
        #expect(hostGroupTitles.contains("Unpin Host"))
        #expect(hostGroupTitles.contains("Mute Host"))
        #expect(hostGroupTitles.contains("Remove 3 Sessions from View"))

        let procGroupMenu = SessionOutlineContextMenuBuilder.makeGroupRowMenu(
            .init(
                kind: .process,
                key: "Safari",
                sessionCount: 2,
                hasFirstSession: true,
                isValidHost: true,
                isHostPinned: false,
                isHostMuted: false,
                onInspectFirst: {},
                onCopyGroupName: {},
                onSelectHost: { _ in },
                onTogglePinHost: { _ in },
                onToggleMuteHost: { _ in },
                onSelectProcess: { _ in },
                onRemoveAll: {}
            ),
            bundle: .main
        )
        let procGroupTitles = procGroupMenu.items.filter { !$0.isSeparatorItem }.map(\.title)
        #expect(procGroupTitles.contains("Show Sessions for Safari"))
        #expect(procGroupTitles.contains("Remove 2 Sessions from View"))
    }

    @Test("Live scroll notifications propagate to onLiveScrollStateChange and onUserNavigateHistory")
    func liveScrollNotificationPropagation() throws {
        _ = NSApplication.shared

        var liveScrollStates: [Bool] = []
        var navigateCount = 0
        let coordinator = NativeSessionOutlineTable.Coordinator(
            onSelectSessionID: { _ in },
            onSortCriteriaChange: { _ in },
            onColumnStateChange: { _ in },
            onLiveScrollStateChange: { liveScrollStates.append($0) },
            onUserNavigateHistory: { navigateCount += 1 },
            contextMenuBuilder: { _ in nil }
        )

        let (window, scrollView, _) = try mountOffscreen(coordinator: coordinator)
        defer {
            coordinator.tearDown()
            window.orderOut(nil)
        }

        NotificationCenter.default.post(name: NSScrollView.willStartLiveScrollNotification, object: scrollView)
        NotificationCenter.default.post(name: NSScrollView.didEndLiveScrollNotification, object: scrollView)

        #expect(liveScrollStates == [true, false])
        #expect(navigateCount == 1)
    }

    @Test("Header context menu toggles optional columns, resets sort order, and updates time header titles live")
    func headerMenuCustomizationAndLiveHeaderTitleRefresh() throws {
        _ = NSApplication.shared

        var latestColumnState = SessionOutlineColumnState.defaultState
        var latestSort: [SessionOutlineSortCriterion] = [
            SessionOutlineSortCriterion(column: .length, ascending: false),
        ]
        let coordinator = NativeSessionOutlineTable.Coordinator(
            onSelectSessionID: { _ in },
            onSortCriteriaChange: { latestSort = $0 },
            onColumnStateChange: { latestColumnState = $0 },
            onLiveScrollStateChange: nil,
            onUserNavigateHistory: {},
            contextMenuBuilder: { _ in nil }
        )

        let (window, _, outlineView) = try mountOffscreen(coordinator: coordinator)
        defer { window.orderOut(nil) }

        let rows = buildFlat([makeSession(host: "api.example.com", bytesUp: 100, bytesDown: 200)])
        coordinator.apply(
            rows: rows,
            isGrouped: false,
            timeFormat: .timeOfDay,
            selectedSessionID: nil,
            sortCriteria: latestSort,
            columnState: latestColumnState,
            revealToken: 0
        )

        let timeCol = try #require(outlineView.tableColumn(withIdentifier: NSUserInterfaceItemIdentifier("time")))
        #expect(timeCol.title == SessionTimeFormat.timeOfDay.columnTitle)

        // Switching timeFormat refreshes the NSTableColumn title immediately without reloadData
        let priorReloads = coordinator.fullReloadCount
        coordinator.apply(
            rows: rows,
            isGrouped: false,
            timeFormat: .utc,
            selectedSessionID: nil,
            sortCriteria: latestSort,
            columnState: latestColumnState,
            revealToken: 0
        )
        #expect(timeCol.title == SessionTimeFormat.utc.columnTitle)
        #expect(coordinator.fullReloadCount == priorReloads)

        // Populate header menu and verify customizable + optional columns + Reset Sort Order + Reset Columns
        let headerMenu = NSMenu()
        coordinator.populateHeaderMenu(headerMenu, bundle: .main)
        let titles = headerMenu.items.filter { !$0.isSeparatorItem }.map(\.title)
        #expect(titles.contains("Timeline"))
        #expect(titles.contains("Latency"))
        #expect(titles.contains("Reset Sort Order"))
        #expect(titles.contains("Reset Columns"))
        #expect(!titles.contains(""), "Status column must not be hideable via header menu")

        // Toggling Timeline marks it visible immediately
        let timelineItem = try #require(headerMenu.item(withTitle: "Timeline"))
        #expect(timelineItem.state == .off)
        invoke(timelineItem)
        #expect(latestColumnState.isVisible(.timeline))
        let timelineCol = try #require(outlineView.tableColumn(withIdentifier: NSUserInterfaceItemIdentifier("timeline")))
        #expect(!timelineCol.isHidden)

        // Reset Sort Order clears sortCriteria
        let resetSortItem = try #require(headerMenu.item(withTitle: "Reset Sort Order"))
        invoke(resetSortItem)
        #expect(latestSort.isEmpty)
        #expect(outlineView.sortDescriptors.isEmpty)
    }

    @Test("SessionPillView and .action SessionHostCellView measure unconstrained width and never truncate pills at width 200")
    func pillAndActionHostCellLayoutAvoidTruncation() throws {
        _ = NSApplication.shared

        // 1. Reused SessionPillView starting from a narrow frame must measure exact unconstrained width
        let pill = SessionPillView(font: SessionOutlineStyle.microFont, horizontalPadding: 5, verticalPadding: 1)
        pill.frame = NSRect(x: 0, y: 0, width: 12, height: 14)
        pill.layoutSubtreeIfNeeded()

        for text in ["9 个会话", "causal", "HTTP/2", "Bonjour 服务"] {
            pill.configure(
                text: text,
                textColor: .labelColor,
                fillColor: NSColor.secondaryLabelColor.withAlphaComponent(0.14),
                font: SessionOutlineStyle.badgeFont
            )
            let unconstrained = measureSingleLineTextField(pill.label)
            let intrinsic = pill.intrinsicContentSize
            #expect(intrinsic.width >= ceil(unconstrained.width) + 12)

            pill.frame = NSRect(origin: .zero, size: intrinsic)
            pill.layoutSubtreeIfNeeded()
            #expect(pill.label.frame.width >= ceil(unconstrained.width))
            #expect(
                pill.label.cell?.expansionFrame(withFrame: pill.label.bounds, in: pill.label) == .zero,
                "SessionPillView truncated '\(text)' at intrinsic width \(intrinsic.width)"
            )
        }

        // 2. Reused SessionHostCellView for an .action row laid out at width 200 gives both pills full unconstrained width
        let sessions = (0 ..< 9).map { index in
            makeSession(host: "www.wikipedia.org", bytesUp: 100, bytesDown: 200, offsetSeconds: Double(index) * 0.1)
        }
        let activity = Activity(
            sessions: sessions,
            evidence: [.dnsAnswerToConnection(name: "www.wikipedia.org", address: "198.18.22.123")]
        )
        let actionRow = try #require(buildGrouped([.action(activity)]).first)

        let cell = SessionHostCellView(frame: NSRect(x: 0, y: 0, width: 60, height: 24))
        cell.configure(with: actionRow, column: .host)
        cell.layoutSubtreeIfNeeded()

        cell.frame = NSRect(x: 0, y: 0, width: 200, height: 36)
        cell.layoutSubtreeIfNeeded()

        let firstPill = cell.firstPillView
        let secondPill = cell.secondPillView
        #expect(!firstPill.isHidden)
        #expect(!secondPill.isHidden)

        let firstUnconstrained = measureSingleLineTextField(firstPill.label)
        let secondUnconstrained = measureSingleLineTextField(secondPill.label)

        #expect(firstPill.frame.width == firstPill.intrinsicContentSize.width)
        #expect(secondPill.frame.width == secondPill.intrinsicContentSize.width)
        #expect(firstPill.frame.width >= ceil(firstUnconstrained.width))
        #expect(secondPill.frame.width >= ceil(secondUnconstrained.width))
        #expect(firstPill.label.frame.width >= ceil(firstUnconstrained.width))
        #expect(secondPill.label.frame.width >= ceil(secondUnconstrained.width))
        #expect(
            firstPill.label.cell?.expansionFrame(withFrame: firstPill.label.bounds, in: firstPill.label) == .zero,
            "Action row count pill truncated at width 200"
        )
        #expect(
            secondPill.label.cell?.expansionFrame(withFrame: secondPill.label.bounds, in: secondPill.label) == .zero,
            "Action row confidence pill truncated at width 200"
        )
        #expect(cell.primaryLabel.frame.maxX < firstPill.frame.minX)
        #expect(firstPill.frame.maxX < secondPill.frame.minX)
        #expect(secondPill.frame.maxX <= 200)
    }

    // MARK: Private

    private func mountOffscreen(
        coordinator: NativeSessionOutlineTable.Coordinator
    ) throws -> (NSWindow, SessionOutlineScrollView, SessionOutlineNSView) {
        let scrollView = coordinator.makeScrollView()
        let outlineView = try #require(coordinator.outlineView)
        let frame = NSRect(x: 0, y: 0, width: 1_000, height: 600)
        let window = NSWindow(
            contentRect: frame,
            styleMask: [.titled],
            backing: .buffered,
            defer: false
        )
        scrollView.frame = frame
        window.contentView = scrollView
        window.layoutIfNeeded()
        return (window, scrollView, outlineView)
    }

    private func makeSession(
        host: String,
        bytesUp: Int,
        bytesDown: Int,
        latency: Double? = 12.5,
        status: SessionStatus = .ok,
        offsetSeconds: TimeInterval = 0
    ) -> SessionSummary {
        SessionSummary(
            id: UUID(),
            startTime: Date(timeIntervalSince1970: 1_700_000_000 + offsetSeconds),
            duration: 0.25,
            processName: "Safari",
            host: host,
            sourceEndpoint: "10.0.0.2:50000",
            destinationEndpoint: "93.184.216.34:443",
            protocolStack: [.tcp, .tls],
            status: status,
            latencyMilliseconds: latency,
            bytesUp: bytesUp,
            bytesDown: bytesDown,
            sni: host
        )
    }

    private func buildFlat(_ sessions: [SessionSummary]) -> [SessionOutlineRowModel] {
        SessionOutlineRowModel.buildFlatRows(
            sessions: sessions,
            sortCriteria: [],
            timeFormat: .timeOfDay,
            captureStart: sessions.first?.startTime,
            timelineSpan: nil,
            visibleOptionalColumns: [],
            noteIDs: [],
            tagsBySessionID: [:],
            displayHostForSession: \.host,
            classifiedSourceForSession: { session in
                ClassifiedSessionSource(
                    category: .app,
                    filterKey: session.processName ?? "Safari",
                    title: session.processName ?? "Safari",
                    subtitle: nil,
                    tableLabel: session.processName ?? "Safari",
                    tableDetail: nil,
                    symbolName: "app.badge",
                    childTarget: nil
                )
            }
        )
    }

    private func buildGrouped(_ rows: [SessionRow]) -> [SessionOutlineRowModel] {
        SessionOutlineRowModel.buildGroupedRows(
            rows: rows,
            timeFormat: .timeOfDay,
            captureStart: nil,
            displayHostForSession: \.host,
            classifiedSourceForSession: { session in
                ClassifiedSessionSource(
                    category: .app,
                    filterKey: session.processName ?? "Safari",
                    title: session.processName ?? "Safari",
                    subtitle: nil,
                    tableLabel: session.processName ?? "Safari",
                    tableDetail: nil,
                    symbolName: "app.badge",
                    childTarget: nil
                )
            }
        )
    }

    private func invoke(_ item: NSMenuItem) {
        guard let target = item.target as? NSObject, let action = item.action else {
            Issue.record("Menu item \(item.title) missing target/action")
            return
        }
        _ = target.perform(action, with: item)
    }
}
