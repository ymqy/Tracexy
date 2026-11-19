import AppKit
import Foundation

// MARK: - SessionOutlineColumnID

/// Typed identifiers for every standard and optional column in the native
/// `NSOutlineView` session table.
///
/// The declaration order in `allCases` is the canonical column order, keeping
/// `latency` immediately between `length` and `status` in both flat and grouped
/// views.
nonisolated enum SessionOutlineColumnID: String, CaseIterable, Codable, Hashable, Sendable, Identifiable {
    case time
    case source
    case destination
    case host
    case client
    case protocolKind = "protocol"
    case length
    case latency
    case status
    case summary

    // Optional columns (hidden by default; flat table only)
    case timeline
    case serverName
    case duration
    case bytesUp
    case bytesDown
    case protocolStack
    case tcpCompleteness

    // MARK: Internal

    nonisolated static let standardColumns: [SessionOutlineColumnID] = [
        .time,
        .source,
        .destination,
        .host,
        .client,
        .protocolKind,
        .length,
        .latency,
        .status,
        .summary,
    ]

    nonisolated static let optionalColumns: [SessionOutlineColumnID] = [
        .timeline,
        .serverName,
        .duration,
        .bytesUp,
        .bytesDown,
        .protocolStack,
        .tcpCompleteness,
    ]

    nonisolated var id: String {
        rawValue
    }

    nonisolated var isOptional: Bool {
        switch self {
        case .timeline,
             .serverName,
             .duration,
             .bytesUp,
             .bytesDown,
             .protocolStack,
             .tcpCompleteness:
            true
        default:
            false
        }
    }

    nonisolated var isDefaultVisible: Bool {
        !isOptional
    }

    /// The narrow status glyph column is always shown and cannot be hidden via
    /// the header context menu (matching `.disabledCustomizationBehavior(.visibility)`).
    nonisolated var allowsVisibilityCustomization: Bool {
        self != .status
    }

    nonisolated var isSortable: Bool {
        self != .protocolStack
    }

    nonisolated var isFixedWidth: Bool {
        switch self {
        case .time,
             .protocolKind,
             .length,
             .latency,
             .status,
             .duration,
             .bytesUp,
             .bytesDown:
            true
        default:
            false
        }
    }

    nonisolated var minWidth: CGFloat {
        switch self {
        case .time: 64
        case .source: 110
        case .destination: 110
        case .host: 130
        case .client: 105
        case .protocolKind: 60
        case .length: 60
        case .latency: 60
        case .status: 20
        case .summary: 160
        case .timeline: 90
        case .serverName: 120
        case .duration: 64
        case .bytesUp: 60
        case .bytesDown: 60
        case .protocolStack: 90
        case .tcpCompleteness: 90
        }
    }

    nonisolated var idealWidth: CGFloat {
        switch self {
        case .time: 72
        case .source: 150
        case .destination: 150
        case .host: 215
        case .client: 175
        case .protocolKind: 72
        case .length: 72
        case .latency: 72
        case .status: 20
        case .summary: 280
        case .timeline: 140
        case .serverName: 180
        case .duration: 80
        case .bytesUp: 72
        case .bytesDown: 72
        case .protocolStack: 130
        case .tcpCompleteness: 110
        }
    }

    nonisolated var maxWidth: CGFloat? {
        switch self {
        case .status: 24
        default: nil
        }
    }

    nonisolated func title(timeFormat: SessionTimeFormat, bundle: Bundle) -> String {
        switch self {
        case .time: timeFormat.columnTitle(in: bundle)
        case .source: String(localized: "Source", bundle: bundle)
        case .destination: String(localized: "Destination", bundle: bundle)
        case .host: String(localized: "Host", bundle: bundle)
        case .client: String(localized: "Client", bundle: bundle)
        case .protocolKind: String(localized: "Protocol", bundle: bundle)
        case .length: String(localized: "Length", bundle: bundle)
        case .latency: String(localized: "Latency", bundle: bundle)
        case .status: ""
        case .summary: String(localized: "Summary", bundle: bundle)
        case .timeline: String(localized: "Timeline", bundle: bundle)
        case .serverName: String(localized: "Server Name", bundle: bundle)
        case .duration: String(localized: "Duration", bundle: bundle)
        case .bytesUp: String(localized: "Sent", bundle: bundle)
        case .bytesDown: String(localized: "Received", bundle: bundle)
        case .protocolStack: String(localized: "Protocols", bundle: bundle)
        case .tcpCompleteness: String(localized: "Completeness", bundle: bundle)
        }
    }

    func title(timeFormat: SessionTimeFormat) -> String {
        title(timeFormat: timeFormat, bundle: AppLanguage.currentLocalizedBundle())
    }
}

// MARK: - SessionOutlineSortCriterion

/// A single column sort rule for flat-mode session sorting.
nonisolated struct SessionOutlineSortCriterion: Equatable, Hashable, Codable, Sendable {
    let column: SessionOutlineColumnID
    let ascending: Bool

    var sortDescriptor: NSSortDescriptor {
        NSSortDescriptor(key: column.rawValue, ascending: ascending)
    }

    init(column: SessionOutlineColumnID, ascending: Bool) {
        self.column = column
        self.ascending = ascending
    }

    init?(sortDescriptor: NSSortDescriptor) {
        guard let key = sortDescriptor.key,
              let column = SessionOutlineColumnID(rawValue: key),
              column.isSortable
        else {
            return nil
        }
        self.column = column
        ascending = sortDescriptor.ascending
    }
}

// MARK: - SessionOutlineColumnState

/// Per-Project persisted visibility, column widths, and column order for the
/// native `NSOutlineView` session table.
nonisolated struct SessionOutlineColumnState: Equatable, Hashable, Codable, Sendable {
    // MARK: Lifecycle

    init(
        version: Int = 1,
        hiddenColumns: Set<SessionOutlineColumnID> = Set(SessionOutlineColumnID.optionalColumns),
        columnWidths: [SessionOutlineColumnID: Double] = [:],
        columnOrder: [SessionOutlineColumnID] = SessionOutlineColumnID.allCases
    ) {
        self.version = version
        var sanitizedHidden = hiddenColumns
        sanitizedHidden.remove(.status)
        self.hiddenColumns = sanitizedHidden
        self.columnWidths = columnWidths
        self.columnOrder = Self.normalizedOrder(columnOrder)
    }

    // MARK: Internal

    static let defaultState = SessionOutlineColumnState()

    var version: Int
    var hiddenColumns: Set<SessionOutlineColumnID>
    var columnWidths: [SessionOutlineColumnID: Double]
    var columnOrder: [SessionOutlineColumnID]

    func isVisible(_ column: SessionOutlineColumnID) -> Bool {
        guard column.allowsVisibilityCustomization else {
            return true
        }
        return !hiddenColumns.contains(column)
    }

    mutating func setVisible(_ visible: Bool, for column: SessionOutlineColumnID) {
        guard column.allowsVisibilityCustomization else {
            return
        }
        if visible {
            hiddenColumns.remove(column)
        } else {
            hiddenColumns.insert(column)
        }
    }

    mutating func toggleVisibility(for column: SessionOutlineColumnID) {
        setVisible(!isVisible(column), for: column)
    }

    func width(for column: SessionOutlineColumnID) -> CGFloat {
        let raw = columnWidths[column].map { CGFloat($0) } ?? column.idealWidth
        let clampedLow = max(column.minWidth, raw)
        if let maxWidth = column.maxWidth {
            return min(maxWidth, clampedLow)
        }
        return min(2_000, clampedLow)
    }

    mutating func setWidth(_ width: CGFloat, for column: SessionOutlineColumnID) {
        let clampedLow = max(column.minWidth, width)
        let clamped = column.maxWidth.map { min($0, clampedLow) } ?? min(2_000, clampedLow)
        columnWidths[column] = Double(clamped.rounded())
    }

    mutating func setOrder(_ order: [SessionOutlineColumnID]) {
        columnOrder = Self.normalizedOrder(order)
    }

    mutating func reset() {
        self = .defaultState
    }

    var visibleOptionalColumns: Set<SessionOutlineColumnID> {
        var result: Set<SessionOutlineColumnID> = []
        for column in SessionOutlineColumnID.optionalColumns where isVisible(column) {
            result.insert(column)
        }
        return result
    }

    /// Loads per-Project column customization from `defaults`.
    ///
    /// Legacy SwiftUI `TableColumnCustomization<SessionSummary>` payloads (or empty
    /// seed `Data()` blobs) cannot be decoded as `SessionOutlineColumnState` and
    /// fall back cleanly to `defaultState` (with `latency` visible and all optional
    /// columns hidden).
    @MainActor
    static func load(
        from defaults: UserDefaults,
        key: String? = nil
    ) -> SessionOutlineColumnState {
        let storageKey = key ?? ProjectScopedSettingsKeys.sessionTableColumns
        let visibilityMigrationKey = TracexyIdentity.current.defaultsKey("migrated.latencyColumnVisible.v1")
        let orderMigrationKey = TracexyIdentity.current.defaultsKey("migrated.latencyColumnOrder.v1")

        let data = defaults.data(forKey: storageKey)
        var decoded: SessionOutlineColumnState?
        if let data, !data.isEmpty {
            decoded = try? JSONDecoder().decode(SessionOutlineColumnState.self, from: data)
        }

        var state = decoded.map {
            SessionOutlineColumnState(
                version: $0.version,
                hiddenColumns: $0.hiddenColumns,
                columnWidths: $0.columnWidths,
                columnOrder: $0.columnOrder
            )
        } ?? .defaultState

        var didMigrate = false
        if !defaults.bool(forKey: visibilityMigrationKey) {
            state.setVisible(true, for: .latency)
            defaults.set(true, forKey: visibilityMigrationKey)
            didMigrate = true
        }
        if !defaults.bool(forKey: orderMigrationKey) {
            state.setOrder(SessionOutlineColumnID.allCases)
            defaults.set(true, forKey: orderMigrationKey)
            didMigrate = true
        }
        if didMigrate, decoded != nil {
            state.save(to: defaults, key: storageKey)
        }
        return state
    }

    @MainActor
    func save(
        to defaults: UserDefaults,
        key: String? = nil
    ) {
        let storageKey = key ?? ProjectScopedSettingsKeys.sessionTableColumns
        guard let data = try? JSONEncoder().encode(self) else {
            return
        }
        defaults.set(data, forKey: storageKey)
    }

    // MARK: Private

    private static func normalizedOrder(_ raw: [SessionOutlineColumnID]) -> [SessionOutlineColumnID] {
        var seen: Set<SessionOutlineColumnID> = []
        var result: [SessionOutlineColumnID] = []
        result.reserveCapacity(SessionOutlineColumnID.allCases.count)
        for column in raw where seen.insert(column).inserted {
            result.append(column)
        }
        for column in SessionOutlineColumnID.allCases where seen.insert(column).inserted {
            result.append(column)
        }
        return result
    }
}

typealias SessionOutlineColumnConfiguration = SessionOutlineColumnState

// MARK: - SessionOutlineLabelEmphasis

nonisolated enum SessionOutlineLabelEmphasis: Equatable, Hashable, Sendable {
    case primary
    case secondary
    case tertiary
}

// MARK: - SessionOutlineGroupKind

nonisolated enum SessionOutlineGroupKind: String, Equatable, Hashable, Sendable {
    case host
    case process
}

// MARK: - SessionOutlineClientPresentation

/// Hot client-cell presentation data, pre-resolved once per row so AppKit cell
/// reconfiguration never re-runs source classification during scrolling.
nonisolated struct SessionOutlineClientPresentation: Equatable, Hashable, Sendable {
    let label: String
    let tooltip: String
    let showsIcon: Bool
    let category: TrafficSourceCategory
    let filterKey: String
    let iconTitle: String
    let subtitle: String?
    let symbolName: String?
    let emphasis: SessionOutlineLabelEmphasis
}

// MARK: - SessionOutlineHostKindData

struct SessionRowHostData: Equatable, Hashable {
    let displayHost: String
    let localDiscoveryBadgeTitle: String?
    let localDiscoveryTooltip: String?
    let tags: [SessionTag]
    let hasNote: Bool

    var tooltip: String {
        localDiscoveryTooltip ?? displayHost
    }
}

struct ActionRowHostData: Equatable, Hashable {
    let title: String
    let sessionCount: Int
    let confidenceTitle: String
    let confidence: ConfidenceTier
    let isContested: Bool
    let evidenceLine: String
}

struct GroupRowHostData: Equatable, Hashable {
    let groupKind: SessionOutlineGroupKind
    let title: String
    let sessionCount: Int
}

enum SessionOutlineRowKind: Equatable, Hashable {
    case session(SessionRowHostData)
    case action(ActionRowHostData)
    case group(GroupRowHostData)
}

// MARK: - SessionOutlineRowModel

/// Lightweight hot presentation model for a single row in `NativeSessionOutlineTable`.
///
/// Cold fields on `SessionSummary` (`decodedLayers`, `representativeBytes`,
/// `dnsAnswers`, `dnsResolvedBindings`, `frameLengths`, `messageTally`) are
/// deliberately excluded so row diffing compares only visible scalars.
struct SessionOutlineRowModel: Identifiable, Equatable, Hashable {
    let id: UUID
    let representativeSessionID: UUID
    let kind: SessionOutlineRowKind

    let startTime: Date?
    let timeText: String
    let timeTooltip: String?
    let isUntimed: Bool

    let sourceEndpoint: String
    let destinationEndpoint: String

    let hostSortKey: String
    let clientSortKey: String
    let client: SessionOutlineClientPresentation

    let primaryProtocol: ProtocolKind?
    let totalBytes: Int
    let lengthText: String
    let latencyMilliseconds: Double?
    let latencyText: String
    let status: SessionStatus
    let summary: String

    // Optional flat-mode column presentation (populated for `.session` rows)
    let timelineFraction: ClosedRange<Double>?
    let timelineHelp: String
    let sni: String?
    let duration: TimeInterval?
    let durationText: String
    let bytesUp: Int
    let bytesUpText: String
    let bytesDown: Int
    let bytesDownText: String
    let protocolStackText: String
    let tcpCompletenessStage: String?
    let tcpCompletenessIsComplete: Bool
    let tcpCompletenessHelp: String?
    let tcpCompletenessLabel: String?
    let sortableCompleteness: Int

    let children: [SessionOutlineRowModel]

    var isActionRow: Bool {
        if case .action = kind {
            return true
        }
        return false
    }

    var preferredRowHeight: CGFloat {
        isActionRow ? 36 : 24
    }
}

// MARK: - Builders & Sorting

extension SessionOutlineRowModel {
    static var untimedTooltip: String {
        String(
            localized: "This capture file records no time for these frames.",
            bundle: AppLanguage.currentLocalizedBundle()
        )
    }

    /// Builds lightweight hot presentation rows for the flat session table,
    /// optionally sorting by `sortCriteria` (empty preserves stable capture order).
    static func buildFlatRows(
        sessions: [SessionSummary],
        sortCriteria: [SessionOutlineSortCriterion],
        timeFormat: SessionTimeFormat,
        captureStart: Date?,
        timelineSpan: ClosedRange<Date>?,
        visibleOptionalColumns: Set<SessionOutlineColumnID>,
        noteIDs: Set<UUID>,
        tagsBySessionID: [UUID: [SessionTag]],
        displayHostForSession: (SessionSummary) -> String,
        classifiedSourceForSession: (SessionSummary) -> ClassifiedSessionSource
    ) -> [SessionOutlineRowModel] {
        let ordered = sortCriteria.isEmpty
            ? sessions
            : sortSessions(sessions, using: sortCriteria)

        let includeTimeline = visibleOptionalColumns.contains(.timeline) && timelineSpan != nil
        let includeDuration = visibleOptionalColumns.contains(.duration)
        let includeBytesUp = visibleOptionalColumns.contains(.bytesUp)
        let includeBytesDown = visibleOptionalColumns.contains(.bytesDown)
        let includeProtocolStack = visibleOptionalColumns.contains(.protocolStack)
        let includeCompleteness = visibleOptionalColumns.contains(.tcpCompleteness)

        var rows: [SessionOutlineRowModel] = []
        rows.reserveCapacity(ordered.count)
        for session in ordered {
            rows.append(
                makeSessionRow(
                    session: session,
                    timeFormat: timeFormat,
                    captureStart: captureStart,
                    timelineSpan: includeTimeline ? timelineSpan : nil,
                    includeTimeline: includeTimeline,
                    includeDuration: includeDuration,
                    includeBytesUp: includeBytesUp,
                    includeBytesDown: includeBytesDown,
                    includeProtocolStack: includeProtocolStack,
                    includeCompleteness: includeCompleteness,
                    tags: tagsBySessionID[session.id] ?? [],
                    hasNote: noteIDs.contains(session.id),
                    displayHost: displayHostForSession(session),
                    classifiedSource: classifiedSourceForSession(session)
                )
            )
        }
        return rows
    }

    /// Builds lightweight hot presentation rows for grouped modes (`.action`,
    /// `.host`, `.process`), including nested child `.session` rows for expandable
    /// `.action` rows.
    static func buildGroupedRows(
        rows: [SessionRow],
        timeFormat: SessionTimeFormat,
        captureStart: Date?,
        displayHostForSession: (SessionSummary) -> String,
        classifiedSourceForSession: (SessionSummary) -> ClassifiedSessionSource
    ) -> [SessionOutlineRowModel] {
        var result: [SessionOutlineRowModel] = []
        result.reserveCapacity(rows.count)
        for row in rows {
            result.append(
                makeGroupedRow(
                    row: row,
                    timeFormat: timeFormat,
                    captureStart: captureStart,
                    displayHostForSession: displayHostForSession,
                    classifiedSourceForSession: classifiedSourceForSession
                )
            )
        }
        return result
    }

    /// Sorts `SessionSummary` values using typed `SessionOutlineSortCriterion`
    /// descriptors, matching `SessionSummary`'s column sort semantics exactly.
    static func sortSessions(
        _ sessions: [SessionSummary],
        using criteria: [SessionOutlineSortCriterion]
    ) -> [SessionSummary] {
        guard !criteria.isEmpty, sessions.count > 1 else {
            return sessions
        }
        return sessions.sorted { lhs, rhs in
            for criterion in criteria {
                let order = compareSessions(lhs, rhs, by: criterion.column)
                if order != .orderedSame {
                    return criterion.ascending
                        ? (order == .orderedAscending)
                        : (order == .orderedDescending)
                }
            }
            return false
        }
    }

    /// Sorts already-built flat `SessionOutlineRowModel` rows in place of re-sorting
    /// `SessionSummary` when needed in tests or pure-model transforms.
    static func sortRows(
        _ rows: [SessionOutlineRowModel],
        using criteria: [SessionOutlineSortCriterion]
    ) -> [SessionOutlineRowModel] {
        guard !criteria.isEmpty, rows.count > 1 else {
            return rows
        }
        return rows.sorted { lhs, rhs in
            for criterion in criteria {
                let order = compareRows(lhs, rhs, by: criterion.column)
                if order != .orderedSame {
                    return criterion.ascending
                        ? (order == .orderedAscending)
                        : (order == .orderedDescending)
                }
            }
            return false
        }
    }

    // MARK: Private

    private static func makeSessionRow(
        session: SessionSummary,
        timeFormat: SessionTimeFormat,
        captureStart: Date?,
        timelineSpan: ClosedRange<Date>?,
        includeTimeline: Bool,
        includeDuration: Bool,
        includeBytesUp: Bool,
        includeBytesDown: Bool,
        includeProtocolStack: Bool,
        includeCompleteness: Bool,
        tags: [SessionTag],
        hasNote: Bool,
        displayHost: String,
        classifiedSource: ClassifiedSessionSource
    ) -> SessionOutlineRowModel {
        let startTime = session.startTime
        let timeText = startTime.map { timeFormat.string(for: $0, captureStart: captureStart) } ?? "—"
        let isUntimed = startTime == nil
        let timeTooltip = isUntimed ? untimedTooltip : nil

        let discovery = LocalDiscoveryNameClassifier.classify(displayHost)
        let hostData = SessionRowHostData(
            displayHost: displayHost,
            localDiscoveryBadgeTitle: discovery?.badgeTitle,
            localDiscoveryTooltip: discovery?.tooltip,
            tags: tags,
            hasNote: hasNote
        )

        let client = makeSessionClientPresentation(classifiedSource)
        let totalBytes = session.totalBytes
        let latencyText = session.latencyMilliseconds.map { String(format: "%.1f ms", $0) } ?? "—"

        let timelineFraction: ClosedRange<Double>?
        let timelineHelp: String
        if includeTimeline {
            timelineFraction = SessionTimelineBar.fraction(of: session, in: timelineSpan)
            timelineHelp = timelineAccessibilityValue(session: session, span: timelineSpan)
        } else {
            timelineFraction = nil
            timelineHelp = ""
        }

        let durationText = includeDuration
            ? (session.duration.map { String(format: "%.3f s", $0) } ?? "—")
            : ""
        let bytesUpText = includeBytesUp ? ByteUnits.string(Int64(session.bytesUp)) : ""
        let bytesDownText = includeBytesDown ? ByteUnits.string(Int64(session.bytesDown)) : ""
        let protocolStackText = includeProtocolStack
            ? session.protocolStack.map(\.label).joined(separator: " ")
            : ""

        let tcpCompletenessStage: String?
        let tcpCompletenessIsComplete: Bool
        let tcpCompletenessHelp: String?
        let tcpCompletenessLabel: String?
        if includeCompleteness, session.protocolStack.contains(.tcp) {
            let completeness = session.tcpCompleteness
            tcpCompletenessStage = completeness.stageString
            tcpCompletenessIsComplete = completeness.isComplete
            tcpCompletenessLabel = completeness.label
            tcpCompletenessHelp = "\(completeness.label) — tcp.completeness == \(completeness.rawValue)"
        } else {
            tcpCompletenessStage = nil
            tcpCompletenessIsComplete = false
            tcpCompletenessHelp = nil
            tcpCompletenessLabel = nil
        }

        return SessionOutlineRowModel(
            id: session.id,
            representativeSessionID: session.id,
            kind: .session(hostData),
            startTime: startTime,
            timeText: timeText,
            timeTooltip: timeTooltip,
            isUntimed: isUntimed,
            sourceEndpoint: session.sourceEndpoint,
            destinationEndpoint: session.destinationEndpoint,
            hostSortKey: session.host,
            clientSortKey: session.sortableProcessName,
            client: client,
            primaryProtocol: session.primaryProtocol,
            totalBytes: totalBytes,
            lengthText: ByteUnits.string(Int64(totalBytes)),
            latencyMilliseconds: session.latencyMilliseconds,
            latencyText: latencyText,
            status: session.status,
            summary: session.infoSummary,
            timelineFraction: timelineFraction,
            timelineHelp: timelineHelp,
            sni: session.sni,
            duration: session.duration,
            durationText: durationText,
            bytesUp: session.bytesUp,
            bytesUpText: bytesUpText,
            bytesDown: session.bytesDown,
            bytesDownText: bytesDownText,
            protocolStackText: protocolStackText,
            tcpCompletenessStage: tcpCompletenessStage,
            tcpCompletenessIsComplete: tcpCompletenessIsComplete,
            tcpCompletenessHelp: tcpCompletenessHelp,
            tcpCompletenessLabel: tcpCompletenessLabel,
            sortableCompleteness: session.sortableCompleteness,
            children: []
        )
    }

    private static func makeGroupedRow(
        row: SessionRow,
        timeFormat: SessionTimeFormat,
        captureStart: Date?,
        displayHostForSession: (SessionSummary) -> String,
        classifiedSourceForSession: (SessionSummary) -> ClassifiedSessionSource
    ) -> SessionOutlineRowModel {
        switch row {
        case let .session(session):
            return makeSessionRow(
                session: session,
                timeFormat: timeFormat,
                captureStart: captureStart,
                timelineSpan: nil,
                includeTimeline: false,
                includeDuration: false,
                includeBytesUp: false,
                includeBytesDown: false,
                includeProtocolStack: false,
                includeCompleteness: false,
                tags: [],
                hasNote: false,
                displayHost: displayHostForSession(session),
                classifiedSource: classifiedSourceForSession(session)
            )

        case let .action(activity):
            let startTime = activity.startTime
            let timeText = startTime.map { timeFormat.string(for: $0, captureStart: captureStart) } ?? "—"
            let isUntimed = startTime == nil
            let latency = activity.sessions.compactMap(\.latencyMilliseconds).max()
            let latencyText = latency.map { String(format: "%.1f ms", $0) } ?? "—"
            let clientLabel = validProcessName(row.processName)
                ?? activity.sessions.first.map { classifiedSourceForSession($0).tableLabel }
                ?? "—"
            let childModels = activity.sessions.map { child in
                makeSessionRow(
                    session: child,
                    timeFormat: timeFormat,
                    captureStart: captureStart,
                    timelineSpan: nil,
                    includeTimeline: false,
                    includeDuration: false,
                    includeBytesUp: false,
                    includeBytesDown: false,
                    includeProtocolStack: false,
                    includeCompleteness: false,
                    tags: [],
                    hasNote: false,
                    displayHost: displayHostForSession(child),
                    classifiedSource: classifiedSourceForSession(child)
                )
            }
            let hostData = ActionRowHostData(
                title: activity.title,
                sessionCount: activity.sessions.count,
                confidenceTitle: activity.confidence.title,
                confidence: activity.confidence,
                isContested: activity.isContested,
                evidenceLine: evidenceLine(for: activity)
            )
            return SessionOutlineRowModel(
                id: activity.id,
                representativeSessionID: activity.sessions.first?.id ?? activity.id,
                kind: .action(hostData),
                startTime: startTime,
                timeText: timeText,
                timeTooltip: isUntimed ? untimedTooltip : nil,
                isUntimed: isUntimed,
                sourceEndpoint: row.sourceEndpoint,
                destinationEndpoint: row.destinationEndpoint,
                hostSortKey: activity.title,
                clientSortKey: clientLabel,
                client: SessionOutlineClientPresentation(
                    label: clientLabel,
                    tooltip: clientLabel,
                    showsIcon: false,
                    category: .unattributed,
                    filterKey: "",
                    iconTitle: "",
                    subtitle: nil,
                    symbolName: nil,
                    emphasis: .secondary
                ),
                primaryProtocol: row.primaryProtocol,
                totalBytes: row.totalBytes,
                lengthText: ByteUnits.string(Int64(row.totalBytes)),
                latencyMilliseconds: latency,
                latencyText: latencyText,
                status: row.status,
                summary: row.summary,
                timelineFraction: nil,
                timelineHelp: "",
                sni: nil,
                duration: nil,
                durationText: "",
                bytesUp: 0,
                bytesUpText: "",
                bytesDown: 0,
                bytesDownText: "",
                protocolStackText: "",
                tcpCompletenessStage: nil,
                tcpCompletenessIsComplete: false,
                tcpCompletenessHelp: nil,
                tcpCompletenessLabel: nil,
                sortableCompleteness: -1,
                children: childModels
            )

        case let .group(group):
            let startTime = group.startTime
            let timeText = startTime.map { timeFormat.string(for: $0, captureStart: captureStart) } ?? "—"
            let isUntimed = startTime == nil
            let latency = group.sessions.compactMap(\.latencyMilliseconds).max()
            let latencyText = latency.map { String(format: "%.1f ms", $0) } ?? "—"
            let clientLabel = validProcessName(row.processName)
                ?? group.sessions.first.map { classifiedSourceForSession($0).tableLabel }
                ?? "—"
            let groupKind: SessionOutlineGroupKind = group.kind == .host ? .host : .process
            let hostData = GroupRowHostData(
                groupKind: groupKind,
                title: group.title,
                sessionCount: group.sessions.count
            )
            return SessionOutlineRowModel(
                id: group.id,
                representativeSessionID: group.sessions.first?.id ?? group.id,
                kind: .group(hostData),
                startTime: startTime,
                timeText: timeText,
                timeTooltip: isUntimed ? untimedTooltip : nil,
                isUntimed: isUntimed,
                sourceEndpoint: row.sourceEndpoint,
                destinationEndpoint: row.destinationEndpoint,
                hostSortKey: group.title,
                clientSortKey: clientLabel,
                client: SessionOutlineClientPresentation(
                    label: clientLabel,
                    tooltip: clientLabel,
                    showsIcon: false,
                    category: .unattributed,
                    filterKey: "",
                    iconTitle: "",
                    subtitle: nil,
                    symbolName: nil,
                    emphasis: .secondary
                ),
                primaryProtocol: row.primaryProtocol,
                totalBytes: row.totalBytes,
                lengthText: ByteUnits.string(Int64(row.totalBytes)),
                latencyMilliseconds: latency,
                latencyText: latencyText,
                status: row.status,
                summary: row.summary,
                timelineFraction: nil,
                timelineHelp: "",
                sni: nil,
                duration: nil,
                durationText: "",
                bytesUp: 0,
                bytesUpText: "",
                bytesDown: 0,
                bytesDownText: "",
                protocolStackText: "",
                tcpCompletenessStage: nil,
                tcpCompletenessIsComplete: false,
                tcpCompletenessHelp: nil,
                tcpCompletenessLabel: nil,
                sortableCompleteness: -1,
                children: []
            )
        }
    }

    private static func makeSessionClientPresentation(
        _ src: ClassifiedSessionSource
    ) -> SessionOutlineClientPresentation {
        let isProcessBacked = src.category == .app
            || src.category == .cli
            || src.category == .thirdPartyService
            || src.category == .systemService
        let emphasis: SessionOutlineLabelEmphasis = if src.category == .unattributed {
            .tertiary
        } else if isProcessBacked {
            .primary
        } else {
            .secondary
        }
        let tooltip = src.tableDetail.map { "\(src.title) — \($0)" } ?? src.title
        return SessionOutlineClientPresentation(
            label: src.tableLabel,
            tooltip: tooltip,
            showsIcon: true,
            category: src.category,
            filterKey: src.filterKey,
            iconTitle: src.title,
            subtitle: src.subtitle,
            symbolName: src.symbolName,
            emphasis: emphasis
        )
    }

    private static func validProcessName(_ processName: String?) -> String? {
        guard let trimmed = processName?.trimmingCharacters(in: .whitespacesAndNewlines),
              !trimmed.isEmpty,
              trimmed != "—"
        else {
            return nil
        }
        return trimmed
    }

    private static func evidenceLine(for activity: Activity) -> String {
        if activity.isContested {
            return "Shared address — also claimed by \(activity.competingNames.joined(separator: ", "))"
        }
        return activity.evidence.map(\.summary).joined(separator: "; ")
    }

    private static func timelineAccessibilityValue(
        session: SessionSummary,
        span: ClosedRange<Date>?
    ) -> String {
        guard let span, let start = session.startTime else {
            return "No capture time"
        }
        let offset = start.timeIntervalSince(span.lowerBound)
        let duration = session.duration.map { String(format: "%.3f s", $0) } ?? "unknown duration"
        return String(format: "Starts %.3f s into the view, lasting ", offset) + duration
    }

    private static func compareComparable<T: Comparable>(_ lhs: T, _ rhs: T) -> ComparisonResult {
        if lhs < rhs {
            return .orderedAscending
        }
        if lhs > rhs {
            return .orderedDescending
        }
        return .orderedSame
    }

    private static func compareSessions(
        _ lhs: SessionSummary,
        _ rhs: SessionSummary,
        by column: SessionOutlineColumnID
    ) -> ComparisonResult {
        switch column {
        case .time,
             .timeline:
            compareComparable(lhs.sortableStartTime, rhs.sortableStartTime)
        case .source:
            compareComparable(lhs.sourceEndpoint, rhs.sourceEndpoint)
        case .destination:
            compareComparable(lhs.destinationEndpoint, rhs.destinationEndpoint)
        case .host:
            compareComparable(lhs.host, rhs.host)
        case .client:
            compareComparable(lhs.sortableProcessName, rhs.sortableProcessName)
        case .protocolKind:
            compareComparable(lhs.primaryProtocolLabel, rhs.primaryProtocolLabel)
        case .length:
            compareComparable(lhs.totalBytes, rhs.totalBytes)
        case .latency:
            compareComparable(lhs.sortableLatency, rhs.sortableLatency)
        case .status:
            compareComparable(lhs.statusRank, rhs.statusRank)
        case .summary:
            compareComparable(lhs.infoSummary, rhs.infoSummary)
        case .serverName:
            compareComparable(lhs.sortableServerName, rhs.sortableServerName)
        case .duration:
            compareComparable(lhs.sortableDuration, rhs.sortableDuration)
        case .bytesUp:
            compareComparable(lhs.bytesUp, rhs.bytesUp)
        case .bytesDown:
            compareComparable(lhs.bytesDown, rhs.bytesDown)
        case .protocolStack:
            .orderedSame
        case .tcpCompleteness:
            compareComparable(lhs.sortableCompleteness, rhs.sortableCompleteness)
        }
    }

    private static func compareRows(
        _ lhs: SessionOutlineRowModel,
        _ rhs: SessionOutlineRowModel,
        by column: SessionOutlineColumnID
    ) -> ComparisonResult {
        switch column {
        case .time,
             .timeline:
            compareComparable(
                lhs.startTime?.timeIntervalSince1970 ?? .infinity,
                rhs.startTime?.timeIntervalSince1970 ?? .infinity
            )
        case .source:
            compareComparable(lhs.sourceEndpoint, rhs.sourceEndpoint)
        case .destination:
            compareComparable(lhs.destinationEndpoint, rhs.destinationEndpoint)
        case .host:
            compareComparable(lhs.hostSortKey, rhs.hostSortKey)
        case .client:
            compareComparable(lhs.clientSortKey, rhs.clientSortKey)
        case .protocolKind:
            compareComparable(lhs.primaryProtocol?.label ?? "", rhs.primaryProtocol?.label ?? "")
        case .length:
            compareComparable(lhs.totalBytes, rhs.totalBytes)
        case .latency:
            compareComparable(
                lhs.latencyMilliseconds ?? .infinity,
                rhs.latencyMilliseconds ?? .infinity
            )
        case .status:
            compareComparable(statusRank(lhs.status), statusRank(rhs.status))
        case .summary:
            compareComparable(lhs.summary, rhs.summary)
        case .serverName:
            compareComparable(
                lhs.sni.flatMap { $0.isEmpty ? nil : $0 } ?? "\u{10FFFF}",
                rhs.sni.flatMap { $0.isEmpty ? nil : $0 } ?? "\u{10FFFF}"
            )
        case .duration:
            compareComparable(lhs.duration ?? .infinity, rhs.duration ?? .infinity)
        case .bytesUp:
            compareComparable(lhs.bytesUp, rhs.bytesUp)
        case .bytesDown:
            compareComparable(lhs.bytesDown, rhs.bytesDown)
        case .protocolStack:
            .orderedSame
        case .tcpCompleteness:
            compareComparable(lhs.sortableCompleteness, rhs.sortableCompleteness)
        }
    }

    private static func statusRank(_ status: SessionStatus) -> Int {
        switch status {
        case .ok: 0
        case .warning: 1
        case .error: 2
        }
    }
}

// MARK: - SessionOutlineStyle

/// Pure AppKit typography, semantic colors, and pre-rendered icon cache matching
/// `Theme.Typography`, `Theme.color(for:)`, and `SourceIconView` with zero
/// SwiftUI `NSHostingView` overhead.
enum SessionOutlineStyle {
    static let monoSmallFont = NSFont.monospacedDigitSystemFont(ofSize: 11, weight: .regular)
    static let monoFont = NSFont.monospacedSystemFont(ofSize: 11.5, weight: .regular)
    static let bodyFont = NSFont.systemFont(ofSize: 12, weight: .regular)
    static let badgeFont = NSFont.systemFont(ofSize: 10, weight: .semibold)
    static let microFont = NSFont.systemFont(ofSize: 10, weight: .regular)

    static func color(for kind: ProtocolKind) -> NSColor {
        switch kind {
        case .ethernet,
             .linuxCooked,
             .other: .secondaryLabelColor
        case .ipv4,
             .ipv6: .systemTeal
        case .arp: .systemBrown
        case .icmp,
             .icmpv6: .systemPink
        case .tcp: .systemBlue
        case .udp: .systemIndigo
        case .sctp: .systemPurple
        case .dns: .systemCyan
        case .tls: .systemPurple
        case .http: .systemGreen
        case .http2: .systemMint
        case .quic: .systemOrange
        case .websocket: .systemPink
        case .stun: .systemYellow
        case .mdns: .systemTeal
        case .dhcp: .systemBrown
        case .ntp: .systemGray
        case .tftp: .systemBrown
        case .ssh: .systemIndigo
        case .ftp,
             .smtp,
             .pop3,
             .imap: .systemBrown
        case .ssdp: .systemTeal
        case .sip: .systemPink
        case .smb: .systemBrown
        case .llmnr,
             .nbns: .systemTeal
        case .kerberos,
             .ldap: .systemIndigo
        case .gre,
             .vxlan: .secondaryLabelColor
        }
    }

    static func color(for status: SessionStatus) -> NSColor {
        switch status {
        case .ok: .systemGreen
        case .warning: .systemOrange
        case .error: .systemRed
        }
    }

    static func color(for tier: ConfidenceTier) -> NSColor {
        switch tier {
        case .causal: .systemGreen
        case .strong: .systemBlue
        case .weak: .systemOrange
        }
    }

    static func color(for tag: SessionTag) -> NSColor {
        switch tag {
        case .red: .systemRed
        case .orange: .systemOrange
        case .yellow: .systemYellow
        case .green: .systemGreen
        case .blue: .systemBlue
        case .purple: .systemPurple
        case .gray: .systemGray
        }
    }

    static func color(for category: TrafficSourceCategory) -> NSColor {
        switch category {
        case .app: .controlAccentColor
        case .cli: .systemIndigo
        case .thirdPartyService: .systemPurple
        case .systemService: .systemCyan
        case .lanDiscovery: .systemTeal
        case .kernelAndLink: .systemOrange
        case .unattributed: .secondaryLabelColor
        }
    }

    static func textColor(for emphasis: SessionOutlineLabelEmphasis) -> NSColor {
        switch emphasis {
        case .primary: .labelColor
        case .secondary: .secondaryLabelColor
        case .tertiary: .tertiaryLabelColor
        }
    }
}

// MARK: - SessionOutlineIconCache

/// Fast in-memory `NSImage` cache for 17x17 client squircle badges, app
/// monogram fallbacks, and compact cell symbols.
enum SessionOutlineIconCache {
    // MARK: Internal

    static func clientIcon(
        for client: SessionOutlineClientPresentation,
        appearance: NSAppearance?
    ) -> NSImage {
        let isDark = isDarkAppearance(appearance)
        let size: CGFloat = 17

        if client.category == .app {
            if AppIconView.isUnattributedPlaceholder(client.iconTitle) {
                return squircleSymbolIcon(
                    category: .unattributed,
                    symbolName: "questionmark",
                    size: size,
                    isDark: isDark
                )
            }
            if let resolved = AppIconView.resolvedIcon(for: client.iconTitle, size: size) {
                return resolved
            }
            return appMonogramIcon(name: client.iconTitle, size: size)
        }

        if client.category == .systemService,
           systemProcessesWithBundleIcons.contains(client.iconTitle)
        {
            let lookupName = client.iconTitle == "Control Center" ? "ControlCenter" : client.iconTitle
            if let resolved = AppIconView.resolvedIcon(for: lookupName, size: size) {
                return resolved
            }
        }

        let symbolName = SourceIconView.resolvedSymbolName(
            category: client.category,
            filterKey: client.filterKey,
            title: client.iconTitle,
            subtitle: client.subtitle,
            fallbackSymbol: client.symbolName
        )
        return squircleSymbolIcon(
            category: client.category,
            symbolName: symbolName,
            size: size,
            isDark: isDark
        )
    }

    static func smallSymbol(
        named name: String,
        color: NSColor,
        colorKey: String,
        pointSize: CGFloat = Theme.Icon.small,
        weight: NSFont.Weight = .regular
    ) -> NSImage? {
        let key = SymbolCacheKey(
            name: name,
            colorKey: colorKey,
            pointSize: Int((pointSize * 10).rounded()),
            weightRaw: Int((weight.rawValue * 100).rounded())
        )
        if let cached = symbolCache[key] {
            return cached
        }
        let config = NSImage.SymbolConfiguration(pointSize: pointSize, weight: weight)
            .applying(.init(paletteColors: [color]))
        guard let image = NSImage(systemSymbolName: name, accessibilityDescription: nil)?
            .withSymbolConfiguration(config)
        else {
            return nil
        }
        if symbolCache.count >= 256 {
            symbolCache.removeAll(keepingCapacity: true)
        }
        symbolCache[key] = image
        return image
    }

    // MARK: Private

    private struct BadgeCacheKey: Hashable {
        let category: TrafficSourceCategory
        let symbolName: String
        let isDark: Bool
    }

    private struct MonogramCacheKey: Hashable {
        let name: String
        let size: Int
    }

    private struct SymbolCacheKey: Hashable {
        let name: String
        let colorKey: String
        let pointSize: Int
        let weightRaw: Int
    }

    private static let systemProcessesWithBundleIcons: Set<String> = [
        "Finder",
        "Safari",
        "Dock",
        "ControlCenter",
        "Control Center",
        "NotificationCenter",
        "SystemUIServer",
        "Spotlight",
    ]

    private static var badgeCache: [BadgeCacheKey: NSImage] = [:]
    private static var monogramCache: [MonogramCacheKey: NSImage] = [:]
    private static var symbolCache: [SymbolCacheKey: NSImage] = [:]

    private static func isDarkAppearance(_ appearance: NSAppearance?) -> Bool {
        let effective = appearance ?? NSApp?.effectiveAppearance
        let match = effective?.bestMatch(from: [.darkAqua, .aqua])
        return match == .darkAqua
    }

    private static func squircleSymbolIcon(
        category: TrafficSourceCategory,
        symbolName: String,
        size: CGFloat,
        isDark: Bool
    ) -> NSImage {
        let key = BadgeCacheKey(category: category, symbolName: symbolName, isDark: isDark)
        if let cached = badgeCache[key] {
            return cached
        }

        let badgeSize = max(12, size - 2)
        let cornerRadius = (badgeSize * 0.26 * 2).rounded() / 2
        let tint = SessionOutlineStyle.color(for: category)
        let fillAlpha: CGFloat = if category == .unattributed {
            isDark ? 0.14 : 0.10
        } else {
            isDark ? 0.18 : 0.13
        }
        let strokeAlpha: CGFloat = if category == .unattributed {
            isDark ? 0.22 : 0.16
        } else {
            isDark ? 0.34 : 0.24
        }

        let image = NSImage(size: NSSize(width: size, height: size), flipped: false) { rect in
            let inset = (size - badgeSize) * 0.5
            let badgeRect = NSRect(x: inset, y: inset, width: badgeSize, height: badgeSize)
            let path = NSBezierPath(roundedRect: badgeRect, xRadius: cornerRadius, yRadius: cornerRadius)
            tint.withAlphaComponent(fillAlpha).setFill()
            path.fill()

            let strokeRect = badgeRect.insetBy(dx: 0.375, dy: 0.375)
            let strokePath = NSBezierPath(
                roundedRect: strokeRect,
                xRadius: max(1, cornerRadius - 0.375),
                yRadius: max(1, cornerRadius - 0.375)
            )
            strokePath.lineWidth = 0.75
            tint.withAlphaComponent(strokeAlpha).setStroke()
            strokePath.stroke()

            let symbolColor: NSColor = category == .unattributed ? .secondaryLabelColor : tint
            let config = NSImage.SymbolConfiguration(pointSize: 8.5, weight: .semibold)
                .applying(.init(paletteColors: [symbolColor]))
            if let symbol = NSImage(systemSymbolName: symbolName, accessibilityDescription: nil)?
                .withSymbolConfiguration(config)
            {
                let symbolSize = symbol.size
                let maxDim = badgeSize - 4
                let scale = min(1, min(maxDim / max(symbolSize.width, 1), maxDim / max(symbolSize.height, 1)))
                let drawWidth = symbolSize.width * scale
                let drawHeight = symbolSize.height * scale
                let drawRect = NSRect(
                    x: rect.midX - drawWidth * 0.5,
                    y: rect.midY - drawHeight * 0.5,
                    width: drawWidth,
                    height: drawHeight
                )
                symbol.draw(in: drawRect)
            }
            return true
        }

        if badgeCache.count >= 512 {
            badgeCache.removeAll(keepingCapacity: true)
        }
        badgeCache[key] = image
        return image
    }

    private static func appMonogramIcon(name: String, size: CGFloat) -> NSImage {
        let key = MonogramCacheKey(name: name, size: Int(size.rounded()))
        if let cached = monogramCache[key] {
            return cached
        }

        let badgeSize = (size * 0.86).rounded()
        let cornerRadius = (badgeSize * 0.26 * 2).rounded() / 2
        let hue = CGFloat(abs(name.hashValue) % 360) / 360.0
        let topColor = NSColor(calibratedHue: hue, saturation: 0.55, brightness: 0.85, alpha: 1.0)
        let bottomColor = NSColor(calibratedHue: hue, saturation: 0.65, brightness: 0.60, alpha: 1.0)
        let letter = String(name.prefix(1)).uppercased()

        let image = NSImage(size: NSSize(width: size, height: size), flipped: false) { rect in
            let inset = (size - badgeSize) * 0.5
            let badgeRect = NSRect(x: inset, y: inset, width: badgeSize, height: badgeSize)
            let path = NSBezierPath(roundedRect: badgeRect, xRadius: cornerRadius, yRadius: cornerRadius)
            NSGraphicsContext.saveGraphicsState()
            path.addClip()
            NSGradient(starting: topColor, ending: bottomColor)?.draw(in: badgeRect, angle: -45)
            NSGraphicsContext.restoreGraphicsState()

            let fontSize = max(9, badgeSize * 0.58)
            let baseFont = NSFont.systemFont(ofSize: fontSize, weight: .bold)
            let roundedFont = baseFont.fontDescriptor.withDesign(.rounded).flatMap {
                NSFont(descriptor: $0, size: fontSize)
            } ?? baseFont
            let attrs: [NSAttributedString.Key: Any] = [
                .font: roundedFont,
                .foregroundColor: NSColor.white,
            ]
            let attributed = NSAttributedString(string: letter, attributes: attrs)
            let textSize = attributed.size()
            let drawPoint = NSPoint(
                x: rect.midX - textSize.width * 0.5,
                y: rect.midY - textSize.height * 0.5
            )
            attributed.draw(at: drawPoint)
            return true
        }

        if monogramCache.count >= 512 {
            monogramCache.removeAll(keepingCapacity: true)
        }
        monogramCache[key] = image
        return image
    }
}

