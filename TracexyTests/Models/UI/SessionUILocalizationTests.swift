import Foundation
import Testing
@testable import Tracexy

@Suite("Session table Latency column layout and UI chrome localization")
struct SessionUILocalizationTests {
    // MARK: Internal

    @Test("Latency column sits immediately between Length and Status/Summary in both flat and grouped tables")
    func latencyColumnOrderInBothTables() throws {
        let source = try readProjectFile("Tracexy/Views/Sessions/SessionCenterView.swift")

        // 1. Flat table: Length -> Latency -> Status -> Summary -> optionalColumns,
        //    and Latency is no longer buried inside optionalColumns.
        let flatStart = try #require(source.range(of: "private func sessionTable(")?.lowerBound)
        let groupedStart = try #require(source.range(of: "private func groupedTable(")?.lowerBound)
        let optionalStart = try #require(source.range(of: "private func optionalColumns(")?.lowerBound)
        let loadStart = try #require(source.range(of: "private func loadColumnCustomization(")?.lowerBound)

        let flatSection = String(source[flatStart ..< groupedStart])
        let lengthInFlat = try #require(flatSection.range(of: ".customizationID(\"length\")")?.lowerBound)
        let latencyInFlat = try #require(flatSection.range(of: "TableColumn(\"Latency\", value: \\.sortableLatency)")?.lowerBound)
        let latencyIDInFlat = try #require(flatSection.range(of: ".customizationID(\"latency\")")?.lowerBound)
        let latencyVisibilityInFlat = try #require(flatSection.range(of: ".defaultVisibility(.automatic)")?.lowerBound)
        let statusInFlat = try #require(flatSection.range(of: ".customizationID(\"status\")")?.lowerBound)
        let summaryInFlat = try #require(flatSection.range(of: ".customizationID(\"summary\")")?.lowerBound)

        #expect(lengthInFlat < latencyInFlat)
        #expect(latencyInFlat < latencyIDInFlat)
        #expect(latencyIDInFlat < latencyVisibilityInFlat)
        #expect(latencyVisibilityInFlat < statusInFlat)
        #expect(statusInFlat < summaryInFlat)

        let optionalSection = String(source[optionalStart ..< loadStart])
        #expect(!optionalSection.contains("TableColumn(\"Latency\""))
        #expect(!optionalSection.contains(".customizationID(\"latency\")"))

        // 2. Grouped table: Length -> Latency -> Status -> Summary.
        let groupedEnd = try #require(source.range(of: "} rows: {")?.lowerBound)
        let groupedSection = String(source[groupedStart ..< groupedEnd])
        let lengthInGrouped = try #require(groupedSection.range(of: "TableColumn(\"Length\")")?.lowerBound)
        let latencyInGrouped = try #require(groupedSection.range(of: "TableColumn(\"Latency\")")?.lowerBound)
        let statusInGrouped = try #require(groupedSection.range(of: "TableColumn(\"\")")?.lowerBound)
        let summaryInGrouped = try #require(groupedSection.range(of: "TableColumn(\"Summary\")")?.lowerBound)

        #expect(lengthInGrouped < latencyInGrouped)
        #expect(latencyInGrouped < statusInGrouped)
        #expect(statusInGrouped < summaryInGrouped)

        // 3. Column customization preserves default visibility and resets stale pre-move column order once.
        let loadSection = String(source[loadStart...])
        #expect(loadSection.contains("customization[visibility: \"latency\"] = .visible"))
        #expect(loadSection.contains("customization.resetOrder()"))
    }

    @Test("SessionTimeFormat column and menu titles resolve cleanly in English and Simplified Chinese")
    func sessionTimeFormatLocalization() throws {
        let bundles = try makeCatalogBundles()
        defer { bundles.teardown() }

        #expect(SessionTimeFormat.allCases.map { $0.columnTitle(in: bundles.en) } == [
            "Time",
            "UTC",
            "Since Start",
        ])
        #expect(SessionTimeFormat.allCases.map { $0.columnTitle(in: bundles.zhHans) } == [
            "时间",
            "UTC",
            "自开始以来",
        ])

        #expect(SessionTimeFormat.allCases.map { $0.menuTitle(in: bundles.en) } == [
            "Time of Day",
            "Time of Day (UTC)",
            "Seconds Since Capture Start",
        ])
        #expect(SessionTimeFormat.allCases.map { $0.menuTitle(in: bundles.zhHans) } == [
            "当日时间",
            "当日时间 (UTC)",
            "自抓包开始以来的秒数",
        ])

        #expect(String(localized: "Latency", bundle: bundles.en) == "Latency")
        #expect(String(localized: "Latency", bundle: bundles.zhHans) == "延迟")
    }

    @Test("InspectorTab and ContextDockTab localize titles while preserving Hex as a technical term")
    func inspectorAndContextDockTabLocalization() throws {
        let bundles = try makeCatalogBundles()
        defer { bundles.teardown() }

        #expect(InspectorTab.allCases.map { $0.title(in: bundles.en) } == [
            "Timeline",
            "Evidence",
            "Ladder",
            "Frames",
            "Stream",
            "Layers",
            "Requests",
            "Payload",
            "Hex",
        ])
        #expect(InspectorTab.allCases.map { $0.title(in: bundles.zhHans) } == [
            "时间线",
            "证据",
            "时序图",
            "数据帧",
            "数据流",
            "协议层",
            "请求",
            "载荷",
            "Hex",
        ])

        #expect(ContextDockTab.allCases.map { $0.title(in: bundles.en) } == [
            "Details",
            "AI Assistant",
        ])
        #expect(ContextDockTab.allCases.map { $0.title(in: bundles.zhHans) } == [
            "详情",
            "AI 助手",
        ])
    }

    @Test("SessionStatusBarModel and HistoryFooterModel localize status text, telemetry chips, and tooltips")
    func footerStatusAndTelemetryLocalization() throws {
        let bundles = try makeCatalogBundles()
        defer { bundles.teardown() }

        // Center status hierarchy in English and Simplified Chinese.
        #expect(SessionStatusBarModel.statusText(
            surface: .sessionList, totalSessions: 0, visibleCount: 0, hasSelection: false, bundle: bundles.en
        ) == "No sessions")
        #expect(SessionStatusBarModel.statusText(
            surface: .sessionList, totalSessions: 0, visibleCount: 0, hasSelection: false, bundle: bundles.zhHans
        ) == "无会话")

        #expect(SessionStatusBarModel.statusText(
            surface: .sessionList, totalSessions: 1, visibleCount: 1, hasSelection: false, bundle: bundles.en
        ) == "1 session")
        #expect(SessionStatusBarModel.statusText(
            surface: .sessionList, totalSessions: 1, visibleCount: 1, hasSelection: false, bundle: bundles.zhHans
        ) == "1 个会话")

        #expect(SessionStatusBarModel.statusText(
            surface: .sessionList, totalSessions: 5, visibleCount: 5, hasSelection: false, bundle: bundles.en
        ) == "5 sessions")
        #expect(SessionStatusBarModel.statusText(
            surface: .sessionList, totalSessions: 5, visibleCount: 5, hasSelection: false, bundle: bundles.zhHans
        ) == "5 个会话")

        #expect(SessionStatusBarModel.statusText(
            surface: .sessionList, totalSessions: 5, visibleCount: 3, hasSelection: false, bundle: bundles.en
        ) == "3 of 5 sessions")
        #expect(SessionStatusBarModel.statusText(
            surface: .sessionList, totalSessions: 5, visibleCount: 3, hasSelection: false, bundle: bundles.zhHans
        ) == "3 / 5 个会话")

        #expect(SessionStatusBarModel.statusText(
            surface: .sessionList, totalSessions: 5, visibleCount: 5, hasSelection: true, bundle: bundles.en
        ) == "1 of 5 selected")
        #expect(SessionStatusBarModel.statusText(
            surface: .sessionList, totalSessions: 5, visibleCount: 5, hasSelection: true, bundle: bundles.zhHans
        ) == "已选 1 / 5")

        #expect(SessionStatusBarModel.statusText(
            surface: .sessionList, totalSessions: 5, visibleCount: 3, hasSelection: true, bundle: bundles.en
        ) == "1 selected, 3 of 5 shown")
        #expect(SessionStatusBarModel.statusText(
            surface: .sessionList, totalSessions: 5, visibleCount: 3, hasSelection: true, bundle: bundles.zhHans
        ) == "已选 1，显示 3 / 5")

        #expect(SessionStatusBarModel.statusText(
            surface: .history, totalSessions: 0, visibleCount: 0, hasSelection: false, bundle: bundles.zhHans
        ) == "无已保存会话")
        #expect(SessionStatusBarModel.statusText(
            surface: .history, totalSessions: 1, visibleCount: 1, hasSelection: false, bundle: bundles.zhHans
        ) == "1 个已保存会话")
        #expect(SessionStatusBarModel.statusText(
            surface: .history, totalSessions: 4, visibleCount: 4, hasSelection: false, bundle: bundles.zhHans
        ) == "4 个已保存会话")

        // Telemetry chips in English and Simplified Chinese.
        let loss = CaptureLoss(
            hasStatistics: true,
            totalDropped: 8,
            isMaterialLoss: true,
            helperDropCount: 4,
            retentionEvictionCount: 120
        )
        let enTelemetry = SessionStatusBarModel.telemetry(
            isCapturing: true,
            loss: loss,
            errorCount: 3,
            hasCaptureDuration: true,
            liveBytesPerSecond: 2_048,
            totalBytes: 4_096,
            bytesUp: 1_024,
            bytesDown: 3_072,
            attribution: (known: 7, total: 10),
            bundle: bundles.en
        )
        let zhTelemetry = SessionStatusBarModel.telemetry(
            isCapturing: true,
            loss: loss,
            errorCount: 3,
            hasCaptureDuration: true,
            liveBytesPerSecond: 2_048,
            totalBytes: 4_096,
            bytesUp: 1_024,
            bytesDown: 3_072,
            attribution: (known: 7, total: 10),
            bundle: bundles.zhHans
        )

        let enByKind = Dictionary(uniqueKeysWithValues: enTelemetry.map { ($0.kind, $0) })
        let zhByKind = Dictionary(uniqueKeysWithValues: zhTelemetry.map { ($0.kind, $0) })

        #expect(enByKind[.packetDrops]?.text == "8 dropped")
        #expect(zhByKind[.packetDrops]?.text == "已丢弃 8")
        #expect(zhByKind[.packetDrops]?.help == "丢包量显著——统计数值可能低于实际流量。")

        #expect(enByKind[.helperDrops]?.text == "4 helper drops")
        #expect(zhByKind[.helperDrops]?.text == "助手丢弃 4")

        #expect(enByKind[.sessionErrors]?.text == "3 session errors")
        #expect(zhByKind[.sessionErrors]?.text == "3 个会话错误")

        let zhSingleError = SessionStatusBarModel.telemetry(
            isCapturing: false,
            loss: CaptureLoss(
                hasStatistics: false, totalDropped: 0, isMaterialLoss: false,
                helperDropCount: 0, retentionEvictionCount: 0
            ),
            errorCount: 1,
            hasCaptureDuration: false,
            liveBytesPerSecond: nil,
            totalBytes: 0,
            bytesUp: 0,
            bytesDown: 0,
            bundle: bundles.zhHans
        ).first { $0.kind == .sessionErrors }
        #expect(zhSingleError?.text == "1 个会话错误")

        let totalFormatted = ByteUnits.string(4_096)
        #expect(enByKind[.totalBytes]?.text == "\(totalFormatted) total")
        #expect(zhByKind[.totalBytes]?.text == "总计 \(totalFormatted)")
        #expect(zhByKind[.totalBytes]?.help == "已归属会话字节数——各会话计入字节数之和，而非原始载荷大小。")

        #expect(enByKind[.attribution]?.text == "Process 7 of 10")
        #expect(zhByKind[.attribution]?.text == "进程已识别 7 / 10")

        #expect(enByKind[.retentionTruncation]?.text == "120 outside memory window")
        #expect(zhByKind[.retentionTruncation]?.text == "内存窗口外 120")

        // Every telemetry tooltip in Simplified Chinese must differ from its English source string.
        for kind in enByKind.keys {
            let enHelp = try #require(enByKind[kind]?.help)
            let zhHelp = try #require(zhByKind[kind]?.help)
            #expect(!zhHelp.isEmpty)
            #expect(zhHelp != enHelp)
        }

        // History footer status text.
        #expect(HistoryFooterModel.statusText(
            captureCount: 0, sessionCount: 0, hasMore: false, bundle: bundles.zhHans
        ) == "无已保存抓包")
        #expect(HistoryFooterModel.statusText(
            captureCount: 1, sessionCount: 1, hasMore: false, bundle: bundles.en
        ) == "1 capture, 1 session")
        #expect(HistoryFooterModel.statusText(
            captureCount: 1, sessionCount: 1, hasMore: false, bundle: bundles.zhHans
        ) == "1 个抓包, 1 个会话")
        #expect(HistoryFooterModel.statusText(
            captureCount: 100, sessionCount: 900, hasMore: true, bundle: bundles.zhHans
        ) == "100+ 个抓包, 900+ 个会话")
    }

    @Test("App subprocess roles and caller-scoped CLI annotations resolve Simplified Chinese translations")
    func appSubprocessAndCallerScopedCLILocalization() throws {
        let bundles = try makeCatalogBundles()
        defer { bundles.teardown() }

        let expectedZhHans: [(String.LocalizationValue, String)] = [
            ("App Main Process", "应用主进程"),
            ("App Helper Process", "应用内辅助进程"),
            ("Embedded CLI", "内嵌终端命令"),
            ("Interactive terminal", "终端交互执行"),
            ("System Call", "系统调用"),
            ("Direct system call", "系统直接调用"),
            ("Terminal", "终端"),
        ]
        for (key, expected) in expectedZhHans {
            #expect(String(localized: key, bundle: bundles.zhHans) == expected)
        }
    }

    @Test("RFC 8375 home.arpa local discovery strings localize cleanly in English and Simplified Chinese")
    func homeArpaLocalization() throws {
        let bundles = try makeCatalogBundles()
        defer { bundles.teardown() }

        let expected: [(String.LocalizationValue, String, String)] = [
            ("Home LAN", "Home LAN", "家庭局域网"),
            (
                "Residential home network domain (RFC 8375)",
                "Residential home network domain (RFC 8375)",
                "家庭局域网保留域 (RFC 8375)"
            ),
            (
                "Home network device hostname (RFC 8375)",
                "Home network device hostname (RFC 8375)",
                "家庭局域网设备主机名 (RFC 8375)"
            ),
        ]

        for (key, enExpected, zhExpected) in expected {
            #expect(String(localized: key, bundle: bundles.en) == enExpected)
            #expect(String(localized: key, bundle: bundles.zhHans) == zhExpected)
        }
    }

    @Test("AppLanguage dynamic bundle switches UI model strings in-process without restart")
    @MainActor
    func zeroRestartDynamicLanguageSwitching() throws {
        let bundles = try makeCatalogBundles()
        defer { bundles.teardown() }

        let loss = CaptureLoss(
            hasStatistics: true,
            totalDropped: 2,
            isMaterialLoss: true,
            helperDropCount: 1,
            retentionEvictionCount: 5
        )

        AppLanguage.withTemporaryLanguageForTesting("en", baseBundle: bundles.root) {
            #expect(InspectorTab.allCases.map(\.title) == [
                "Timeline",
                "Evidence",
                "Ladder",
                "Frames",
                "Stream",
                "Layers",
                "Requests",
                "Payload",
                "Hex",
            ])
            #expect(ContextDockTab.allCases.map(\.title) == ["Details", "AI Assistant"])
            #expect(SessionTimeFormat.allCases.map(\.columnTitle) == ["Time", "UTC", "Since Start"])
            #expect(SessionTimeFormat.allCases.map(\.menuTitle) == [
                "Time of Day",
                "Time of Day (UTC)",
                "Seconds Since Capture Start",
            ])
            #expect(FrameTimeFormat.sinceSessionStart.columnTitle == "Time")
            #expect(FrameTimeFormat.sinceSessionStart.menuTitle == "Seconds Since Session Start")
            #expect(FrameTimePrecision.seconds.title == "Seconds")
            #expect(SidebarItem.overview.title == "Overview")
            #expect(SidebarItem.sessions.title == "Sessions")
            #expect(SidebarSection.monitor.title == "Monitor")
            #expect(CaptureDisplayState.capturing.title == "Capturing")
            #expect(AppLanguage.system.title == "System Default")
            #expect(DefaultView.sessions.title == "Sessions")
            #expect(ByteUnits.binary.title == "Binary — KiB")
            #expect(CaptureFilterMode.all.title == "All traffic")
            #expect(SessionScopeAction.resetTitle == "Reset Session Filters")

            #expect(SessionStatusBarModel.statusText(
                surface: .sessionList,
                totalSessions: 5,
                visibleCount: 3,
                hasSelection: true
            ) == "1 selected, 3 of 5 shown")

            let enTelemetry = Dictionary(uniqueKeysWithValues: SessionStatusBarModel.telemetry(
                isCapturing: true,
                loss: loss,
                errorCount: 2,
                hasCaptureDuration: false,
                liveBytesPerSecond: nil,
                totalBytes: 0,
                bytesUp: 0,
                bytesDown: 0,
                attribution: (known: 3, total: 4)
            ).map { ($0.kind, $0.text) })
            #expect(enTelemetry[.packetDrops] == "2 dropped")
            #expect(enTelemetry[.helperDrops] == "1 helper drops")
            #expect(enTelemetry[.sessionErrors] == "2 session errors")
            #expect(enTelemetry[.attribution] == "Process 3 of 4")
            #expect(enTelemetry[.retentionTruncation] == "5 outside memory window")

            #expect(HistoryFooterModel.statusText(
                captureCount: 1,
                sessionCount: 1,
                hasMore: false
            ) == "1 capture, 1 session")
        }

        AppLanguage.withTemporaryLanguageForTesting("zh-Hans", baseBundle: bundles.root) {
            #expect(InspectorTab.allCases.map(\.title) == [
                "时间线",
                "证据",
                "时序图",
                "数据帧",
                "数据流",
                "协议层",
                "请求",
                "载荷",
                "Hex",
            ])
            #expect(ContextDockTab.allCases.map(\.title) == ["详情", "AI 助手"])
            #expect(SessionTimeFormat.allCases.map(\.columnTitle) == ["时间", "UTC", "自开始以来"])
            #expect(SessionTimeFormat.allCases.map(\.menuTitle) == [
                "当日时间",
                "当日时间 (UTC)",
                "自抓包开始以来的秒数",
            ])
            #expect(FrameTimeFormat.sinceSessionStart.columnTitle == "时间")
            #expect(FrameTimeFormat.sinceSessionStart.menuTitle == "自会话开始以来的秒数")
            #expect(FrameTimePrecision.seconds.title == "秒")
            #expect(SidebarItem.overview.title == "概览")
            #expect(SidebarItem.sessions.title == "会话")
            #expect(SidebarSection.monitor.title == "监控")
            #expect(CaptureDisplayState.capturing.title == "正在抓包")
            #expect(AppLanguage.system.title == "跟随系统")
            #expect(DefaultView.sessions.title == "会话")
            #expect(ByteUnits.binary.title == "二进制 — KiB")
            #expect(CaptureFilterMode.all.title == "全部流量")
            #expect(SessionScopeAction.resetTitle == "重置会话过滤器")

            #expect(SessionStatusBarModel.statusText(
                surface: .sessionList,
                totalSessions: 5,
                visibleCount: 3,
                hasSelection: true
            ) == "已选 1，显示 3 / 5")

            let zhTelemetry = Dictionary(uniqueKeysWithValues: SessionStatusBarModel.telemetry(
                isCapturing: true,
                loss: loss,
                errorCount: 2,
                hasCaptureDuration: false,
                liveBytesPerSecond: nil,
                totalBytes: 0,
                bytesUp: 0,
                bytesDown: 0,
                attribution: (known: 3, total: 4)
            ).map { ($0.kind, $0.text) })
            #expect(zhTelemetry[.packetDrops] == "已丢弃 2")
            #expect(zhTelemetry[.helperDrops] == "助手丢弃 1")
            #expect(zhTelemetry[.sessionErrors] == "2 个会话错误")
            #expect(zhTelemetry[.attribution] == "进程已识别 3 / 4")
            #expect(zhTelemetry[.retentionTruncation] == "内存窗口外 5")

            #expect(HistoryFooterModel.statusText(
                captureCount: 1,
                sessionCount: 1,
                hasMore: false
            ) == "1 个抓包, 1 个会话")
        }

        // Restored after temporary testing scope exits so default test isolation holds.
        #expect(AppLanguage.currentLocalizedBundle() == .main)
    }

    @Test("Hosted split views and main scene synchronize language changes live")
    func hostedSplitViewsPropagateLanguageOverride() throws {
        let app = try readProjectFile("Tracexy/TracexyApp.swift")
        let workspaceSplit = try readProjectFile("Tracexy/Views/Main/NativeWorkspaceSplitView.swift")
        let bottomSplit = try readProjectFile("Tracexy/Views/Main/NativeBottomInspectorSplitView.swift")

        #expect(app.contains(".onChange(of: language, initial: true)"))
        #expect(app.contains("AppLanguage.syncCurrentLanguage(newValue)"))

        for source in [workspaceSplit, bottomSplit] {
            #expect(source.contains("@AppStorage(SettingsKeys.language, store: TracexyIdentity.applicationDefaults)"))
            #expect(source.contains("AppLanguage.syncCurrentLanguage(language)"))
            #expect(source.contains(".appLocaleOverride(locale)"))
        }
    }

    // MARK: Private

    private enum CatalogError: Error {
        case rootNotFound
        case invalidCatalog
        case bundleCreationFailed
    }

    private struct CatalogBundles {
        let root: Bundle
        let en: Bundle
        let zhHans: Bundle
        let teardown: () -> Void
    }

    private func makeCatalogBundles() throws -> CatalogBundles {
        let root = try resolveProjectRoot()
        let xcstringsURL = root.appendingPathComponent("Tracexy/Localizable.xcstrings")
        let data = try Data(contentsOf: xcstringsURL)
        guard let catalog = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              catalog["sourceLanguage"] as? String == "en",
              let stringsMap = catalog["strings"] as? [String: [String: Any]] else
        {
            throw CatalogError.invalidCatalog
        }

        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("tracexy-i18n-tests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)

        for language in ["en", "zh-Hans"] {
            var dict: [String: String] = [:]
            for (key, entry) in stringsMap {
                if let locs = entry["localizations"] as? [String: Any],
                   let langObj = locs[language] as? [String: Any],
                   let unit = langObj["stringUnit"] as? [String: Any],
                   let state = unit["state"] as? String,
                   ["translated", "needs_review", "new"].contains(state),
                   let value = unit["value"] as? String
                {
                    dict[key] = value
                } else if language == "en" {
                    dict[key] = key
                }
            }
            let lprojURL = tempDir.appendingPathComponent("\(language).lproj", isDirectory: true)
            try FileManager.default.createDirectory(at: lprojURL, withIntermediateDirectories: true)
            let plistData = try PropertyListSerialization.data(
                fromPropertyList: dict,
                format: .binary,
                options: 0
            )
            try plistData.write(to: lprojURL.appendingPathComponent("Localizable.strings"))
        }

        guard let rootBundle = Bundle(url: tempDir),
              let enBundle = Bundle(url: tempDir.appendingPathComponent("en.lproj", isDirectory: true)),
              let zhBundle = Bundle(url: tempDir.appendingPathComponent("zh-Hans.lproj", isDirectory: true)) else
        {
            try? FileManager.default.removeItem(at: tempDir)
            throw CatalogError.bundleCreationFailed
        }

        return CatalogBundles(
            root: rootBundle,
            en: enBundle,
            zhHans: zhBundle,
            teardown: { try? FileManager.default.removeItem(at: tempDir) }
        )
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
            throw CatalogError.rootNotFound
        }
        url.deleteLastPathComponent()
        return url
    }
}
