import Foundation
import Testing
@testable import Tracexy

@Suite("Session table Latency column layout and UI chrome localization")
struct SessionUILocalizationTests {
    // MARK: Internal

    @Test("Latency column sits immediately between Length and Status/Summary in both flat and grouped tables")
    func latencyColumnOrderInBothTables() throws {
        // 1. Canonical standard column order (shared by flat and grouped modes):
        //    Length -> Latency -> Status -> Summary, and Latency is NOT optional.
        let standard = SessionOutlineColumnID.standardColumns
        let lengthIdx = try #require(standard.firstIndex(of: .length))
        let latencyIdx = try #require(standard.firstIndex(of: .latency))
        let statusIdx = try #require(standard.firstIndex(of: .status))
        let summaryIdx = try #require(standard.firstIndex(of: .summary))

        #expect(lengthIdx + 1 == latencyIdx)
        #expect(latencyIdx + 1 == statusIdx)
        #expect(statusIdx + 1 == summaryIdx)
        #expect(!SessionOutlineColumnID.optionalColumns.contains(.latency))
        #expect(SessionOutlineColumnID.latency.isDefaultVisible)
        #expect(!SessionOutlineColumnID.status.allowsVisibilityCustomization)

        // 2. Default column state keeps Latency visible and resets stale pre-move column order once.
        let suiteName = "tracexy.tests.latencyColumnOrder.\(UUID().uuidString)"
        let defaults = try #require(UserDefaults(suiteName: suiteName))
        defer { defaults.removePersistentDomain(forName: suiteName) }

        let stale = SessionOutlineColumnState(
            hiddenColumns: Set(SessionOutlineColumnID.optionalColumns).union([.latency]),
            columnOrder: [.time, .summary, .host, .latency]
        )
        stale.save(to: defaults)

        let migrated = SessionOutlineColumnState.load(from: defaults)
        #expect(migrated.isVisible(.latency))
        #expect(migrated.columnOrder == SessionOutlineColumnID.allCases)
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

    @Test("AppLanguage dynamic bundle switches source and local discovery classifiers without explicit bundle")
    @MainActor
    func zeroRestartClassifierLanguageSwitching() throws {
        let bundles = try makeCatalogBundles()
        defer { bundles.teardown() }

        let mdnsSrc = IPEndpoint(ip: "192.168.0.20", port: 5353)
        let mdnsDst = IPEndpoint(ip: "224.0.0.251", port: 5353)
        let mdnsSession = SessionSummary(
            id: UUID(),
            startTime: Date(timeIntervalSince1970: 1_700_000_000),
            duration: 0.05,
            processName: nil,
            host: "_companion-link._tcp.local",
            sourceEndpoint: mdnsSrc.display,
            destinationEndpoint: mdnsDst.display,
            sourceEndpointValue: mdnsSrc,
            destinationEndpointValue: mdnsDst,
            protocolStack: [.udp, .mdns],
            status: .ok,
            latencyMilliseconds: nil,
            bytesUp: 120,
            bytesDown: 0,
            packetsUp: 1,
            packetsDown: 0
        )
        let localIPs: Set<String> = ["192.168.0.130"]

        AppLanguage.withTemporaryLanguageForTesting("en", baseBundle: bundles.root) {
            #expect(TrafficSourceCategory.allCases.map(\.title) == [
                "Apps",
                "CLI Tools",
                "Third-Party Services",
                "System Services",
                "LAN & Discovery",
                "Kernel & Link",
                "Unattributed",
            ])

            let classified = SessionSourceClassifier.classify(mdnsSession, localIPs: localIPs)
            #expect(classified.category == .lanDiscovery)
            #expect(classified.tableLabel == "LAN · Bonjour")
            #expect(SessionSourceClassifier.displayTitle(forFilterKey: "kernel:arp") == "ARP Resolution")

            let grouped = SessionSourceClassifier.group(sessions: [mdnsSession], localIPs: localIPs)
            #expect(grouped.first?.items.first?.subtitle == "Local network service discovery (UDP 5353)")

            let continuity = LocalDiscoveryNameClassifier.classify("_companion-link._tcp.local")
            #expect(continuity?.badgeTitle == "Apple Continuity")
            #expect(continuity?.detailTitle == "Apple Continuity & Companion Link")

            let homeArpa = LocalDiscoveryNameClassifier.classify("home.arpa")
            #expect(homeArpa?.badgeTitle == "Home LAN")
            #expect(homeArpa?.detailTitle == "Residential home network domain (RFC 8375)")

            #expect(SidebarNavigatorMode.allCases.map(\.title) == ["Browse", "Focus", "Library"])
            #expect(SessionFilterCategory.security.title == "Findings")
            #expect(SessionFilterCategory.errors.title == "Errors")
            #expect(SessionSearchField.allFields.displayName == "All Fields")
            #expect(ByteUnits.string(684) == "684 bytes")
        }

        AppLanguage.withTemporaryLanguageForTesting("zh-Hans", baseBundle: bundles.root) {
            #expect(TrafficSourceCategory.allCases.map(\.title) == [
                "应用",
                "命令行工具",
                "第三方服务",
                "系统服务",
                "局域网邻机与广播",
                "内核与基础协议",
                "未归属",
            ])

            let classified = SessionSourceClassifier.classify(mdnsSession, localIPs: localIPs)
            #expect(classified.category == .lanDiscovery)
            #expect(classified.tableLabel == "局域网 · Bonjour")
            #expect(SessionSourceClassifier.displayTitle(forFilterKey: "kernel:arp") != "ARP Resolution")

            let grouped = SessionSourceClassifier.group(sessions: [mdnsSession], localIPs: localIPs)
            #expect(grouped.first?.items.first?.subtitle != "Local network service discovery (UDP 5353)")

            let continuity = LocalDiscoveryNameClassifier.classify("_companion-link._tcp.local")
            #expect(continuity?.badgeTitle == "Apple 连续互通")
            #expect(continuity?.detailTitle == "Apple 连续互通与设备协同")

            let homeArpa = LocalDiscoveryNameClassifier.classify("home.arpa")
            #expect(homeArpa?.badgeTitle == "家庭局域网")
            #expect(homeArpa?.detailTitle == "家庭局域网保留域 (RFC 8375)")

            #expect(SidebarNavigatorMode.allCases.map(\.title) == ["浏览", "焦点", "资料库"])
            #expect(SessionFilterCategory.security.title == "诊断发现")
            #expect(SessionFilterCategory.errors.title == "错误")
            #expect(SessionSearchField.allFields.displayName == "全部字段")
            #expect(ByteUnits.string(684) == "684字节")
        }

        #expect(AppLanguage.currentLocalizedBundle() == .main)
    }

    @Test("Switching from custom language override back to System Default resolves host system localization live")
    @MainActor
    func customOverrideToSystemDefaultResolvesHostLanguageLive() throws {
        let bundles = try makeCatalogBundles()
        defer { bundles.teardown() }

        AppLanguage.withTemporaryLanguageForTesting("en", baseBundle: bundles.root) {
            #expect(AppLanguage.currentLocalizedBundle() == bundles.en)
            #expect(AppLanguage.english.localeOverride?.identifier == "en")
            #expect(AppLanguage.system.title == "System Default")

            // Switching from custom `"en"` back to `"system"` under a Chinese host OS
            // must resolve both the `.lproj` bundle and SwiftUI `localeOverride` to `zh-Hans`.
            AppLanguage.withTemporaryLanguageForTesting(
                "system",
                baseBundle: bundles.root,
                systemLanguages: ["zh-Hans-CN", "en-US"]
            ) {
                #expect(AppLanguage.currentLocalizedBundle() == bundles.zhHans)
                #expect(AppLanguage.system.localeOverride?.identifier == "zh-Hans")
                #expect(AppLanguage.currentLocaleOverride()?.identifier == "zh-Hans")
                #expect(AppLanguage.system.title == "跟随系统")
                #expect(SidebarItem.sessions.title == "会话")
            }

            // Switching to `"system"` under a Vietnamese host OS must resolve to `vi`.
            AppLanguage.withTemporaryLanguageForTesting(
                "system",
                baseBundle: bundles.root,
                systemLanguages: ["vi-VN"]
            ) {
                #expect(AppLanguage.currentLocalizedBundle() == bundles.vi)
                #expect(AppLanguage.system.localeOverride?.identifier == "vi")
                #expect(AppLanguage.currentLocaleOverride()?.identifier == "vi")
                #expect(AppLanguage.system.title == "Mặc định hệ thống")
                #expect(SidebarItem.sessions.title == "Phiên")
            }

            // Nested scope exit restores outer `"en"` state cleanly.
            #expect(AppLanguage.currentLocalizedBundle() == bundles.en)
            #expect(AppLanguage.system.localeOverride == nil)
        }

        // Outer scope exit restores test-safe defaults cleanly.
        #expect(AppLanguage.currentLocalizedBundle() == .main)
        #expect(AppLanguage.system.localeOverride == nil)
        #expect(AppLanguage.currentLocaleOverride() == nil)
    }

    @Test("Firewall rules, checksum validation, and tool models switch languages dynamically without restart")
    @MainActor
    func toolModelsDynamicLanguageSwitching() throws {
        let bundles = try makeCatalogBundles()
        defer { bundles.teardown() }

        AppLanguage.withTemporaryLanguageForTesting("en", baseBundle: bundles.root) {
            #expect(FirewallProduct.pf.title == "Packet Filter (pf)")
            #expect(FirewallProduct.ciscoACL.title == "Cisco IOS access list")
            #expect(FirewallProduct.windows.title == "Windows Firewall (netsh)")
            #expect(FirewallRuleScope.allCases.map(\.title) == [
                "Source address",
                "Destination address",
                "Destination port",
                "Both addresses and the port",
            ])
            #expect(ChecksumStatus.correct.note == "[correct]")
            #expect(ChecksumStatus.partial.note == "[partial, likely checksum offload]")
            #expect(ChecksumStatus.incorrect(expected: 0x1A2B).note == "[incorrect, should be 0x1a2b]")
            #expect(ChecksumStatus.incorrect32(expected: 0x1234_5678).note == "[incorrect, should be 0x12345678]")
            #expect(ChecksumStatus.notPresent.note == "[not present]")
            #expect(ChecksumStatus.unverified.note == "[unverified, not fully captured]")
        }

        AppLanguage.withTemporaryLanguageForTesting("zh-Hans", baseBundle: bundles.root) {
            #expect(FirewallProduct.pf.title == "Packet Filter (pf)")
            #expect(FirewallProduct.ciscoACL.title == "Cisco IOS 访问控制列表")
            #expect(FirewallProduct.windows.title == "Windows 防火墙 (netsh)")
            #expect(FirewallRuleScope.allCases.map(\.title) == [
                "源地址",
                "目标地址",
                "目标端口",
                "双方地址与端口",
            ])
            #expect(ChecksumStatus.correct.note == "[正确]")
            #expect(ChecksumStatus.partial.note == "[不完整，可能启用了校验和卸载]")
            #expect(ChecksumStatus.incorrect(expected: 0x1A2B).note == "[错误，应为 0x1a2b]")
            #expect(ChecksumStatus.incorrect32(expected: 0x1234_5678).note == "[错误，应为 0x12345678]")
            #expect(ChecksumStatus.notPresent.note == "[不存在]")
            #expect(ChecksumStatus.unverified.note == "[未验证，未完整捕获]")
        }

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
        let vi: Bundle
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

        for language in ["en", "zh-Hans", "vi"] {
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
              let zhBundle = Bundle(url: tempDir.appendingPathComponent("zh-Hans.lproj", isDirectory: true)),
              let viBundle = Bundle(url: tempDir.appendingPathComponent("vi.lproj", isDirectory: true)) else
        {
            try? FileManager.default.removeItem(at: tempDir)
            throw CatalogError.bundleCreationFailed
        }

        return CatalogBundles(
            root: rootBundle,
            en: enBundle,
            zhHans: zhBundle,
            vi: viBundle,
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
