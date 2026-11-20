import Foundation
import Testing
@testable import Tracexy

@Suite("WebKit & Safari Helper Attribution and App Classification")
struct WebKitSafariAttributionTests {
    // MARK: - Fixtures

    nonisolated private static let prebootSafariExec =
        ["", "System", "Volumes", "Preboot", "Cryptexes", "App", "System", "Applications", "Safari.app", "Contents", "MacOS", "Safari"]
            .joined(separator: "/")
    nonisolated private static let applicationsSafariExec = "/Applications/Safari.app/Contents/MacOS/Safari"
    nonisolated private static let safariHost = PktapHeader.SafariHostAppInfo(
        displayName: "Safari",
        executablePath: prebootSafariExec,
        bundleIdentifier: "com.apple.Safari"
    )
    nonisolated private static let webkitNetworkingExec =
        "/System/Library/Frameworks/WebKit.framework/Versions/A/XPCServices/"
            + "com.apple.WebKit.Networking.xpc/Contents/MacOS/com.apple.WebKit.Networking"
    nonisolated private static let webkitWebContentExec =
        "/System/Library/Frameworks/WebKit.framework/Versions/A/XPCServices/"
            + "com.apple.WebKit.WebContent.xpc/Contents/MacOS/com.apple.WebKit.WebContent"
    nonisolated private static let webkitGPUExec =
        "/System/Library/Frameworks/WebKit.framework/Versions/A/XPCServices/"
            + "com.apple.WebKit.GPU.xpc/Contents/MacOS/com.apple.WebKit.GPU"
    nonisolated private static let mailExec = "/System/Applications/Mail.app/Contents/MacOS/Mail"

    // MARK: - 1. Un-delegated WebKit XPC when Safari IS Running

    @Test("Promotes un-delegated com.apple.WebKit.Networking/.WebContent/.GPU to Safari when Safari is running")
    func promotesUndelegatedWebKitXPCToSafariWhenRunning() throws {
        let xpcCases: [(pid: Int32, path: String, leaf: String)] = [
            (7_101, Self.webkitNetworkingExec, "com.apple.WebKit.Networking"),
            (7_102, Self.webkitWebContentExec, "com.apple.WebKit.WebContent"),
            (7_103, Self.webkitGPUExec, "com.apple.WebKit.GPU"),
        ]

        for testCase in xpcCases {
            let parsed = makeParsed(
                process: "com.apple.WebKit",
                pid: testCase.pid,
                effectivePID: testCase.pid,
                interface: "lo0"
            )
            let resolved = PktapHeader.resolveAttribution(
                parsed: parsed,
                executablePathLookup: { $0 == testCase.pid ? testCase.path : nil },
                bsdProcessLookup: { $0 == testCase.pid ? (ppid: 1, uid: 501, hasTTY: false) : nil },
                displayNameFromPath: { PktapHeader.displayName(fromExecutablePath: $0) },
                bundleIdentifierFromPath: { path in path == testCase.path ? testCase.leaf : nil },
                outerMainExecutableFromAppPath: { _ in nil },
                runningSafariHostLookup: { Self.safariHost },
                safariBundleLookup: { nil }
            )
            #expect(resolved.processName == "Safari")
            #expect(resolved.provenance?.executablePath == Self.prebootSafariExec)
            #expect(resolved.provenance?.bundleIdentifier == "com.apple.Safari")
            #expect(resolved.provenance?.viaProcessName == testCase.leaf)
            #expect(resolved.provenance?.originProcessName == testCase.leaf)
            #expect(resolved.provenance?.callerKind == .app)
            #expect(resolved.provenance?.isKernelTask == false)
        }

        // Also verifies `AttributionCache` propagates Safari promotion and caches steady-state hits.
        var clock: UInt64 = 10_000_000_000
        var runningSafariCalls = 0
        let netPID: Int32 = 7_110
        var cache = PktapHeader.AttributionCache(
            nowNanoseconds: { clock },
            executablePathLookup: { $0 == netPID ? Self.webkitNetworkingExec : nil },
            bsdSnapshotLookup: { pid in
                guard pid == netPID else { return nil }
                return PktapHeader.BSDProcessSnapshot(
                    ppid: 1, uid: 501, hasTTY: false, startTimeSec: 1_700_050_000, startTimeUsec: 12
                )
            },
            displayNameFromPath: { PktapHeader.displayName(fromExecutablePath: $0) },
            bundleIdentifierFromPath: { $0 == Self.webkitNetworkingExec ? "com.apple.WebKit.Networking" : nil },
            outerMainExecutableFromAppPath: { _ in nil },
            runningSafariHostLookup: {
                runningSafariCalls += 1
                return Self.safariHost
            },
            safariBundleLookup: { nil }
        )
        let lo0Parsed = makeParsed(process: "com.apple.WebKit", pid: netPID, effectivePID: 0, interface: "lo0")
        let first = cache.resolve(parsed: lo0Parsed)
        #expect(first.processName == "Safari")
        #expect(first.provenance?.viaProcessName == "com.apple.WebKit.Networking")
        #expect(first.provenance?.bundleIdentifier == "com.apple.Safari")
        #expect(first.provenance?.executablePath == Self.prebootSafariExec)
        #expect(first.provenance?.callerKind == .app)

        // Cached packets within debounce window hit cache with zero extra lookups.
        for _ in 0 ..< 50 {
            clock += 1_000_000
            let hit = cache.resolve(parsed: lo0Parsed)
            #expect(hit == first)
        }
        #expect(runningSafariCalls == 1)

        // Truncated 16-char `pth_comm == "com.apple.WebKit"` with exited PID still attributes to Safari while running,
        // whereas a non-WebKit full executable path is NOT misclassified even if `pth_comm` were truncated.
        let exitedWebKit = makeParsed(process: "com.apple.WebKit", pid: 7_199, effectivePID: 0, interface: "en0")
        let exitedResolved = PktapHeader.resolveAttribution(
            parsed: exitedWebKit,
            executablePathLookup: { _ in nil },
            bsdProcessLookup: { _ in nil },
            runningSafariHostLookup: { Self.safariHost },
            safariBundleLookup: { nil }
        )
        #expect(exitedResolved.processName == "Safari")
        #expect(exitedResolved.provenance?.viaProcessName == "com.apple.WebKit")

        let unrelatedWithSameComm = PktapHeader.resolveAttribution(
            parsed: exitedWebKit,
            executablePathLookup: { $0 == 7_199 ? "/usr/local/bin/mytool" : nil },
            bsdProcessLookup: { _ in nil },
            displayNameFromPath: { PktapHeader.displayName(fromExecutablePath: $0) },
            bundleIdentifierFromPath: { _ in nil },
            runningSafariHostLookup: { Self.safariHost },
            safariBundleLookup: { nil }
        )
        #expect(unrelatedWithSameComm.processName == "mytool")
        #expect(unrelatedWithSameComm.provenance?.bundleIdentifier == nil)
    }

    @Test("RunningSafariLookupCache caches hits for 2s TTL and re-verifies PID in O(1) without rescanning proc_listallpids")
    func runningSafariLookupCacheAvoidsListAllPIDsStorm() {
        var clock: UInt64 = 1_000_000_000
        var listAllCalls = 0
        var pidPathCalls = 0
        let safariPID: Int32 = 4_200
        var execByPID: [Int32: String] = [
            100: "/usr/sbin/mDNSResponder",
            safariPID: Self.prebootSafariExec,
        ]

        var cache = PktapHeader.RunningSafariLookupCache(
            nowNanoseconds: { clock },
            ttlNanoseconds: 2_000_000_000,
            allPIDsLookup: {
                listAllCalls += 1
                return Array(execByPID.keys.sorted())
            },
            executablePathLookup: { pid in
                pidPathCalls += 1
                return execByPID[pid]
            }
        )

        // Initial miss scans `allPIDsLookup` once and discovers Safari.
        #expect(cache.resolve() == Self.safariHost)
        #expect(listAllCalls == 1)
        let callsAfterDiscovery = pidPathCalls

        // Steady-state calls inside 2s TTL incur zero syscalls.
        for _ in 0 ..< 100 {
            clock += 10_000_000
            #expect(cache.resolve() == Self.safariHost)
        }
        #expect(listAllCalls == 1)
        #expect(pidPathCalls == callsAfterDiscovery)

        // Crossing 2s TTL re-verifies cached Safari PID via O(1) `proc_pidpath` with ZERO `proc_listallpids` calls!
        clock += 2_000_000_000
        #expect(cache.resolve() == Self.safariHost)
        #expect(listAllCalls == 1)
        #expect(pidPathCalls == callsAfterDiscovery + 1)

        // When Safari exits and TTL expires, cache falls back to scanning and returns nil.
        execByPID.removeValue(forKey: safariPID)
        clock += 2_000_000_000
        #expect(cache.resolve() == nil)
        #expect(listAllCalls == 2)
    }

    // MARK: - 2. Explicit Delegation Preservation (Mail.app)

    @Test("Preserves explicit effectivePID delegation to Mail.app even while Safari is running")
    func preservesEffectivePIDDelegationToMailWhileSafariRunning() {
        let webkitPID: Int32 = 7_201
        let mailPID: Int32 = 7_202
        let parsed = makeParsed(
            process: "com.apple.WebKit",
            pid: webkitPID,
            effectivePID: mailPID,
            effectiveProcess: "Mail",
            interface: "en0"
        )

        let resolved = PktapHeader.resolveAttribution(
            parsed: parsed,
            executablePathLookup: { pid in
                switch pid {
                case webkitPID: Self.webkitNetworkingExec
                case mailPID: Self.mailExec
                default: nil
                }
            },
            bsdProcessLookup: { pid in
                switch pid {
                case webkitPID, mailPID: (ppid: 1, uid: 501, hasTTY: false)
                default: nil
                }
            },
            displayNameFromPath: { path in
                if path == Self.mailExec { return "Mail" }
                return PktapHeader.displayName(fromExecutablePath: path)
            },
            bundleIdentifierFromPath: { path in
                switch path {
                case Self.mailExec: "com.apple.mail"
                case Self.webkitNetworkingExec: "com.apple.WebKit.Networking"
                default: nil
                }
            },
            outerMainExecutableFromAppPath: { appPath in
                appPath == "/System/Applications/Mail.app" ? "Mail" : nil
            },
            runningSafariHostLookup: { Self.safariHost },
            safariBundleLookup: { Self.safariHost }
        )

        #expect(resolved.processName == "Mail")
        #expect(resolved.provenance?.executablePath == Self.mailExec)
        #expect(resolved.provenance?.bundleIdentifier == "com.apple.mail")
        #expect(resolved.provenance?.viaProcessName == "com.apple.WebKit.Networking")
        #expect(resolved.provenance?.originProcessName == "Mail")

        // When a distinct `effectivePID` exited and had no `effectiveProcess`, do NOT hijack it to Safari.
        let exitedDelegatorParsed = makeParsed(
            process: "com.apple.WebKit",
            pid: webkitPID,
            effectivePID: 9_999,
            effectiveProcess: "",
            interface: "en0"
        )
        let unresolvedDelegator = PktapHeader.resolveAttribution(
            parsed: exitedDelegatorParsed,
            executablePathLookup: { $0 == webkitPID ? Self.webkitNetworkingExec : nil },
            bsdProcessLookup: { $0 == webkitPID ? (ppid: 1, uid: 501, hasTTY: false) : nil },
            displayNameFromPath: { PktapHeader.displayName(fromExecutablePath: $0) },
            bundleIdentifierFromPath: { $0 == Self.webkitNetworkingExec ? "com.apple.WebKit.Networking" : nil },
            outerMainExecutableFromAppPath: { _ in nil },
            runningSafariHostLookup: { Self.safariHost },
            safariBundleLookup: { Self.safariHost }
        )
        #expect(unresolvedDelegator.processName == "com.apple.WebKit.Networking")
        #expect(unresolvedDelegator.provenance?.bundleIdentifier == "com.apple.WebKit.Networking")
    }

    // MARK: - 3. Un-delegated WebKit XPC when Safari is NOT Running

    @Test("Leaves un-delegated com.apple.WebKit.Networking untouched when Safari is not running")
    func leavesWebKitNetworkingUntouchedWhenSafariNotRunning() {
        let webkitPID: Int32 = 7_301
        let parsed = makeParsed(
            process: "com.apple.WebKit",
            pid: webkitPID,
            effectivePID: webkitPID,
            interface: "en0"
        )

        let resolved = PktapHeader.resolveAttribution(
            parsed: parsed,
            executablePathLookup: { $0 == webkitPID ? Self.webkitNetworkingExec : nil },
            bsdProcessLookup: { $0 == webkitPID ? (ppid: 1, uid: 501, hasTTY: false) : nil },
            displayNameFromPath: { PktapHeader.displayName(fromExecutablePath: $0) },
            bundleIdentifierFromPath: { $0 == Self.webkitNetworkingExec ? "com.apple.WebKit.Networking" : nil },
            outerMainExecutableFromAppPath: { _ in nil },
            runningSafariHostLookup: { nil },
            safariBundleLookup: { Self.safariHost }
        )

        #expect(resolved.processName == "com.apple.WebKit.Networking")
        #expect(resolved.provenance?.executablePath == Self.webkitNetworkingExec)
        #expect(resolved.provenance?.bundleIdentifier == "com.apple.WebKit.Networking")
        #expect(resolved.provenance?.viaProcessName == nil)
    }

    // MARK: - 4. Safari-Exclusive Helpers

    @Test("Unconditionally promotes Safari-exclusive helpers to Safari when Safari bundle exists on disk")
    func promotesSafariExclusiveHelpersToSafari() {
        let helperCases: [(pid: Int32, path: String, leaf: String, bundleID: String?)] = [
            (
                7_401,
                "/System/Library/PrivateFrameworks/SafariPlatformSupport.framework/Versions/A/XPCServices/"
                    + "com.apple.SafariPlatformSupport.Helper.xpc/Contents/MacOS/com.apple.SafariPlatformSupport.Helper",
                "com.apple.SafariPlatformSupport.Helper",
                "com.apple.SafariPlatformSupport.Helper"
            ),
            (
                7_402,
                "/System/Cryptexes/App/usr/libexec/SafariBookmarksSyncAgent",
                "SafariBookmarksSyncAgent",
                nil
            ),
            (
                7_403,
                "/System/Cryptexes/App/usr/libexec/com.apple.Safari.History",
                "com.apple.Safari.History",
                "com.apple.Safari.History"
            ),
            (
                7_404,
                "/System/Library/PrivateFrameworks/SafariShared.framework/Versions/A/XPCServices/"
                    + "SafariHistoryServiceAgent.xpc/Contents/MacOS/SafariHistoryServiceAgent",
                "SafariHistoryServiceAgent",
                "com.apple.SafariShared"
            ),
            (
                7_405,
                "/System/Library/PrivateFrameworks/SafariSafeBrowsing.framework/Versions/A/com.apple.Safari.SafeBrowsing.Service",
                "com.apple.Safari.SafeBrowsing.Service",
                "com.apple.Safari.SafeBrowsing.Service"
            ),
        ]

        // Even when Safari is NOT running (`runningSafariHostLookup` returns nil), disk bundle lookup resolves Safari.
        let diskSafari = PktapHeader.SafariHostAppInfo(
            displayName: "Safari",
            executablePath: Self.applicationsSafariExec,
            bundleIdentifier: "com.apple.Safari"
        )
        for testCase in helperCases {
            let parsed = makeParsed(
                process: String(testCase.leaf.prefix(16)),
                pid: testCase.pid,
                effectivePID: testCase.pid,
                interface: "en0"
            )
            let resolved = PktapHeader.resolveAttribution(
                parsed: parsed,
                executablePathLookup: { $0 == testCase.pid ? testCase.path : nil },
                bsdProcessLookup: { $0 == testCase.pid ? (ppid: 1, uid: 501, hasTTY: false) : nil },
                displayNameFromPath: { PktapHeader.displayName(fromExecutablePath: $0) },
                bundleIdentifierFromPath: { $0 == testCase.path ? testCase.bundleID : nil },
                outerMainExecutableFromAppPath: { _ in nil },
                runningSafariHostLookup: { nil },
                safariBundleLookup: { diskSafari }
            )
            #expect(resolved.processName == "Safari")
            #expect(resolved.provenance?.executablePath == Self.applicationsSafariExec)
            #expect(resolved.provenance?.bundleIdentifier == "com.apple.Safari")
            #expect(resolved.provenance?.viaProcessName == testCase.leaf)
            #expect(resolved.provenance?.originProcessName == testCase.leaf)
            #expect(resolved.provenance?.callerKind == .app)
        }

        // `resolveInstalledSafariHostApp` prefers running Safari PID over disk fallback, then falls back cleanly.
        let preferRunning = PktapHeader.resolveInstalledSafariHostApp(
            runningSafariLookup: { Self.safariHost },
            fileExists: { $0 == Self.applicationsSafariExec }
        )
        #expect(preferRunning?.executablePath == Self.prebootSafariExec)

        let diskFallback = PktapHeader.resolveInstalledSafariHostApp(
            runningSafariLookup: { nil },
            fileExists: { $0 == Self.applicationsSafariExec }
        )
        #expect(diskFallback == diskSafari)

        // Main `Safari` binary itself is NOT treated as a Safari-exclusive helper (`viaProcessName == nil`).
        #expect(!PktapHeader.isSafariExclusiveHelper(
            processName: "Safari",
            executablePath: Self.prebootSafariExec,
            bundleIdentifier: "com.apple.Safari"
        ))
    }

    // MARK: - 5. ProcessResolver Loopback (`127.0.0.1` / `[::1]`) Socket Attribution

    @Test("ProcessResolver resolves 127.0.0.1 and [::1] WebKit.Networking sockets to Safari when Safari is running")
    @MainActor
    func processResolverAttributesLoopbackWebKitSocketsToSafari() throws {
        let webkitPID: Int32 = 8_501
        var mutableTable = ProcessResolver.SocketTable()
        let v4Endpoint = ProcessResolver.SocketEndpoint(ip: "127.0.0.1", port: 54_110)
        let v6Endpoint = ProcessResolver.SocketEndpoint(ip: "::1", port: 54_111)
        let webkitProc = ProcessResolver.ResolvedProcess(pid: webkitPID, command: "com.apple.WebKit")
        mutableTable.specific[v4Endpoint] = webkitProc
        mutableTable.specific[v6Endpoint] = webkitProc
        let table = mutableTable

        let safariRunningLookup = PktapHeader.SafariHostLookup(
            runningSafariHostLookup: { Self.safariHost },
            safariBundleLookup: { Self.safariHost }
        )
        let resolverWhenRunning = ProcessResolver(
            socketTableProvider: { table },
            populateImmediately: true,
            localIPsProvider: { ["127.0.0.1", "::1", "192.168.0.130"] },
            attributionResolver: { pid, command in
                ProcessResolver.resolveProcessAttribution(
                    pid: pid,
                    command: command,
                    executablePathProvider: { $0 == webkitPID ? Self.webkitNetworkingExec : nil },
                    bsdProcessInspector: { $0 == webkitPID ? (ppid: 1, uid: 501, hasTTY: false) : nil },
                    bundleNameLookup: { _ in nil },
                    bundleIdentifierLookup: { path in
                        path.hasSuffix("com.apple.WebKit.Networking.xpc") ? "com.apple.WebKit.Networking" : nil
                    },
                    outerMainExecutableLookup: { _ in nil },
                    runningAppNameLookup: { _ in nil },
                    runningAppBundleIdentifierLookup: { _ in nil },
                    safariHostLookup: safariRunningLookup
                )
            }
        )

        let v4Attr = try #require(resolverWhenRunning.attribution(forEndpoints: "127.0.0.1:54110", "127.0.0.1:3000"))
        #expect(v4Attr.appName == "Safari")
        #expect(v4Attr.provenance.executablePath == Self.prebootSafariExec)
        #expect(v4Attr.provenance.bundleIdentifier == "com.apple.Safari")
        #expect(v4Attr.provenance.viaProcessName == "com.apple.WebKit.Networking")
        #expect(v4Attr.provenance.originProcessName == "com.apple.WebKit.Networking")
        #expect(v4Attr.provenance.callerKind == .app)

        let v6Attr = try #require(resolverWhenRunning.attribution(forEndpoints: "[::1]:54111", "[::1]:8080"))
        #expect(v6Attr.appName == "Safari")
        #expect(v6Attr.provenance.viaProcessName == "com.apple.WebKit.Networking")
        #expect(v6Attr.provenance.bundleIdentifier == "com.apple.Safari")

        // When Safari is NOT running, the same socket stays `com.apple.WebKit.Networking`.
        let safariStoppedLookup = PktapHeader.SafariHostLookup(
            runningSafariHostLookup: { nil },
            safariBundleLookup: { Self.safariHost }
        )
        let resolverWhenStopped = ProcessResolver(
            socketTableProvider: { table },
            populateImmediately: true,
            localIPsProvider: { ["127.0.0.1", "::1"] },
            attributionResolver: { pid, command in
                ProcessResolver.resolveProcessAttribution(
                    pid: pid,
                    command: command,
                    executablePathProvider: { $0 == webkitPID ? Self.webkitNetworkingExec : nil },
                    bsdProcessInspector: { $0 == webkitPID ? (ppid: 1, uid: 501, hasTTY: false) : nil },
                    bundleNameLookup: { _ in nil },
                    bundleIdentifierLookup: { path in
                        path.hasSuffix("com.apple.WebKit.Networking.xpc") ? "com.apple.WebKit.Networking" : nil
                    },
                    outerMainExecutableLookup: { _ in nil },
                    runningAppNameLookup: { _ in nil },
                    runningAppBundleIdentifierLookup: { _ in nil },
                    safariHostLookup: safariStoppedLookup
                )
            }
        )
        let stoppedAttr = try #require(resolverWhenStopped.attribution(forEndpoints: "127.0.0.1:54110", "127.0.0.1:3000"))
        #expect(stoppedAttr.appName == "com.apple.WebKit.Networking")
        #expect(stoppedAttr.provenance.viaProcessName == nil)
    }

    // MARK: - 6. SessionSourceClassifier & Sidebar Source Rollup

    @Test("Classifies Safari WebKit sessions under .app with localized via subtitle, clean tableLabel, and subprocess rollup")
    func classifiesAndGroupsSafariWebKitSessionsUnderApps() throws {
        let localIPs: Set<String> = ["192.168.0.130", "127.0.0.1", "::1"]
        let localhostSession = makeSession(
            processName: "Safari",
            host: "127.0.0.1",
            src: ("127.0.0.1", 54_110),
            dst: ("127.0.0.1", 3_000),
            protos: [.tcp, .http]
        )
        let webSession = makeSession(
            processName: "Safari",
            host: "webkit.org",
            src: ("192.168.0.130", 54_200),
            dst: ("17.253.144.10", 443),
            protos: [.tcp, .tls, .http2]
        )
        let helperSession = makeSession(
            processName: "Safari",
            host: "safebrowsing.apple.com",
            src: ("192.168.0.130", 54_201),
            dst: ("17.253.144.11", 443),
            protos: [.tcp, .tls]
        )

        let webkitContext = SessionProcessContext(
            executablePath: Self.prebootSafariExec,
            bundleIdentifier: "com.apple.Safari",
            viaProcessName: "com.apple.WebKit.Networking",
            originProcessName: "com.apple.WebKit.Networking",
            callerKind: .app
        )
        let helperContext = SessionProcessContext(
            executablePath: Self.applicationsSafariExec,
            bundleIdentifier: "com.apple.Safari",
            viaProcessName: "com.apple.SafariPlatformSupport.Helper",
            originProcessName: "com.apple.SafariPlatformSupport.Helper",
            callerKind: .app
        )

        let (enBundle, zhBundle, cleanup) = try makeLocalizedBundles()
        defer { cleanup() }

        let enClassified = SessionSourceClassifier.classify(
            localhostSession,
            context: webkitContext,
            localIPs: localIPs,
            appBundleExistsLookup: { _ in false },
            bundle: enBundle
        )
        #expect(enClassified.category == .app)
        #expect(enClassified.filterKey == "Safari")
        #expect(enClassified.title == "Safari")
        #expect(enClassified.subtitle == "via com.apple.WebKit.Networking")
        #expect(enClassified.tableLabel == "Safari · WebKit.Networking")
        #expect(enClassified.tableDetail == "via com.apple.WebKit.Networking")
        #expect(enClassified.symbolName == nil)

        let zhClassified = SessionSourceClassifier.classify(
            webSession,
            context: webkitContext,
            localIPs: localIPs,
            appBundleExistsLookup: { _ in false },
            bundle: zhBundle
        )
        #expect(zhClassified.category == .app)
        #expect(zhClassified.subtitle == "经由 com.apple.WebKit.Networking")
        #expect(zhClassified.tableLabel == "Safari · WebKit.Networking")

        let helperClassified = SessionSourceClassifier.classify(
            helperSession,
            context: helperContext,
            localIPs: localIPs,
            appBundleExistsLookup: { _ in false },
            bundle: enBundle
        )
        #expect(helperClassified.category == .app)
        #expect(helperClassified.tableLabel == "Safari · SafariPlatformSupport.Helper")
        #expect(helperClassified.subtitle == "via com.apple.SafariPlatformSupport.Helper")

        // Sidebar rollup groups all Safari sessions under `.app -> Safari` with expandable subprocess rows.
        let groups = SessionSourceClassifier.group(
            sessions: [localhostSession, webSession, helperSession],
            contextsBySessionID: [
                localhostSession.id: webkitContext,
                webSession.id: webkitContext,
                helperSession.id: helperContext,
            ],
            localIPs: localIPs,
            appBundleExistsLookup: { _ in false },
            bundle: zhBundle
        )
        let appsGroup = try #require(groups.first { $0.category == .app })
        #expect(appsGroup.totalSessions == 3)
        let safariItem = try #require(appsGroup.items.first { $0.filterKey == "Safari" })
        #expect(safariItem.title == "Safari")
        #expect(safariItem.count == 3)
        #expect(safariItem.subtitle == "经由 com.apple.WebKit.Networking, com.apple.SafariPlatformSupport.Helper")
        #expect(safariItem.subprocesses.count == 2)

        let networkingSub = try #require(
            safariItem.subprocesses.first { $0.filterKey == "app-proc:Safari:com.apple.WebKit.Networking" }
        )
        #expect(networkingSub.title == "com.apple.WebKit.Networking")
        #expect(networkingSub.count == 2)
        #expect(networkingSub.children.map(\.value) == ["127.0.0.1", "webkit.org"])

        let supportSub = try #require(
            safariItem.subprocesses.first { $0.filterKey == "app-proc:Safari:com.apple.SafariPlatformSupport.Helper" }
        )
        #expect(supportSub.title == "com.apple.SafariPlatformSupport.Helper")
        #expect(supportSub.count == 1)
        #expect(supportSub.children.map(\.value) == ["safebrowsing.apple.com"])

        // Filter matching works for both top-level `"Safari"` and concrete subprocess `"app-proc:Safari:..."`.
        #expect(SessionSourceClassifier.matchesFilterKey("Safari", session: localhostSession, context: webkitContext))
        #expect(SessionSourceClassifier.matchesFilterKey(
            "app-proc:Safari:com.apple.WebKit.Networking",
            session: localhostSession,
            context: webkitContext
        ))
        #expect(!SessionSourceClassifier.matchesFilterKey(
            "app-proc:Safari:com.apple.SafariPlatformSupport.Helper",
            session: localhostSession,
            context: webkitContext
        ))
    }

    // MARK: - Helpers

    private func makeParsed(
        process: String,
        pid: Int32,
        effectivePID: Int32,
        effectiveProcess: String = "",
        interface: String = "en0"
    )
        -> PktapHeader.Parsed
    {
        PktapHeader.Parsed(
            frame: [0x45, 0x00, 0x00, 0x28],
            typeNext: PktapHeader.typeNextPacket,
            innerDLT: 1,
            process: process,
            pid: pid,
            effectivePID: effectivePID,
            effectiveProcess: effectiveProcess,
            interface: interface
        )
    }

    private func makeSession(
        processName: String?,
        host: String,
        src: (String, UInt16),
        dst: (String, UInt16),
        protos: [ProtocolKind]
    )
        -> SessionSummary
    {
        let srcEndpoint = IPEndpoint(ip: src.0, port: src.1)
        let dstEndpoint = IPEndpoint(ip: dst.0, port: dst.1)
        return SessionSummary(
            id: UUID(),
            startTime: Date(timeIntervalSince1970: 1_700_000_000),
            duration: 0.15,
            processName: processName,
            host: host,
            sourceEndpoint: srcEndpoint.display,
            destinationEndpoint: dstEndpoint.display,
            sourceEndpointValue: srcEndpoint,
            destinationEndpointValue: dstEndpoint,
            protocolStack: protos,
            status: .ok,
            latencyMilliseconds: 8.0,
            bytesUp: 256,
            bytesDown: 1_024,
            packetsUp: 3,
            packetsDown: 5,
            tcpCompleteness: [.syn, .synAck, .ack, .data]
        )
    }

    private func makeLocalizedBundles() throws -> (en: Bundle, zh: Bundle, cleanup: () -> Void) {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("tracexy-webkit-safari-lproj-\(UUID().uuidString)", isDirectory: true)
        let tables: [String: [String: String]] = [
            "en.lproj": [
                "via %@": "via %@",
                "App Helper Process": "App Helper Process",
            ],
            "zh-Hans.lproj": [
                "via %@": "经由 %@",
                "App Helper Process": "应用辅助进程",
            ],
        ]
        for (folder, entries) in tables {
            let lproj = tempDir.appendingPathComponent(folder, isDirectory: true)
            try FileManager.default.createDirectory(at: lproj, withIntermediateDirectories: true)
            let plist = try PropertyListSerialization.data(fromPropertyList: entries, format: .binary, options: 0)
            try plist.write(to: lproj.appendingPathComponent("Localizable.strings"))
        }
        let enBundle = try #require(Bundle(url: tempDir.appendingPathComponent("en.lproj", isDirectory: true)))
        let zhBundle = try #require(Bundle(url: tempDir.appendingPathComponent("zh-Hans.lproj", isDirectory: true)))
        return (enBundle, zhBundle, { try? FileManager.default.removeItem(at: tempDir) })
    }
}
