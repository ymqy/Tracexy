import AppKit
import Darwin
import Foundation

/// Maps a local socket endpoint → the owning app name by enumerating live sockets
/// in-process via Darwin `<libproc.h>` (`proc_listallpids` / `proc_pidfdinfo`, with
/// `netstat -anvl` parsing retained for offline fixtures and injected runners) and
/// verifying candidate endpoints against this Mac's interface addresses.
@MainActor
final class ProcessResolver {
    // MARK: Lifecycle

    init(
        socketTableProvider: @escaping @Sendable () -> SocketTable = { ProcessResolver.collectLibprocSockets() },
        populateImmediately: Bool = true,
        localIPsProvider: @escaping @Sendable () -> Set<String> = { ProcessResolver.discoverLocalIPs() },
        appNameResolver: (@Sendable (Int32, String) -> String)? = nil,
        provenanceResolver: (@Sendable (Int32, String, String) -> ProcessProvenance)? = nil
    ) {
        self.socketTableProvider = socketTableProvider
        self.localIPsProvider = localIPsProvider
        let combinedResolver: @Sendable (Int32, String) -> (appName: String, provenance: ProcessProvenance) = { pid, command in
            if appNameResolver == nil, provenanceResolver == nil {
                return ProcessResolver.resolveProcessAttribution(pid: pid, command: command)
            }
            let defaultAttribution = (appNameResolver == nil || provenanceResolver == nil)
                ? ProcessResolver.resolveProcessAttribution(pid: pid, command: command)
                : (appName: "", provenance: ProcessProvenance())
            let appName = appNameResolver?(pid, command) ?? defaultAttribution.appName
            let provenance = provenanceResolver?(pid, command, appName) ?? defaultAttribution.provenance
            return (appName: appName, provenance: provenance)
        }
        attributionResolver = combinedResolver
        localIPs = ProcessResolver.normalizeLocalIPs(localIPsProvider())
        if populateImmediately {
            resolvedTable = Self.resolveEntries(socketTableProvider(), using: combinedResolver)
        }
    }

    convenience init(
        netstatRunner: @escaping @Sendable () -> String,
        localIPsProvider: @escaping @Sendable () -> Set<String> = { ProcessResolver.discoverLocalIPs() },
        appNameResolver: (@Sendable (Int32, String) -> String)? = nil,
        provenanceResolver: (@Sendable (Int32, String, String) -> ProcessProvenance)? = nil
    ) {
        self.init(
            socketTableProvider: { ProcessResolver.parseNetstat(netstatRunner()) },
            populateImmediately: false,
            localIPsProvider: localIPsProvider,
            appNameResolver: appNameResolver,
            provenanceResolver: provenanceResolver
        )
    }

    // MARK: Internal

    nonisolated struct ResolvedProcess: Equatable, Sendable {
        let pid: Int32
        let command: String
    }

    nonisolated struct SocketEndpoint: Hashable, Sendable {
        let ip: String
        let port: UInt16
    }

    nonisolated struct SocketTable: Equatable, Sendable {
        var specific: [SocketEndpoint: ResolvedProcess] = [:]
        var wildcard: [UInt16: ResolvedProcess] = [:]

        var isEmpty: Bool {
            specific.isEmpty && wildcard.isEmpty
        }

        func process(
            forEndpoints source: String,
            _ destination: String,
            localIPs: Set<String>
        )
            -> ResolvedProcess?
        {
            let normalizedIPs = ProcessResolver.normalizeLocalIPs(localIPs)
            return lookup(endpoint: source, normalizedLocalIPs: normalizedIPs)
                ?? lookup(endpoint: destination, normalizedLocalIPs: normalizedIPs)
        }

        fileprivate func lookup(
            endpoint rawEndpoint: String,
            normalizedLocalIPs: Set<String>
        )
            -> ResolvedProcess?
        {
            guard let endpoint = ProcessResolver.parseEndpoint(rawEndpoint),
                  normalizedLocalIPs.contains(endpoint.ip) else
            {
                return nil
            }
            return specific[endpoint] ?? wildcard[endpoint.port]
        }
    }

    nonisolated struct ResolvedSocketTable: Equatable, Sendable {
        var specific: [SocketEndpoint: String] = [:]
        var wildcard: [UInt16: String] = [:]
        var specificProvenance: [SocketEndpoint: ProcessProvenance] = [:]
        var wildcardProvenance: [UInt16: ProcessProvenance] = [:]

        func appName(
            forEndpoints source: String,
            _ destination: String,
            localIPs: Set<String>
        )
            -> String?
        {
            let normalizedIPs = ProcessResolver.normalizeLocalIPs(localIPs)
            return appName(
                forEndpoints: source,
                destination,
                normalizedLocalIPs: normalizedIPs
            )
        }

        func attribution(
            forEndpoints source: String,
            _ destination: String,
            localIPs: Set<String>
        )
            -> (appName: String, provenance: ProcessProvenance)?
        {
            let normalizedIPs = ProcessResolver.normalizeLocalIPs(localIPs)
            return attribution(
                forEndpoints: source,
                destination,
                normalizedLocalIPs: normalizedIPs
            )
        }

        fileprivate func appName(
            forEndpoints source: String,
            _ destination: String,
            normalizedLocalIPs: Set<String>
        )
            -> String?
        {
            lookup(endpoint: source, normalizedLocalIPs: normalizedLocalIPs)
                ?? lookup(endpoint: destination, normalizedLocalIPs: normalizedLocalIPs)
        }

        fileprivate func attribution(
            forEndpoints source: String,
            _ destination: String,
            normalizedLocalIPs: Set<String>
        )
            -> (appName: String, provenance: ProcessProvenance)?
        {
            lookupAttribution(endpoint: source, normalizedLocalIPs: normalizedLocalIPs)
                ?? lookupAttribution(endpoint: destination, normalizedLocalIPs: normalizedLocalIPs)
        }

        private func lookup(
            endpoint rawEndpoint: String,
            normalizedLocalIPs: Set<String>
        )
            -> String?
        {
            guard let endpoint = ProcessResolver.parseEndpoint(rawEndpoint),
                  normalizedLocalIPs.contains(endpoint.ip) else
            {
                return nil
            }
            return specific[endpoint] ?? wildcard[endpoint.port]
        }

        private func lookupAttribution(
            endpoint rawEndpoint: String,
            normalizedLocalIPs: Set<String>
        )
            -> (appName: String, provenance: ProcessProvenance)?
        {
            guard let endpoint = ProcessResolver.parseEndpoint(rawEndpoint),
                  normalizedLocalIPs.contains(endpoint.ip) else
            {
                return nil
            }
            if let specificApp = specific[endpoint] {
                return (
                    appName: specificApp,
                    provenance: specificProvenance[endpoint] ?? ProcessProvenance()
                )
            }
            if let wildcardApp = wildcard[endpoint.port] {
                return (
                    appName: wildcardApp,
                    provenance: wildcardProvenance[endpoint.port] ?? ProcessProvenance()
                )
            }
            return nil
        }
    }

    static let shared = ProcessResolver()
    static let refreshThrottleInterval: TimeInterval = 0.4

    // MARK: - Live Darwin libproc Socket Enumeration & Netstat Parsing

    /// Enumerates live TCP and UDP sockets in-process via Darwin `<libproc.h>`
    /// (`proc_listallpids` + `proc_pidinfo(PROC_PIDLISTFDS)` +
    /// `proc_pidfdinfo(PROC_PIDFDSOCKETINFO)`), avoiding child processes and working
    /// reliably inside ad-hoc signed builds where macOS 26 suppresses `netstat` PCBs.
    nonisolated static func collectLibprocSockets() -> SocketTable {
        var table = SocketTable()
        let estimatedCount = proc_listallpids(nil, 0)
        guard estimatedCount > 0 else {
            return table
        }
        var pids = [pid_t](repeating: 0, count: max(256, Int(estimatedCount) * 2))
        let pidCount = Int(pids.withUnsafeMutableBytes { buffer in
            proc_listallpids(buffer.baseAddress, Int32(buffer.count))
        })
        guard pidCount > 0 else {
            return table
        }

        let fdStride = MemoryLayout<proc_fdinfo>.stride
        let socketInfoSize = Int32(MemoryLayout<socket_fdinfo>.size)
        var timeWaitEndpoints: Set<SocketEndpoint> = []
        var commandByPID: [Int32: String] = [:]

        for pidIndex in 0 ..< min(pidCount, pids.count) {
            let pid = pids[pidIndex]
            guard pid > 0 else {
                continue
            }
            let byteCapacity = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, nil, 0)
            guard byteCapacity > 0 else {
                continue
            }
            var fds = [proc_fdinfo](repeating: proc_fdinfo(), count: Int(byteCapacity) / fdStride + 16)
            let bytesFilled = fds.withUnsafeMutableBytes { buffer in
                proc_pidinfo(pid, PROC_PIDLISTFDS, 0, buffer.baseAddress, Int32(buffer.count))
            }
            guard bytesFilled > 0 else {
                continue
            }
            let fdCount = min(fds.count, Int(bytesFilled) / fdStride)
            for fdIndex in 0 ..< fdCount where fds[fdIndex].proc_fdtype == UInt32(PROX_FDTYPE_SOCKET) {
                var sinfo = socket_fdinfo()
                let filled = proc_pidfdinfo(
                    pid,
                    fds[fdIndex].proc_fd,
                    PROC_PIDFDSOCKETINFO,
                    &sinfo,
                    socketInfoSize
                )
                guard filled >= socketInfoSize else {
                    continue
                }
                let family = sinfo.psi.soi_family
                let kind = sinfo.psi.soi_kind
                guard family == AF_INET || family == AF_INET6,
                      kind == SOCKINFO_TCP || kind == SOCKINFO_IN else
                {
                    continue
                }
                let insi = kind == SOCKINFO_TCP
                    ? sinfo.psi.soi_proto.pri_tcp.tcpsi_ini
                    : sinfo.psi.soi_proto.pri_in
                let port = UInt16(bigEndian: UInt16(truncatingIfNeeded: insi.insi_lport))
                guard port > 0,
                      let normalizedIP = extractSocketLocalIP(insi: insi, family: family) else
                {
                    continue
                }
                let command: String
                if let cached = commandByPID[pid] {
                    command = cached
                } else {
                    let resolved = procCommandName(forPID: pid)
                    commandByPID[pid] = resolved
                    command = resolved
                }
                let process = ResolvedProcess(pid: pid, command: command)
                if normalizedIP == "0.0.0.0" || normalizedIP == "::" {
                    if table.wildcard[port] == nil {
                        table.wildcard[port] = process
                    }
                } else {
                    let isTimeWait = kind == SOCKINFO_TCP
                        && sinfo.psi.soi_proto.pri_tcp.tcpsi_state == TSI_S_TIME_WAIT
                    let endpoint = SocketEndpoint(ip: normalizedIP, port: port)
                    if table.specific[endpoint] == nil {
                        table.specific[endpoint] = process
                        if isTimeWait {
                            timeWaitEndpoints.insert(endpoint)
                        }
                    } else if !isTimeWait, timeWaitEndpoints.contains(endpoint) {
                        table.specific[endpoint] = process
                        timeWaitEndpoints.remove(endpoint)
                    }
                }
            }
        }
        return table
    }

    /// Parses `/usr/sbin/netstat -anv` (or `-anvl`) output into specific `(ip, port)`
    /// and wildcard `(*, port)` socket ownership maps across TCP and UDP.
    nonisolated static func parseNetstat(_ output: String) -> SocketTable {
        var table = SocketTable()
        var timeWaitEndpoints: Set<SocketEndpoint> = []
        for rawLine in output.split(whereSeparator: \.isNewline) {
            guard let row = parseNetstatRow(rawLine) else {
                continue
            }
            switch row.address {
            case let .specific(endpoint):
                if table.specific[endpoint] == nil {
                    table.specific[endpoint] = row.process
                    if row.isTimeWait {
                        timeWaitEndpoints.insert(endpoint)
                    }
                } else if !row.isTimeWait, timeWaitEndpoints.contains(endpoint) {
                    table.specific[endpoint] = row.process
                    timeWaitEndpoints.remove(endpoint)
                }
            case let .wildcard(port):
                if table.wildcard[port] == nil {
                    table.wildcard[port] = row.process
                }
            }
        }
        return table
    }

    /// Alias preserving `ProcessResolver.parse(_:)` readability alongside `parseNetstat(_:)`.
    nonisolated static func parse(_ output: String) -> SocketTable {
        parseNetstat(output)
    }

    /// Extracts the port from an `"ip:port"` string (handles IPv6's inner colons,
    /// bracketed forms like `"[::1]:443"`, and wildcard forms like `"*:5353"`).
    nonisolated static func port(from endpoint: String) -> UInt16? {
        if endpoint.hasPrefix("[") {
            guard let closeBracket = endpoint.firstIndex(of: "]") else {
                return nil
            }
            let remainder = endpoint[endpoint.index(after: closeBracket)...]
            guard remainder.first == ":" else {
                return nil
            }
            let digits = remainder.dropFirst().prefix { $0.isNumber }
            return UInt16(digits)
        }
        guard let lastColon = endpoint.lastIndex(of: ":") else {
            return nil
        }
        let portSlice = endpoint[endpoint.index(after: lastColon)...]
        let digits = portSlice.prefix { $0.isNumber }
        return UInt16(digits)
    }

    /// Parses a `SessionSummary` endpoint string (`"192.168.0.130:55718"`,
    /// `"[fe80::1]:1024"`, `"[fe80::1%en0]:1024"`, or `"fe80:0:0:0:0:0:0:1:1024"`)
    /// into a canonical `(ip, port)` pair, rejecting wildcards and port `0`.
    nonisolated static func parseEndpoint(_ endpoint: String) -> SocketEndpoint? {
        let trimmed = endpoint.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            return nil
        }
        if trimmed.hasPrefix("[") {
            guard let closeBracket = trimmed.firstIndex(of: "]") else {
                return nil
            }
            let rawHost = String(trimmed[trimmed.index(after: trimmed.startIndex) ..< closeBracket])
            let remainder = trimmed[trimmed.index(after: closeBracket)...]
            guard remainder.first == ":" else {
                return nil
            }
            let portSlice = remainder.dropFirst()
            guard !portSlice.isEmpty,
                  portSlice.allSatisfy({ $0 >= "0" && $0 <= "9" }),
                  let port = UInt16(portSlice),
                  port > 0,
                  let ip = normalizeIP(rawHost) else
            {
                return nil
            }
            return SocketEndpoint(ip: ip, port: port)
        }

        guard let lastColon = trimmed.lastIndex(of: ":") else {
            return nil
        }
        let rawHost = String(trimmed[..<lastColon])
        let portSlice = trimmed[trimmed.index(after: lastColon)...]
        guard !portSlice.isEmpty,
              portSlice.allSatisfy({ $0 >= "0" && $0 <= "9" }),
              let port = UInt16(portSlice),
              port > 0,
              let ip = normalizeIP(rawHost) else
        {
            return nil
        }
        return SocketEndpoint(ip: ip, port: port)
    }

    /// Normalizes an IPv4 or IPv6 address (stripping optional brackets and `%zone`
    /// suffixes) into canonical RFC 5952 compressed form via `IPAddressValue`.
    nonisolated static func normalizeIP(_ raw: String) -> String? {
        var candidate = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if candidate.hasPrefix("["), candidate.hasSuffix("]"), candidate.count >= 2 {
            candidate.removeFirst()
            candidate.removeLast()
        }
        if let zoneSeparator = candidate.firstIndex(of: "%") {
            candidate = String(candidate[..<zoneSeparator])
        }
        return IPAddressValue(parsing: candidate)?.compressedText
    }

    /// Normalizes a set of raw local IP strings into canonical lookup keys.
    nonisolated static func normalizeLocalIPs(_ ips: Set<String>) -> Set<String> {
        var normalized: Set<String> = []
        normalized.reserveCapacity(ips.count)
        for ip in ips {
            if let canonical = normalizeIP(ip) {
                normalized.insert(canonical)
            }
        }
        return normalized
    }

    /// Discovers all active local IPv4 & IPv6 interface addresses on this Mac via
    /// `getifaddrs`, always including loopback `127.0.0.1` and `::1`.
    nonisolated static func discoverLocalIPs() -> Set<String> {
        var ips: Set<String> = ["127.0.0.1", "::1"]
        var firstAddress: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&firstAddress) == 0, let head = firstAddress else {
            return ips
        }
        defer { freeifaddrs(head) }

        var cursor: UnsafeMutablePointer<ifaddrs>? = head
        while let entry = cursor {
            defer { cursor = entry.pointee.ifa_next }
            guard let sockaddrPtr = entry.pointee.ifa_addr else {
                continue
            }
            let family = Int32(sockaddrPtr.pointee.sa_family)
            if family == AF_INET {
                var sin = sockaddrPtr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee }
                var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
                if inet_ntop(AF_INET, &sin.sin_addr, &buffer, socklen_t(buffer.count)) != nil,
                   let normalized = normalizeIP(String(cString: buffer))
                {
                    ips.insert(normalized)
                }
            } else if family == AF_INET6 {
                var sin6 = sockaddrPtr.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { $0.pointee }
                var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
                if inet_ntop(AF_INET6, &sin6.sin6_addr, &buffer, socklen_t(buffer.count)) != nil,
                   let normalized = normalizeIP(String(cString: buffer))
                {
                    ips.insert(normalized)
                }
            }
        }
        return ips
    }

    // MARK: - Bundle & App Name Resolution (pure / injectable)

    /// Extracts the outermost `.app` bundle path (up to the FIRST `.app/`) from an
    /// executable path, collapsing nested Helper `.app`, `.appex`, and `.xpc` binaries
    /// into their parent application bundle.
    nonisolated static func outermostAppBundlePath(fromExecutablePath path: String) -> String? {
        guard let range = path.range(of: ".app/") else {
            return nil
        }
        let bundleEnd = path.index(range.lowerBound, offsetBy: 4)
        let bundlePath = String(path[..<bundleEnd])
        guard bundlePath.count > 4 else {
            return nil
        }
        return bundlePath
    }

    /// Resolves the display name of an `.app` bundle path using its Info.plist
    /// (`CFBundleDisplayName` ?? `CFBundleName`), falling back to the bundle folder
    /// name without `.app`.
    nonisolated static func appNameFromAppBundlePath(
        _ bundlePath: String,
        bundleNameLookup: (String) -> String? = bundleDisplayName(atPath:)
    )
        -> String?
    {
        if let bundleName = bundleNameLookup(bundlePath), !bundleName.isEmpty {
            return bundleName
        }
        let lastComponent = (bundlePath as NSString).lastPathComponent
        if lastComponent.lowercased().hasSuffix(".app") {
            let stripped = String(lastComponent.dropLast(4)).trimmingCharacters(in: .whitespacesAndNewlines)
            return stripped.isEmpty ? nil : stripped
        }
        let trimmed = lastComponent.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }

    /// Reads localized or raw `CFBundleDisplayName` / `CFBundleName` from `Bundle(path:)`.
    nonisolated static func bundleDisplayName(atPath bundlePath: String) -> String? {
        guard let bundle = Bundle(path: bundlePath) else {
            return nil
        }
        let candidates: [Any?] = [
            bundle.localizedInfoDictionary?["CFBundleDisplayName"],
            bundle.infoDictionary?["CFBundleDisplayName"],
            bundle.localizedInfoDictionary?["CFBundleName"],
            bundle.infoDictionary?["CFBundleName"],
        ]
        for candidate in candidates {
            if let value = candidate as? String {
                let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
                if !trimmed.isEmpty {
                    return trimmed
                }
            }
        }
        return nil
    }

    /// Reads the executable path for `pid` using `Darwin.proc_pidpath`.
    nonisolated static func executablePath(forPID pid: Int32) -> String? {
        guard pid > 0 else {
            return nil
        }
        var buffer = [CChar](repeating: 0, count: 4_096)
        guard proc_pidpath(pid, &buffer, UInt32(buffer.count)) > 0 else {
            return nil
        }
        let path = String(cString: buffer)
        return path.isEmpty ? nil : path
    }

    /// Resolves a socket's `(pid, command)` to both a user-facing app/daemon name and
    /// full `ProcessProvenance` (`executablePath`, outermost `bundleIdentifier`,
    /// nested helper `viaProcessName`, `parentProcessName`, `hasControllingTTY`, `isRootUser`).
    nonisolated static func resolveProcessAttribution(
        pid: Int32,
        command: String,
        executablePathProvider: (Int32) -> String? = executablePath(forPID:),
        bsdProcessInspector: (Int32) -> (ppid: Int32, uid: UInt32, hasTTY: Bool)? = PktapHeader.inspectBSDProcess(pid:),
        bundleNameLookup: (String) -> String? = bundleDisplayName(atPath:),
        bundleIdentifierLookup: (String) -> String? = PktapHeader.bundleIdentifier(atBundlePath:),
        outerMainExecutableLookup: (String) -> String? = PktapHeader.bundleExecutableName(atBundlePath:),
        runningAppNameLookup: (Int32) -> String? = runningApplicationName(forPID:),
        runningAppBundleIdentifierLookup: (Int32) -> String? = runningApplicationBundleIdentifier(forPID:)
    )
        -> (appName: String, provenance: ProcessProvenance)
    {
        let resolvedExecPath = pid > 0 ? executablePathProvider(pid) : nil
        let appName = resolveAppNameFromResolvedPath(
            pid: pid,
            command: command,
            resolvedExecPath: resolvedExecPath,
            bundleNameLookup: bundleNameLookup,
            runningAppNameLookup: runningAppNameLookup
        )

        var resolvedBundleID = resolvedExecPath.flatMap { execPath in
            PktapHeader.bundleIdentifier(
                fromExecutablePath: execPath,
                bundleIdentifierLookup: bundleIdentifierLookup
            )
        }
        if resolvedBundleID == nil,
           pid > 0,
           let runningID = runningAppBundleIdentifierLookup(pid)?.trimmingCharacters(in: .whitespacesAndNewlines),
           !runningID.isEmpty
        {
            resolvedBundleID = runningID
        }

        let viaName = resolvedExecPath.flatMap { execPath in
            PktapHeader.nestedHelperViaName(
                executablePath: execPath,
                outerAppDisplayName: appName,
                outerMainExecutableLookup: outerMainExecutableLookup
            )
        }

        let bsdInfo = pid > 0 ? bsdProcessInspector(pid) : nil
        let hasTTY = bsdInfo?.hasTTY ?? false
        let isRootUser = bsdInfo.map { $0.uid == 0 } ?? false
        var parentProcessName: String?
        if let ppid = bsdInfo?.ppid,
           ppid > 1,
           ppid != pid,
           let parentExecPath = executablePathProvider(ppid)
        {
            if let outerBundlePath = outermostAppBundlePath(fromExecutablePath: parentExecPath) {
                parentProcessName = appNameFromAppBundlePath(
                    outerBundlePath,
                    bundleNameLookup: bundleNameLookup
                )
            } else {
                let basename = (parentExecPath as NSString).lastPathComponent
                    .trimmingCharacters(in: .whitespacesAndNewlines)
                if !basename.isEmpty, basename != "/" {
                    parentProcessName = basename
                }
            }
        }

        let provenance = ProcessProvenance(
            executablePath: resolvedExecPath,
            bundleIdentifier: resolvedBundleID,
            viaProcessName: viaName,
            parentProcessName: parentProcessName,
            hasControllingTTY: hasTTY,
            isRootUser: isRootUser,
            isKernelTask: false
        )
        return (appName: appName, provenance: provenance)
    }

    /// Resolves a socket's `(pid, command)` to a user-facing app or daemon name:
    /// 1) Outermost `.app` bundle from `proc_pidpath` (via `Bundle` Info.plist or bundle basename),
    /// 2) `NSRunningApplication(processIdentifier: pid)?.localizedName` when not inside an `.app/`,
    /// 3) Executable basename from `proc_pidpath`, else `command`.
    nonisolated static func resolveAppName(
        pid: Int32,
        command: String,
        executablePathProvider: (Int32) -> String? = executablePath(forPID:),
        bundleNameLookup: (String) -> String? = bundleDisplayName(atPath:),
        runningAppNameLookup: (Int32) -> String? = runningApplicationName(forPID:)
    )
        -> String
    {
        let resolvedExecPath = pid > 0 ? executablePathProvider(pid) : nil
        return resolveAppNameFromResolvedPath(
            pid: pid,
            command: command,
            resolvedExecPath: resolvedExecPath,
            bundleNameLookup: bundleNameLookup,
            runningAppNameLookup: runningAppNameLookup
        )
    }

    // MARK: - Live Lookup & Refresh

    /// Normalized local interface IP addresses currently known for this Mac.
    var currentLocalIPs: Set<String> {
        localIPs
    }

    /// The app owning a session, found by matching either endpoint's local `(ip, port)`
    /// (with wildcard `*.port` fallback only when the endpoint IP belongs to this Mac).
    func appName(forEndpoints source: String, _ destination: String) -> String? {
        resolvedTable.appName(
            forEndpoints: source,
            destination,
            normalizedLocalIPs: localIPs
        )
    }

    /// Full `(appName, provenance)` owning a session, found by matching either
    /// endpoint's local `(ip, port)` (with wildcard `*.port` fallback only when
    /// the endpoint IP belongs to this Mac).
    func attribution(
        forEndpoints source: String,
        _ destination: String
    )
        -> (appName: String, provenance: ProcessProvenance)?
    {
        resolvedTable.attribution(
            forEndpoints: source,
            destination,
            normalizedLocalIPs: localIPs
        )
    }

    /// Refreshes the socket→app table (throttled to 0.4s). Socket enumeration and
    /// `getifaddrs` run off-main; the resolved table updates on the main actor when done.
    func refresh(force: Bool = false) {
        if isRefreshing {
            if force {
                pendingForcedRefresh = true
            }
            return
        }
        let now = Date()
        guard force || now.timeIntervalSince(lastRefresh) >= Self.refreshThrottleInterval else {
            return
        }
        isRefreshing = true
        lastRefresh = now
        let provider = socketTableProvider
        let ipProvider = localIPsProvider
        let resolver = attributionResolver
        Task.detached(priority: .utility) {
            let parsed = provider()
            let discoveredIPs = Self.normalizeLocalIPs(ipProvider())
            let resolved = Self.resolveEntries(parsed, using: resolver)
            await MainActor.run {
                self.localIPs = discoveredIPs
                self.resolvedTable = resolved
                self.isRefreshing = false
                if self.pendingForcedRefresh {
                    self.pendingForcedRefresh = false
                    self.refresh(force: true)
                }
            }
        }
    }

    // MARK: Private

    nonisolated private enum NetstatAddress: Equatable {
        case specific(SocketEndpoint)
        case wildcard(UInt16)
    }

    nonisolated private struct ParsedRow {
        let address: NetstatAddress
        let isTimeWait: Bool
        let process: ResolvedProcess
    }

    nonisolated private static let supportedProtocols: Set<Substring> = [
        "tcp", "tcp4", "tcp6", "tcp46",
        "udp", "udp4", "udp6", "udp46",
    ]

    private let socketTableProvider: @Sendable () -> SocketTable
    private let localIPsProvider: @Sendable () -> Set<String>
    private let attributionResolver: @Sendable (Int32, String) -> (appName: String, provenance: ProcessProvenance)
    private var resolvedTable = ResolvedSocketTable()
    private var localIPs: Set<String>
    private var lastRefresh = Date.distantPast
    private var isRefreshing = false
    private var pendingForcedRefresh = false

    nonisolated private static func extractSocketLocalIP(insi: in_sockinfo, family: Int32) -> String? {
        let hasIPv4 = (insi.insi_vflag & UInt8(INI_IPV4)) != 0
        let hasIPv6 = (insi.insi_vflag & UInt8(INI_IPV6)) != 0

        if (hasIPv4 && !hasIPv6) || (!hasIPv4 && !hasIPv6 && family == AF_INET) {
            var addr4 = insi.insi_laddr.ina_46.i46a_addr4
            var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
            guard inet_ntop(AF_INET, &addr4, &buffer, socklen_t(buffer.count)) != nil else {
                return nil
            }
            return normalizeIP(String(cString: buffer))
        }

        if hasIPv6 || (!hasIPv4 && !hasIPv6 && family == AF_INET6) {
            var addr6 = insi.insi_laddr.ina_6
            let isIPv4Mapped = withUnsafeMutableBytes(of: &addr6) { raw -> Bool in
                guard raw.count == 16 else {
                    return false
                }
                // Strip KAME embedded interface scope ID on fe80::/10 link-local PCBs
                // so the address matches `getifaddrs` and wire IPv6 headers.
                if raw[0] == 0xFE, (raw[1] & 0xC0) == 0x80 {
                    raw[2] = 0
                    raw[3] = 0
                }
                return raw[0 ..< 10].allSatisfy { $0 == 0 } && raw[10] == 0xFF && raw[11] == 0xFF
            }
            if isIPv4Mapped {
                var addr4 = insi.insi_laddr.ina_46.i46a_addr4
                var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
                guard inet_ntop(AF_INET, &addr4, &buffer, socklen_t(buffer.count)) != nil else {
                    return nil
                }
                return normalizeIP(String(cString: buffer))
            }
            var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
            guard inet_ntop(AF_INET6, &addr6, &buffer, socklen_t(buffer.count)) != nil else {
                return nil
            }
            return normalizeIP(String(cString: buffer))
        }

        return nil
    }

    nonisolated private static func procCommandName(forPID pid: Int32) -> String {
        guard pid > 0 else {
            return ""
        }
        var nameBuffer = [CChar](repeating: 0, count: 256)
        if proc_name(pid, &nameBuffer, UInt32(nameBuffer.count)) > 0 {
            let name = String(cString: nameBuffer).trimmingCharacters(in: .whitespacesAndNewlines)
            if !name.isEmpty {
                return name
            }
        }
        if let execPath = executablePath(forPID: pid) {
            let basename = (execPath as NSString).lastPathComponent
                .trimmingCharacters(in: .whitespacesAndNewlines)
            if !basename.isEmpty, basename != "/" {
                return basename
            }
        }
        return ""
    }

    nonisolated private static func resolveAppNameFromResolvedPath(
        pid: Int32,
        command: String,
        resolvedExecPath: String?,
        bundleNameLookup: (String) -> String?,
        runningAppNameLookup: (Int32) -> String?
    )
        -> String
    {
        if let execPath = resolvedExecPath,
           let outerBundlePath = outermostAppBundlePath(fromExecutablePath: execPath),
           let appName = appNameFromAppBundlePath(outerBundlePath, bundleNameLookup: bundleNameLookup)
        {
            return appName
        }

        if pid > 0,
           let runningName = runningAppNameLookup(pid)?.trimmingCharacters(in: .whitespacesAndNewlines),
           !runningName.isEmpty
        {
            return runningName
        }

        if let execPath = resolvedExecPath {
            let basename = (execPath as NSString).lastPathComponent
                .trimmingCharacters(in: .whitespacesAndNewlines)
            if !basename.isEmpty, basename != "/" {
                return basename
            }
        }

        return command
    }

    nonisolated private static func runningApplicationName(forPID pid: Int32) -> String? {
        guard pid > 0 else {
            return nil
        }
        return NSRunningApplication(processIdentifier: pid)?.localizedName
    }

    nonisolated private static func runningApplicationBundleIdentifier(forPID pid: Int32) -> String? {
        guard pid > 0 else {
            return nil
        }
        return NSRunningApplication(processIdentifier: pid)?.bundleIdentifier
    }

    nonisolated private static func parseNetstatRow(_ rawLine: Substring) -> ParsedRow? {
        let tokens = rawLine.split(whereSeparator: \.isWhitespace)
        guard tokens.count >= 10,
              supportedProtocols.contains(tokens[0]),
              tokens[1].allSatisfy({ $0 >= "0" && $0 <= "9" }),
              tokens[2].allSatisfy({ $0 >= "0" && $0 <= "9" }),
              let address = parseNetstatAddress(tokens[3]) else
        {
            return nil
        }

        let hasStateColumn = !tokens[5].allSatisfy { $0 >= "0" && $0 <= "9" }
        let isTimeWait = hasStateColumn && tokens[5] == "TIME_WAIT"
        let statsStart = hasStateColumn ? 6 : 5
        let processStart = statsStart + 4
        guard processStart < tokens.count else {
            return nil
        }
        for statsIndex in statsStart ..< processStart {
            guard tokens[statsIndex].allSatisfy({ $0 >= "0" && $0 <= "9" }) else {
                return nil
            }
        }
        guard let process = extractProcessAndPID(from: tokens, startingAt: processStart) else {
            return nil
        }
        return ParsedRow(address: address, isTimeWait: isTimeWait, process: process)
    }

    nonisolated private static func parseNetstatAddress(_ token: Substring) -> NetstatAddress? {
        guard token != "*.*", let lastDot = token.lastIndex(of: ".") else {
            return nil
        }
        let rawHost = String(token[..<lastDot])
        let portSlice = token[token.index(after: lastDot)...]
        guard !portSlice.isEmpty,
              portSlice != "*",
              portSlice.allSatisfy({ $0 >= "0" && $0 <= "9" }),
              let port = UInt16(portSlice),
              port > 0 else
        {
            return nil
        }

        if rawHost == "*" {
            return .wildcard(port)
        }
        guard let normalizedIP = normalizeIP(rawHost) else {
            return nil
        }
        if normalizedIP == "0.0.0.0" || normalizedIP == "::" {
            return .wildcard(port)
        }
        return .specific(SocketEndpoint(ip: normalizedIP, port: port))
    }

    nonisolated private static func extractProcessAndPID(
        from tokens: [Substring],
        startingAt processStart: Int
    )
        -> ResolvedProcess?
    {
        var index = tokens.count - 1
        while index >= processStart {
            let token = tokens[index]
            if let lastColon = token.lastIndex(of: ":") {
                let pidSlice = token[token.index(after: lastColon)...]
                let trailingAreFlags = tokens[(index + 1)...].allSatisfy { trailing in
                    !trailing.isEmpty && trailing.allSatisfy(\.isHexDigit)
                }
                if trailingAreFlags,
                   !pidSlice.isEmpty,
                   pidSlice.allSatisfy({ $0 >= "0" && $0 <= "9" }),
                   let pid = Int32(pidSlice)
                {
                    let tailCommand = token[..<lastColon]
                    var commandParts = tokens[processStart ..< index].map(String.init)
                    if !tailCommand.isEmpty {
                        commandParts.append(String(tailCommand))
                    }
                    let command = commandParts.joined(separator: " ")
                        .trimmingCharacters(in: .whitespaces)
                    guard !command.isEmpty || pid > 0 else {
                        return nil
                    }
                    return ResolvedProcess(pid: pid, command: command)
                }
            }
            index -= 1
        }
        return nil
    }

    nonisolated private static func resolveEntries(
        _ parsed: SocketTable,
        using attributionResolver: (Int32, String) -> (appName: String, provenance: ProcessProvenance)
    )
        -> ResolvedSocketTable
    {
        var attributionByPID: [Int32: (appName: String, provenance: ProcessProvenance)] = [:]
        var resolved = ResolvedSocketTable()
        resolved.specific.reserveCapacity(parsed.specific.count)
        resolved.wildcard.reserveCapacity(parsed.wildcard.count)
        resolved.specificProvenance.reserveCapacity(parsed.specific.count)
        resolved.wildcardProvenance.reserveCapacity(parsed.wildcard.count)

        func resolve(_ info: ResolvedProcess) -> (appName: String, provenance: ProcessProvenance) {
            if info.pid > 0, let cached = attributionByPID[info.pid] {
                return cached
            }
            let entry = attributionResolver(info.pid, info.command)
            if info.pid > 0 {
                attributionByPID[info.pid] = entry
            }
            return entry
        }

        for (endpoint, info) in parsed.specific {
            let entry = resolve(info)
            resolved.specific[endpoint] = entry.appName
            resolved.specificProvenance[endpoint] = entry.provenance
        }
        for (port, info) in parsed.wildcard {
            let entry = resolve(info)
            resolved.wildcard[port] = entry.appName
            resolved.wildcardProvenance[port] = entry.provenance
        }
        return resolved
    }
}
