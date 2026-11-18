import Darwin
import Foundation

// MARK: - TracexyHelperProtocol

@objc
protocol TracexyHelperProtocol {
    /// Helper binary version, build number, protocol version.
    func getHelperInfo(withReply reply: @escaping (String, Int, Int) -> Void)

    /// Ask an already approved protocol-v5 helper to exit after acknowledging
    /// the request. launchd keeps the registration and resolves `BundleProgram`
    /// from the current app bundle on the next connection.
    func prepareForExecutableRefresh(withReply reply: @escaping (Bool) -> Void)

    /// Report the exact executable this helper process launched from. The digest
    /// and per-launch UUID prove convergence after an in-place app update; they do
    /// not replace signing or caller validation.
    func getExecutableIdentity(
        withReply reply: @escaping (String, String, Int32, String, Int, Int) -> Void
    )

    /// Begin capturing with a typed, validated `configuration` (interface, snap
    /// length, promiscuous mode, optional BPF and optimizer choice). Reply:
    /// (started, errorMessage).
    ///
    /// The helper re-validates the configuration and compiles any BPF against
    /// libpcap *before* replying, so an out-of-bounds value or a bad filter
    /// expression fails closed with a clear message and no capture is reported
    /// started. This is protocol v4 — the immutable `CaptureConfiguration` command
    /// surface replaced v3's bare `interface: String`. Protocol v4 remains safe
    /// for capture during its explicit one-time migration to v5; v3 and older do
    /// not receive a downgraded start request.
    func startCapture(configuration: CaptureConfiguration, withReply reply: @escaping (Bool, String) -> Void)

    /// Stop the active capture and return the worker's final flushed batch plus
    /// final accounting. Returning this atomically avoids a stop→fetch race with
    /// the next capture generation.
    func stopCapture(withReply reply: @escaping (FrameBatchMessage) -> Void)

    /// Drain buffered frames as a typed, `NSSecureCoding` batch.
    ///
    /// Replaces the legacy `([Data], Int)` surface: every frame now carries its
    /// own libpcap timestamp, captured length, original on-wire length, and link
    /// type, and the batch carries the helper's cumulative buffer-drop count and
    /// `pcap_stats` accounting (see `FrameBatchMessage`). This is a protocol-v2
    /// change — the app fails closed against a v1 helper (`getHelperInfo` still
    /// classifies the mismatch) rather than falling back to an untyped drain.
    /// Process attribution stays an app-side enrichment (see `ProcessResolver`).
    func fetchFrames(withReply reply: @escaping (FrameBatchMessage) -> Void)
}

// MARK: - PktapHeader

/// Parser for the macOS PKTAP per-packet metadata header (DLT_PKTAP = 258).
/// pktap prefixes each captured frame with the originating process — the only
/// way passive capture can attribute traffic to an app. Lives in Shared so the
/// helper produces it and the app tests it. Layout per xnu `net/pktap.h`.
nonisolated enum PktapHeader {
    // MARK: Internal

    struct Parsed: Sendable, Equatable {
        let frame: [UInt8]
        let typeNext: UInt32
        let innerDLT: UInt32
        let process: String
        let pid: Int32
        /// Effective PID — the *delegating* app for traffic carried by a daemon
        /// (e.g. nsurlsessiond). Prefer it when resolving the owning app.
        let effectivePID: Int32
        /// Kernel name (`pth_ecomm`) for `effectivePID` when present at offset 88.
        let effectiveProcess: String
        let interface: String
    }

    enum TransportProto: UInt8, Equatable, Hashable, Sendable {
        case tcp = 6
        case udp = 17
    }

    /// Allocation-free canonical IP key for fast inbound packet destination lookup.
    enum InboundIPKey: Equatable, Hashable, Sendable {
        case v4(UInt32)
        case v6(UInt64, UInt64)

        var isWildcard: Bool {
            switch self {
            case let .v4(addr):
                addr == 0
            case let .v6(hi, lo):
                hi == 0 && lo == 0
            }
        }

        var isMulticastOrBroadcast: Bool {
            switch self {
            case let .v4(addr):
                let firstOctet = UInt8((addr >> 24) & 0xFF)
                return addr == 0xFFFFFFFF || (firstOctet >= 224 && firstOctet <= 239)
            case let .v6(hi, _):
                return UInt8((hi >> 56) & 0xFF) == 0xFF
            }
        }

        static func normalizedV6(
            _ b0: UInt8, _ b1: UInt8, _ b2: UInt8, _ b3: UInt8,
            _ b4: UInt8, _ b5: UInt8, _ b6: UInt8, _ b7: UInt8,
            _ b8: UInt8, _ b9: UInt8, _ b10: UInt8, _ b11: UInt8,
            _ b12: UInt8, _ b13: UInt8, _ b14: UInt8, _ b15: UInt8
        )
            -> InboundIPKey
        {
            var s2 = b2
            var s3 = b3
            // Strip KAME embedded interface scope ID on fe80::/10 link-local PCBs.
            if b0 == 0xFE, (b1 & 0xC0) == 0x80 {
                s2 = 0
                s3 = 0
            }
            let hi = (UInt64(b0) << 56) | (UInt64(b1) << 48) | (UInt64(s2) << 40) | (UInt64(s3) << 32)
                | (UInt64(b4) << 24) | (UInt64(b5) << 16) | (UInt64(b6) << 8) | UInt64(b7)
            let lo = (UInt64(b8) << 56) | (UInt64(b9) << 48) | (UInt64(b10) << 40) | (UInt64(b11) << 32)
                | (UInt64(b12) << 24) | (UInt64(b13) << 16) | (UInt64(b14) << 8) | UInt64(b15)
            // Collapse IPv4-mapped IPv6 (`::ffff:a.b.c.d`) to `.v4`.
            if hi == 0, (lo >> 32) == 0x0000FFFF {
                return .v4(UInt32(truncatingIfNeeded: lo))
            }
            return .v6(hi, lo)
        }
    }

    struct InboundPacketTarget: Equatable, Hashable, Sendable {
        let proto: TransportProto
        let destinationIP: InboundIPKey
        let destinationPort: UInt16
    }

    struct InboundSocketPortMap: Sendable {
        struct SpecificKey: Equatable, Hashable, Sendable {
            let proto: TransportProto
            let ip: InboundIPKey
            let port: UInt16
        }

        struct WildcardKey: Equatable, Hashable, Sendable {
            let proto: TransportProto
            let port: UInt16
        }

        var localIPs: Set<InboundIPKey> = []
        var specific: [SpecificKey: Int32] = [:]
        var wildcard: [WildcardKey: Int32] = [:]
        var commandByPID: [Int32: String] = [:]

        func lookup(target: InboundPacketTarget) -> (pid: Int32, command: String)? {
            guard !target.destinationIP.isMulticastOrBroadcast,
                  localIPs.contains(target.destinationIP) else
            {
                return nil
            }
            let specificKey = SpecificKey(
                proto: target.proto,
                ip: target.destinationIP,
                port: target.destinationPort
            )
            let wildcardKey = WildcardKey(
                proto: target.proto,
                port: target.destinationPort
            )
            guard let pid = specific[specificKey] ?? wildcard[wildcardKey], pid > 0 else {
                return nil
            }
            return (pid: pid, command: commandByPID[pid] ?? "")
        }
    }

    /// Standard pcap/pcapng `LINKTYPE_PKTAP` value (258).
    static let dlt: UInt32 = 258
    /// Darwin `<net/bpf.h>` runtime `DLT_PKTAP` (`DLT_USER2 = 149`) used by live
    /// macOS `/usr/lib/libpcap.A.dylib` (`pcap_datalink_name_to_val("PKTAP") == 149`).
    static let darwinDLT: UInt32 = 149
    /// `pth_type_next` values from XNU `<net/pktap.h>`.
    static let typeNextNone: UInt32 = 0
    static let typeNextPacket: UInt32 = 1
    static let typeNextDrop: UInt32 = 2

    /// True when `rawDLT` is either Darwin's live `DLT_PKTAP (149)` or `LINKTYPE_PKTAP (258)`.
    static func isPktapDLT(_ rawDLT: UInt32) -> Bool {
        rawDLT == darwinDLT || rawDLT == dlt
    }

    /// Splits a DLT_PKTAP packet into its wrapped frame + process metadata.
    static func parse(_ bytes: [UInt8]) -> Parsed? {
        guard bytes.count >= Field.minimumSize else {
            return nil
        }
        let headerLength = Int(u32le(bytes, Field.length))
        guard headerLength >= Field.minimumSize, headerLength <= bytes.count else {
            return nil
        }
        let typeNext = u32le(bytes, Field.typeNext)
        // Accept PTH_TYPE_PACKET (1) and PTH_TYPE_NONE (0); reject PTH_TYPE_DROP (2)
        // kernel drop notifications and any unknown non-packet record types.
        guard typeNext == typeNextNone || typeNext == typeNextPacket else {
            return nil
        }
        let pid = Int32(bitPattern: u32le(bytes, Field.pid))
        let effectivePID = headerLength >= Field.epid + 4
            ? Int32(bitPattern: u32le(bytes, Field.epid))
            : pid
        let effectiveProcess = headerLength >= Field.ecomm + 1
            ? cString(bytes, at: Field.ecomm, max: min(17, headerLength - Field.ecomm))
            : ""
        return Parsed(
            frame: Array(bytes[headerLength...]),
            typeNext: typeNext,
            innerDLT: u32le(bytes, Field.innerDLT),
            process: cString(bytes, at: Field.comm, max: 17),
            pid: pid,
            effectivePID: effectivePID,
            effectiveProcess: effectiveProcess,
            interface: cString(bytes, at: Field.ifName, max: 24)
        )
    }

    /// Extracts the outermost `.app` bundle path when an executable lives inside an
    /// application bundle (collapsing nested helper `.app` or `.xpc` bundles).
    static func outermostAppBundlePath(fromExecutablePath path: String) -> String? {
        guard let range = path.range(of: ".app/") else {
            return nil
        }
        let bundlePrefix = String(path[..<range.lowerBound])
        let bundleName = (bundlePrefix as NSString).lastPathComponent
        guard !bundlePrefix.isEmpty, !bundleName.isEmpty, bundleName != "/" else {
            return nil
        }
        return bundlePrefix + ".app"
    }

    /// Derives a display app name from a process executable path:
    /// "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" → "Google Chrome".
    /// Falls back to the executable's file name for non-bundled daemons.
    static func appName(fromExecutablePath path: String) -> String {
        if let range = path.range(of: ".app/") {
            let bundlePath = String(path[..<range.lowerBound])
            return (bundlePath as NSString).lastPathComponent
        }
        return (path as NSString).lastPathComponent
    }

    /// Resolves a user-facing display name from an executable path, checking the
    /// outermost `.app` bundle's `CFBundleDisplayName` / `CFBundleName` before
    /// falling back to `appName(fromExecutablePath:)` or the executable basename.
    static func displayName(fromExecutablePath path: String) -> String? {
        guard !path.isEmpty else {
            return nil
        }
        if let bundlePath = outermostAppBundlePath(fromExecutablePath: path) {
            if let bundle = Bundle(path: bundlePath) {
                if let displayName = nonEmptyBundleValue(forKey: "CFBundleDisplayName", in: bundle) {
                    return displayName
                }
                if let bundleName = nonEmptyBundleValue(forKey: "CFBundleName", in: bundle) {
                    return bundleName
                }
            }
            let fallback = appName(fromExecutablePath: path)
            return fallback.isEmpty || fallback == "/" ? nil : fallback
        }
        let basename = (path as NSString).lastPathComponent
        return basename.isEmpty || basename == "/" ? nil : basename
    }

    /// Resolves a live process's executable path via `Darwin.proc_pidpath`.
    static func executablePath(forPID pid: Int32) -> String? {
        guard pid > 0 else {
            return nil
        }
        var buffer = [CChar](repeating: 0, count: 4_096)
        guard proc_pidpath(pid, &buffer, UInt32(buffer.count)) > 0 else {
            return nil
        }
        let path = decodeNullTerminatedUTF8(buffer)
        return path.isEmpty ? nil : path
    }

    /// Resolves a live process's display name via `Darwin.proc_pidpath`.
    static func resolveDisplayName(forPID pid: Int32) -> String? {
        guard let path = executablePath(forPID: pid) else {
            return nil
        }
        return displayName(fromExecutablePath: path)
    }

    /// Inspects live BSD process credentials and controlling terminal state via
    /// `Darwin.sysctl` (`[CTL_KERN, KERN_PROC, KERN_PROC_PID, pid]`, `kinfo_proc`).
    static func inspectBSDProcess(pid: Int32) -> (ppid: Int32, uid: UInt32, hasTTY: Bool)? {
        guard pid > 0 else {
            return nil
        }
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, pid]
        var kp = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.stride
        let rc = sysctl(&mib, UInt32(mib.count), &kp, &size, nil, 0)
        guard rc == 0, size >= MemoryLayout<kinfo_proc>.size, kp.kp_proc.p_pid == pid else {
            return nil
        }
        let ppid = kp.kp_eproc.e_ppid
        let uid = kp.kp_eproc.e_ucred.cr_uid
        let nodev = dev_t(-1)
        let tdev = kp.kp_eproc.e_tdev
        let hasTTY = tdev != nodev && tdev != 0
        return (ppid: ppid, uid: uid, hasTTY: hasTTY)
    }

    /// Resolves the `CFBundleIdentifier` of the outermost `.app` bundle (or outer
    /// `.systemextension`, `.appex`, `.xpc`, or `.framework` bundle) containing `path`.
    static func bundleIdentifier(
        fromExecutablePath path: String,
        bundleIdentifierLookup: (String) -> String? = bundleIdentifier(atBundlePath:)
    )
        -> String?
    {
        guard !path.isEmpty else {
            return nil
        }
        for candidate in candidateBundlePaths(fromExecutablePath: path) {
            if let identifier = trimmedNonEmpty(bundleIdentifierLookup(candidate)) {
                return identifier
            }
        }
        return nil
    }

    /// Reads `CFBundleIdentifier` from a bundle directory on disk.
    static func bundleIdentifier(atBundlePath bundlePath: String) -> String? {
        guard let bundle = Bundle(path: bundlePath) else {
            return nil
        }
        if let identifier = trimmedNonEmpty(bundle.bundleIdentifier) {
            return identifier
        }
        return nonEmptyBundleValue(forKey: "CFBundleIdentifier", in: bundle)
    }

    /// Reads `CFBundleExecutable` from a bundle directory on disk.
    static func bundleExecutableName(atBundlePath bundlePath: String) -> String? {
        guard let bundle = Bundle(path: bundlePath) else {
            return nil
        }
        return nonEmptyBundleValue(forKey: "CFBundleExecutable", in: bundle)
    }

    /// Returns the leaf helper or daemon executable basename when `path` is nested
    /// inside an outer `.app/` bundle and differs from the outer `.app`'s main binary
    /// and display name (e.g., `UU远程.app/Contents/MacOS/UURemoteDaemon` → `"UURemoteDaemon"`,
    /// `Antigravity.app/.../Antigravity Helper` → `"Antigravity Helper"`).
    static func nestedHelperViaName(
        executablePath path: String,
        outerAppDisplayName: String,
        outerMainExecutableLookup: (String) -> String? = bundleExecutableName(atBundlePath:)
    )
        -> String?
    {
        guard let outerAppPath = outermostAppBundlePath(fromExecutablePath: path) else {
            return nil
        }
        let leaf = (path as NSString).lastPathComponent
            .trimmingCharacters(in: .whitespacesAndNewlines)
        let trimmedDisplay = outerAppDisplayName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !leaf.isEmpty, leaf != "/", leaf != trimmedDisplay else {
            return nil
        }
        let directMainBinaryPath = outerAppPath + "/Contents/MacOS/" + leaf
        if path == directMainBinaryPath {
            let outerFolderName = appName(fromExecutablePath: path)
                .trimmingCharacters(in: .whitespacesAndNewlines)
            if leaf == outerFolderName {
                return nil
            }
            if let mainExecutable = trimmedNonEmpty(outerMainExecutableLookup(outerAppPath)),
               leaf == mainExecutable
            {
                return nil
            }
        }
        return leaf
    }

    /// Resolves the attributing process name for a parsed `pktap` header:
    /// prefers `effectivePID` (attributes `nsurlsessiond` / `mDNSResponder`
    /// delegated traffic to the real client app), falls back to `pid`, and when
    /// live `proc_pidpath` lookup fails (process already exited), prefers
    /// `pth_ecomm` (`effectiveProcess`) before `pth_comm` (`process`).
    static func resolveProcessName(
        parsed: Parsed,
        pidLookup: (Int32) -> String? = resolveDisplayName(forPID:)
    )
        -> String?
    {
        if parsed.effectivePID > 0,
           let effectiveName = pidLookup(parsed.effectivePID)?.trimmingCharacters(in: .whitespacesAndNewlines),
           !effectiveName.isEmpty
        {
            return effectiveName
        }
        if parsed.pid > 0,
           parsed.pid != parsed.effectivePID,
           let directName = pidLookup(parsed.pid)?.trimmingCharacters(in: .whitespacesAndNewlines),
           !directName.isEmpty
        {
            return directName
        }
        let effectiveFallback = parsed.effectiveProcess.trimmingCharacters(in: .whitespacesAndNewlines)
        if !effectiveFallback.isEmpty {
            return effectiveFallback
        }
        let fallback = parsed.process.trimmingCharacters(in: .whitespacesAndNewlines)
        return fallback.isEmpty ? nil : fallback
    }

    /// Resolves both the user-facing `processName` and full `ProcessProvenance`
    /// (`executablePath`, `bundleIdentifier`, `viaProcessName`, `parentProcessName`,
    /// `hasControllingTTY`, `isRootUser`, `isKernelTask`) from a parsed `pktap` header.
    static func resolveAttribution(
        parsed: Parsed,
        executablePathLookup: (Int32) -> String? = executablePath(forPID:),
        bsdProcessLookup: (Int32) -> (ppid: Int32, uid: UInt32, hasTTY: Bool)? = inspectBSDProcess(pid:),
        displayNameFromPath: (String) -> String? = displayName(fromExecutablePath:),
        bundleIdentifierFromPath: (String) -> String? = { bundleIdentifier(fromExecutablePath: $0) },
        outerMainExecutableFromAppPath: (String) -> String? = bundleExecutableName(atBundlePath:)
    )
        -> (processName: String?, provenance: ProcessProvenance?)
    {
        // XNU `kernel_task` frames carry `pid == 0` with no delegating user `effectivePID`.
        // Keep `processName == nil` while setting `isKernelTask == true` for classification.
        if parsed.pid == 0, parsed.effectivePID <= 0 {
            return (processName: nil, provenance: ProcessProvenance(isKernelTask: true))
        }

        func resolveLive(pid: Int32) -> (name: String, path: String)? {
            guard pid > 0,
                  let rawPath = trimmedNonEmpty(executablePathLookup(pid)),
                  let resolvedName = trimmedNonEmpty(displayNameFromPath(rawPath)) else
            {
                return nil
            }
            return (name: resolvedName, path: rawPath)
        }

        let primaryPID: Int32
        let primaryName: String
        let primaryExecPath: String?
        var delegatedViaName: String?

        if parsed.effectivePID > 0, let liveEffective = resolveLive(pid: parsed.effectivePID) {
            primaryPID = parsed.effectivePID
            primaryName = liveEffective.name
            primaryExecPath = liveEffective.path
            if parsed.pid > 0, parsed.pid != parsed.effectivePID {
                let carrier = resolveLive(pid: parsed.pid)?.name ?? trimmedNonEmpty(parsed.process)
                if let carrier, carrier != primaryName {
                    delegatedViaName = carrier
                }
            }
        } else if parsed.effectivePID > 0, let effectiveComm = trimmedNonEmpty(parsed.effectiveProcess) {
            primaryPID = parsed.effectivePID
            primaryName = effectiveComm
            primaryExecPath = nil
            if parsed.pid > 0, parsed.pid != parsed.effectivePID {
                let carrier = resolveLive(pid: parsed.pid)?.name ?? trimmedNonEmpty(parsed.process)
                if let carrier, carrier != primaryName {
                    delegatedViaName = carrier
                }
            }
        } else if let liveDirect = resolveLive(pid: parsed.pid) {
            primaryPID = parsed.pid
            primaryName = liveDirect.name
            primaryExecPath = liveDirect.path
        } else if let directComm = trimmedNonEmpty(parsed.process) {
            primaryPID = parsed.pid
            primaryName = directComm
            primaryExecPath = nil
        } else {
            return (processName: nil, provenance: nil)
        }

        let resolvedBundleID = primaryExecPath.flatMap { trimmedNonEmpty(bundleIdentifierFromPath($0)) }
        let resolvedViaName: String?
        if let delegatedViaName {
            resolvedViaName = delegatedViaName
        } else if let primaryExecPath {
            resolvedViaName = nestedHelperViaName(
                executablePath: primaryExecPath,
                outerAppDisplayName: primaryName,
                outerMainExecutableLookup: outerMainExecutableFromAppPath
            )
        } else {
            resolvedViaName = nil
        }

        let bsdInfo = primaryPID > 0 ? bsdProcessLookup(primaryPID) : nil
        let hasTTY = bsdInfo?.hasTTY ?? false
        let isRootUser = bsdInfo.map { $0.uid == 0 } ?? false
        var parentProcessName: String?
        if let ppid = bsdInfo?.ppid,
           ppid > 1,
           ppid != primaryPID,
           let parentPath = trimmedNonEmpty(executablePathLookup(ppid)),
           let parentName = trimmedNonEmpty(displayNameFromPath(parentPath))
        {
            parentProcessName = parentName
        }

        let provenance = ProcessProvenance(
            executablePath: primaryExecPath,
            bundleIdentifier: resolvedBundleID,
            viaProcessName: resolvedViaName,
            parentProcessName: parentProcessName,
            hasControllingTTY: hasTTY,
            isRootUser: isRootUser,
            isKernelTask: false
        )
        return (processName: primaryName, provenance: provenance)
    }

    // MARK: - Inbound Packet Target Parsing & Root libproc Socket Map

    /// Parses the inner IPv4/IPv6 TCP/UDP destination `(proto, ip, port)` from an
    /// unwrapped frame (`Ethernet`, `BSD Loopback`, `DLT_LOOP`, or `Raw IP`) for
    /// pure-inbound socket fallback attribution before XNU socket demux.
    static func parseInboundTarget(innerBytes bytes: [UInt8], innerDLT: UInt32) -> InboundPacketTarget? {
        switch innerDLT {
        case 1: // DLT_EN10MB (Ethernet)
            guard bytes.count >= 14 else {
                return nil
            }
            var etherType = (UInt16(bytes[12]) << 8) | UInt16(bytes[13])
            var l3Offset = 14
            var vlanTags = 0
            while (etherType == 0x8100 || etherType == 0x88A8) && vlanTags < 2 {
                guard l3Offset + 4 <= bytes.count else {
                    return nil
                }
                etherType = (UInt16(bytes[l3Offset + 2]) << 8) | UInt16(bytes[l3Offset + 3])
                l3Offset += 4
                vlanTags += 1
            }
            switch etherType {
            case 0x0800:
                return parseIPv4InboundTarget(bytes, offset: l3Offset)
            case 0x86DD:
                return parseIPv6InboundTarget(bytes, offset: l3Offset)
            default:
                return nil
            }

        case 0, 108: // DLT_NULL (BSD Loopback) / DLT_LOOP
            guard bytes.count > 4 else {
                return nil
            }
            let familyLE = u32le(bytes, 0)
            let familyBE = familyLE.byteSwapped
            if familyLE == UInt32(AF_INET) || familyBE == UInt32(AF_INET) {
                return parseIPv4InboundTarget(bytes, offset: 4)
            }
            if familyLE == UInt32(AF_INET6) || familyBE == UInt32(AF_INET6)
                || familyLE == 24 || familyBE == 24
                || familyLE == 28 || familyBE == 28
            {
                return parseIPv6InboundTarget(bytes, offset: 4)
            }
            return nil

        case 12, 101: // Darwin DLT_RAW (12) / LINKTYPE_RAW (101)
            guard !bytes.isEmpty else {
                return nil
            }
            switch bytes[0] >> 4 {
            case 4:
                return parseIPv4InboundTarget(bytes, offset: 0)
            case 6:
                return parseIPv6InboundTarget(bytes, offset: 0)
            default:
                return nil
            }

        default:
            return nil
        }
    }

    /// Collects active local interface IPs (`getifaddrs`) and all TCP/UDP sockets
    /// (`proc_listallpids` + `proc_pidfdinfo`) into a compact port map for inbound
    /// packet attribution inside `TracexyCaptureHelper`.
    static func collectInboundSocketPortMap() -> InboundSocketPortMap {
        var map = InboundSocketPortMap()
        map.localIPs = discoverLocalInboundIPKeys()

        let estimatedCount = proc_listallpids(nil, 0)
        guard estimatedCount > 0 else {
            return map
        }
        var pids = [pid_t](repeating: 0, count: max(256, Int(estimatedCount) * 2))
        let pidCount = Int(pids.withUnsafeMutableBytes { buffer in
            proc_listallpids(buffer.baseAddress, Int32(buffer.count))
        })
        guard pidCount > 0 else {
            return map
        }

        let fdStride = MemoryLayout<proc_fdinfo>.stride
        let socketInfoSize = Int32(MemoryLayout<socket_fdinfo>.size)
        var timeWaitKeys: Set<InboundSocketPortMap.SpecificKey> = []

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
                guard family == AF_INET || family == AF_INET6 else {
                    continue
                }
                let proto: TransportProto
                let insi: in_sockinfo
                if kind == SOCKINFO_TCP {
                    proto = .tcp
                    insi = sinfo.psi.soi_proto.pri_tcp.tcpsi_ini
                } else if kind == SOCKINFO_IN,
                          sinfo.psi.soi_protocol == IPPROTO_UDP || sinfo.psi.soi_protocol == 0
                {
                    proto = .udp
                    insi = sinfo.psi.soi_proto.pri_in
                } else {
                    continue
                }
                let port = UInt16(bigEndian: UInt16(truncatingIfNeeded: insi.insi_lport))
                guard port > 0,
                      let ipKey = extractInboundSocketLocalIP(insi: insi, family: family) else
                {
                    continue
                }
                if map.commandByPID[pid] == nil {
                    map.commandByPID[pid] = procCommandName(forPID: pid)
                }
                if ipKey.isWildcard {
                    let wildcardKey = InboundSocketPortMap.WildcardKey(proto: proto, port: port)
                    if map.wildcard[wildcardKey] == nil {
                        map.wildcard[wildcardKey] = pid
                    }
                } else {
                    let isTimeWait = kind == SOCKINFO_TCP
                        && sinfo.psi.soi_proto.pri_tcp.tcpsi_state == TSI_S_TIME_WAIT
                    let specificKey = InboundSocketPortMap.SpecificKey(proto: proto, ip: ipKey, port: port)
                    if map.specific[specificKey] == nil {
                        map.specific[specificKey] = pid
                        if isTimeWait {
                            timeWaitKeys.insert(specificKey)
                        }
                    } else if !isTimeWait, timeWaitKeys.contains(specificKey) {
                        map.specific[specificKey] = pid
                        timeWaitKeys.remove(specificKey)
                    }
                }
            }
        }
        return map
    }

    // MARK: Private

    /// Field byte offsets within the (little-endian, host-order) header.
    /// `pth_svc` is uint32-aligned after the 17-byte `pth_comm`, so 3 bytes of
    /// padding push `pth_epid` to offset 84 and `pth_ecomm` to offset 88.
    private enum Field {
        static let length = 0 // uint32 pth_length (size of this header)
        static let typeNext = 4 // uint32 pth_type_next (0 = NONE, 1 = PACKET, 2 = DROP)
        static let innerDLT = 8 // uint32 pth_dlt (DLT of the wrapped frame)
        static let ifName = 12 // char[24] pth_ifname
        static let pid = 52 // int32 pth_pid
        static let comm = 56 // char[17] pth_comm (process name)
        static let epid = 84 // int32 pth_epid (effective / delegating process)
        static let ecomm = 88 // char[17] pth_ecomm (effective / delegating process name)
        static let minimumSize = 73 // through the end of pth_comm
    }

    private static let nonAppBundleSuffixes = [
        ".systemextension/",
        ".appex/",
        ".xpc/",
        ".framework/",
    ]

    private static func trimmedNonEmpty(_ value: String?) -> String? {
        guard let trimmed = value?.trimmingCharacters(in: .whitespacesAndNewlines),
              !trimmed.isEmpty else
        {
            return nil
        }
        return trimmed
    }

    private static func candidateBundlePaths(fromExecutablePath path: String) -> [String] {
        if let outerApp = outermostAppBundlePath(fromExecutablePath: path) {
            return [outerApp]
        }
        var matches: [(lowerBound: String.Index, bundlePath: String)] = []
        for suffix in nonAppBundleSuffixes {
            if let range = path.range(of: suffix) {
                let bundlePrefix = String(path[..<range.lowerBound])
                let bundleName = (bundlePrefix as NSString).lastPathComponent
                if !bundlePrefix.isEmpty, !bundleName.isEmpty, bundleName != "/" {
                    let suffixWithoutSlash = String(suffix.dropLast())
                    matches.append((range.lowerBound, bundlePrefix + suffixWithoutSlash))
                }
            }
        }
        matches.sort { $0.lowerBound < $1.lowerBound }
        return matches.map(\.bundlePath)
    }

    private static func nonEmptyBundleValue(forKey key: String, in bundle: Bundle) -> String? {
        if let localized = (bundle.object(forInfoDictionaryKey: key) as? String)?
            .trimmingCharacters(in: .whitespacesAndNewlines),
            !localized.isEmpty
        {
            return localized
        }
        if let raw = (bundle.infoDictionary?[key] as? String)?
            .trimmingCharacters(in: .whitespacesAndNewlines),
            !raw.isEmpty
        {
            return raw
        }
        return nil
    }

    private static func parseIPv4InboundTarget(_ bytes: [UInt8], offset: Int) -> InboundPacketTarget? {
        guard offset + 20 <= bytes.count, (bytes[offset] >> 4) == 4 else {
            return nil
        }
        let ihl = Int(bytes[offset] & 0x0F) * 4
        guard ihl >= 20, offset + ihl + 4 <= bytes.count else {
            return nil
        }
        let fragOffset = ((UInt16(bytes[offset + 6]) << 8) | UInt16(bytes[offset + 7])) & 0x1FFF
        guard fragOffset == 0,
              let proto = TransportProto(rawValue: bytes[offset + 9]) else
        {
            return nil
        }
        let dstIP4 = (UInt32(bytes[offset + 16]) << 24)
            | (UInt32(bytes[offset + 17]) << 16)
            | (UInt32(bytes[offset + 18]) << 8)
            | UInt32(bytes[offset + 19])
        let l4 = offset + ihl
        let dstPort = (UInt16(bytes[l4 + 2]) << 8) | UInt16(bytes[l4 + 3])
        guard dstPort > 0 else {
            return nil
        }
        return InboundPacketTarget(proto: proto, destinationIP: .v4(dstIP4), destinationPort: dstPort)
    }

    private static func parseIPv6InboundTarget(_ bytes: [UInt8], offset: Int) -> InboundPacketTarget? {
        guard offset + 40 <= bytes.count, (bytes[offset] >> 4) == 6 else {
            return nil
        }
        let d = offset + 24
        let dstIP = InboundIPKey.normalizedV6(
            bytes[d], bytes[d + 1], bytes[d + 2], bytes[d + 3],
            bytes[d + 4], bytes[d + 5], bytes[d + 6], bytes[d + 7],
            bytes[d + 8], bytes[d + 9], bytes[d + 10], bytes[d + 11],
            bytes[d + 12], bytes[d + 13], bytes[d + 14], bytes[d + 15]
        )
        var nextHeader = bytes[offset + 6]
        var cursor = offset + 40
        for _ in 0 ..< 6 {
            if let proto = TransportProto(rawValue: nextHeader) {
                guard cursor + 4 <= bytes.count else {
                    return nil
                }
                let dstPort = (UInt16(bytes[cursor + 2]) << 8) | UInt16(bytes[cursor + 3])
                guard dstPort > 0 else {
                    return nil
                }
                return InboundPacketTarget(proto: proto, destinationIP: dstIP, destinationPort: dstPort)
            }
            if nextHeader == 0 || nextHeader == 43 || nextHeader == 60 {
                guard cursor + 2 <= bytes.count else {
                    return nil
                }
                let extLen = (Int(bytes[cursor + 1]) + 1) * 8
                nextHeader = bytes[cursor]
                cursor += extLen
            } else if nextHeader == 44 {
                guard cursor + 8 <= bytes.count else {
                    return nil
                }
                let fragOff = ((UInt16(bytes[cursor + 2]) << 8) | UInt16(bytes[cursor + 3])) & 0xFFF8
                guard fragOff == 0 else {
                    return nil
                }
                nextHeader = bytes[cursor]
                cursor += 8
            } else {
                return nil
            }
        }
        return nil
    }

    private static func discoverLocalInboundIPKeys() -> Set<InboundIPKey> {
        var keys: Set<InboundIPKey> = [.v4(0x7F00_0001), .v6(0, 1)]
        var firstAddress: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&firstAddress) == 0, let head = firstAddress else {
            return keys
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
                let sin = sockaddrPtr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee }
                keys.insert(.v4(UInt32(bigEndian: sin.sin_addr.s_addr)))
            } else if family == AF_INET6 {
                var sin6 = sockaddrPtr.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { $0.pointee }
                let key = withUnsafeBytes(of: &sin6.sin6_addr) { raw -> InboundIPKey? in
                    guard raw.count == 16 else {
                        return nil
                    }
                    return InboundIPKey.normalizedV6(
                        raw[0], raw[1], raw[2], raw[3],
                        raw[4], raw[5], raw[6], raw[7],
                        raw[8], raw[9], raw[10], raw[11],
                        raw[12], raw[13], raw[14], raw[15]
                    )
                }
                if let key {
                    keys.insert(key)
                }
            }
        }
        return keys
    }

    private static func extractInboundSocketLocalIP(insi: in_sockinfo, family: Int32) -> InboundIPKey? {
        let hasIPv4 = (insi.insi_vflag & UInt8(INI_IPV4)) != 0
        let hasIPv6 = (insi.insi_vflag & UInt8(INI_IPV6)) != 0

        if (hasIPv4 && !hasIPv6) || (!hasIPv4 && !hasIPv6 && family == AF_INET) {
            return .v4(UInt32(bigEndian: insi.insi_laddr.ina_46.i46a_addr4.s_addr))
        }
        if hasIPv6 || (!hasIPv4 && !hasIPv6 && family == AF_INET6) {
            var addr6 = insi.insi_laddr.ina_6
            let v6Key = withUnsafeBytes(of: &addr6) { raw -> InboundIPKey? in
                guard raw.count == 16 else {
                    return nil
                }
                let isMappedV4 = raw[0 ..< 10].allSatisfy { $0 == 0 } && raw[10] == 0xFF && raw[11] == 0xFF
                if isMappedV4 {
                    return .v4(UInt32(bigEndian: insi.insi_laddr.ina_46.i46a_addr4.s_addr))
                }
                return InboundIPKey.normalizedV6(
                    raw[0], raw[1], raw[2], raw[3],
                    raw[4], raw[5], raw[6], raw[7],
                    raw[8], raw[9], raw[10], raw[11],
                    raw[12], raw[13], raw[14], raw[15]
                )
            }
            return v6Key
        }
        return nil
    }

    private static func procCommandName(forPID pid: Int32) -> String {
        guard pid > 0 else {
            return ""
        }
        var nameBuffer = [CChar](repeating: 0, count: 256)
        if proc_name(pid, &nameBuffer, UInt32(nameBuffer.count)) > 0 {
            let name = decodeNullTerminatedUTF8(nameBuffer).trimmingCharacters(in: .whitespacesAndNewlines)
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

    private static func decodeNullTerminatedUTF8(_ buffer: [CChar]) -> String {
        let prefix = buffer.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }
        return String(decoding: prefix, as: UTF8.self)
    }

    private static func u32le(_ bytes: [UInt8], _ offset: Int) -> UInt32 {
        UInt32(bytes[offset])
            | (UInt32(bytes[offset + 1]) << 8)
            | (UInt32(bytes[offset + 2]) << 16)
            | (UInt32(bytes[offset + 3]) << 24)
    }

    private static func cString(_ bytes: [UInt8], at offset: Int, max: Int) -> String {
        var scalars: [UInt8] = []
        for index in offset ..< min(offset + max, bytes.count) {
            let byte = bytes[index]
            if byte == 0 {
                break
            }
            scalars.append(byte)
        }
        return String(bytes: scalars, encoding: .utf8) ?? ""
    }
}
