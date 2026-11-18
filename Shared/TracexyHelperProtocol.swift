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

    /// Resolves a live process's display name via `Darwin.proc_pidpath`.
    static func resolveDisplayName(forPID pid: Int32) -> String? {
        guard pid > 0 else {
            return nil
        }
        var buffer = [CChar](repeating: 0, count: 4_096)
        guard proc_pidpath(pid, &buffer, UInt32(buffer.count)) > 0 else {
            return nil
        }
        return displayName(fromExecutablePath: String(cString: buffer))
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
