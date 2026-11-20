import Foundation
import OSLog

/// libpcap-backed live capture for the privileged helper.
///
/// Teardown is race-free via ``CaptureWorkerLifecycle``: the caller requests stop
/// and waits, and only the worker thread reads stats, does the final flush, and
/// closes the pcap handle before signaling. Closing the handle from the caller's
/// thread while `pcap_next_ex` is mid-read frees it under the reader and crashes
/// (`EXC_BAD_ACCESS` in `pcap_read_bpf`) — so the close lives on the worker.
final class PcapCapture: @unchecked Sendable {
    // MARK: Lifecycle

    init() throws {
        guard let library = dlopen("/usr/lib/libpcap.A.dylib", RTLD_NOW) ?? dlopen("libpcap.A.dylib", RTLD_NOW) else {
            throw Failure(message: "libpcap not available")
        }
        self.library = library
        openLive = try PcapCapture.symbol(library, "pcap_open_live", as: OpenLiveFn.self)
        nextEx = try PcapCapture.symbol(library, "pcap_next_ex", as: NextExFn.self)
        closeHandle = try PcapCapture.symbol(library, "pcap_close", as: CloseFn.self)
        dataLink = try PcapCapture.symbol(library, "pcap_datalink", as: DataLinkFn.self)
        // Optional: `pcap_stats` is unsupported on some sources, so a missing
        // symbol must not fail the capture — the app is then told accounting is
        // unavailable rather than shown a fabricated clean figure.
        stats = try? PcapCapture.symbol(library, "pcap_stats", as: StatsFn.self)
        // Optional: only needed when a BPF filter is configured. Resolved lazily so
        // a plain (no-filter) capture never fails on a missing symbol; a requested
        // filter with these unavailable fails the start with a clear message.
        compileFilter = try? PcapCapture.symbol(library, "pcap_compile", as: CompileFn.self)
        setFilter = try? PcapCapture.symbol(library, "pcap_setfilter", as: SetFilterFn.self)
        freeCode = try? PcapCapture.symbol(library, "pcap_freecode", as: FreeCodeFn.self)
        getError = try? PcapCapture.symbol(library, "pcap_geterr", as: GetErrFn.self)
        // Optional: macOS `pktap` per-packet process attribution + user-space BPF
        // evaluation (`pcap_compile` fails directly on `DLT_PKTAP = 258`).
        createHandle = try? PcapCapture.symbol(library, "pcap_create", as: CreateFn.self)
        setSnaplen = try? PcapCapture.symbol(library, "pcap_set_snaplen", as: SetIntOptionFn.self)
        setPromisc = try? PcapCapture.symbol(library, "pcap_set_promisc", as: SetIntOptionFn.self)
        setTimeout = try? PcapCapture.symbol(library, "pcap_set_timeout", as: SetIntOptionFn.self)
        setBufferSize = try? PcapCapture.symbol(library, "pcap_set_buffer_size", as: SetIntOptionFn.self)
        setWantPktap = try? PcapCapture.symbol(library, "pcap_set_want_pktap", as: SetIntOptionFn.self)
        setDataLink = try? PcapCapture.symbol(library, "pcap_set_datalink", as: SetIntOptionFn.self)
        dataLinkNameToVal = try? PcapCapture.symbol(library, "pcap_datalink_name_to_val", as: DataLinkNameToValFn.self)
        activateHandle = try? PcapCapture.symbol(library, "pcap_activate", as: ActivateFn.self)
        openDead = try? PcapCapture.symbol(library, "pcap_open_dead", as: OpenDeadFn.self)
        offlineFilter = try? PcapCapture.symbol(library, "pcap_offline_filter", as: OfflineFilterFn.self)
    }

    // MARK: Internal

    /// Requested kernel BPF ring buffer size (`16 MB`) applied before `pcap_activate`
    /// so high-rate `pktap` captures (carrying 108–256-byte outer headers) and live
    /// BPF handles avoid dropping outbound packets before read-loop drain.
    static let defaultKernelBufferSize: Int32 = 16 * 1024 * 1024

    struct Failure: Error { let message: String }

    /// pcap_pkthdr — must match the C layout: { struct timeval ts; u32 caplen; u32 len }.
    struct PcapPacketHeader {
        var ts: timeval
        var caplen: UInt32
        var len: UInt32
    }

    /// True when `interface` explicitly targets a macOS `pktap`/`iptap`
    /// pseudo-interface (either all-interfaces `"pktap"`/`"iptap"` or a
    /// scoped `"pktap,<if>"`/`"iptap,<if>"` selector).
    static func isExplicitPktapInterface(_ interface: String) -> Bool {
        let lower = interface.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return lower == "pktap" || lower.hasPrefix("pktap,") || lower == "iptap" || lower.hasPrefix("iptap,")
    }

    /// True when `interface` is the all-interfaces `"pktap"` or `"iptap"`
    /// pseudo-interface without a single-interface suffix.
    static func isAllInterfacesPktap(_ interface: String) -> Bool {
        let lower = interface.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return lower == "pktap" || lower == "iptap"
    }

    /// Expected standard inner link type for an interface when `pktap` wraps frames
    /// in `DLT_PKTAP (258)`: BSD Loopback (`0`) for `lo*` and tunnel interfaces,
    /// Ethernet (`1`) otherwise.
    static func expectedInnerDLT(for interface: String) -> UInt32 {
        let lower = normalizedInterfaceName(interface)
        if lower.hasPrefix("lo") || isTunnelInterface(lower) {
            return dltNull
        }
        return dltEthernet
    }

    /// Start capturing on `interface`.
    ///
    /// - `onBatch` delivers typed frames, each carrying its own libpcap timestamp,
    ///   captured length, original on-wire length, and link type.
    /// - `onStatistics` delivers a `pcap_stats` sample, or `nil` when accounting
    ///   is unavailable — never a silent gap the UI would read as "no loss".
    ///
    /// Opening the handle happens synchronously: on failure this throws (so the
    /// caller never reports a started capture that isn't running), and on success
    /// it returns a standard link type (DLT) *before* the worker starts, so the
    /// caller can report an authoritative link type even before the first frame
    /// arrives.
    /// - `onReadFailure` fires once, from the worker, when libpcap reports a read
    ///   error (the interface went away, the device was reconfigured) and the loop
    ///   ends on its own. It never fires for an ordinary `stop()`.
    @discardableResult
    func start(
        configuration: CaptureConfiguration,
        onBatch: @escaping @Sendable ([CapturedFrameMessage]) -> Void,
        onStatistics: @escaping @Sendable (HelperCaptureStats?) -> Void,
        onReadFailure: @escaping @Sendable (String) -> Void = { _ in }
    )
        throws -> UInt32
    {
        lifecycle.stop()
        // Re-validate on the privileged side even though the app validated too:
        // bounds must hold regardless of what crossed the wire (defense in depth).
        let config: CaptureConfiguration
        switch configuration.validated() {
        case let .success(normalized):
            config = normalized
        case let .failure(error):
            throw Failure(message: error.message)
        }
        let snaplen = Int32(config.snapLength)
        // macOS XNU `pktap`/`iptap` pseudo-interfaces do not support promiscuous
        // mode; always pass `promisc = 0` so explicit `pktap` captures activate
        // with `DLT_PKTAP (149)` even when Promiscuous Mode is enabled in Settings.
        let isExplicitPktap = Self.isExplicitPktapInterface(config.interface)
        let promisc: Int32 = (!isExplicitPktap && config.promiscuous) ? 1 : 0
        let handle: OpaquePointer
        if let pktapHandle = openPktapHandle(interface: config.interface, snaplen: snaplen, promisc: promisc) {
            handle = pktapHandle
        } else if let bufferedLiveHandle = openLiveHandle(
            interface: config.interface,
            snaplen: snaplen,
            promisc: promisc
        ) {
            handle = bufferedLiveHandle
        } else {
            var errbuf = [CChar](repeating: 0, count: 256)
            guard let liveHandle = config.interface.withCString({ name in
                openLive(name, snaplen, promisc, 100, &errbuf)
            }) else {
                throw Failure(message: String(cString: errbuf))
            }
            handle = liveHandle
        }

        let rawDLT = UInt32(bitPattern: dataLink(handle))
        let isPktap = PktapHeader.isPktapDLT(rawDLT)
        let reportedLinkType = isPktap
            ? Self.expectedInnerDLT(for: config.interface)
            : rawDLT
        if isPktap {
            Self.logger.notice(
                "Activated pktap capture on \(config.interface, privacy: .public) (rawDLT=\(rawDLT), innerDLT=\(reportedLinkType), snaplen=\(snaplen))"
            )
        } else {
            Self.logger.notice(
                "Activated plain BPF capture on \(config.interface, privacy: .public) (rawDLT=\(rawDLT), promisc=\(promisc), snaplen=\(snaplen))"
            )
        }

        // Compile + validate any BPF filter before reporting the capture started.
        // Calling `pcap_compile` directly on `DLT_PKTAP` (`149` / `258`) fails on macOS,
        // so `pktap` captures validate synchronously against a dead handle for the
        // expected inner DLT and then evaluate per inner frame in user space.
        if let expression = config.bpf {
            do {
                if isPktap {
                    try validatePktapFilter(
                        expression,
                        optimizerFlag: config.bpfOptimizerFlag,
                        interface: config.interface,
                        snaplen: snaplen
                    )
                } else {
                    try applyFilter(expression, optimizerFlag: config.bpfOptimizerFlag, handle: handle)
                }
            } catch {
                closeHandle(handle)
                throw error
            }
        }
        // The raw C handle and close fn are not `Sendable`; carry them across the
        // worker boundary in a narrow `@unchecked Sendable` box rather than
        // suppressing concurrency checking. The handle is only ever touched on the
        // worker thread that owns the read loop.
        let owned = OwnedHandle(handle: handle, close: closeHandle)
        let bpfExpression = config.bpf
        let bpfOptimizerFlag = config.bpfOptimizerFlag
        lifecycle.start(name: "com.amunx.tracexy.helper.capture") { [weak self] isRunning in
            self?.loop(
                handle: owned.handle,
                rawDLT: rawDLT,
                snaplen: snaplen,
                bpfExpression: bpfExpression,
                bpfOptimizerFlag: bpfOptimizerFlag,
                isRunning: isRunning,
                onBatch: onBatch,
                onStatistics: onStatistics,
                onReadFailure: onReadFailure
            )
            // Close on the SAME thread that read from it, and only after the loop
            // has fully exited. See the type comment.
            owned.close(owned.handle)
        }
        return reportedLinkType
    }

    /// Requests stop and blocks until the worker has flushed, closed its handle,
    /// and exited. Idempotent.
    func stop() {
        lifecycle.stop()
    }

    // MARK: Private

    /// Narrow `@unchecked Sendable` owner for the raw pcap handle and its close
    /// function, so the worker closure can carry them across the concurrency
    /// boundary without globally suppressing checking. Safe because the handle is
    /// only ever dereferenced (and closed) on the single worker thread.
    private struct OwnedHandle: @unchecked Sendable {
        let handle: OpaquePointer
        let close: CloseFn
    }

    private enum CachedInnerFilter {
        case compiled(deadHandle: OpaquePointer, program: UnsafeMutableRawPointer)
        case rejected
    }

    private typealias OpenLiveFn = @convention(c) (
        UnsafePointer<CChar>?,
        Int32,
        Int32,
        Int32,
        UnsafeMutablePointer<CChar>?
    )
        -> OpaquePointer?
    private typealias NextExFn = @convention(c) (
        OpaquePointer?,
        UnsafeMutablePointer<UnsafeMutableRawPointer?>?,
        UnsafeMutablePointer<UnsafePointer<UInt8>?>?
    )
        -> Int32
    private typealias CloseFn = @convention(c) (OpaquePointer?) -> Void
    private typealias DataLinkFn = @convention(c) (OpaquePointer?) -> Int32
    private typealias StatsFn = @convention(c) (OpaquePointer?, UnsafeMutableRawPointer?) -> Int32
    /// `int pcap_compile(pcap_t*, struct bpf_program*, const char*, int optimize, bpf_u_int32 netmask)`.
    private typealias CompileFn = @convention(c) (
        OpaquePointer?, UnsafeMutableRawPointer?, UnsafePointer<CChar>?, Int32, UInt32
    )
        -> Int32
    /// `int pcap_setfilter(pcap_t*, struct bpf_program*)`.
    private typealias SetFilterFn = @convention(c) (OpaquePointer?, UnsafeMutableRawPointer?) -> Int32
    /// `void pcap_freecode(struct bpf_program*)`.
    private typealias FreeCodeFn = @convention(c) (UnsafeMutableRawPointer?) -> Void
    /// `char *pcap_geterr(pcap_t*)`.
    private typealias GetErrFn = @convention(c) (OpaquePointer?) -> UnsafePointer<CChar>?
    /// `pcap_t *pcap_create(const char *source, char *errbuf)`.
    private typealias CreateFn = @convention(c) (
        UnsafePointer<CChar>?,
        UnsafeMutablePointer<CChar>?
    )
        -> OpaquePointer?
    /// `int pcap_set_{snaplen,promisc,timeout,buffer_size,want_pktap,datalink}(pcap_t*, int)`.
    private typealias SetIntOptionFn = @convention(c) (OpaquePointer?, Int32) -> Int32
    /// `int pcap_datalink_name_to_val(const char *)`.
    private typealias DataLinkNameToValFn = @convention(c) (UnsafePointer<CChar>?) -> Int32
    /// `int pcap_activate(pcap_t*)`.
    private typealias ActivateFn = @convention(c) (OpaquePointer?) -> Int32
    /// `pcap_t *pcap_open_dead(int linktype, int snaplen)`.
    private typealias OpenDeadFn = @convention(c) (Int32, Int32) -> OpaquePointer?
    /// `int pcap_offline_filter(const struct bpf_program*, const struct pcap_pkthdr*, const u_char*)`.
    private typealias OfflineFilterFn = @convention(c) (
        UnsafeRawPointer?,
        UnsafeRawPointer?,
        UnsafePointer<UInt8>?
    )
        -> Int32

    private static let bpfProgramSize = 16
    private static let bpfNetmaskUnknown: UInt32 = 0xFFFFFFFF
    private static let dltNull: UInt32 = 0
    private static let dltEthernet: UInt32 = 1
    /// Darwin `<net/bpf.h>` `DLT_RAW = 12` expected by macOS `pcap_open_dead`.
    private static let darwinDLTRawIP: UInt32 = 12
    /// Standard pcap/pcapng `LINKTYPE_RAW = 101` expected by `PacketDecoder` and savefiles.
    private static let linkTypeRawIP: UInt32 = 101
    /// Extra outer snaplen headroom so `DLT_PKTAP (258)` metadata (`108–256` bytes)
    /// never starves small user snap lengths such as 64 or 128 bytes.
    private static let pktapSnaplenHeadroom: Int32 = 512
    private static let maxInnerFilterCacheEntries = 64
    private static let logger = Logger(subsystem: TracexyIdentity.current.logSubsystem, category: "PcapCapture")

    private let library: UnsafeMutableRawPointer
    private let openLive: OpenLiveFn
    private let nextEx: NextExFn
    private let closeHandle: CloseFn
    private let dataLink: DataLinkFn
    private let stats: StatsFn?
    private let compileFilter: CompileFn?
    private let setFilter: SetFilterFn?
    private let freeCode: FreeCodeFn?
    private let getError: GetErrFn?
    private let createHandle: CreateFn?
    private let setSnaplen: SetIntOptionFn?
    private let setPromisc: SetIntOptionFn?
    private let setTimeout: SetIntOptionFn?
    private let setBufferSize: SetIntOptionFn?
    private let setWantPktap: SetIntOptionFn?
    private let setDataLink: SetIntOptionFn?
    private let dataLinkNameToVal: DataLinkNameToValFn?
    private let activateHandle: ActivateFn?
    private let openDead: OpenDeadFn?
    private let offlineFilter: OfflineFilterFn?

    private let lifecycle = CaptureWorkerLifecycle()

    private static func normalizedInterfaceName(_ interface: String) -> String {
        let lower = interface.lowercased()
        if lower.hasPrefix("pktap,") {
            return String(lower.dropFirst("pktap,".count))
        }
        if lower.hasPrefix("iptap,") {
            return String(lower.dropFirst("iptap,".count))
        }
        return lower
    }

    private static func isTunnelInterface(_ interface: String) -> Bool {
        let lower = normalizedInterfaceName(interface)
        return lower.hasPrefix("utun")
            || lower.hasPrefix("gif")
            || lower.hasPrefix("stf")
            || lower.hasPrefix("ipsec")
            || lower.hasPrefix("ppp")
    }

    private static func symbol<T>(_ library: UnsafeMutableRawPointer, _ name: String, as _: T.Type) throws -> T {
        guard let pointer = dlsym(library, name) else {
            throw Failure(message: "missing symbol \(name)")
        }
        return unsafeBitCast(pointer, to: T.self)
    }

    /// Tries to open a `pktap` capture handle (`DLT_PKTAP = 149` on Darwin `<net/bpf.h>`,
    /// `LINKTYPE_PKTAP = 258` in savefiles).
    ///
    /// On macOS, `libpcap` only clones a `pktap` pseudo-interface when `pcap_create`
    /// is given `"pktap,<interface>"` and promiscuous mode is disabled (`man tcpdump`),
    /// and `/usr/sbin/tcpdump` selects `"PKTAP"` (`149`) via `pcap_set_datalink` after
    /// `pcap_activate`. Returns `nil` and closes any intermediate handle if `promisc != 0`,
    /// `interface` is a pipe/file path, or `PKTAP` link type activation fails.
    private func openPktapHandle(interface: String, snaplen: Int32, promisc: Int32) -> OpaquePointer? {
        guard promisc == 0,
              !interface.contains("/"),
              let createHandle,
              let setSnaplen,
              let setTimeout,
              let activateHandle else
        {
            return nil
        }
        let source = Self.isExplicitPktapInterface(interface)
            ? interface
            : "pktap,\(interface)"
        var errbuf = [CChar](repeating: 0, count: 256)
        guard let handle = source.withCString({ name in createHandle(name, &errbuf) }) else {
            return nil
        }
        let outerSnaplen = snaplen + Self.pktapSnaplenHeadroom
        guard setSnaplen(handle, outerSnaplen) == 0,
              setTimeout(handle, 100) == 0 else
        {
            closeHandle(handle)
            return nil
        }
        // Request a 16 MB kernel BPF ring buffer before `pcap_activate`; ignore
        // any non-zero return so an OS/device clamp never prevents capture start.
        _ = setBufferSize?(handle, Self.defaultKernelBufferSize)
        _ = setWantPktap?(handle, 1)
        guard activateHandle(handle) >= 0 else {
            closeHandle(handle)
            return nil
        }
        if !PktapHeader.isPktapDLT(UInt32(bitPattern: dataLink(handle))) {
            let resolvedDLT = "PKTAP".withCString { name in dataLinkNameToVal?(name) } ?? -1
            let targetDLT = resolvedDLT > 0 ? resolvedDLT : Int32(bitPattern: PktapHeader.darwinDLT)
            _ = setDataLink?(handle, targetDLT)
        }
        guard PktapHeader.isPktapDLT(UInt32(bitPattern: dataLink(handle))) else {
            closeHandle(handle)
            return nil
        }
        return handle
    }

    /// Opens a plain BPF live handle via `pcap_create` so `pcap_set_buffer_size`
    /// (`16 MB`) applies before `pcap_activate` even when `pktap` is bypassed
    /// (for example in promiscuous mode). Returns `nil` to fall back to
    /// `pcap_open_live` when unavailable or if activation fails.
    private func openLiveHandle(interface: String, snaplen: Int32, promisc: Int32) -> OpaquePointer? {
        guard !interface.contains("/"),
              let createHandle,
              let setSnaplen,
              let setPromisc,
              let setTimeout,
              let activateHandle else
        {
            return nil
        }
        var errbuf = [CChar](repeating: 0, count: 256)
        guard let handle = interface.withCString({ name in createHandle(name, &errbuf) }) else {
            return nil
        }
        guard setSnaplen(handle, snaplen) == 0,
              setPromisc(handle, promisc) == 0,
              setTimeout(handle, 100) == 0 else
        {
            closeHandle(handle)
            return nil
        }
        _ = setBufferSize?(handle, Self.defaultKernelBufferSize)
        guard activateHandle(handle) >= 0 else {
            closeHandle(handle)
            return nil
        }
        return handle
    }

    /// Compile and install a BPF filter on an open handle, freeing the compiled
    /// program on every path. Throws with libpcap's own error text (via
    /// `pcap_geterr`) so a bad expression surfaces the real reason.
    private func applyFilter(_ expression: String, optimizerFlag: Int32, handle: OpaquePointer) throws {
        guard let compileFilter, let setFilter, let freeCode else {
            throw Failure(message: "BPF filtering is unavailable on this system.")
        }
        // `struct bpf_program { u_int bf_len; struct bpf_insn *bf_insns; }` is 16
        // bytes on LP64. Zero it so a failed compile leaves nothing to free.
        let program = UnsafeMutableRawPointer.allocate(byteCount: Self.bpfProgramSize, alignment: 8)
        program.initializeMemory(as: UInt8.self, repeating: 0, count: Self.bpfProgramSize)
        defer { program.deallocate() }
        let compiled = expression.withCString { cstr in
            compileFilter(handle, program, cstr, optimizerFlag, Self.bpfNetmaskUnknown)
        }
        guard compiled == 0 else {
            throw Failure(message: filterErrorMessage(handle: handle, fallback: "invalid BPF filter expression."))
        }
        // Once compiled, free the program regardless of how setfilter goes — the
        // kernel/handle keeps its own copy after a successful install.
        defer { freeCode(program) }
        guard setFilter(handle, program) == 0 else {
            throw Failure(message: filterErrorMessage(handle: handle, fallback: "could not apply the BPF filter."))
        }
    }

    /// Validates a BPF filter synchronously against a dead handle for the expected
    /// inner DLT so an invalid expression still fails closed before `start()`
    /// returns. All-interfaces `pktap`/`iptap` probes Ethernet (`1`), BSD Loopback
    /// (`0`), and Darwin `DLT_RAW (12)`, succeeding when any compiles the filter.
    /// Tunnel interfaces (`0` BSD Loopback) also try Darwin `DLT_RAW (12)`.
    func validatePktapFilter(
        _ expression: String,
        optimizerFlag: Int32,
        interface: String,
        snaplen: Int32
    )
        throws
    {
        guard openDead != nil, compileFilter != nil, freeCode != nil, offlineFilter != nil else {
            throw Failure(message: "BPF filtering is unavailable on this system.")
        }
        let probeDLTs: [UInt32] = if Self.isAllInterfacesPktap(interface) {
            [Self.dltEthernet, Self.dltNull, Self.darwinDLTRawIP]
        } else if Self.isTunnelInterface(interface) {
            [Self.expectedInnerDLT(for: interface), Self.darwinDLTRawIP]
        } else {
            [Self.expectedInnerDLT(for: interface)]
        }

        var primaryError: Error?
        for dlt in probeDLTs {
            do {
                try compileDeadFilterProbe(
                    expression,
                    optimizerFlag: optimizerFlag,
                    dlt: dlt,
                    snaplen: snaplen
                )
                return
            } catch {
                if primaryError == nil {
                    primaryError = error
                }
            }
        }
        if let primaryError {
            throw primaryError
        }
    }

    private func compileDeadFilterProbe(
        _ expression: String,
        optimizerFlag: Int32,
        dlt: UInt32,
        snaplen: Int32
    )
        throws
    {
        guard let openDead, let compileFilter, let freeCode else {
            throw Failure(message: "BPF filtering is unavailable on this system.")
        }
        let pcapDLT = dlt == Self.linkTypeRawIP ? Self.darwinDLTRawIP : dlt
        guard let deadHandle = openDead(Int32(bitPattern: pcapDLT), snaplen) else {
            throw Failure(message: "BPF filtering is unavailable on this system.")
        }
        defer { closeHandle(deadHandle) }

        let program = UnsafeMutableRawPointer.allocate(byteCount: Self.bpfProgramSize, alignment: 8)
        program.initializeMemory(as: UInt8.self, repeating: 0, count: Self.bpfProgramSize)
        defer { program.deallocate() }

        let compiled = expression.withCString { cstr in
            compileFilter(deadHandle, program, cstr, optimizerFlag, Self.bpfNetmaskUnknown)
        }
        guard compiled == 0 else {
            throw Failure(message: filterErrorMessage(handle: deadHandle, fallback: "invalid BPF filter expression."))
        }
        freeCode(program)
    }

    private func compileCachedInnerFilter(
        expression: String,
        optimizerFlag: Int32,
        dlt: UInt32,
        snaplen: Int32
    )
        -> CachedInnerFilter
    {
        let pcapDLT = dlt == Self.linkTypeRawIP ? Self.darwinDLTRawIP : dlt
        guard let openDead,
              let compileFilter,
              let deadHandle = openDead(Int32(bitPattern: pcapDLT), snaplen) else
        {
            return .rejected
        }
        let program = UnsafeMutableRawPointer.allocate(byteCount: Self.bpfProgramSize, alignment: 8)
        program.initializeMemory(as: UInt8.self, repeating: 0, count: Self.bpfProgramSize)
        let compiled = expression.withCString { cstr in
            compileFilter(deadHandle, program, cstr, optimizerFlag, Self.bpfNetmaskUnknown)
        }
        guard compiled == 0 else {
            program.deallocate()
            closeHandle(deadHandle)
            return .rejected
        }
        return .compiled(deadHandle: deadHandle, program: program)
    }

    private func matchesInnerFilter(
        expression: String,
        optimizerFlag: Int32,
        snaplen: Int32,
        innerDLT: UInt32,
        innerHeader: PcapPacketHeader,
        innerBytes: [UInt8],
        cache: inout [UInt32: CachedInnerFilter]
    )
        -> Bool
    {
        guard let offlineFilter else {
            return false
        }
        let entry: CachedInnerFilter
        if let existing = cache[innerDLT] {
            entry = existing
        } else {
            if cache.count >= Self.maxInnerFilterCacheEntries {
                releaseInnerFilterCache(&cache)
            }
            let compiled = compileCachedInnerFilter(
                expression: expression,
                optimizerFlag: optimizerFlag,
                dlt: innerDLT,
                snaplen: snaplen
            )
            cache[innerDLT] = compiled
            entry = compiled
        }
        guard case let .compiled(_, program) = entry else {
            return false
        }
        var headerCopy = innerHeader
        var emptyByte: UInt8 = 0
        return withUnsafePointer(to: &headerCopy) { headerPtr in
            innerBytes.withUnsafeBufferPointer { buffer in
                if let baseAddress = buffer.baseAddress {
                    return offlineFilter(UnsafeRawPointer(program), UnsafeRawPointer(headerPtr), baseAddress) != 0
                }
                return withUnsafePointer(to: &emptyByte) { emptyPtr in
                    offlineFilter(UnsafeRawPointer(program), UnsafeRawPointer(headerPtr), emptyPtr) != 0
                }
            }
        }
    }

    private func releaseInnerFilterCache(_ cache: inout [UInt32: CachedInnerFilter]) {
        for entry in cache.values {
            if case let .compiled(deadHandle, program) = entry {
                freeCode?(program)
                program.deallocate()
                closeHandle(deadHandle)
            }
        }
        cache.removeAll()
    }

    private func makeFrameMessage(
        header: PcapPacketHeader,
        data: UnsafePointer<UInt8>,
        rawDLT: UInt32,
        snaplen: Int32,
        bpfExpression: String?,
        bpfOptimizerFlag: Int32,
        innerFilterCache: inout [UInt32: CachedInnerFilter],
        attributionCache: inout PktapHeader.AttributionCache,
        inboundSocketFallback: inout PktapHeader.InboundSocketResolver
    )
        -> CapturedFrameMessage?
    {
        let captured = Int(header.caplen)
        guard PktapHeader.isPktapDLT(rawDLT) else {
            return CapturedFrameMessage(
                bytes: Data(bytes: data, count: captured),
                timestampSeconds: Int64(header.ts.tv_sec),
                timestampMicroseconds: Int64(header.ts.tv_usec),
                capturedLength: Int64(header.caplen),
                originalLength: Int64(header.len),
                linkType: rawDLT
            )
        }

        let rawBytes = Array(UnsafeBufferPointer(start: data, count: captured))
        // Drop both `PTH_TYPE_DROP (2)` (rejected in `PktapHeader.parse`) and
        // `PTH_TYPE_NONE (0)` metadata-only records with 0 payload bytes.
        guard let parsed = PktapHeader.parse(rawBytes), !parsed.frame.isEmpty else {
            return nil
        }
        let pktapHeaderLen = captured - parsed.frame.count
        let maxInnerBytes = max(0, Int(snaplen))
        let innerBytes = parsed.frame.count > maxInnerBytes
            ? Array(parsed.frame.prefix(maxInnerBytes))
            : parsed.frame
        let innerDLT = parsed.innerDLT
        let normalizedLinkType = innerDLT == Self.darwinDLTRawIP ? Self.linkTypeRawIP : innerDLT
        let innerCaplen = innerBytes.count
        let innerOrigLen = max(innerCaplen, Int(header.len) - pktapHeaderLen)

        if let bpfExpression {
            let innerHeader = PcapPacketHeader(
                ts: header.ts,
                caplen: UInt32(innerCaplen),
                len: UInt32(innerOrigLen)
            )
            guard matchesInnerFilter(
                expression: bpfExpression,
                optimizerFlag: bpfOptimizerFlag,
                snaplen: snaplen,
                innerDLT: innerDLT,
                innerHeader: innerHeader,
                innerBytes: innerBytes,
                cache: &innerFilterCache
            ) else {
                return nil
            }
        }

        let isPureInboundUnattributed = parsed.pid < 0
            && parsed.effectivePID <= 0
            && parsed.process.isEmpty
            && parsed.effectiveProcess.isEmpty

        let attribution: PktapHeader.AttributionCache.Result
        if isPureInboundUnattributed {
            if let socketOwner = inboundSocketFallback.resolveOwner(
                innerBytes: innerBytes,
                innerDLT: normalizedLinkType
            ) {
                let syntheticParsed = PktapHeader.Parsed(
                    frame: [],
                    typeNext: PktapHeader.typeNextPacket,
                    innerDLT: normalizedLinkType,
                    process: socketOwner.command,
                    pid: socketOwner.pid,
                    effectivePID: socketOwner.pid,
                    effectiveProcess: "",
                    interface: parsed.interface
                )
                attribution = attributionCache.resolve(parsed: syntheticParsed)
            } else {
                attribution = PktapHeader.AttributionCache.Result(processName: nil, provenance: nil)
            }
        } else {
            attribution = attributionCache.resolve(parsed: parsed)
        }

        return CapturedFrameMessage(
            bytes: Data(innerBytes),
            timestampSeconds: Int64(header.ts.tv_sec),
            timestampMicroseconds: Int64(header.ts.tv_usec),
            capturedLength: Int64(innerCaplen),
            originalLength: Int64(innerOrigLen),
            linkType: normalizedLinkType,
            processName: attribution.processName,
            processProvenance: attribution.provenance
        )
    }

    private func filterErrorMessage(handle: OpaquePointer, fallback: String) -> String {
        if let getError, let cstr = getError(handle) {
            let message = String(cString: cstr)
            if !message.isEmpty {
                return message
            }
        }
        return fallback
    }

    /// Sampled by the worker thread itself. `pcap_stats` needs the same handle the
    /// read loop owns, and that handle is closed on this thread when the loop
    /// exits — reading it from anywhere else would race that teardown.
    private func sampleStatistics(handle: OpaquePointer) -> HelperCaptureStats? {
        guard let stats else {
            return nil
        }
        // `struct pcap_stat` is { u_int ps_recv; u_int ps_drop; u_int ps_ifdrop }
        // on this platform, but some builds append further fields. A Swift struct
        // isn't representable across `@convention(c)`, so read raw memory and
        // over-allocate: writing past three slots stays inside our buffer.
        let slotCount = 8
        let buffer = UnsafeMutableRawPointer.allocate(
            byteCount: MemoryLayout<UInt32>.stride * slotCount,
            alignment: MemoryLayout<UInt32>.alignment
        )
        defer { buffer.deallocate() }
        buffer.initializeMemory(as: UInt32.self, repeating: 0, count: slotCount)
        guard stats(handle, buffer) == 0 else {
            return nil
        }
        let fields = buffer.assumingMemoryBound(to: UInt32.self)
        return HelperCaptureStats(
            received: fields[0],
            droppedByKernel: fields[1],
            droppedByInterface: fields[2]
        )
    }

    private func loop(
        handle: OpaquePointer,
        rawDLT: UInt32,
        snaplen: Int32,
        bpfExpression: String?,
        bpfOptimizerFlag: Int32,
        isRunning: () -> Bool,
        onBatch: @escaping @Sendable ([CapturedFrameMessage]) -> Void,
        onStatistics: @escaping @Sendable (HelperCaptureStats?) -> Void,
        onReadFailure: @escaping @Sendable (String) -> Void
    ) {
        var batch: [CapturedFrameMessage] = []
        var innerFilterCache: [UInt32: CachedInnerFilter] = [:]
        var attributionCache = PktapHeader.AttributionCache()
        var inboundSocketFallback = PktapHeader.InboundSocketResolver()
        defer {
            releaseInnerFilterCache(&innerFilterCache)
        }

        var lastFlush = Date()
        var readFailure: String?
        while isRunning() {
            var headerRaw: UnsafeMutableRawPointer?
            var dataPointer: UnsafePointer<UInt8>?
            let result = nextEx(handle, &headerRaw, &dataPointer)
            if result == 1, let headerRaw, let data = dataPointer {
                let header = headerRaw.assumingMemoryBound(to: PcapPacketHeader.self).pointee
                if let message = makeFrameMessage(
                    header: header,
                    data: data,
                    rawDLT: rawDLT,
                    snaplen: snaplen,
                    bpfExpression: bpfExpression,
                    bpfOptimizerFlag: bpfOptimizerFlag,
                    innerFilterCache: &innerFilterCache,
                    attributionCache: &attributionCache,
                    inboundSocketFallback: &inboundSocketFallback
                ) {
                    batch.append(message)
                }
            } else if result < 0 {
                // A read error ends the capture on the source's terms. Report why so
                // the app can stop and say so, instead of showing a capture that is
                // still "running" while nothing arrives any more.
                readFailure = filterErrorMessage(
                    handle: handle,
                    fallback: "the capture source stopped delivering packets."
                )
                break
            }
            if !batch.isEmpty, Date().timeIntervalSince(lastFlush) > 0.25 {
                onBatch(batch)
                batch.removeAll(keepingCapacity: true)
                lastFlush = Date()
                // Once per flush, not per packet: a syscall that only has to be as
                // fresh as the numbers it qualifies.
                onStatistics(sampleStatistics(handle: handle))
            }
        }
        if !batch.isEmpty {
            onBatch(batch)
        }
        // Final reading, so a short capture still reports its loss.
        onStatistics(sampleStatistics(handle: handle))
        if let readFailure {
            onReadFailure(readFailure)
        }
    }
}
