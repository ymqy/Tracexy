import Foundation

// MARK: - ProcessProvenance

/// Rich process origin metadata resolved alongside a packet or socket's display
/// name. Ferried inside `CapturedFrameMessage` using primitive `NSString` and
/// `Bool` archive keys so `TracexyHelperInterface`'s class allow-list stays
/// unchanged and protocol-v6 peers remain backward-compatible.
nonisolated struct ProcessProvenance: Equatable, Hashable, Sendable, Codable {
    // MARK: Lifecycle

    init(
        executablePath: String? = nil,
        bundleIdentifier: String? = nil,
        viaProcessName: String? = nil,
        parentProcessName: String? = nil,
        hasControllingTTY: Bool = false,
        isRootUser: Bool = false,
        isKernelTask: Bool = false
    ) {
        self.executablePath = executablePath
        self.bundleIdentifier = bundleIdentifier
        self.viaProcessName = viaProcessName
        self.parentProcessName = parentProcessName
        self.hasControllingTTY = hasControllingTTY
        self.isRootUser = isRootUser
        self.isKernelTask = isKernelTask
    }

    // MARK: Internal

    var executablePath: String?
    var bundleIdentifier: String?
    var viaProcessName: String?
    var parentProcessName: String?
    var hasControllingTTY: Bool
    var isRootUser: Bool
    var isKernelTask: Bool
}

// MARK: - CapturedFrameMessage

/// One captured frame, ferried across the app↔helper XPC boundary as a typed,
/// `NSSecureCoding` object rather than a bare `Data`.
///
/// The legacy surface drained a `[Data]` plus a single link type: every frame in
/// a batch then shared one wall-clock timestamp assigned app-side, the captured
/// length was inferred from `bytes.count`, and the true on-wire length was lost.
/// That is exactly the kind of quiet fidelity loss the capture path must not
/// have. This type carries each frame's own libpcap timestamp (seconds +
/// microseconds, as `struct timeval` reports it), the captured length, the
/// original on-wire length (which exceeds the captured length when a snaplen
/// truncated the packet), and the per-frame link type — nothing is inferred or
/// shared across a batch.
///
/// Decoding is deliberately total: `init(coder:)` never traps and never rejects,
/// it reads whatever is present. Validation and truthful rejection happen at the
/// app-side conversion to `CapturedFrame`, so a malformed message degrades to a
/// dropped frame instead of a decode failure that could wedge the connection.
@objc(TracexyCapturedFrameMessage)
nonisolated final class CapturedFrameMessage: NSObject, NSSecureCoding, @unchecked Sendable {
    // MARK: Lifecycle

    init(
        bytes: Data,
        timestampSeconds: Int64,
        timestampMicroseconds: Int64,
        capturedLength: Int64,
        originalLength: Int64,
        linkType: UInt32,
        processName: String? = nil,
        processProvenance: ProcessProvenance? = nil
    ) {
        self.bytes = bytes
        self.timestampSeconds = timestampSeconds
        self.timestampMicroseconds = timestampMicroseconds
        self.capturedLength = capturedLength
        self.originalLength = originalLength
        self.linkType = linkType
        self.processName = processName
        self.processProvenance = processProvenance
    }

    required init?(coder: NSCoder) {
        bytes = (coder.decodeObject(of: NSData.self, forKey: Key.bytes)).map { $0 as Data } ?? Data()
        timestampSeconds = coder.decodeInt64(forKey: Key.timestampSeconds)
        timestampMicroseconds = coder.decodeInt64(forKey: Key.timestampMicroseconds)
        capturedLength = coder.decodeInt64(forKey: Key.capturedLength)
        originalLength = coder.decodeInt64(forKey: Key.originalLength)
        linkType = UInt32(bitPattern: coder.decodeInt32(forKey: Key.linkType))
        // Absent from replies of a helper without pktap attribution: nil.
        processName = coder.decodeObject(of: NSString.self, forKey: Key.processName) as? String

        let executablePath = coder.decodeObject(of: NSString.self, forKey: Key.executablePath) as? String
        let bundleIdentifier = coder.decodeObject(of: NSString.self, forKey: Key.bundleIdentifier) as? String
        let viaProcessName = coder.decodeObject(of: NSString.self, forKey: Key.viaProcessName) as? String
        let parentProcessName = coder.decodeObject(of: NSString.self, forKey: Key.parentProcessName) as? String
        let hasProvenance = executablePath != nil
            || bundleIdentifier != nil
            || viaProcessName != nil
            || parentProcessName != nil
            || coder.containsValue(forKey: Key.hasControllingTTY)
            || coder.containsValue(forKey: Key.isRootUser)
            || coder.containsValue(forKey: Key.isKernelTask)
        if hasProvenance {
            processProvenance = ProcessProvenance(
                executablePath: executablePath,
                bundleIdentifier: bundleIdentifier,
                viaProcessName: viaProcessName,
                parentProcessName: parentProcessName,
                hasControllingTTY: coder.decodeBool(forKey: Key.hasControllingTTY),
                isRootUser: coder.decodeBool(forKey: Key.isRootUser),
                isKernelTask: coder.decodeBool(forKey: Key.isKernelTask)
            )
        } else {
            processProvenance = nil
        }
    }

    // MARK: Internal

    static var supportsSecureCoding: Bool {
        true
    }

    let bytes: Data
    /// `struct timeval` seconds, straight from the libpcap per-packet header.
    let timestampSeconds: Int64
    /// `struct timeval` microseconds. Kept separate from seconds so the precise
    /// capture instant survives — never collapsed to a shared batch `Date`.
    let timestampMicroseconds: Int64
    /// Bytes actually captured (`pcap_pkthdr.caplen`). The app requires this to
    /// agree with `bytes.count`; malformed metadata is rejected, not normalized.
    let capturedLength: Int64
    /// Original on-wire length (`pcap_pkthdr.len`), which may exceed the captured
    /// length. Carried explicitly so it is never inferred from `bytes.count`.
    let originalLength: Int64
    /// The DLT for *this* frame. Homogeneous for a normal capture, but carried
    /// per frame so a link type is always authoritative rather than assumed.
    let linkType: UInt32
    /// Originating process display name resolved from `pktap` metadata, or `nil`
    /// when `pktap` was unavailable or did not identify a process.
    let processName: String?
    /// Rich process origin provenance resolved alongside `processName`, or `nil`
    /// when unavailable.
    let processProvenance: ProcessProvenance?

    func encode(with coder: NSCoder) {
        coder.encode(bytes as NSData, forKey: Key.bytes)
        coder.encode(timestampSeconds, forKey: Key.timestampSeconds)
        coder.encode(timestampMicroseconds, forKey: Key.timestampMicroseconds)
        coder.encode(capturedLength, forKey: Key.capturedLength)
        coder.encode(originalLength, forKey: Key.originalLength)
        coder.encode(Int32(bitPattern: linkType), forKey: Key.linkType)
        if let processName {
            coder.encode(processName as NSString, forKey: Key.processName)
        }
        if let provenance = processProvenance {
            if let executablePath = provenance.executablePath {
                coder.encode(executablePath as NSString, forKey: Key.executablePath)
            }
            if let bundleIdentifier = provenance.bundleIdentifier {
                coder.encode(bundleIdentifier as NSString, forKey: Key.bundleIdentifier)
            }
            if let viaProcessName = provenance.viaProcessName {
                coder.encode(viaProcessName as NSString, forKey: Key.viaProcessName)
            }
            if let parentProcessName = provenance.parentProcessName {
                coder.encode(parentProcessName as NSString, forKey: Key.parentProcessName)
            }
            coder.encode(provenance.hasControllingTTY, forKey: Key.hasControllingTTY)
            coder.encode(provenance.isRootUser, forKey: Key.isRootUser)
            coder.encode(provenance.isKernelTask, forKey: Key.isKernelTask)
        }
    }

    // MARK: Private

    private enum Key {
        static let bytes = "b"
        static let timestampSeconds = "ts"
        static let timestampMicroseconds = "tu"
        static let capturedLength = "cl"
        static let originalLength = "ol"
        static let linkType = "lt"
        static let processName = "pn"
        static let executablePath = "ep"
        static let bundleIdentifier = "bi"
        static let viaProcessName = "vp"
        static let parentProcessName = "pp"
        static let hasControllingTTY = "tty"
        static let isRootUser = "rt"
        static let isKernelTask = "kt"
    }
}

// MARK: - FrameBatchMessage

/// A drained batch of captured frames plus the capture accounting that qualifies
/// it. Everything the UI needs to state honestly *how much it might have missed*
/// travels with the frames, so no number is presented without its caveat.
@objc(TracexyFrameBatchMessage)
nonisolated final class FrameBatchMessage: NSObject, NSSecureCoding, @unchecked Sendable {
    // MARK: Lifecycle

    init(
        frames: [CapturedFrameMessage],
        bufferDroppedCount: UInt64,
        captureLinkType: UInt32,
        stats: HelperCaptureStats?,
        readFailure: String? = nil
    ) {
        self.frames = frames
        self.bufferDroppedCount = bufferDroppedCount
        self.captureLinkType = captureLinkType
        self.readFailure = readFailure
        statsAvailable = stats != nil
        statsReceived = stats?.received ?? 0
        statsDroppedByKernel = stats?.droppedByKernel ?? 0
        statsDroppedByInterface = stats?.droppedByInterface ?? 0
    }

    required init?(coder: NSCoder) {
        let decodedFrames = coder.decodeObject(
            of: [NSArray.self, CapturedFrameMessage.self], forKey: Key.frames
        ) as? [CapturedFrameMessage]
        frames = decodedFrames ?? []
        bufferDroppedCount = UInt64(bitPattern: coder.decodeInt64(forKey: Key.bufferDropped))
        captureLinkType = UInt32(bitPattern: coder.decodeInt32(forKey: Key.captureLinkType))
        statsAvailable = coder.decodeBool(forKey: Key.statsAvailable)
        statsReceived = UInt32(bitPattern: coder.decodeInt32(forKey: Key.statsReceived))
        statsDroppedByKernel = UInt32(bitPattern: coder.decodeInt32(forKey: Key.statsDroppedByKernel))
        statsDroppedByInterface = UInt32(bitPattern: coder.decodeInt32(forKey: Key.statsDroppedByInterface))
        // Absent from replies of a helper older than this key: no failure known.
        readFailure = coder.decodeObject(of: NSString.self, forKey: Key.readFailure) as? String
    }

    // MARK: Internal

    static var supportsSecureCoding: Bool {
        true
    }

    let frames: [CapturedFrameMessage]
    /// Cumulative count of frames the helper's *own* bounded buffer evicted
    /// because the app did not drain fast enough. Distinct from kernel/interface
    /// loss and from the app's UI-retention eviction — a different stage of the
    /// pipeline, never conflated with them.
    let bufferDroppedCount: UInt64
    /// Representative outer DLT for the capture, used to write a faithful savefile.
    let captureLinkType: UInt32
    /// Whether `pcap_stats` was available for this capture. When false the app
    /// must show accounting as *unknown* rather than imply a perfect capture.
    let statsAvailable: Bool
    let statsReceived: UInt32
    let statsDroppedByKernel: UInt32
    let statsDroppedByInterface: UInt32
    /// libpcap's reason when the helper's read loop ended on its own (the interface
    /// went away, the device was reconfigured). The frames in this batch are the
    /// complete tail delivered before that; `nil` while the source is still read.
    let readFailure: String?

    /// The kernel/interface accounting, or `nil` when `pcap_stats` was unavailable.
    var stats: HelperCaptureStats? {
        guard statsAvailable else {
            return nil
        }
        return HelperCaptureStats(
            received: statsReceived,
            droppedByKernel: statsDroppedByKernel,
            droppedByInterface: statsDroppedByInterface
        )
    }

    func encode(with coder: NSCoder) {
        coder.encode(frames as NSArray, forKey: Key.frames)
        coder.encode(Int64(bitPattern: bufferDroppedCount), forKey: Key.bufferDropped)
        coder.encode(Int32(bitPattern: captureLinkType), forKey: Key.captureLinkType)
        coder.encode(statsAvailable, forKey: Key.statsAvailable)
        coder.encode(Int32(bitPattern: statsReceived), forKey: Key.statsReceived)
        coder.encode(Int32(bitPattern: statsDroppedByKernel), forKey: Key.statsDroppedByKernel)
        coder.encode(Int32(bitPattern: statsDroppedByInterface), forKey: Key.statsDroppedByInterface)
        if let readFailure {
            coder.encode(readFailure as NSString, forKey: Key.readFailure)
        }
    }

    // MARK: Private

    private enum Key {
        static let frames = "f"
        static let bufferDropped = "d"
        static let captureLinkType = "lt"
        static let statsAvailable = "sa"
        static let readFailure = "rf"
        static let statsReceived = "sr"
        static let statsDroppedByKernel = "sk"
        static let statsDroppedByInterface = "si"
    }
}

// MARK: - HelperCaptureStats

/// Raw kernel/interface capture accounting sampled from `pcap_stats`, shared
/// verbatim from the helper to the app. The app maps it onto its richer
/// `CaptureStatistics` (which adds fidelity/threshold logic); the helper only
/// reports the three counters libpcap gives it.
nonisolated struct HelperCaptureStats: Sendable, Equatable {
    var received: UInt32
    var droppedByKernel: UInt32
    var droppedByInterface: UInt32
}

// MARK: - CaptureConfigurationError

/// Why an immutable capture configuration was rejected. Carries a user-facing
/// `message` so the app can surface *why* a capture never started, and the helper
/// can fail the start reply with the same explanation.
nonisolated enum CaptureConfigurationError: Error, Equatable {
    case emptyInterface
    case interfaceTooLong
    case bpfTooLong

    // MARK: Internal

    var message: String {
        switch self {
        case .emptyInterface:
            "no capture interface was specified."
        case .interfaceTooLong:
            "the capture interface name is too long."
        case .bpfTooLong:
            "the BPF filter expression is too long."
        }
    }
}

// MARK: - CaptureConfiguration

/// The immutable capture parameters ferried across the app↔helper XPC boundary as
/// a typed, `NSSecureCoding` object: the interface to open, the snap length, the
/// promiscuous flag, an optional BPF filter expression, and its compile optimizer
/// choice.
///
/// This is the *only* privileged command surface — a fixed, validated description
/// of a capture, never an arbitrary command. Both the app (before it asks the
/// helper to start) and the helper (before it opens libpcap) run the same
/// ``validated()`` so bounds are enforced on both sides: the snap length is
/// clamped into a supported range, the interface must be present and reasonable,
/// and an over-long BPF expression is rejected with a clear message. Syntactic BPF
/// validation happens against libpcap at open time — a bad expression fails the
/// start *before* any capture is reported running.
///
/// Decoding is deliberately total: `init(coder:)` never traps. Whatever crosses
/// the wire is validated by ``validated()`` on receipt, so a malformed message is
/// rejected truthfully rather than trusted.
@objc(TracexyCaptureConfiguration)
nonisolated final class CaptureConfiguration: NSObject, NSSecureCoding, @unchecked Sendable {
    // MARK: Lifecycle

    init(interface: String, snapLength: Int, promiscuous: Bool, bpf: String?, optimizeBPF: Bool = true) {
        self.interface = interface
        self.snapLength = snapLength
        self.promiscuous = promiscuous
        self.bpf = bpf
        self.optimizeBPF = optimizeBPF
    }

    required init?(coder: NSCoder) {
        interface = (coder.decodeObject(of: NSString.self, forKey: Key.interface) as String?) ?? ""
        // A snap length written as Int64; a nonsensical value is caught by `validated()`.
        snapLength = Int(coder.decodeInt64(forKey: Key.snapLength))
        promiscuous = coder.decodeBool(forKey: Key.promiscuous)
        optimizeBPF = coder.containsValue(forKey: Key.optimizeBPF)
            ? coder.decodeBool(forKey: Key.optimizeBPF)
            : true
        // A missing/empty BPF string decodes to `nil` — no filter.
        let decodedBPF = coder.decodeObject(of: NSString.self, forKey: Key.bpf) as String?
        bpf = (decodedBPF?.isEmpty ?? true) ? nil : decodedBPF
    }

    // MARK: Internal

    /// Supported snap-length range. The floor keeps enough of a frame for L2–L4
    /// headers; the ceiling matches the largest preset the UI offers and is well
    /// above any real frame, so a larger persisted value is clamped rather than
    /// trusted into an oversized buffer.
    static let snapLengthRange: ClosedRange<Int> = 64 ... 262_144
    /// Full-frame default used when a persisted snap length is missing or unusable.
    static let defaultSnapLength = 65_536
    /// Upper bound on a BPF expression's length. A real filter is short; anything
    /// longer is rejected rather than handed to `pcap_compile`.
    static let maxBPFLength = 1_024
    /// Upper bound on an interface name's length (BSD names are a handful of chars).
    static let maxInterfaceLength = 128

    static var supportsSecureCoding: Bool {
        true
    }

    let interface: String
    let snapLength: Int
    let promiscuous: Bool
    /// Trimmed BPF expression, or `nil` for "capture everything". Never an empty
    /// string — an empty filter is normalized to `nil` so it is unambiguous.
    let bpf: String?
    /// Whether libpcap optimizes the BPF program when a filter is present.
    /// Missing values from protocol-v4/v5 archives default to the historical
    /// optimized behavior.
    let optimizeBPF: Bool

    var bpfOptimizerFlag: Int32 {
        optimizeBPF ? 1 : 0
    }

    /// Clamp a raw snap length into the supported range. A non-positive value is
    /// treated as unset and becomes the full-frame default; anything else is
    /// clamped to the nearest supported bound.
    static func clampedSnapLength(_ raw: Int) -> Int {
        guard raw > 0 else {
            return defaultSnapLength
        }
        return min(max(raw, snapLengthRange.lowerBound), snapLengthRange.upperBound)
    }

    /// Validate and normalize. Returns a copy with a clamped snap length and a
    /// trimmed/normalized BPF, or the reason it was rejected. Never traps.
    func validated() -> Result<CaptureConfiguration, CaptureConfigurationError> {
        let trimmedInterface = interface.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedInterface.isEmpty else {
            return .failure(.emptyInterface)
        }
        guard trimmedInterface.count <= Self.maxInterfaceLength else {
            return .failure(.interfaceTooLong)
        }
        var normalizedBPF: String?
        if let bpf {
            let trimmed = bpf.trimmingCharacters(in: .whitespacesAndNewlines)
            if trimmed.isEmpty {
                normalizedBPF = nil
            } else if trimmed.count > Self.maxBPFLength {
                return .failure(.bpfTooLong)
            } else {
                normalizedBPF = trimmed
            }
        }
        return .success(CaptureConfiguration(
            interface: trimmedInterface,
            snapLength: Self.clampedSnapLength(snapLength),
            promiscuous: promiscuous,
            bpf: normalizedBPF,
            optimizeBPF: optimizeBPF
        ))
    }

    func encode(with coder: NSCoder) {
        coder.encode(interface as NSString, forKey: Key.interface)
        coder.encode(Int64(snapLength), forKey: Key.snapLength)
        coder.encode(promiscuous, forKey: Key.promiscuous)
        coder.encode(optimizeBPF, forKey: Key.optimizeBPF)
        if let bpf {
            coder.encode(bpf as NSString, forKey: Key.bpf)
        }
    }

    // MARK: Private

    private enum Key {
        static let interface = "if"
        static let snapLength = "sl"
        static let promiscuous = "pr"
        static let bpf = "bpf"
        static let optimizeBPF = "ob"
    }
}

// MARK: - TracexyHelperInterface

/// Builds the `NSXPCInterface` for `TracexyHelperProtocol` with the secure-coding
/// allow-list configured for the typed `fetchFrames` reply. Shared so the app's
/// `remoteObjectInterface` and the helper's `exportedInterface` are configured
/// identically — a mismatch would silently fail decoding at runtime.
nonisolated enum TracexyHelperInterface {
    static func make() -> NSXPCInterface {
        let interface = NSXPCInterface(with: TracexyHelperProtocol.self)
        // Class metatypes aren't `Hashable` in Swift, so the allow-list is built
        // as an `NSSet` and bridged — the standard shape for this ObjC API.
        let classes: [Any] = [
            FrameBatchMessage.self,
            CapturedFrameMessage.self,
            NSArray.self,
            NSData.self,
            NSString.self,
        ]
        if let allowed = NSSet(array: classes) as? Set<AnyHashable> {
            interface.setClasses(
                allowed,
                for: #selector(TracexyHelperProtocol.fetchFrames(withReply:)),
                argumentIndex: 0,
                ofReply: true
            )
            interface.setClasses(
                allowed,
                for: #selector(TracexyHelperProtocol.stopCapture(withReply:)),
                argumentIndex: 0,
                ofReply: true
            )
        }
        // The immutable capture configuration is the one typed object the app
        // *sends* to the helper, so its allow-list is set on the request argument
        // (`ofReply: false`) rather than a reply.
        if let allowedConfig = NSSet(array: [CaptureConfiguration.self, NSString.self]) as? Set<AnyHashable> {
            interface.setClasses(
                allowedConfig,
                for: #selector(TracexyHelperProtocol.startCapture(configuration:withReply:)),
                argumentIndex: 0,
                ofReply: false
            )
        }
        return interface
    }
}
