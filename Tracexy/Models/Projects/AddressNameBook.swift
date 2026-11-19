import Foundation
import Observation

// MARK: - LearnedAddressEntry

private nonisolated struct LearnedAddressEntry: Codable, Equatable, Sendable {
    let address: String
    let name: String
}

// MARK: - AddressNameBook

/// Names the investigator gave to addresses in this Project ("192.0.2.5 is the NAS"),
/// alongside passively learned IP-to-domain mappings reused across captures.
/// Manual and subnet names keep their explicit label form; learned domain names are
/// reused cleanly when a session's host is a bare IP, never replacing a name the
/// capture itself supplied (DNS, SNI, HTTP Host), and never sent anywhere. Written
/// through to the Project's own preference suite.
@MainActor
@Observable
final class AddressNameBook {
    // MARK: Internal

    nonisolated static let maximumEntries = 500
    nonisolated static let maximumNameCharacters = 60
    nonisolated static let maximumLearnedEntries = 4_000
    nonisolated static let maximumLearnedDomainCharacters = 253

    nonisolated static let maximumSubnets = 200

    private(set) var names: [String: String] = [:]
    private(set) var learnedNames: [String: String] = [:]
    private(set) var canEditNames = true
    /// ``subnetNames`` as validated blocks.
    private(set) var subnets: [SubnetName] = []

    /// Named IPv4 blocks, keyed by their text (`192.168.1.0/24`).
    private(set) var subnetNames: [String: String] = [:] {
        didSet {
            subnets = subnetNames.compactMap { text, name in
                SubnetNames.block(text).map { SubnetName(block: $0, name: name) }
            }
        }
    }

    func bind(to defaults: UserDefaults) {
        self.defaults = defaults
        if let data = defaults.data(forKey: ProjectScopedSettingsKeys.addressNames) {
            do {
                storedNames = try JSONDecoder().decode([String: String].self, from: data)
                canEditNames = true
            } catch {
                // Keep corrupt user data intact until it can be recovered; never
                // replace it with an empty dictionary during an unrelated save.
                storedNames = [:]
                canEditNames = false
            }
        } else {
            storedNames = [:]
            canEditNames = true
        }
        names = Self.canonicalProjection(storedNames)
        let subnetData = defaults.data(forKey: ProjectScopedSettingsKeys.subnetNames) ?? Data()
        subnetNames = (try? JSONDecoder().decode([String: String].self, from: subnetData)) ?? [:]
        loadLearnedNames(from: defaults)
    }

    func learnedName(for address: String) -> String? {
        learnedNames[Self.canonical(address)]
    }

    /// The name to show for `address`: the one given to the address itself, else its
    /// most specific named subnet's form (`office.5`), else a learned domain name.
    func displayName(for address: String) -> String? {
        manualOrSubnetName(for: address) ?? learnedName(for: address)
    }

    /// Set, replace or (blank) remove the name of an IPv4 block. Returns `false` for
    /// text that is not an IPv4 block, or when the list is full and the block new.
    @discardableResult
    func setSubnetName(_ name: String, for blockText: String) -> Bool {
        guard let block = SubnetNames.block(blockText) else {
            return false
        }
        let key = SubnetNames.text(of: block)
        let trimmed = String(name.trimmingCharacters(in: .whitespacesAndNewlines).prefix(Self.maximumNameCharacters))
        if trimmed.isEmpty {
            subnetNames.removeValue(forKey: key)
        } else {
            guard subnetNames[key] != nil || subnetNames.count < Self.maximumSubnets else {
                return false
            }
            subnetNames[key] = trimmed
        }
        if let data = try? JSONEncoder().encode(subnetNames) {
            defaults?.set(data, forKey: ProjectScopedSettingsKeys.subnetNames)
        }
        return true
    }

    func name(for address: String) -> String? {
        names[Self.canonical(address)]
    }

    /// Distinct names stored for alternative spellings of one canonical IP.
    /// Callers can surface the conflict before an explicit save resolves it.
    func conflictingNames(for address: String) -> [String] {
        let key = Self.canonical(address)
        let values = Set(storedNames.compactMap { storedAddress, name in
            Self.canonical(storedAddress) == key ? name : nil
        })
        return values.count > 1 ? values.sorted() : []
    }

    /// Adds imported names only for addresses this Project does not already name.
    /// Existing and conflicting aliases are deliberately preserved for review.
    func importNames(_ imported: [String: String]) -> AddressNameImportResult {
        guard canEditNames else {
            return AddressNameImportResult(added: 0, alreadyNamed: imported.count, invalid: 0, full: false)
        }
        var added = 0
        var alreadyNamed = 0
        var invalid = 0
        let existingAddresses = Set(storedNames.keys.map(Self.canonical))
        var addresses = existingAddresses
        for address in imported.keys.sorted() {
            guard let value = IPAddressValue(parsing: address),
                  let name = imported[address]?.trimmingCharacters(in: .whitespacesAndNewlines),
                  !name.isEmpty else
            {
                invalid += 1
                continue
            }
            let key = Self.canonical(value.compressedText)
            guard !addresses.contains(key) else {
                alreadyNamed += 1
                continue
            }
            guard addresses.count < Self.maximumEntries else {
                names = Self.canonicalProjection(storedNames)
                persist()
                return AddressNameImportResult(
                    added: added, alreadyNamed: alreadyNamed, invalid: invalid, full: true
                )
            }
            storedNames[key] = String(name.prefix(Self.maximumNameCharacters))
            addresses.insert(key)
            added += 1
        }
        names = Self.canonicalProjection(storedNames)
        if added > 0 {
            persist()
        }
        return AddressNameImportResult(added: added, alreadyNamed: alreadyNamed, invalid: invalid, full: false)
    }

    /// Set, replace or (blank) remove the name for `address`. Returns `false` for a
    /// string that is not an IP address, or when the book is full and the address new.
    @discardableResult
    func setName(_ name: String, for address: String) -> Bool {
        guard canEditNames, IPAddressValue(parsing: address) != nil else {
            return false
        }
        let key = Self.canonical(address)
        let trimmed = String(name.trimmingCharacters(in: .whitespacesAndNewlines).prefix(Self.maximumNameCharacters))
        let matchingKeys = storedNames.keys.filter { Self.canonical($0) == key }
        if trimmed.isEmpty {
            for matchingKey in matchingKeys {
                storedNames.removeValue(forKey: matchingKey)
            }
        } else {
            let distinctAddresses = Set(storedNames.keys.map(Self.canonical))
            guard distinctAddresses.contains(key) || distinctAddresses.count < Self.maximumEntries else {
                return false
            }
            // Saving is an explicit conflict resolution for this IP. Other
            // addresses and their original key/value pairs remain untouched.
            for matchingKey in matchingKeys {
                storedNames.removeValue(forKey: matchingKey)
            }
            storedNames[key] = trimmed
        }
        names = Self.canonicalProjection(storedNames)
        persist()
        return true
    }

    /// The host a session list should show: the investigator's name or named subnet
    /// for a bare address host, a reused learned domain name, or the capture's own host.
    func displayHost(for session: SessionSummary) -> String {
        guard IPAddressValue(parsing: session.host) != nil else {
            return session.host
        }
        if let manualOrSubnet = manualOrSubnetName(for: session.host) {
            return "\(manualOrSubnet) (\(session.host))"
        }
        if let learned = learnedName(for: session.host) {
            return learned
        }
        return session.host
    }

    /// Passively learn IP-to-domain mappings from DNS/mDNS answers and from TLS/QUIC
    /// SNI observed on Fake-IP / CGNAT / IPv6 ULA ranges. Mutates observable state and
    /// persists to defaults only when at least one mapping is added or updated.
    func learn(from sessions: [SessionSummary]) {
        guard !sessions.isEmpty else {
            return
        }
        var workingNames = learnedNames
        var didChange = false

        func record(_ address: IPAddressValue, domain rawDomain: String) {
            guard DNSNameSanitizer.isValidUnicastTargetIP(address) else {
                return
            }
            let capped = String(rawDomain.prefix(Self.maximumLearnedDomainCharacters))
            guard let domain = DNSNameSanitizer.sanitizedHostname(capped) else {
                return
            }
            let key = address.compressedText.lowercased()
            learnedSequence &+= 1
            learnedTicks[key] = learnedSequence
            if workingNames[key] != domain {
                workingNames[key] = domain
                didChange = true
            }
        }

        for session in sessions {
            if !session.dnsResolvedBindings.isEmpty {
                for binding in session.dnsResolvedBindings {
                    if let parsed = DNSNameSanitizer.sanitizedUnicastIP(binding.ip),
                       let domain = DNSNameSanitizer.sanitizedHostname(binding.hostname)
                    {
                        record(parsed, domain: domain)
                    }
                }
            } else if let rawQuery = session.dnsQuery,
                      let query = DNSNameSanitizer.sanitizedHostname(rawQuery)
            {
                for answer in session.dnsAnswers {
                    if let parsed = DNSNameSanitizer.sanitizedUnicastIP(answer) {
                        record(parsed, domain: query)
                    }
                }
            }

            if let rawSNI = session.sni,
               let sni = DNSNameSanitizer.sanitizedHostname(rawSNI)
            {
                let destination = Self.parsedEndpoint(
                    session.destinationEndpointValue,
                    fallback: session.destinationEndpoint
                )
                let source = Self.parsedEndpoint(
                    session.sourceEndpointValue,
                    fallback: session.sourceEndpoint
                )
                if let destination, Self.isFakeIP(destination.ip) {
                    record(destination.ip, domain: sni)
                } else if let source, Self.isFakeIP(source.ip),
                          Self.canTreatSourceAsFakeIPResponder(source: source, destination: destination)
                {
                    record(source.ip, domain: sni)
                }
            }
        }

        guard didChange else {
            return
        }
        trimLearnedCapacity(&workingNames)
        learnedNames = workingNames
        persistLearnedNames()
    }

    // MARK: Private

    @ObservationIgnored private var defaults: UserDefaults?
    @ObservationIgnored private var storedNames: [String: String] = [:]
    @ObservationIgnored private var learnedTicks: [String: UInt64] = [:]
    @ObservationIgnored private var learnedSequence: UInt64 = 0

    private var canPersistLearnedToDefaults: Bool {
        guard let defaults else {
            return false
        }
        return !TracexyIdentity.isRunningTests || defaults !== UserDefaults.standard
    }

    private func manualOrSubnetName(for address: String) -> String? {
        name(for: address) ?? SubnetNames.lookup(address, in: subnets).map { SubnetNames.label(address, in: $0) }
    }

    private func loadLearnedNames(from defaults: UserDefaults) {
        learnedTicks = [:]
        learnedSequence = 0
        guard canPersistLearnedToDefaults,
              let data = defaults.data(forKey: ProjectScopedSettingsKeys.learnedAddressNames) else
        {
            learnedNames = [:]
            return
        }

        var workingNames: [String: String] = [:]
        var needsScrubPersist = false
        let decoder = JSONDecoder()
        if let entries = try? decoder.decode([LearnedAddressEntry].self, from: data) {
            for entry in entries {
                if !insertLoadedLearnedEntry(address: entry.address, name: entry.name, into: &workingNames) {
                    needsScrubPersist = true
                }
            }
        } else if let dictionary = try? decoder.decode([String: String].self, from: data) {
            for key in dictionary.keys.sorted() {
                if let name = dictionary[key] {
                    if !insertLoadedLearnedEntry(address: key, name: name, into: &workingNames) {
                        needsScrubPersist = true
                    }
                }
            }
        }
        trimLearnedCapacity(&workingNames)
        learnedNames = workingNames
        if needsScrubPersist {
            persistLearnedNames()
        }
    }

    @discardableResult
    private func insertLoadedLearnedEntry(
        address: String,
        name: String,
        into workingNames: inout [String: String]
    )
        -> Bool
    {
        guard let parsed = DNSNameSanitizer.sanitizedUnicastIP(address) else {
            return false
        }
        let capped = String(
            name.trimmingCharacters(in: .whitespacesAndNewlines)
                .prefix(Self.maximumLearnedDomainCharacters)
        )
        guard let sanitized = DNSNameSanitizer.sanitizedHostname(capped) else {
            return false
        }
        let key = parsed.compressedText.lowercased()
        learnedSequence &+= 1
        learnedTicks[key] = learnedSequence
        workingNames[key] = sanitized
        return address == key && name == sanitized
    }

    private func trimLearnedCapacity(_ workingNames: inout [String: String]) {
        let overflow = workingNames.count - Self.maximumLearnedEntries
        guard overflow > 0 else {
            return
        }
        let oldestKeys = workingNames.keys.sorted { lhs, rhs in
            let leftTick = learnedTicks[lhs] ?? 0
            let rightTick = learnedTicks[rhs] ?? 0
            if leftTick != rightTick {
                return leftTick < rightTick
            }
            return lhs < rhs
        }.prefix(overflow)
        for key in oldestKeys {
            workingNames.removeValue(forKey: key)
            learnedTicks.removeValue(forKey: key)
        }
    }

    private func persistLearnedNames() {
        guard canPersistLearnedToDefaults else {
            return
        }
        let orderedKeys = learnedNames.keys.sorted { lhs, rhs in
            let leftTick = learnedTicks[lhs] ?? 0
            let rightTick = learnedTicks[rhs] ?? 0
            if leftTick != rightTick {
                return leftTick < rightTick
            }
            return lhs < rhs
        }
        let entries = orderedKeys.compactMap { key in
            learnedNames[key].map { LearnedAddressEntry(address: key, name: $0) }
        }
        if let data = try? JSONEncoder().encode(entries) {
            defaults?.set(data, forKey: ProjectScopedSettingsKeys.learnedAddressNames)
        }
    }

    /// Router / TUN Fake-IP pools where each virtual address maps 1-to-1 to a domain:
    /// IPv4 `198.18.0.0/15`, RFC 6598 `100.64.0.0/10`, Sing-box IPv6 `fc00::/18`, and
    /// Clash/Mihomo IPv6 `fdfe:dcba:9876::/48` (excluding standard `fd00::/8` SLAAC ULA).
    private static func isFakeIP(_ address: IPAddressValue) -> Bool {
        switch address.family {
        case .v4:
            guard address.bytes.count == 4 else {
                return false
            }
            let first = address.bytes[0]
            let second = address.bytes[1]
            let isBenchmarkFakeIP = first == 198 && (second & 0xFE) == 18
            let isCGNATFakeIP = first == 100 && (second & 0xC0) == 64
            return isBenchmarkFakeIP || isCGNATFakeIP
        case .v6:
            return DNSNameSanitizer.isIPv6FakeIP(address)
        }
    }

    /// Avoids labeling the local TUN/ULA client address (e.g. `198.18.0.1:54321 -> 1.1.1.1:443`)
    /// with the remote server's SNI, while still catching mid-stream sessions whose first
    /// captured frame came from the Fake-IP responder on a non-standard port.
    private static func canTreatSourceAsFakeIPResponder(
        source: (ip: IPAddressValue, port: UInt16?),
        destination: (ip: IPAddressValue, port: UInt16?)?
    )
        -> Bool
    {
        guard let destination else {
            return true
        }
        if let srcPort = source.port, let dstPort = destination.port, srcPort > 0, dstPort > 0 {
            if srcPort <= dstPort {
                return true
            }
            return isLocalClientAddress(destination.ip)
        }
        return isLocalClientAddress(destination.ip)
    }

    private static func isLocalClientAddress(_ address: IPAddressValue) -> Bool {
        switch address.family {
        case .v4:
            guard address.bytes.count == 4 else {
                return false
            }
            let b0 = address.bytes[0]
            let b1 = address.bytes[1]
            return b0 == 10
                || b0 == 127
                || (b0 == 172 && (b1 & 0xF0) == 16)
                || (b0 == 192 && b1 == 168)
                || (b0 == 169 && b1 == 254)
                || (b0 == 100 && (b1 & 0xC0) == 64)
        case .v6:
            guard address.bytes.count == 16 else {
                return false
            }
            let b0 = address.bytes[0]
            let b1 = address.bytes[1]
            let isLoopback = address.bytes.dropLast().allSatisfy { $0 == 0 } && address.bytes[15] == 1
            let isLinkLocal = b0 == 0xFE && (b1 & 0xC0) == 0x80
            let isULA = (b0 & 0xFE) == 0xFC
            return isLoopback || isLinkLocal || isULA
        }
    }

    private static func parsedEndpoint(
        _ endpoint: IPEndpoint?,
        fallback text: String
    )
        -> (ip: IPAddressValue, port: UInt16?)?
    {
        if let endpoint, let ip = IPAddressValue(parsing: endpoint.ip) {
            return (ip, endpoint.port)
        }
        guard !text.isEmpty, text != "—" else {
            return nil
        }
        if text.hasPrefix("["), let closeIndex = text.firstIndex(of: "]") {
            let host = String(text[text.index(after: text.startIndex) ..< closeIndex])
            let rest = text[text.index(after: closeIndex)...]
            if let ip = IPAddressValue(parsing: host) {
                if rest.isEmpty {
                    return (ip, nil)
                }
                if rest.hasPrefix(":"), let port = UInt16(rest.dropFirst()) {
                    return (ip, port)
                }
            }
            return nil
        }
        if let colonIndex = text.lastIndex(of: ":"),
           let port = UInt16(text[text.index(after: colonIndex)...]),
           let ip = IPAddressValue(parsing: String(text[..<colonIndex]))
        {
            return (ip, port)
        }
        if let ip = IPAddressValue(parsing: text) {
            return (ip, nil)
        }
        return nil
    }

    /// One spelling per address, so `2001:DB8::1` and `2001:db8::1` share a name.
    private static func canonical(_ address: String) -> String {
        IPAddressValue(parsing: address)?.compressedText.lowercased() ?? address.lowercased()
    }

    /// Build a stable display projection without rewriting the user's stored keys.
    /// A canonical spelling wins display; collisions remain intact until explicit edit.
    private static func canonicalProjection(_ storedNames: [String: String]) -> [String: String] {
        storedNames.keys.sorted { lhs, rhs in
            let lhsCanonical = canonical(lhs)
            let rhsCanonical = canonical(rhs)
            let lhsIsCanonical = lhs == lhsCanonical
            let rhsIsCanonical = rhs == rhsCanonical
            if lhsIsCanonical != rhsIsCanonical {
                return lhsIsCanonical
            }
            return lhs < rhs
        }.reduce(into: [:]) { result, key in
            let canonicalKey = canonical(key)
            if result[canonicalKey] == nil {
                result[canonicalKey] = storedNames[key]
            }
        }
    }

    private func persist() {
        guard canEditNames, let data = try? JSONEncoder().encode(storedNames) else {
            return
        }
        defaults?.set(data, forKey: ProjectScopedSettingsKeys.addressNames)
    }
}

// MARK: - AddressNameImportResult

struct AddressNameImportResult: Equatable {
    let added: Int
    let alreadyNamed: Int
    let invalid: Int
    let full: Bool
}
