import Foundation

// MARK: - ResolvedAddressSource

/// Where a name for an address came from.
nonisolated enum ResolvedAddressSource: Hashable, Sendable {
    /// A unicast DNS answer observed in this capture.
    case dns
    /// A multicast DNS (Bonjour) answer observed in this capture.
    case mdns
    /// A name the user gave the address in this Project.
    case named
    /// A name the user gave an IPv4 block in this Project (the row's address is the block).
    case namedSubnet
    /// A name mapping embedded in this PCAPNG capture.
    case captureFile

    // MARK: Internal

    var label: String {
        switch self {
        case .dns: "DNS answer"
        case .mdns: "mDNS answer"
        case .named: "Named by you"
        case .namedSubnet: "Subnet named by you"
        case .captureFile: "Capture file"
        }
    }
}

// MARK: - ResolvedAddressRow

/// One address and one name it was given, with the session that taught it.
nonisolated struct ResolvedAddressRow: Identifiable, Hashable, Sendable {
    let address: String
    let name: String
    let source: ResolvedAddressSource
    /// The DNS or mDNS session whose answer carried the name; `nil` for Project- or
    /// capture-file-provided names.
    let sessionID: UUID?
    /// How many sessions' answers gave this address this name.
    let answerCount: Int
    /// Whether answers in this capture gave the address more than one name, so a
    /// session to it may be labelled with a different one.
    let hasOtherNames: Bool

    var id: String {
        "\(address)|\(name)|\(source.label)"
    }
}

// MARK: - ResolvedAddresses

/// Names learned for addresses from DNS/mDNS session facts or a PCAPNG Name Resolution
/// Block, beside Project-provided names. DNS/mDNS rows link to the answering session;
/// file mappings retain their container source without fabricating a session.
nonisolated enum ResolvedAddresses {
    // MARK: Internal

    static func rows(
        sessions: [SessionSummary],
        namedAddresses: [String: String],
        namedSubnets: [String: String] = [:],
        captureFileRecords: [CaptureNameResolutionRecord] = [],
        cachedDNSNames: [String: String] = [:]
    )
        -> [ResolvedAddressRow]
    {
        struct Learned {
            var source: ResolvedAddressSource
            var sessionID: UUID
            var ordinal: UInt64
            var count: Int
        }
        var learned: [String: [String: Learned]] = [:]
        for session in sessions {
            let source: ResolvedAddressSource = session.protocolStack.contains(.mdns) ? .mdns : .dns
            let ordinal = session.firstCaptureOrdinal ?? .max
            func recordLearned(address: String, name: String) {
                if var existing = learned[address]?[name] {
                    existing.count += 1
                    if ordinal < existing.ordinal {
                        existing.ordinal = ordinal
                        existing.sessionID = session.id
                        existing.source = source
                    }
                    learned[address]?[name] = existing
                } else {
                    learned[address, default: [:]][name] = Learned(
                        source: source, sessionID: session.id, ordinal: ordinal, count: 1
                    )
                }
            }

            if !session.dnsResolvedBindings.isEmpty {
                var seenInSession = Set<DNSAddressBinding>()
                for binding in session.dnsResolvedBindings {
                    guard let parsed = DNSNameSanitizer.sanitizedUnicastIP(binding.ip),
                          let name = DNSNameSanitizer.sanitizedHostname(binding.hostname) else
                    {
                        continue
                    }
                    let canonical = DNSAddressBinding(ip: parsed.compressedText, hostname: name)
                    guard seenInSession.insert(canonical).inserted else {
                        continue
                    }
                    recordLearned(address: canonical.ip, name: canonical.hostname)
                }
            } else if let rawQuery = session.dnsQuery,
                      let name = DNSNameSanitizer.sanitizedHostname(rawQuery),
                      !session.dnsAnswers.isEmpty
            {
                var seenInSession = Set<String>()
                for answer in session.dnsAnswers {
                    guard let parsed = DNSNameSanitizer.sanitizedUnicastIP(answer) else {
                        continue
                    }
                    let address = parsed.compressedText
                    guard seenInSession.insert(address).inserted else {
                        continue
                    }
                    recordLearned(address: address, name: name)
                }
            }
        }

        var rows: [ResolvedAddressRow] = []
        for (address, names) in learned {
            for (name, fact) in names {
                rows.append(ResolvedAddressRow(
                    address: address, name: name, source: fact.source, sessionID: fact.sessionID,
                    answerCount: fact.count, hasOtherNames: names.count > 1
                ))
            }
        }
        for (address, name) in namedAddresses {
            rows.append(ResolvedAddressRow(
                address: address, name: name, source: .named, sessionID: nil,
                answerCount: 0, hasOtherNames: false
            ))
        }
        if !cachedDNSNames.isEmpty {
            var coveredAddresses: Set<IPAddressValue> = []
            for address in learned.keys {
                if let parsed = IPAddressValue(parsing: address) {
                    coveredAddresses.insert(parsed)
                }
            }
            for address in namedAddresses.keys {
                if let parsed = IPAddressValue(parsing: address) {
                    coveredAddresses.insert(parsed)
                }
            }
            for rawAddress in cachedDNSNames.keys.sorted() {
                guard let parsed = DNSNameSanitizer.sanitizedUnicastIP(rawAddress),
                      !coveredAddresses.contains(parsed),
                      let rawName = cachedDNSNames[rawAddress],
                      let name = DNSNameSanitizer.sanitizedHostname(rawName) else
                {
                    continue
                }
                coveredAddresses.insert(parsed)
                rows.append(ResolvedAddressRow(
                    address: parsed.compressedText, name: name, source: .dns, sessionID: nil,
                    answerCount: 0, hasOtherNames: false
                ))
            }
        }
        for (block, name) in namedSubnets {
            rows.append(ResolvedAddressRow(
                address: block, name: name, source: .namedSubnet, sessionID: nil,
                answerCount: 0, hasOtherNames: false
            ))
        }
        var fileNames: [String: Set<String>] = [:]
        for record in captureFileRecords {
            guard let address = IPAddressValue(parsing: record.address)?.compressedText,
                  !record.name.text.isEmpty else
            {
                continue
            }
            fileNames[address, default: []].insert(record.name.text)
        }
        for (address, names) in fileNames {
            for name in names {
                rows.append(ResolvedAddressRow(
                    address: address, name: name, source: .captureFile, sessionID: nil,
                    answerCount: 0, hasOtherNames: names.count > 1
                ))
            }
        }
        return rows.sorted(by: precedes)
    }

    /// The Session Expression that finds the sessions a row explains.
    static func term(_ row: ResolvedAddressRow) -> String {
        row.source == .namedSubnet ? "ip in \(row.address)" : "ip == \(row.address)"
    }

    /// Whether `row` matches a filter typed by the user, over address and name.
    static func matches(_ row: ResolvedAddressRow, filter: String) -> Bool {
        let needle = filter.trimmingCharacters(in: .whitespaces)
        guard !needle.isEmpty else {
            return true
        }
        return row.address.localizedCaseInsensitiveContains(needle)
            || row.name.localizedCaseInsensitiveContains(needle)
    }

    // MARK: Private

    /// IPv4 before IPv6, each in numeric order; then name; then source.
    private static func precedes(_ lhs: ResolvedAddressRow, _ rhs: ResolvedAddressRow) -> Bool {
        // A subnet row sorts by its network address.
        let left = IPAddressValue(parsing: String(lhs.address.prefix { $0 != "/" }))
        let right = IPAddressValue(parsing: String(rhs.address.prefix { $0 != "/" }))
        if let left, let right, left != right {
            if left.bytes.count != right.bytes.count {
                return left.bytes.count < right.bytes.count
            }
            return left.bytes.lexicographicallyPrecedes(right.bytes)
        }
        if lhs.address != rhs.address {
            return lhs.address < rhs.address
        }
        if lhs.name != rhs.name {
            return lhs.name.localizedStandardCompare(rhs.name) == .orderedAscending
        }
        return lhs.source.label < rhs.source.label
    }
}
