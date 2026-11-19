import Foundation

// MARK: - FrameAddressNames

/// View ▸ Name Resolution ▸ Resolve Network Addresses for the frame lists: the name
/// to show for an address — one given in this Project, else the first name the
/// capture's own DNS or mDNS answers carried, else its named subnet's form — or the
/// address itself. Only names the Project or the capture already hold are used;
/// nothing is ever looked up on the network.
@MainActor
enum FrameAddressNames {
    static func resolver(
        sessions: [SessionSummary], book: AddressNameBook,
        captureFileRecords: [CaptureNameResolutionRecord] = []
    )
        -> (String) -> String
    {
        var learned: [String: String] = [:]
        for row in ResolvedAddresses.rows(sessions: sessions, namedAddresses: [:]) {
            let key = normalizedKey(for: row.address)
            if learned[key] == nil {
                learned[key] = row.name
            }
        }
        for record in captureFileRecords {
            guard let address = IPAddressValue(parsing: record.address)?.compressedText.lowercased(),
                  learned[address] == nil, !record.name.text.isEmpty else
            {
                continue
            }
            learned[address] = record.name.text
        }
        return { address in
            let key = normalizedKey(for: address)
            return book.name(for: address) ?? learned[key] ?? book.displayName(for: address) ?? address
        }
    }

    nonisolated private static func normalizedKey(for address: String) -> String {
        IPAddressValue(parsing: address)?.compressedText.lowercased() ?? address.lowercased()
    }
}
