import CommonCrypto
import CryptoKit
import Foundation

// MARK: - QUICInitialDecoder

/// Passive RFC 9001 §5.2 and RFC 9369 §3.3 QUIC Initial packet unprotection.
///
/// QUIC Initial packets are protected with keys derived deterministically from a
/// public version-specific salt and the connection's clear-text Destination
/// Connection ID. Removing header protection and opening the AES-128-GCM payload
/// requires zero endpoint key material and zero network I/O, allowing passive
/// extraction of the TLS 1.3 `ClientHello` (SNI, ALPN) and `ServerHello`.
///
/// Every read is bounds-checked and overflow-safe; unsupported versions, truncated
/// datagrams, or AEAD tag mismatches return `nil` without trapping.
nonisolated enum QUICInitialDecoder {
    // MARK: Internal

    /// Which Initial traffic secret authenticated the packet.
    enum Role: Equatable, Sendable {
        case client
        case server
    }

    /// Plaintext handshake metadata recovered from a QUIC Initial datagram.
    struct DecodedInitial: Equatable, Sendable {
        let role: Role
        let packetNumber: UInt64
        let sni: String?
        let alpn: [String]
        let handshakeLabel: String?
        let tlsRecords: [TLSRecordFact]
    }

    /// Attempts to unprotect coalesced QUIC Initial packet(s) from offset 0 of a
    /// UDP datagram payload (`buf`).
    ///
    /// - Parameters:
    ///   - buf: UDP payload positioned at the start of the QUIC datagram.
    ///   - clientDestinationCID: Optional override for the Initial key-derivation
    ///     Connection ID. When `nil`, each packet's clear-text Destination CID is used.
    static func decodeInitial(
        _ buf: PacketBuffer,
        clientDestinationCID: [UInt8]? = nil
    )
        -> DecodedInitial?
    {
        var offset = 0
        var packetCount = 0
        var matchedRole: Role?
        var firstPacketNumber: UInt64?
        var cryptoSegments: [CryptoSegment] = []

        while offset < buf.length, packetCount < maxCoalescedInitialPackets {
            guard let header = parseInitialHeader(buf, at: offset) else {
                break
            }
            packetCount += 1
            let ikm = clientDestinationCID ?? header.dcid
            let initialSecret = hkdfExtract(salt: header.spec.salt, ikm: ikm)
            let candidateRoles: [Role] = if let matchedRole {
                [matchedRole]
            } else {
                [.client, .server]
            }
            guard let unprotected = unprotectPacket(
                buf,
                header: header,
                initialSecret: initialSecret,
                roles: candidateRoles
            ) else {
                if packetCount == 1 {
                    return nil
                }
                break
            }
            if matchedRole == nil {
                matchedRole = unprotected.role
            }
            if firstPacketNumber == nil {
                firstPacketNumber = unprotected.packetNumber
            }
            cryptoSegments.append(contentsOf: extractCryptoSegments(from: unprotected.plaintext))
            offset = header.packetEnd
        }

        guard let role = matchedRole, let packetNumber = firstPacketNumber else {
            return nil
        }

        let cryptoBytes = assembleContiguousCrypto(cryptoSegments)
        let parsedHandshake = parseTLSHandshake(cryptoBytes)
        return DecodedInitial(
            role: role,
            packetNumber: packetNumber,
            sni: parsedHandshake.sni,
            alpn: parsedHandshake.alpn,
            handshakeLabel: parsedHandshake.handshakeLabel,
            tlsRecords: parsedHandshake.tlsRecords
        )
    }

    /// Unprotects a QUIC Initial datagram when authentic and enriches the QUIC layer
    /// and `DecodedPacket` with SNI, ALPN, handshake role, and neutral `TLSRecordFact`s.
    static func enrich(
        _ buf: PacketBuffer,
        typeName: String,
        summary: inout String,
        fields: inout [DecodedField],
        into packet: inout DecodedPacket
    ) {
        guard let initial = decodeInitial(buf) else {
            return
        }
        if let sni = initial.sni {
            packet.sni = sni
            fields.append(DecodedField(name: "Server Name (SNI)", value: sni))
        }
        if !initial.alpn.isEmpty {
            fields.append(DecodedField(name: "ALPN", value: initial.alpn.joined(separator: ", ")))
        }
        if !initial.tlsRecords.isEmpty {
            packet.tlsRecords.append(contentsOf: initial.tlsRecords)
        }
        if let handshakeLabel = initial.handshakeLabel {
            fields.append(DecodedField(name: "TLS Handshake", value: handshakeLabel))
            summary = if let sni = initial.sni {
                "\(typeName) · \(handshakeLabel) · \(sni)"
            } else {
                "\(typeName) · \(handshakeLabel)"
            }
        } else if let sni = initial.sni {
            summary = "\(typeName) · \(sni)"
        }
    }

    // MARK: Private

    private struct VersionSpec {
        let salt: [UInt8]
        let keyLabel: String
        let ivLabel: String
        let hpLabel: String
    }

    private struct InitialHeader {
        let spec: VersionSpec
        let packetOffset: Int
        let firstByte: UInt8
        let dcid: [UInt8]
        let pnOffset: Int
        let payloadLength: Int
        let packetEnd: Int
    }

    private struct UnprotectedPacket {
        let role: Role
        let packetNumber: UInt64
        let plaintext: [UInt8]
    }

    private struct CryptoSegment {
        let offset: Int
        let bytes: [UInt8]
    }

    private struct ParsedHandshake {
        var sni: String?
        var alpn: [String] = []
        var handshakeLabel: String?
        var tlsRecords: [TLSRecordFact] = []
    }

    private static let quicV1: UInt32 = 0x00000001
    private static let quicV2: UInt32 = 0x6B3343CF
    private static let maxCIDLength = 20
    private static let aeadTagLength = 16
    private static let sampleLength = 16
    private static let minProtectedPayloadLength = 20
    private static let maxCoalescedInitialPackets = 4
    private static let maxFramesPerPacket = 64
    private static let maxAckRanges = 256
    private static let maxCryptoBytes = 4_096
    private static let maxTLSExtensions = 64
    private static let maxALPNProtocols = 16

    /// RFC 9001 §5.2 Initial salt for QUIC v1 (`38762cf7f55934b34d179ae6a4c80cadccbb7f0a`).
    private static let v1Spec = VersionSpec(
        salt: [
            0x38, 0x76, 0x2C, 0xF7, 0xF5, 0x59, 0x34, 0xB3, 0x4D, 0x17,
            0x9A, 0xE6, 0xA4, 0xC8, 0x0C, 0xAD, 0xCC, 0xBB, 0x7F, 0x0A,
        ],
        keyLabel: "quic key",
        ivLabel: "quic iv",
        hpLabel: "quic hp"
    )

    /// RFC 9369 §3.3.1 Initial salt for QUIC v2 (`0dede3def700a6db819381be6e269dcbf9bd2ed9`).
    private static let v2Spec = VersionSpec(
        salt: [
            0x0D, 0xED, 0xE3, 0xDE, 0xF7, 0x00, 0xA6, 0xDB, 0x81, 0x93,
            0x81, 0xBE, 0x6E, 0x26, 0x9D, 0xCB, 0xF9, 0xBD, 0x2E, 0xD9,
        ],
        keyLabel: "quicv2 key",
        ivLabel: "quicv2 iv",
        hpLabel: "quicv2 hp"
    )

    /// Matches version and long-header type bits for QUIC v1 (RFC 9000 §17.2.2: `0x00`)
    /// and QUIC v2 (RFC 9369 §3.2: `0x01`).
    private static func initialVersionSpec(firstByte: UInt8, version: UInt32) -> VersionSpec? {
        guard (firstByte & 0xC0) == 0xC0 else {
            return nil
        }
        let packetType = (firstByte & 0x30) >> 4
        switch (version, packetType) {
        case (quicV1, 0x00):
            return v1Spec
        case (quicV2, 0x01):
            return v2Spec
        default:
            return nil
        }
    }

    /// Parses the clear-text prefix of a QUIC Initial Long Header at `packetOffset`.
    private static func parseInitialHeader(_ buf: PacketBuffer, at packetOffset: Int) -> InitialHeader? {
        guard packetOffset <= buf.length - 7,
              let firstByte = try? buf.u8(packetOffset),
              let version = try? buf.u32(packetOffset + 1),
              let spec = initialVersionSpec(firstByte: firstByte, version: version),
              let dcidLen = try? Int(buf.u8(packetOffset + 5)),
              dcidLen <= maxCIDLength,
              let dcid = try? buf.bytes(packetOffset + 6, dcidLen) else
        {
            return nil
        }
        let scidLenOffset = packetOffset + 6 + dcidLen
        guard let scidLen = try? Int(buf.u8(scidLenOffset)),
              scidLen <= maxCIDLength else
        {
            return nil
        }
        let afterSCID = scidLenOffset + 1 + scidLen
        guard afterSCID <= buf.length,
              let (tokenLengthRaw, afterTokenLen) = readVarintBuffer(buf, at: afterSCID),
              let tokenLength = exactLength(tokenLengthRaw, maxAllowed: buf.length - afterTokenLen) else
        {
            return nil
        }
        let lengthVarintOffset = afterTokenLen + tokenLength
        guard let (payloadLengthRaw, pnOffset) = readVarintBuffer(buf, at: lengthVarintOffset),
              let payloadLength = exactLength(payloadLengthRaw, maxAllowed: buf.length - pnOffset),
              payloadLength >= minProtectedPayloadLength else
        {
            return nil
        }
        return InitialHeader(
            spec: spec,
            packetOffset: packetOffset,
            firstByte: firstByte,
            dcid: dcid,
            pnOffset: pnOffset,
            payloadLength: payloadLength,
            packetEnd: pnOffset + payloadLength
        )
    }

    /// Removes header protection and opens the AES-128-GCM ciphertext under the first
    /// matching Initial traffic role (`"client in"` then `"server in"`).
    private static func unprotectPacket(
        _ buf: PacketBuffer,
        header: InitialHeader,
        initialSecret: SymmetricKey,
        roles: [Role]
    )
        -> UnprotectedPacket?
    {
        guard let sample = try? buf.bytes(header.pnOffset + 4, sampleLength) else {
            return nil
        }
        let headerPrefixLength = header.pnOffset - header.packetOffset
        guard let rawHeaderPrefix = try? buf.bytes(header.packetOffset, headerPrefixLength) else {
            return nil
        }

        for role in roles {
            let roleLabel = role == .client ? "client in" : "server in"
            let trafficSecret = SymmetricKey(
                data: hkdfExpandLabel(secret: initialSecret, label: roleLabel, length: 32)
            )
            let key = hkdfExpandLabel(secret: trafficSecret, label: header.spec.keyLabel, length: 16)
            let iv = hkdfExpandLabel(secret: trafficSecret, label: header.spec.ivLabel, length: 12)
            let hp = hkdfExpandLabel(secret: trafficSecret, label: header.spec.hpLabel, length: 16)

            guard let mask = aes128BlockEncrypt(key: hp, block: sample) else {
                continue
            }
            let unmaskedFirst = header.firstByte ^ (mask[0] & 0x0F)
            let pnLen = Int(unmaskedFirst & 0x03) + 1
            guard let maskedPN = try? buf.bytes(header.pnOffset, pnLen) else {
                continue
            }

            var unmaskedPN = [UInt8](repeating: 0, count: pnLen)
            var packetNumber: UInt64 = 0
            for index in 0 ..< pnLen {
                let unmaskedByte = maskedPN[index] ^ mask[1 + index]
                unmaskedPN[index] = unmaskedByte
                packetNumber = (packetNumber << 8) | UInt64(unmaskedByte)
            }

            var nonceBytes = iv
            for index in 0 ..< pnLen {
                nonceBytes[12 - pnLen + index] ^= unmaskedPN[index]
            }

            var aad = rawHeaderPrefix
            aad[0] = unmaskedFirst
            aad.append(contentsOf: unmaskedPN)

            let ciphertextOffset = header.pnOffset + pnLen
            let ciphertextLength = header.payloadLength - pnLen - aeadTagLength
            let tagOffset = ciphertextOffset + ciphertextLength
            guard ciphertextLength >= 0,
                  let ciphertext = try? buf.bytes(ciphertextOffset, ciphertextLength),
                  let tag = try? buf.bytes(tagOffset, aeadTagLength),
                  let nonce = try? AES.GCM.Nonce(data: nonceBytes),
                  let sealedBox = try? AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag),
                  let plaintext = try? AES.GCM.open(
                      sealedBox,
                      using: SymmetricKey(data: key),
                      authenticating: aad
                  ) else
            {
                continue
            }
            return UnprotectedPacket(
                role: role,
                packetNumber: packetNumber,
                plaintext: Array(plaintext)
            )
        }
        return nil
    }

    // MARK: QUIC Initial Frame Walk

    /// Walks plaintext frames allowed in QUIC Initial packets (`PADDING`, `PING`,
    /// `ACK`, `CRYPTO`, `CONNECTION_CLOSE`) and collects bounded `CRYPTO` segments.
    private static func extractCryptoSegments(from plaintext: [UInt8]) -> [CryptoSegment] {
        var segments: [CryptoSegment] = []
        var offset = 0
        var frameCount = 0

        while offset < plaintext.count, frameCount < maxFramesPerPacket {
            // Fast-skip contiguous PADDING (0x00) runs without counting each zero byte
            // against the non-padding frame guard.
            if plaintext[offset] == 0x00 {
                while offset < plaintext.count, plaintext[offset] == 0x00 {
                    offset += 1
                }
                continue
            }
            frameCount += 1
            guard let (frameType, nextOffset) = readVarintSlice(plaintext, at: offset) else {
                break
            }
            offset = nextOffset

            switch frameType {
            case 0x01: // PING
                continue
            case 0x02,
                 0x03: // ACK (0x03 carries trailing ECN counts)
                guard let afterAck = skipAckFrame(plaintext, at: offset, hasECN: frameType == 0x03) else {
                    return segments
                }
                offset = afterAck
            case 0x06: // CRYPTO
                guard let (cryptoOffsetRaw, afterCryptoOffset) = readVarintSlice(plaintext, at: offset),
                      let (cryptoLengthRaw, dataStart) = readVarintSlice(plaintext, at: afterCryptoOffset),
                      let cryptoLength = exactLength(cryptoLengthRaw, maxAllowed: plaintext.count - dataStart) else
                {
                    return segments
                }
                offset = dataStart + cryptoLength
                if cryptoLength > 0,
                   let cryptoOffset = exactLength(cryptoOffsetRaw, maxAllowed: maxCryptoBytes - 1)
                {
                    let copyCount = min(cryptoLength, maxCryptoBytes - cryptoOffset)
                    let slice = Array(plaintext[dataStart ..< (dataStart + copyCount)])
                    segments.append(CryptoSegment(offset: cryptoOffset, bytes: slice))
                }
            case 0x1C: // CONNECTION_CLOSE (QUIC layer)
                guard let (_, afterError) = readVarintSlice(plaintext, at: offset),
                      let (_, afterTriggerType) = readVarintSlice(plaintext, at: afterError),
                      let (reasonLenRaw, reasonStart) = readVarintSlice(plaintext, at: afterTriggerType),
                      let reasonLen = exactLength(reasonLenRaw, maxAllowed: plaintext.count - reasonStart) else
                {
                    return segments
                }
                offset = reasonStart + reasonLen
            default:
                return segments
            }
        }
        return segments
    }

    private static func skipAckFrame(_ bytes: [UInt8], at start: Int, hasECN: Bool) -> Int? {
        guard let (_, afterLargest) = readVarintSlice(bytes, at: start),
              let (_, afterDelay) = readVarintSlice(bytes, at: afterLargest),
              let (rangeCountRaw, afterRangeCount) = readVarintSlice(bytes, at: afterDelay),
              let rangeCount = exactLength(rangeCountRaw, maxAllowed: maxAckRanges),
              let (_, afterFirstRange) = readVarintSlice(bytes, at: afterRangeCount) else
        {
            return nil
        }
        var offset = afterFirstRange
        for _ in 0 ..< rangeCount {
            guard let (_, afterGap) = readVarintSlice(bytes, at: offset),
                  let (_, afterAckLen) = readVarintSlice(bytes, at: afterGap) else
            {
                return nil
            }
            offset = afterAckLen
        }
        if hasECN {
            guard let (_, afterECT0) = readVarintSlice(bytes, at: offset),
                  let (_, afterECT1) = readVarintSlice(bytes, at: afterECT0),
                  let (_, afterCE) = readVarintSlice(bytes, at: afterECT1) else
            {
                return nil
            }
            offset = afterCE
        }
        return offset
    }

    /// Reassembles possibly split, overlapping, or out-of-order `CRYPTO` ranges into
    /// the contiguous byte prefix starting at stream offset 0 (bounded to 4,096 bytes).
    private static func assembleContiguousCrypto(_ segments: [CryptoSegment]) -> [UInt8] {
        guard !segments.isEmpty else {
            return []
        }
        let sorted = segments.sorted { $0.offset < $1.offset }
        var contiguous: [UInt8] = []
        for segment in sorted {
            if segment.offset > contiguous.count {
                break
            }
            let endOffset = segment.offset + segment.bytes.count
            if endOffset > contiguous.count {
                let newStart = contiguous.count - segment.offset
                contiguous.append(contentsOf: segment.bytes[newStart...])
            }
        }
        return contiguous
    }

    // MARK: TLS 1.3 Handshake Parsing

    /// Extracts SNI, ALPN, handshake label, and neutral `TLSRecordFact` from the
    /// contiguous `CRYPTO` stream starting at offset 0.
    private static func parseTLSHandshake(_ crypto: [UInt8]) -> ParsedHandshake {
        var result = ParsedHandshake()
        guard crypto.count >= 4 else {
            return result
        }
        let messageType = crypto[0]
        let declaredHandshakeBody = Int(crypto[1]) << 16 | Int(crypto[2]) << 8 | Int(crypto[3])
        let declaredRecordBody = 4 + declaredHandshakeBody
        let handshakeEnd = min(declaredRecordBody, crypto.count)

        switch messageType {
        case 0x01:
            result.handshakeLabel = "Client Hello"
            parseClientHello(crypto, end: handshakeEnd, into: &result)
        case 0x02:
            result.handshakeLabel = "Server Hello"
            parseServerHello(crypto, end: handshakeEnd, into: &result)
        default:
            return result
        }

        // Wrap a synthetic 5-byte TLS Handshake record header `[22, 0x03, 0x03, hi, lo]`
        // around the raw TLS handshake message so `TLSFactsDecoder` applies identical
        // completeness and `supported_versions` rules without duplicating its parser.
        let clampedRecordBody = min(declaredRecordBody, Int(UInt16.max))
        let capturedHandshakeBytes = min(crypto.count, clampedRecordBody)
        var syntheticRecord: [UInt8] = [
            22, 0x03, 0x03,
            UInt8((clampedRecordBody >> 8) & 0xFF),
            UInt8(clampedRecordBody & 0xFF),
        ]
        syntheticRecord.reserveCapacity(5 + capturedHandshakeBytes)
        syntheticRecord.append(contentsOf: crypto.prefix(capturedHandshakeBytes))
        if let fact = TLSFactsDecoder.recordFact(PacketBuffer(syntheticRecord)),
           fact.handshake != nil
        {
            result.tlsRecords.append(fact)
        }
        return result
    }

    private static func parseClientHello(
        _ crypto: [UInt8],
        end: Int,
        into result: inout ParsedHandshake
    ) {
        // Handshake header (4) + legacy_version (2) + random (32) + session_id_len (1)
        guard end >= 39 else {
            return
        }
        let sessionIDLen = Int(crypto[38])
        var offset = 39 + sessionIDLen
        guard sessionIDLen <= 32, offset + 2 <= end else {
            return
        }
        let cipherSuitesLen = readU16(crypto, at: offset)
        offset += 2 + cipherSuitesLen
        guard cipherSuitesLen >= 2, cipherSuitesLen.isMultiple(of: 2), offset + 1 <= end else {
            return
        }
        let compressionLen = Int(crypto[offset])
        offset += 1 + compressionLen
        guard compressionLen >= 1, offset + 2 <= end else {
            return
        }
        let extensionsTotalLen = readU16(crypto, at: offset)
        offset += 2
        let extensionsEnd = min(offset + extensionsTotalLen, end)
        walkExtensions(crypto, start: offset, end: extensionsEnd, allowSNI: true, into: &result)
    }

    private static func parseServerHello(
        _ crypto: [UInt8],
        end: Int,
        into result: inout ParsedHandshake
    ) {
        // Handshake header (4) + legacy_version (2) + random (32) + session_id_len (1)
        guard end >= 39 else {
            return
        }
        let sessionIDLen = Int(crypto[38])
        // cipher_suite (2) + compression_method (1)
        var offset = 39 + sessionIDLen + 3
        guard sessionIDLen <= 32, offset + 2 <= end else {
            return
        }
        let extensionsTotalLen = readU16(crypto, at: offset)
        offset += 2
        let extensionsEnd = min(offset + extensionsTotalLen, end)
        walkExtensions(crypto, start: offset, end: extensionsEnd, allowSNI: false, into: &result)
    }

    private static func walkExtensions(
        _ crypto: [UInt8],
        start: Int,
        end: Int,
        allowSNI: Bool,
        into result: inout ParsedHandshake
    ) {
        var offset = start
        var extensionCount = 0
        while offset + 4 <= end, extensionCount < maxTLSExtensions {
            extensionCount += 1
            let extType = readU16(crypto, at: offset)
            let extLen = readU16(crypto, at: offset + 2)
            let extData = offset + 4
            guard extLen <= end - extData else {
                break
            }
            if extType == 0x0000, allowSNI, result.sni == nil {
                result.sni = parseServerNameExtension(crypto, at: extData, length: extLen)
            } else if extType == 0x0010, result.alpn.isEmpty {
                result.alpn = parseALPNExtension(crypto, at: extData, length: extLen)
            }
            offset = extData + extLen
        }
    }

    /// RFC 6066 §3 `ServerNameList`: 2-byte list length, followed by `name_type` (0 =
    /// `host_name`), 2-byte `HostName` length, and UTF-8/ASCII host bytes.
    private static func parseServerNameExtension(
        _ crypto: [UInt8],
        at start: Int,
        length: Int
    )
        -> String?
    {
        guard length >= 2 else {
            return nil
        }
        let listLen = readU16(crypto, at: start)
        guard listLen <= length - 2 else {
            return nil
        }
        let listEnd = start + 2 + listLen
        var offset = start + 2
        while offset + 3 <= listEnd {
            let nameType = crypto[offset]
            let nameLen = readU16(crypto, at: offset + 1)
            let nameStart = offset + 3
            guard nameLen <= listEnd - nameStart else {
                return nil
            }
            if nameType == 0x00, nameLen > 0 {
                let bytes = crypto[nameStart ..< (nameStart + nameLen)]
                if let text = String(bytes: bytes, encoding: .utf8),
                   !text.isEmpty,
                   !text.utf8.contains(where: { $0 < 0x20 || $0 == 0x7F })
                {
                    return text
                }
            }
            offset = nameStart + nameLen
        }
        return nil
    }

    /// RFC 7301 §3.1 `ProtocolNameList`: 2-byte list length, then 1-byte length-prefixed
    /// protocol identifiers (e.g. `"h3"`).
    private static func parseALPNExtension(
        _ crypto: [UInt8],
        at start: Int,
        length: Int
    )
        -> [String]
    {
        guard length >= 2 else {
            return []
        }
        let listLen = readU16(crypto, at: start)
        guard listLen <= length - 2 else {
            return []
        }
        let listEnd = start + 2 + listLen
        var offset = start + 2
        var protocols: [String] = []
        while offset < listEnd, protocols.count < maxALPNProtocols {
            let nameLen = Int(crypto[offset])
            let nameStart = offset + 1
            guard nameLen > 0, nameLen <= listEnd - nameStart else {
                break
            }
            let bytes = crypto[nameStart ..< (nameStart + nameLen)]
            if let text = String(bytes: bytes, encoding: .utf8),
               !text.isEmpty,
               !text.utf8.contains(where: { $0 < 0x20 || $0 == 0x7F })
            {
                protocols.append(text)
            }
            offset = nameStart + nameLen
        }
        return protocols
    }

    // MARK: Cryptographic Primitives

    private static func hkdfExtract(salt: [UInt8], ikm: [UInt8]) -> SymmetricKey {
        let prk = HKDF<SHA256>.extract(
            inputKeyMaterial: SymmetricKey(data: ikm),
            salt: salt
        )
        return SymmetricKey(data: prk)
    }

    /// TLS 1.3 `HKDF-Expand-Label(Secret, Label, "", Length)` (RFC 8446 §7.1).
    private static func hkdfExpandLabel(
        secret: SymmetricKey,
        label: String,
        length: Int
    )
        -> [UInt8]
    {
        let fullLabel = Array(("tls13 " + label).utf8)
        var hkdfLabel: [UInt8] = [
            UInt8((length >> 8) & 0xFF),
            UInt8(length & 0xFF),
            UInt8(fullLabel.count),
        ]
        hkdfLabel.append(contentsOf: fullLabel)
        hkdfLabel.append(0x00)
        let derived = HKDF<SHA256>.expand(
            pseudoRandomKey: secret,
            info: hkdfLabel,
            outputByteCount: length
        )
        return derived.withUnsafeBytes { Array($0) }
    }

    /// Single-block AES-128-ECB encryption for RFC 9001 §5.4.3 header protection.
    private static func aes128BlockEncrypt(key: [UInt8], block: [UInt8]) -> [UInt8]? {
        guard key.count == kCCKeySizeAES128, block.count == kCCBlockSizeAES128 else {
            return nil
        }
        var output = [UInt8](repeating: 0, count: kCCBlockSizeAES128)
        var dataOutMoved = 0
        let status = key.withUnsafeBytes { keyPtr in
            block.withUnsafeBytes { blockPtr in
                output.withUnsafeMutableBytes { outPtr in
                    CCCrypt(
                        CCOperation(kCCEncrypt),
                        CCAlgorithm(kCCAlgorithmAES),
                        CCOptions(kCCOptionECBMode),
                        keyPtr.baseAddress,
                        kCCKeySizeAES128,
                        nil,
                        blockPtr.baseAddress,
                        kCCBlockSizeAES128,
                        outPtr.baseAddress,
                        kCCBlockSizeAES128,
                        &dataOutMoved
                    )
                }
            }
        }
        guard status == kCCSuccess, dataOutMoved == kCCBlockSizeAES128 else {
            return nil
        }
        return output
    }

    // MARK: Integer & Varint Readers

    private static func readU16(_ bytes: [UInt8], at offset: Int) -> Int {
        Int(bytes[offset]) << 8 | Int(bytes[offset + 1])
    }

    /// Converts a 62-bit QUIC varint to `Int` only when it fits within `0 ... maxAllowed`.
    private static func exactLength(_ raw: UInt64, maxAllowed: Int) -> Int? {
        guard maxAllowed >= 0, raw <= UInt64(maxAllowed) else {
            return nil
        }
        return Int(raw)
    }

    /// RFC 9000 §16 variable-length integer reader over `PacketBuffer`.
    private static func readVarintBuffer(_ buf: PacketBuffer, at offset: Int) -> (UInt64, Int)? {
        guard let first = try? buf.u8(offset) else {
            return nil
        }
        let length = 1 << (first >> 6)
        guard let raw = try? buf.bytes(offset, length) else {
            return nil
        }
        var value = UInt64(raw[0] & 0x3F)
        for index in 1 ..< length {
            value = (value << 8) | UInt64(raw[index])
        }
        return (value, offset + length)
    }

    /// RFC 9000 §16 variable-length integer reader over `[UInt8]`.
    private static func readVarintSlice(_ bytes: [UInt8], at offset: Int) -> (UInt64, Int)? {
        guard offset >= 0, offset < bytes.count else {
            return nil
        }
        let first = bytes[offset]
        let length = 1 << (first >> 6)
        guard length <= bytes.count - offset else {
            return nil
        }
        var value = UInt64(first & 0x3F)
        for index in 1 ..< length {
            value = (value << 8) | UInt64(bytes[offset + index])
        }
        return (value, offset + length)
    }
}
