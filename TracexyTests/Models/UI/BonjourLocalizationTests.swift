import Foundation
import Testing
@testable import Tracexy

@Suite("Bonjour, DNS-SD, .arpa, and local discovery localization")
struct BonjourLocalizationTests {
    // MARK: Internal

    @Test("Sidebar local services & devices keys resolve exact English and Simplified Chinese strings")
    func sidebarLocalNamesLocalization() throws {
        let bundles = try makeCatalogBundles()
        defer { bundles.teardown() }

        let expectedEntries: [(key: String, zhHans: String)] = [
            ("Local Services & Devices", "本地服务与设备名"),
            ("No visible local names", "无可见的本地名称"),
            ("Copy Local Names", "复制本地名称"),
            ("Copy Local Name", "复制本地名称"),
            ("Restore Hidden Local Names", "恢复隐藏的本地名称"),
            ("Show sessions for %@", "显示 %@ 的会话"),
        ]

        assertResolvedEntries(expectedEntries, in: bundles)

        // Verify String(localized:) interpolation resolves formatted sidebar keys cleanly.
        let host = "Studio.local"
        #expect(String(localized: "Show sessions for \(host)", bundle: bundles.en) == "Show sessions for Studio.local")
        #expect(String(localized: "Show sessions for \(host)", bundle: bundles.zhHans) == "显示 Studio.local 的会话")
    }

    @Test("Bonjour, DNS-SD, and .arpa semantic annotation keys resolve exact English and Simplified Chinese strings")
    func bonjourAndArpaSemanticLocalization() throws {
        let bundles = try makeCatalogBundles()
        defer { bundles.teardown() }

        let expectedEntries: [(key: String, zhHans: String)] = [
            ("Browse Domain Probe", "服务浏览域探测"),
            ("DNS-SD legacy browse domain enumeration", "局域网服务浏览域探测 (DNS-SD)"),
            ("Browse Domain Query", "浏览域查询"),
            ("DNS-SD browse domain discovery", "局域网默认浏览域查询 (DNS-SD)"),
            ("Registration Domain", "注册域查询"),
            ("DNS-SD registration domain discovery", "局域网服务注册域查询 (DNS-SD)"),
            ("Service Enumeration", "全量服务枚举"),
            ("All local Bonjour service types query", "局域网全部服务类型枚举"),
            ("Apple Continuity", "Apple 连续互通"),
            ("Apple Continuity & Companion Link", "Apple 连续互通与设备协同"),
            ("AirPlay Video", "AirPlay 投屏"),
            ("AirPlay video & screen mirroring", "AirPlay 隔空播放与屏幕镜像"),
            ("AirPlay Audio", "AirPlay 音频"),
            ("AirPlay remote audio streaming (RAOP)", "AirPlay 隔空音频投送"),
            ("AirDrop", "隔空投送"),
            ("AirDrop peer discovery", "AirDrop 隔空投送发现"),
            ("Remote Dev Link", "远程开发连接"),
            ("Apple remote device development link", "Apple 远程设备开发连接"),
            ("iOS Wireless Sync", "iOS 无线调试"),
            ("iPhone & iPad wireless sync and debug", "iOS 设备无线同步与调试"),
            ("HomeKit", "HomeKit 家居"),
            ("Apple HomeKit smart home accessory", "Apple HomeKit 智能家居配件"),
            ("Matter / Thread", "Matter 家居"),
            ("Matter & Thread smart home mesh", "Matter / Thread 智能家居组网"),
            ("Sleep Proxy", "睡眠唤醒代理"),
            ("Bonjour Wake-on-LAN sleep proxy", "Bonjour 局域网睡眠唤醒代理"),
            ("Time Machine", "时间机器备份"),
            ("Time Machine wireless backup disk", "时间机器局域网备份发现"),
            ("LAN File Sharing", "局域网文件共享"),
            ("SMB / AFP local network file sharing", "SMB / AFP 局域网文件共享"),
            ("Screen Sharing", "屏幕共享"),
            ("VNC / macOS screen sharing discovery", "macOS 局域网屏幕共享发现"),
            ("Remote Apple Events", "远程 Apple 事件"),
            ("macOS Remote Apple Events (EPPC)", "macOS 远程 Apple 事件发现"),
            ("AirPrint", "无线打印机"),
            ("LAN printer & AirPrint discovery", "局域网无线打印机 (AirPrint)"),
            ("AirScan", "无线扫描仪"),
            ("LAN scanner & AirScan discovery", "局域网无线扫描仪 (AirScan)"),
            ("Google Cast", "Chromecast 投屏"),
            ("Chromecast media device discovery", "Chromecast 局域网投屏发现"),
            ("Spotify Connect", "Spotify 音箱"),
            ("Spotify Connect speaker discovery", "Spotify 局域网音箱发现"),
            ("Sonos", "Sonos 音响"),
            ("Sonos speaker system discovery", "Sonos 局域网音响发现"),
            ("Smart Home", "智能家居设备"),
            ("Smart home LAN device discovery", "智能家居局域网设备发现"),
            ("LAN Web Service", "局域网 Web"),
            ("Local HTTP web interface discovery", "局域网 HTTP 管理服务发现"),
            ("LAN SSH", "局域网 SSH"),
            ("Local SSH server discovery", "局域网 SSH 终端服务发现"),
            ("Bonjour Service", "Bonjour 服务"),
            ("Bonjour LAN service (%@ · %@)", "Bonjour 局域网服务 (%@ · %@)"),
            ("LAN Device", "局域网设备"),
            ("Local network device hostname (mDNS)", "局域网设备主机名 (mDNS)"),
            ("Encrypted DNS Probe", "加密 DNS 探测"),
            ("Discovery of Designated Resolvers (DDR)", "系统加密 DNS (DDR) 自动发现"),
            ("Reverse DNS", "反向域名反查"),
            ("Reverse IP-to-hostname lookup (PTR)", "IP 反向域名解析 (PTR)"),
            ("IPv4 Synthesis Probe", "DNS64 探测"),
            ("NAT64 / DNS64 prefix discovery (RFC 7050)", "NAT64 / DNS64 前缀自动发现"),
            ("%@ — %@ (local LAN discovery only, not public internet)", "%@ — %@（仅限本地局域网发现，不访问公网）"),
            ("%@ — %@", "%@ — %@"),
        ]

        assertResolvedEntries(expectedEntries, in: bundles)

        // Verify String(localized:) interpolation for formatted Bonjour templates.
        let serviceName = "_airplay"
        let transport = "TCP"
        #expect(
            String(localized: "Bonjour LAN service (\(serviceName) · \(transport))", bundle: bundles.en)
                == "Bonjour LAN service (_airplay · TCP)"
        )
        #expect(
            String(localized: "Bonjour LAN service (\(serviceName) · \(transport))", bundle: bundles.zhHans)
                == "Bonjour 局域网服务 (_airplay · TCP)"
        )

        let titleEn = String(localized: "AirPlay Video", bundle: bundles.en)
        let detailEn = String(localized: "AirPlay video & screen mirroring", bundle: bundles.en)
        let titleZh = String(localized: "AirPlay Video", bundle: bundles.zhHans)
        let detailZh = String(localized: "AirPlay video & screen mirroring", bundle: bundles.zhHans)

        #expect(
            String(
                localized: "\(titleEn) — \(detailEn) (local LAN discovery only, not public internet)",
                bundle: bundles.en
            ) == "AirPlay Video — AirPlay video & screen mirroring (local LAN discovery only, not public internet)"
        )
        #expect(
            String(
                localized: "\(titleZh) — \(detailZh) (local LAN discovery only, not public internet)",
                bundle: bundles.zhHans
            ) == "AirPlay 投屏 — AirPlay 隔空播放与屏幕镜像（仅限本地局域网发现，不访问公网）"
        )
        #expect(
            String(localized: "\(titleEn) — \(detailEn)", bundle: bundles.en)
                == "AirPlay Video — AirPlay video & screen mirroring"
        )
        #expect(
            String(localized: "\(titleZh) — \(detailZh)", bundle: bundles.zhHans)
                == "AirPlay 投屏 — AirPlay 隔空播放与屏幕镜像"
        )
    }

    @Test("All Bonjour keys exist in Localizable.xcstrings with translated zh-Hans entries")
    func bonjourKeysCatalogState() throws {
        let stringsMap = try loadCatalogStrings()

        let requiredKeys = [
            "Local Services & Devices",
            "No visible local names",
            "Copy Local Names",
            "Copy Local Name",
            "Restore Hidden Local Names",
            "Show sessions for %@",
            "Browse Domain Probe",
            "DNS-SD legacy browse domain enumeration",
            "Browse Domain Query",
            "DNS-SD browse domain discovery",
            "Registration Domain",
            "DNS-SD registration domain discovery",
            "Service Enumeration",
            "All local Bonjour service types query",
            "Apple Continuity",
            "Apple Continuity & Companion Link",
            "AirPlay Video",
            "AirPlay video & screen mirroring",
            "AirPlay Audio",
            "AirPlay remote audio streaming (RAOP)",
            "AirDrop",
            "AirDrop peer discovery",
            "Remote Dev Link",
            "Apple remote device development link",
            "iOS Wireless Sync",
            "iPhone & iPad wireless sync and debug",
            "HomeKit",
            "Apple HomeKit smart home accessory",
            "Matter / Thread",
            "Matter & Thread smart home mesh",
            "Sleep Proxy",
            "Bonjour Wake-on-LAN sleep proxy",
            "Time Machine",
            "Time Machine wireless backup disk",
            "LAN File Sharing",
            "SMB / AFP local network file sharing",
            "Screen Sharing",
            "VNC / macOS screen sharing discovery",
            "Remote Apple Events",
            "macOS Remote Apple Events (EPPC)",
            "AirPrint",
            "LAN printer & AirPrint discovery",
            "AirScan",
            "LAN scanner & AirScan discovery",
            "Google Cast",
            "Chromecast media device discovery",
            "Spotify Connect",
            "Spotify Connect speaker discovery",
            "Sonos",
            "Sonos speaker system discovery",
            "Smart Home",
            "Smart home LAN device discovery",
            "LAN Web Service",
            "Local HTTP web interface discovery",
            "LAN SSH",
            "Local SSH server discovery",
            "Bonjour Service",
            "Bonjour LAN service (%@ · %@)",
            "LAN Device",
            "Local network device hostname (mDNS)",
            "Encrypted DNS Probe",
            "Discovery of Designated Resolvers (DDR)",
            "Reverse DNS",
            "Reverse IP-to-hostname lookup (PTR)",
            "IPv4 Synthesis Probe",
            "NAT64 / DNS64 prefix discovery (RFC 7050)",
            "%@ — %@ (local LAN discovery only, not public internet)",
            "%@ — %@",
        ]

        #expect(requiredKeys.count == 68)

        for key in requiredKeys {
            let entry = try #require(stringsMap[key], "Missing key in Localizable.xcstrings: \(key)")
            let localizations = try #require(entry["localizations"] as? [String: Any], "Missing localizations for: \(key)")
            let zhHans = try #require(localizations["zh-Hans"] as? [String: Any], "Missing zh-Hans for: \(key)")
            let unit = try #require(zhHans["stringUnit"] as? [String: Any], "Missing stringUnit for: \(key)")
            let state = try #require(unit["state"] as? String)
            let value = try #require(unit["value"] as? String)
            #expect(state == "translated", "Expected translated zh-Hans state for: \(key)")
            #expect(!value.isEmpty, "Expected non-empty zh-Hans value for: \(key)")
        }
    }

    @Test("Format specifier counts are consistent across en, zh-Hans, and vi for the entire catalog")
    func formatSpecifierCountConsistencyAcrossCatalog() throws {
        let stringsMap = try loadCatalogStrings()
        let regex = try NSRegularExpression(
            pattern: #"%(?:%|(?:[0-9]+\$)?[-+#0]*(?:[0-9]+|\*)?(?:\.(?:[0-9]+|\*))?(?:hh|h|ll|l|q|L|z|t|j)?[@dDiouxXfFeEgGaAcCsSp])"#
        )

        var mismatches: [String] = []

        for (key, entry) in stringsMap.sorted(by: { $0.key < $1.key }) {
            let sourceCount = formatSpecifierCount(in: key, regex: regex)
            guard let localizations = entry["localizations"] as? [String: Any] else {
                continue
            }

            for language in ["en", "zh-Hans", "vi"] {
                guard let langObject = localizations[language] as? [String: Any] else {
                    continue
                }

                if let unit = langObject["stringUnit"] as? [String: Any],
                   let value = unit["value"] as? String
                {
                    let localizedCount = formatSpecifierCount(in: value, regex: regex)
                    if localizedCount != sourceCount {
                        mismatches.append(
                            "\(key) [\(language)]: expected \(sourceCount) specifiers, found \(localizedCount) in \"\(value)\""
                        )
                    }
                } else if let variations = langObject["variations"] as? [String: Any],
                          let plural = variations["plural"] as? [String: [String: Any]]
                {
                    for (form, formObject) in plural.sorted(by: { $0.key < $1.key }) {
                        guard let unit = formObject["stringUnit"] as? [String: Any],
                              let value = unit["value"] as? String else
                        {
                            continue
                        }
                        let localizedCount = formatSpecifierCount(in: value, regex: regex)
                        if localizedCount != sourceCount {
                            mismatches.append(
                                "\(key) [\(language).plural.\(form)]: expected \(sourceCount) specifiers, found \(localizedCount) in \"\(value)\""
                            )
                        }
                    }
                }
            }
        }

        #expect(mismatches.isEmpty, "Format specifier mismatches:\n\(mismatches.joined(separator: "\n"))")
    }

    // MARK: Private

    private enum CatalogError: Error {
        case rootNotFound
        case invalidCatalog
        case bundleCreationFailed
    }

    private struct CatalogBundles {
        let en: Bundle
        let zhHans: Bundle
        let teardown: () -> Void
    }

    private func assertResolvedEntries(
        _ entries: [(key: String, zhHans: String)],
        in bundles: CatalogBundles
    ) {
        let missingSentinel = "__MISSING_LOCALIZATION__"
        for (key, expectedZhHans) in entries {
            let resolvedEn = bundles.en.localizedString(forKey: key, value: missingSentinel, table: nil)
            let resolvedZh = bundles.zhHans.localizedString(forKey: key, value: missingSentinel, table: nil)
            #expect(resolvedEn == key, "English mismatch for key: \(key)")
            #expect(resolvedZh == expectedZhHans, "zh-Hans mismatch for key: \(key)")
        }
    }

    private func formatSpecifierCount(in text: String, regex: NSRegularExpression) -> Int {
        let nsText = text as NSString
        let range = NSRange(location: 0, length: nsText.length)
        return regex.matches(in: text, range: range).reduce(into: 0) { count, match in
            let token = nsText.substring(with: match.range)
            if token != "%%" {
                count += 1
            }
        }
    }

    private func loadCatalogStrings() throws -> [String: [String: Any]] {
        let root = try resolveProjectRoot()
        let xcstringsURL = root.appendingPathComponent("Tracexy/Localizable.xcstrings")
        let data = try Data(contentsOf: xcstringsURL)
        guard let catalog = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              catalog["sourceLanguage"] as? String == "en",
              let stringsMap = catalog["strings"] as? [String: [String: Any]] else
        {
            throw CatalogError.invalidCatalog
        }
        return stringsMap
    }

    private func makeCatalogBundles() throws -> CatalogBundles {
        let stringsMap = try loadCatalogStrings()

        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("tracexy-bonjour-i18n-tests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)

        for language in ["en", "zh-Hans"] {
            var dict: [String: String] = [:]
            for (key, entry) in stringsMap {
                if let locs = entry["localizations"] as? [String: Any],
                   let langObj = locs[language] as? [String: Any],
                   let unit = langObj["stringUnit"] as? [String: Any],
                   let state = unit["state"] as? String,
                   ["translated", "needs_review", "new"].contains(state),
                   let value = unit["value"] as? String
                {
                    dict[key] = value
                } else if language == "en" {
                    dict[key] = key
                }
            }
            let lprojURL = tempDir.appendingPathComponent("\(language).lproj", isDirectory: true)
            try FileManager.default.createDirectory(at: lprojURL, withIntermediateDirectories: true)
            let plistData = try PropertyListSerialization.data(
                fromPropertyList: dict,
                format: .binary,
                options: 0
            )
            try plistData.write(to: lprojURL.appendingPathComponent("Localizable.strings"))
        }

        guard let enBundle = Bundle(url: tempDir.appendingPathComponent("en.lproj", isDirectory: true)),
              let zhBundle = Bundle(url: tempDir.appendingPathComponent("zh-Hans.lproj", isDirectory: true)) else
        {
            try? FileManager.default.removeItem(at: tempDir)
            throw CatalogError.bundleCreationFailed
        }

        return CatalogBundles(
            en: enBundle,
            zhHans: zhBundle,
            teardown: { try? FileManager.default.removeItem(at: tempDir) }
        )
    }

    private func resolveProjectRoot() throws -> URL {
        var url = URL(fileURLWithPath: #filePath)
        while url.lastPathComponent != "TracexyTests", url.path != "/" {
            url.deleteLastPathComponent()
        }
        guard url.lastPathComponent == "TracexyTests" else {
            throw CatalogError.rootNotFound
        }
        url.deleteLastPathComponent()
        return url
    }
}
