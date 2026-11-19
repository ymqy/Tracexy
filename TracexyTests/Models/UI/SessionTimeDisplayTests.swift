import Foundation
import Testing
@testable import Tracexy

/// View ▸ Session Time: three formats, an honest fallback when a capture has no
/// timed frame, and a per-Project choice that survives rebinding.
@MainActor
struct SessionTimeDisplayTests {
    @Test
    func formatsReadAsNamed() {
        let start = Date(timeIntervalSince1970: 1_800_000_000) // 2027-01-15T08:00:00Z
        let later = start.addingTimeInterval(83.4567)
        #expect(SessionTimeFormat.utc.string(for: later, captureStart: start) == "08:01:23")
        #expect(SessionTimeFormat.sinceCaptureStart.string(for: later, captureStart: start) == "83.457")
        #expect(SessionTimeFormat.sinceCaptureStart.string(for: start, captureStart: start) == "0.000")
        #expect(SessionTimeFormat.sinceCaptureStart
            .string(for: start.addingTimeInterval(-1), captureStart: start) == "-1.000")
        // No timed frame to count from: the time of day, never an invented origin.
        #expect(SessionTimeFormat.sinceCaptureStart.string(for: later, captureStart: nil) == "—")
        #expect(SessionTimeFormat.allCases.map(\.columnTitle) == ["Time", "UTC", "Since Start"])
    }

    @Test
    func choiceIsKeptPerProjectSuite() throws {
        let first = "session-time-a-\(UUID().uuidString)"
        let second = "session-time-b-\(UUID().uuidString)"
        let defaultsA = try #require(UserDefaults(suiteName: first))
        let defaultsB = try #require(UserDefaults(suiteName: second))
        defer {
            TestPreferences.remove(first)
            TestPreferences.remove(second)
        }
        let display = SessionTimeDisplay()
        display.bind(to: defaultsA)
        #expect(display.format == .timeOfDay)
        display.format = .utc
        display.bind(to: defaultsB)
        #expect(display.format == .timeOfDay)
        // Binding never writes the incoming Project's value into the other suite.
        #expect(defaultsB.string(forKey: ProjectScopedSettingsKeys.sessionTimeFormat) == nil)
        display.bind(to: defaultsA)
        #expect(display.format == .utc)
    }

    @Test
    func timeOfDayCacheMatchesDirectFormattingAcrossRepeatedAndDistinctSeconds() {
        let base = Date(timeIntervalSince1970: 1_800_000_000)
        let samples: [Date] = [
            base,
            base.addingTimeInterval(0.001),
            base.addingTimeInterval(0.499),
            base.addingTimeInterval(0.999),
            base.addingTimeInterval(1.0),
            base.addingTimeInterval(1.75),
            base.addingTimeInterval(59.9),
            base.addingTimeInterval(60.0),
            base.addingTimeInterval(3_661.25),
            Date(timeIntervalSince1970: -0.2),
            Date(timeIntervalSince1970: -1.2),
        ]

        // Populate cache and verify first pass matches direct Date.FormatStyle output.
        for date in samples {
            let expected = date.formatted(.dateTime.hour().minute().second())
            let formatted = SessionTimeFormat.timeOfDay.string(for: date, captureStart: nil)
            #expect(formatted == expected)
        }

        // Repeat pass hits the whole-second cache and remains byte-for-byte identical.
        for date in samples {
            let expected = date.formatted(.dateTime.hour().minute().second())
            let formatted = SessionTimeFormat.timeOfDay.string(for: date, captureStart: nil)
            #expect(formatted == expected)
        }

        // Distinct seconds produce distinct strings; sub-seconds in the same second match.
        #expect(
            SessionTimeFormat.timeOfDay.string(for: base.addingTimeInterval(0.001), captureStart: nil)
                == SessionTimeFormat.timeOfDay.string(for: base.addingTimeInterval(0.999), captureStart: nil)
        )
        #expect(
            SessionTimeFormat.timeOfDay.string(for: base, captureStart: nil)
                != SessionTimeFormat.timeOfDay.string(for: base.addingTimeInterval(1.0), captureStart: nil)
        )
    }

    @Test
    func byteUnitsFormattingMatchesAcrossBinaryDecimalAndLanguageOverrides() throws {
        let suiteName = "byte-units-cache-\(UUID().uuidString)"
        let customDefaults = try #require(UserDefaults(suiteName: suiteName))
        defer { TestPreferences.remove(suiteName) }

        let sampleSizes: [Int64] = [0, 1, 684, 999, 1_000, 1_022, 1_024, 4_096, 1_000_000, 1_048_576]

        // 1. Custom UserDefaults suite: binary vs decimal under system default locale.
        try AppLanguage.withTemporaryLanguageForTesting("system") {
            customDefaults.set(ByteUnits.binary.rawValue, forKey: SettingsKeys.byteUnits)
            for bytes in sampleSizes {
                let expected = ByteCountFormatter.string(fromByteCount: bytes, countStyle: .binary)
                #expect(ByteUnits.string(bytes, defaults: customDefaults) == expected)
                #expect(ByteUnits.string(bytes, defaults: customDefaults) == expected)
            }

            customDefaults.set(ByteUnits.decimal.rawValue, forKey: SettingsKeys.byteUnits)
            for bytes in sampleSizes {
                let expected = ByteCountFormatter.string(fromByteCount: bytes, countStyle: .decimal)
                #expect(ByteUnits.string(bytes, defaults: customDefaults) == expected)
                #expect(ByteUnits.string(bytes, defaults: customDefaults) == expected)
            }
            let binarySuite = "byte-units-bin-\(UUID().uuidString)"
            let binaryDefaults = try #require(UserDefaults(suiteName: binarySuite))
            defer { TestPreferences.remove(binarySuite) }
            binaryDefaults.set(ByteUnits.binary.rawValue, forKey: SettingsKeys.byteUnits)
            #expect(ByteUnits.string(1_000, defaults: customDefaults) != ByteUnits.string(1_000, defaults: binaryDefaults))
        }

        // 2. Application defaults cache invalidates immediately on UserDefaults mutation.
        let appDefaults = TracexyIdentity.applicationDefaults
        let previousValue = appDefaults.object(forKey: SettingsKeys.byteUnits)
        defer {
            if let previousValue {
                appDefaults.set(previousValue, forKey: SettingsKeys.byteUnits)
            } else {
                appDefaults.removeObject(forKey: SettingsKeys.byteUnits)
            }
        }
        AppLanguage.withTemporaryLanguageForTesting("en") {
            appDefaults.set(ByteUnits.binary.rawValue, forKey: SettingsKeys.byteUnits)
            #expect(ByteUnits.current(defaults: appDefaults) == .binary)
            let binary1000 = ByteUnits.string(1_000, defaults: appDefaults)
            #expect(binary1000 == Int64(1_000).formatted(.byteCount(style: .binary).locale(Locale(identifier: "en"))))

            appDefaults.set(ByteUnits.decimal.rawValue, forKey: SettingsKeys.byteUnits)
            #expect(ByteUnits.current(defaults: appDefaults) == .decimal)
            let decimal1000 = ByteUnits.string(1_000, defaults: appDefaults)
            #expect(decimal1000 == Int64(1_000).formatted(.byteCount(style: .decimal).locale(Locale(identifier: "en"))))
            #expect(binary1000 != decimal1000)
        }

        // 3. Explicit language overrides remain isolated in the cache.
        customDefaults.set(ByteUnits.binary.rawValue, forKey: SettingsKeys.byteUnits)
        AppLanguage.withTemporaryLanguageForTesting("en") {
            let expected = Int64(1_022).formatted(.byteCount(style: .binary).locale(Locale(identifier: "en")))
            #expect(ByteUnits.string(1_022, defaults: customDefaults) == expected)
            #expect(ByteUnits.string(1_022, defaults: customDefaults) == expected)
        }
        AppLanguage.withTemporaryLanguageForTesting("zh-Hans") {
            let expected = Int64(1_022).formatted(.byteCount(style: .binary).locale(Locale(identifier: "zh-Hans")))
            #expect(ByteUnits.string(1_022, defaults: customDefaults) == expected)
            #expect(ByteUnits.string(1_022, defaults: customDefaults) == expected)
        }
    }
}
