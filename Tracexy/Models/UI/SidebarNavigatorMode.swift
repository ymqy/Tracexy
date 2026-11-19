import Foundation

/// The three sidebar navigator modes — a Browse/Focus/Library
/// segmented control. Each mode swaps the whole sidebar body so only one kind of
/// work is on screen at a time — the antidote to a single over-stacked list.
enum SidebarNavigatorMode: String, CaseIterable, Identifiable, Hashable {
    case browse
    case focus
    case library

    // MARK: Internal

    nonisolated var id: String {
        rawValue
    }

    nonisolated var title: String {
        let bundle = AppLanguage.currentLocalizedBundle()
        return switch self {
        case .browse: String(localized: "Browse", bundle: bundle)
        case .focus: String(localized: "Focus", bundle: bundle)
        case .library: String(localized: "Library", bundle: bundle)
        }
    }

    nonisolated var systemImage: String {
        switch self {
        case .browse: "sidebar.left"
        case .focus: "scope"
        case .library: "books.vertical"
        }
    }
}
