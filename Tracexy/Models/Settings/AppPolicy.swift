import Foundation

// MARK: - AppPolicy

/// App-level capacity and capability limits.
///
/// Limits are *injected* at the composition root rather than read from a
/// global, so the types that own state never learn where their numbers came
/// from. `Core/` engines never see this protocol at all: capture, decode and
/// session building stay limit-neutral, and only app-layer state owners and
/// their gates are handed plain `Int`/`Bool` values through their own
/// initializers.
///
/// The shipping baseline is ``DefaultAppPolicy``.
protocol AppPolicy: Sendable {
    /// Maximum local Projects, including the default Project.
    var maxProjects: Int { get }
    /// Maximum user-created workspace tabs, including the first one.
    var maxWorkspaceTabs: Int { get }
    /// Maximum saved focus sets in the sidebar's focus library.
    var maxFocusSets: Int { get }
    /// Maximum pinned favorite hosts.
    var maxPinnedHosts: Int { get }
    /// Maximum advanced session-filter rule rows in a single workspace.
    var maxSessionFilterRules: Int { get }
    /// Maximum one-click filter buttons a Project may grow to.
    var maxFilterButtons: Int { get }
    /// Maximum named expression macros a Project may grow to.
    var maxExpressionMacros: Int { get }
    /// Maximum local GeoIP/ASN database files a Project may refer to.
    var maxGeoIPDatabases: Int { get }
}

extension AppPolicy {
    var maxProjects: Int {
        ProjectLimits.maximumProjects
    }

    var maxWorkspaceTabs: Int {
        ProjectLimits.maximumWorkspacesPerProject
    }

    var maxFocusSets: Int {
        1_000
    }

    var maxPinnedHosts: Int {
        1_000
    }

    var maxSessionFilterRules: Int {
        ProjectLimits.maximumFilterRules
    }

    var maxFilterButtons: Int {
        ProjectLimits.maximumFilterButtons
    }

    var maxExpressionMacros: Int {
        ProjectLimits.maximumExpressionMacros
    }

    var maxGeoIPDatabases: Int {
        ProjectLimits.maximumGeoIPDatabases
    }
}

// MARK: - DefaultAppPolicy

/// The baseline policy every build starts from. Values are stated explicitly
/// rather than inherited from the protocol extension so this file reads as the
/// single answer to "what are the limits?".
struct DefaultAppPolicy: AppPolicy {
    let maxProjects = ProjectLimits.maximumProjects
    let maxWorkspaceTabs = ProjectLimits.maximumWorkspacesPerProject
    let maxFocusSets = 1_000
    let maxPinnedHosts = 1_000
    let maxSessionFilterRules = ProjectLimits.maximumFilterRules
    let maxFilterButtons = ProjectLimits.maximumFilterButtons
    let maxExpressionMacros = ProjectLimits.maximumExpressionMacros
    let maxGeoIPDatabases = ProjectLimits.maximumGeoIPDatabases
}
