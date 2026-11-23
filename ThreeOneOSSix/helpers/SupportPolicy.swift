import Foundation

enum ExploitSupportPolicy {
    static let verifiedIOS17Range = "17.0–17.7.x"
    static let verifiedIOS18Range = "18.0–18.7.1"

    /// The iOS 18 release that closed the kernel exploit window.
    ///
    /// Apple fixed CVE-2025-43510 and CVE-2025-43520 — the bugs this project's
    /// kernel chain (DarkSword lineage) depends on — in iOS 18.7.2. Every
    /// later 18.x build is therefore unsupported by design, not by an
    /// oversight in the version table. Kept as a constant so the explanation
    /// shown to users cannot drift from the boundary enforced above.
    static let ios18KernelPatchedAt = "18.7.2"
    static let verifiedIOS26BadQueryRange = "26.0–26.6.1"
    static let verifiedIOS26WorseQueryRange = "26.7–26.7.3"

    /// Every 27.0–27.2 build is accepted unconditionally, so the range must
    /// stop at the minor version — writing "27.2.1" here would claim a patch
    /// boundary that `supportsWorseQuery` does not enforce.
    static let verifiedIOS27Range = "27.0–27.2.x"

    /// 27.3 is the only 27.x line that is build-gated, so it gets its own
    /// label. Rendering it inside `verifiedIOS27Range` would hide the fact
    /// that the boundary is a build number, not a version number.
    static let verifiedIOS27BuildGatedRange = "27.3 beta 1"

    /// Builds where `worse_query` was verified working on 27.3.
    /// 24C5049d (beta 2) and 24C5049f (reissue) are deliberately absent:
    /// Apple closed the technique there and no public replacement exists.
    static let verifiedIOS27Builds: [String] = [
        "24C5037i"   // iOS 27.3 beta 1 — operator-verified on hardware
    ]

    static func supportsKernelExploit(
        major: Int,
        minor: Int,
        patch: Int,
        isA10: Bool = false
    ) -> Bool {
        guard minor >= 0, patch >= 0 else { return false }

        // A10 Fusion hangs inside the kernel chain on iOS 17. Refusing costs a
        // device that otherwise looks supported one capability; running it
        // costs a device-level hang that reboots the phone.
        if isA10 && major == 17 { return false }

        if major == 17 {
            return minor <= 7
        }

        if major == 18 {
            return minor < 7 || (minor == 7 && patch <= 1)
        }

        return false
    }

    /// bad_query still works on the builds it was verified for; it is kept as
    /// the primary backend there because it also reaches System Data.
    static func supportsBadQuery(major: Int, minor: Int, patch: Int) -> Bool {
        guard major == 26, minor >= 0, patch >= 0 else { return false }
        return minor < 6 || (minor == 6 && patch <= 1)
    }

    /// worse_query targets iOS 26.0–26.7.3 and 27.0–27.2.x.
    ///
    /// 26.7.3 shipped alongside 27.2.1 on 2026-11-09. No public source lists
    /// it, but none lists it as patched either, and the technique was still
    /// working on 26.7.2 — so it is allowed as unverified rather than
    /// refused. If it turns out to be patched on a given device the probe
    /// fails and the app reports it; nothing is lost by trying.
    ///
    /// 27.3 is gated by `verifiedIOS27Builds` because the technique was
    /// patched mid-cycle. `build` defaults to an empty string on purpose: an
    /// empty build is not in the whitelist, so any call site that forgets to
    /// pass one fails closed on 27.3 instead of silently approving an
    /// unverified build.
    static func supportsWorseQuery(
        major: Int,
        minor: Int,
        patch: Int,
        build: String = ""
    ) -> Bool {
        guard minor >= 0, patch >= 0 else { return false }
        if major == 26 {
            return minor == 7 && patch <= 3
        }
        if major == 27 {
            if minor <= 2 {
                return true
            }
            if minor == 3 {
                // 27.3.0 only: beta 1 is a 27.3.0 build. Without the patch
                // check, a hypothetical 27.3.1 that reused a whitelisted
                // build string would slip through. Build numbers are unique
                // in practice, but the boundary should not depend on that.
                return patch == 0 && verifiedIOS27Builds.contains(build)
            }
        }
        return false
    }

    /// True for iOS 18 builds at or past the patch that closed the kernel
    /// exploit window (18.7.2+). Those are unsupported permanently, so the UI
    /// explains the reason instead of showing a bare "unsupported".
    static func isIOS18KernelPatched(major: Int, minor: Int, patch: Int) -> Bool {
        guard major == 18 else { return false }
        if minor > 7 { return true }
        return minor == 7 && patch >= 2
    }

    /// Whether this launch needs the user to press Unlock before container
    /// access exists.
    ///
    /// Only the kernel backend qualifies. `bad_query` and `worse_query` obtain
    /// access from system APIs and are effectively always on, so a banner there
    /// would ask the user to confirm a step that does nothing. Pure so the rule
    /// can be tested without a device.
    static func requiresExplicitUnlock(isKernelBackend: Bool, hasAccess: Bool) -> Bool {
        isKernelBackend && !hasAccess
    }

    static func isSupported(
        major: Int,
        minor: Int,
        patch: Int,
        build: String,
        isA10: Bool = false
    ) -> Bool {
        if supportsKernelExploit(major: major, minor: minor, patch: patch, isA10: isA10) {
            return true
        }
        if supportsBadQuery(major: major, minor: minor, patch: patch) { return true }
        if supportsWorseQuery(major: major, minor: minor, patch: patch, build: build) {
            return true
        }
        return false
    }
}

/// Why a device is unsupported, as a localization key plus its arguments.
/// Pure on purpose: onboarding and `AppState.detectSupport()` both need this
/// explanation, and two hand-written copies would drift the moment one of the
/// version boundaries changes. Returns `nil` when the device *is* supported.
enum RejectionReason {
    struct Reason: Equatable {
        let key: String
        let arguments: [String]
    }

    static func make(
        major: Int,
        minor: Int,
        patch: Int,
        build: String,
        osVersion: String,
        isA10: Bool = false
    ) -> Reason? {
        let supported = ExploitSupportPolicy.isSupported(
            major: major, minor: minor, patch: patch, build: build, isA10: isA10
        )
        if supported { return nil }

        // A10 + iOS 17 is refused by chip, not by OS version. Without its own
        // branch the user would read "unsupported: iOS 17.7.9 (21H…)" — which
        // implies the OS is too new when the OS is in fact supported on every
        // other chip. The action is different too: stay put, don't update.
        if isA10 && major == 17 {
            return Reason(key: "status.unsupported_a10_ios17", arguments: [])
        }

        // iOS 18.7.2+ has a permanent, explainable cause: Apple patched the
        // kernel bugs this project depends on, so no future build of 3106 can
        // support them. A bare version string would leave the user with
        // nothing to act on.
        if ExploitSupportPolicy.isIOS18KernelPatched(major: major, minor: minor, patch: patch) {
            return Reason(key: "status.unsupported_ios18_patched",
                          arguments: [ExploitSupportPolicy.ios18KernelPatchedAt])
        }

        // 27.3 is build-gated: the technique was patched mid-cycle, so the
        // user needs to know which build to stay on.
        if major == 27 && minor == 3 {
            return Reason(key: "status.unsupported_ios27_build",
                          arguments: [ExploitSupportPolicy.verifiedIOS27Builds.joined(separator: ", ")])
        }

        return Reason(key: "status.unsupported_reason", arguments: [osVersion])
    }
}