//! AppArmor profile synthesis (PLAN 6.2.1).
//!
//! A manifest's `security.mac_profile` names the profile; the rule content is
//! synthesized from the declaration itself: attachment paths from the
//! package's declared binaries (`capabilities.binaries`), capability rules
//! from `security.capabilities`, wrapped in a least-privilege baseline
//! (`abstractions/base` plus read-only attachment rules). Rendering is pure —
//! the library never shells out; hosts with `apparmor_parser` installed can
//! validate the output offline (see the `hardening_int` integration tests).

use std::collections::BTreeSet;

use crate::manifest::SecurityBlock;
use crate::security::filecaps;

/// Errors raised while synthesizing an AppArmor profile.
#[derive(Debug, thiserror::Error)]
pub enum AppArmorError {
    /// The `security.mac_profile` reference is not a usable profile name.
    #[error(
        "invalid mac_profile name '{name}' (expected [A-Za-z0-9][A-Za-z0-9._-]*; \
         it becomes the AppArmor profile name)"
    )]
    InvalidProfileName {
        /// The offending reference.
        name: String,
    },
    /// The manifest declares a `mac_profile` but no binaries to attach to.
    #[error("mac_profile '{name}' declares no binaries; an AppArmor profile needs at least one attachment path")]
    NoAttachment {
        /// The profile reference, for context.
        name: String,
    },
    /// A `security.capabilities` entry is not a known `CAP_*` name.
    #[error(transparent)]
    Capability(#[from] filecaps::FileCapsError),
}

/// A synthesized AppArmor profile (PLAN 6.2.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppArmorProfile {
    /// Profile name — the `security.mac_profile` reference, verbatim.
    pub name: String,
    /// Attachment paths (sorted, `/usr/bin/<binary>` per declared binary).
    pub attachments: Vec<String>,
    /// Capability rules (sorted, kernel spelling without the `CAP_` prefix).
    pub capabilities: Vec<String>,
}

impl AppArmorProfile {
    /// Synthesize a profile from a manifest's security declaration
    /// (PLAN 6.2.1).
    ///
    /// * `mac_profile` — the `security.mac_profile` reference (profile name).
    /// * `binaries` — the manifest's declared binaries; each becomes a
    ///   `/usr/bin/<name>` attachment path.
    /// * `security` — the declaration whose `capabilities` union becomes the
    ///   profile's `capability` rules.
    pub fn from_security(
        mac_profile: &str,
        binaries: &[String],
        security: &SecurityBlock,
    ) -> Result<Self, AppArmorError> {
        Self::validate_name(mac_profile)?;
        if binaries.is_empty() {
            return Err(AppArmorError::NoAttachment {
                name: mac_profile.to_string(),
            });
        }

        let attachments: BTreeSet<String> = binaries
            .iter()
            .map(|bin| format!("/usr/bin/{bin}"))
            .collect();

        // Union of every declared path's grant; duplicates collapse, order is
        // deterministic, and unknown names fail here (typed, at synthesis).
        let mut bits: BTreeSet<u64> = BTreeSet::new();
        for caps in security.capabilities.values() {
            for name in caps {
                bits.insert(filecaps::parse_cap_name(name)?);
            }
        }
        let capabilities: Vec<String> = bits
            .into_iter()
            .filter_map(|bit| {
                filecaps::CAPABILITIES
                    .iter()
                    .find(|(_, known)| *known == bit)
                    .map(|(name, _)| name["CAP_".len()..].to_ascii_lowercase())
            })
            .collect();

        Ok(Self {
            name: mac_profile.to_string(),
            attachments: attachments.into_iter().collect(),
            capabilities,
        })
    }

    /// Render the profile as `apparmor_parser`-valid profile text.
    ///
    /// Output is byte-identical for equal profiles: sorted attachments and
    /// capability rules, no timestamps, no host-dependent content.
    pub fn render(&self) -> String {
        let attachment = if self.attachments.len() == 1 {
            self.attachments[0].clone()
        } else {
            format!("{{{}}}", self.attachments.join(","))
        };

        let mut out = String::new();
        out.push_str("# synthesized by ExtOS from security.mac_profile '");
        out.push_str(&self.name);
        out.push_str("'\n#include <tunables/global>\n\n");
        out.push_str("profile ");
        out.push_str(&self.name);
        out.push(' ');
        out.push_str(&attachment);
        out.push_str(" flags=(attach_disconnected) {\n");
        out.push_str("  #include <abstractions/base>\n\n");
        for cap in &self.capabilities {
            out.push_str("  capability ");
            out.push_str(cap);
            out.push_str(",\n");
        }
        if !self.capabilities.is_empty() {
            out.push('\n');
        }
        for path in &self.attachments {
            out.push_str("  ");
            out.push_str(path);
            out.push_str(" mr,\n");
        }
        out.push_str("  /usr/lib/** r,\n");
        out.push_str("  /etc/** r,\n");
        out.push_str("}\n");
        out
    }

    /// Profile names become AppArmor identifiers — keep them conservative.
    fn validate_name(name: &str) -> Result<(), AppArmorError> {
        let valid = !name.is_empty()
            && name.chars().next().is_some_and(|c| c.is_ascii_alphanumeric())
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
        if valid {
            Ok(())
        } else {
            Err(AppArmorError::InvalidProfileName {
                name: name.to_string(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn security(caps: &[(&str, &[&str])]) -> SecurityBlock {
        SecurityBlock {
            capabilities: caps
                .iter()
                .map(|(p, names)| {
                    (
                        (*p).to_string(),
                        names.iter().map(|n| (*n).to_string()).collect(),
                    )
                })
                .collect::<HashMap<_, _>>(),
            mac_profile: None,
        }
    }

    #[test]
    fn synthesizes_deterministic_profile() {
        let sec = security(&[
            ("usr/bin/ping", &["CAP_NET_RAW", "CAP_NET_ADMIN"]),
            ("usr/bin/other", &["CAP_NET_RAW"]),
        ]);
        let profile = AppArmorProfile::from_security(
            "net-tools",
            &["ping".to_string(), "other".to_string()],
            &sec,
        )
        .unwrap();

        assert_eq!(profile.name, "net-tools");
        assert_eq!(
            profile.attachments,
            vec!["/usr/bin/other", "/usr/bin/ping"]
        );
        assert_eq!(profile.capabilities, vec!["net_admin", "net_raw"]);

        let text = profile.render();
        assert_eq!(text, profile.render(), "rendering must be stable");
        assert!(text.starts_with("# synthesized by ExtOS"));
        assert!(text.contains("#include <tunables/global>"));
        assert!(text.contains("profile net-tools {/usr/bin/other,/usr/bin/ping} flags=(attach_disconnected) {"));
        assert!(text.contains("  capability net_admin,\n"));
        assert!(text.contains("  capability net_raw,\n"));
        assert!(text.contains("  /usr/bin/ping mr,\n"));
        assert!(text.ends_with("}\n"));
    }

    #[test]
    fn single_attachment_renders_without_braces() {
        let sec = security(&[]);
        let profile =
            AppArmorProfile::from_security("hello", &["hello".to_string()], &sec).unwrap();
        assert!(profile.render().contains("profile hello /usr/bin/hello flags="));
        assert_eq!(profile.capabilities, Vec::<String>::new());
    }

    #[test]
    fn rejects_hostile_profile_names() {
        for bad in ["", "../escape", "has space", "-leading-dash", "tab\there"] {
            let err = AppArmorProfile::from_security(bad, &["x".to_string()], &security(&[]))
                .expect_err(bad);
            assert!(matches!(err, AppArmorError::InvalidProfileName { .. }), "{err:?}");
        }
    }

    #[test]
    fn rejects_profiles_without_binaries() {
        let err = AppArmorProfile::from_security("lonely", &[], &security(&[])).unwrap_err();
        assert!(matches!(err, AppArmorError::NoAttachment { .. }), "{err:?}");
    }

    #[test]
    fn unknown_capability_fails_at_synthesis() {
        let sec = security(&[("usr/bin/x", &["CAP_NOT_A_REAL_CAP"])]);
        let err =
            AppArmorProfile::from_security("p", &["x".to_string()], &sec).unwrap_err();
        assert!(matches!(
            err,
            AppArmorError::Capability(filecaps::FileCapsError::UnknownCapability { .. })
        ));
    }
}
