//! D-Bus proxy filter rules for container IPC (PLAN 6.2.3).
//!
//! D-Bus sockets currently reach Level 2/3 containers as bind-mounted sockets
//! (the disclosed Phase-4 deviation: bind rather than proxy). The profile this
//! module synthesizes is the *enforcement contract* for that IPC: it names
//! exactly which well-known names a container may own and which destinations
//! it may message, and renders as `dbus-daemon` policy XML so a proxy process
//! (or a restricted `dbus-broker` bus) can be dropped in front of the bound
//! socket without re-deriving policy from the isolation level.
//!
//! Levels: [`IsolationLevel::Isolated`] / [`IsolationLevel::Cli`] never see a
//! bus (`filter_for_level` → `None`); [`IsolationLevel::Privileged`] shares
//! the host bus unfiltered (also `None`, disclosed); Levels 2/3 get the
//! default-deny desktop profile.

use crate::container::IsolationLevel;

/// Which bus a profile governs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bus {
    /// The per-user session bus.
    Session,
    /// The system bus.
    System,
}

impl Bus {
    /// Canonical name used in diagnostics.
    pub fn as_str(self) -> &'static str {
        match self {
            Bus::Session => "session",
            Bus::System => "system",
        }
    }
}

/// The kind of access a filter rule grants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleKind {
    /// The container may own (register) the well-known name.
    Own,
    /// The container may send messages to the destination.
    SendDestination,
}

/// One allow-rule of a filter profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DBusFilterRule {
    /// The access kind.
    pub kind: RuleKind,
    /// Bus name or glob (`org.mpris.MediaPlayer2.*`).
    pub name: String,
}

/// Errors raised while building or rendering a filter profile.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DBusFilterError {
    /// A rule name contains characters that are neither a valid D-Bus name
    /// nor safe XML — rejected before it can reach a config file.
    #[error("invalid D-Bus filter name '{name}' (expected [A-Za-z0-9._*-])")]
    InvalidName {
        /// The offending name.
        name: String,
    },
}

impl DBusFilterRule {
    /// Create a rule, validating the name (XML-safety: no whitespace, quotes,
    /// angle brackets or ampersands — the proxy consumes rendered XML).
    pub fn new(kind: RuleKind, name: impl Into<String>) -> Result<Self, DBusFilterError> {
        let name = name.into();
        let ok = !name.is_empty()
            && name.is_ascii()
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '*'));
        if ok {
            Ok(Self { kind, name })
        } else {
            Err(DBusFilterError::InvalidName { name })
        }
    }
}

/// A default-deny D-Bus filter profile for one bus (PLAN 6.2.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DBusFilterProfile {
    /// Which bus this profile governs.
    pub bus: Bus,
    /// Explicitly allowed accesses, in application order.
    pub allow: Vec<DBusFilterRule>,
    /// Whether everything not explicitly allowed is denied (always `true` for
    /// synthesized profiles; the field exists so a future profile source
    /// cannot silently weaken the default).
    pub default_deny: bool,
}

/// The D-Bus filter for `level`, if its isolation model includes a proxied
/// bus (PLAN 6.2.3).
///
/// Returns the session-bus desktop profile for Levels 2/3 — names a container
/// typically needs (notifications, portals, screen-saver inhibition, MPRIS
/// registration) — and `None` for levels with no bus in scope (0/1) or with
/// the unfiltered host bus (4).
pub fn filter_for_level(level: IsolationLevel) -> Option<DBusFilterProfile> {
    let allow = match level {
        IsolationLevel::Isolated | IsolationLevel::Cli | IsolationLevel::Privileged => {
            return None;
        }
        IsolationLevel::Gui | IsolationLevel::Networked => vec![
            DBusFilterRule::new(RuleKind::Own, "org.mpris.MediaPlayer2.*").ok()?,
            DBusFilterRule::new(RuleKind::SendDestination, "org.freedesktop.Notifications")
                .ok()?,
            DBusFilterRule::new(RuleKind::SendDestination, "org.freedesktop.portal.*").ok()?,
            DBusFilterRule::new(RuleKind::SendDestination, "org.freedesktop.ScreenSaver").ok()?,
            DBusFilterRule::new(RuleKind::SendDestination, "org.mpris.MediaPlayer2.*").ok()?,
        ],
    };
    Some(DBusFilterProfile {
        bus: Bus::Session,
        allow,
        default_deny: true,
    })
}

impl DBusFilterProfile {
    /// Render the profile as a `dbus-daemon` policy fragment.
    ///
    /// Output is byte-identical for equal profiles. `user` names the
    /// in-container account the policy applies to. With `default_deny`, catch
    /// all `<deny>` rules close the policy after the explicit allows.
    pub fn render_dbus_daemon_policy(&self, user: &str) -> Result<String, DBusFilterError> {
        // The user attribute reaches the XML verbatim — same charset rule.
        DBusFilterRule::new(RuleKind::SendDestination, user)?;
        let mut out = String::new();
        out.push_str(&format!(
            "<!-- ExtOS D-Bus proxy filter (PLAN 6.2.3) — {} bus, default-deny -->\n",
            self.bus.as_str()
        ));
        out.push_str("<busconfig>\n");
        out.push_str(&format!("  <policy user=\"{user}\">\n"));
        for rule in &self.allow {
            match rule.kind {
                RuleKind::Own => out.push_str(&format!("    <allow own=\"{}\"/>\n", rule.name)),
                RuleKind::SendDestination => {
                    out.push_str(&format!(
                        "    <allow send_destination=\"{}\"/>\n",
                        rule.name
                    ));
                }
            }
        }
        if self.default_deny {
            out.push_str("    <deny own=\"*\"/>\n");
            out.push_str("    <deny send_destination=\"*\"/>\n");
        }
        out.push_str("  </policy>\n");
        out.push_str("</busconfig>\n");
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn levels_without_a_proxied_bus_have_no_filter() {
        for level in [
            IsolationLevel::Isolated,
            IsolationLevel::Cli,
            IsolationLevel::Privileged,
        ] {
            assert!(
                filter_for_level(level).is_none(),
                "level {} must not carry a filter",
                level
            );
        }
    }

    #[test]
    fn desktop_levels_get_the_default_deny_session_profile() {
        for level in [IsolationLevel::Gui, IsolationLevel::Networked] {
            let profile = filter_for_level(level).expect("profile for desktop level");
            assert_eq!(profile.bus, Bus::Session);
            assert!(profile.default_deny);
            let names: Vec<_> = profile.allow.iter().map(|r| r.name.as_str()).collect();
            assert!(names.contains(&"org.freedesktop.Notifications"));
            assert!(names.contains(&"org.freedesktop.portal.*"));
            assert!(names.contains(&"org.mpris.MediaPlayer2.*"));
        }
    }

    #[test]
    fn renders_deterministic_policy_xml() {
        let profile = filter_for_level(IsolationLevel::Gui).unwrap();
        let xml = profile.render_dbus_daemon_policy("extos-container").unwrap();
        assert_eq!(
            xml,
            profile
                .render_dbus_daemon_policy("extos-container")
                .unwrap(),
            "rendering must be stable"
        );
        assert!(xml.starts_with("<!-- ExtOS D-Bus proxy filter"));
        assert!(xml.contains("<busconfig>"));
        assert!(xml.contains("<policy user=\"extos-container\">"));
        assert!(xml.contains("<allow send_destination=\"org.freedesktop.Notifications\"/>"));
        assert!(xml.contains("<allow own=\"org.mpris.MediaPlayer2.*\"/>"));
        assert!(xml.contains("<deny own=\"*\"/>"));
        assert!(xml.contains("<deny send_destination=\"*\"/>"));
        assert!(xml.ends_with("</busconfig>\n"));
    }

    #[test]
    fn hostile_names_are_typed_rejected() {
        for bad in [
            "org.foo\"><script>",
            "has space",
            "tab\there",
            "",
            "unicode-é",
        ] {
            let err = DBusFilterRule::new(RuleKind::Own, bad).expect_err(bad);
            assert!(
                matches!(err, DBusFilterError::InvalidName { .. }),
                "{bad:?} must be rejected"
            );
        }
        // The same rule guards the policy user (rendered verbatim otherwise).
        let profile = filter_for_level(IsolationLevel::Gui).unwrap();
        assert!(profile.render_dbus_daemon_policy("bad user").is_err());
    }
}
