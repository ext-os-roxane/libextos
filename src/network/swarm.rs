//! P2P swarm declarative surface (PLAN 7.3.2).
//!
//! **The libp2p runtime is Phase 8.2 (PLAN 8.2.1).** This module ships only
//! the declarative surface: it parses the `swarm.nix` document into a typed
//! [`SwarmConfig`](crate::network::swarm::SwarmConfig) and renders the
//! libp2p-compatible TOML settings
//! ([`render_libp2p_settings`](crate::network::swarm::render_libp2p_settings))
//! that the Phase 8.2 runtime will consume. No libp2p crate is linked and no
//! network I/O happens here.
//!
//! # `swarm.nix` grammar
//!
//! ```nix
//! swarm = {
//!   enabled = true;
//!   listen = "/ip4/0.0.0.0/tcp/4001";
//!   bootstrap = [ "p2p://swarm.extos.org" ];
//! };
//! ```
//!
//! [`parse_swarm_config`](crate::network::swarm::parse_swarm_config) accepts
//! either the full document (a top-level `swarm = { … };` binding) or the
//! inner `swarm` attribute set itself; a top-level `swarm` binding wins when
//! both are present, and an unknown extra top-level key is rejected so a
//! typo cannot hide a declaration. All keys are optional: `enabled` defaults
//! to `false`, `listen` to
//! [`DEFAULT_LISTEN_MULTIADDR`](crate::network::swarm::DEFAULT_LISTEN_MULTIADDR),
//! and `bootstrap` to an empty peer list. Unknown keys are typed errors, so
//! a typo cannot silently disable a setting.
//!
//! Peer strings (`listen` and `bootstrap` entries) must be non-empty and
//! contain no whitespace, quotes, backslashes, or control characters —
//! validated syntactically only; there is no multiaddr parsing dependency.
//!
//! # Examples
//!
//! ```
//! use libextos::config::parse_nix;
//! use libextos::network::swarm::{parse_swarm_config, render_libp2p_settings};
//!
//! let doc = parse_nix(
//!     r#"swarm = {
//!         enabled = true;
//!         listen = "/ip4/0.0.0.0/tcp/4001";
//!         bootstrap = [ "p2p://swarm.extos.org" ];
//!     }"#,
//! )
//! .unwrap();
//! let config = parse_swarm_config(&doc).unwrap();
//! assert!(config.enabled);
//! assert_eq!(config.bootstrap, vec!["p2p://swarm.extos.org"]);
//!
//! let toml = render_libp2p_settings(&config);
//! assert_eq!(
//!     toml,
//!     "[swarm]\nenabled = true\nlisten_multiaddr = \"/ip4/0.0.0.0/tcp/4001\"\nbootstrap_peers = [ \"p2p://swarm.extos.org\" ]\n"
//! );
//! ```

use std::collections::BTreeSet;

use crate::config::NixValue;
use crate::error::ExtosError;
use crate::network::hostile_str_reason;

/// The canonical default listening multiaddr, used when `swarm.nix` omits
/// `listen`.
pub const DEFAULT_LISTEN_MULTIADDR: &str = "/ip4/0.0.0.0/tcp/4001";

/// A parsed `swarm.nix` document (PLAN 7.3.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwarmConfig {
    /// Whether the Phase 8.2 swarm runtime should be started.
    pub enabled: bool,
    /// The listening multiaddr (defaults to [`DEFAULT_LISTEN_MULTIADDR`]).
    pub listen: String,
    /// Bootstrap peer addresses, verbatim as declared; rendering sorts them.
    pub bootstrap: Vec<String>,
}

/// Build a `ConfigParse` error attributed to the `swarm.nix` grammar.
fn spec_err(message: impl Into<String>) -> ExtosError {
    ExtosError::ConfigParse {
        path: "swarm.nix".into(),
        line: 0,
        message: message.into(),
    }
}

/// Syntactically validate one peer string (non-empty, no whitespace, quotes,
/// or control characters).
fn validate_peer(field: &str, value: &str) -> Result<(), ExtosError> {
    if let Some(reason) = hostile_str_reason(value) {
        return Err(spec_err(format!("{field} {reason}: {value:?}")));
    }
    Ok(())
}

/// Parse a `swarm.nix` document (PLAN 7.3.2).
///
/// Accepts the full document (a top-level `swarm = { … };` binding) or the
/// inner `swarm` attribute set itself; in the full-document shape a
/// top-level `swarm` binding wins when both are present and an unknown
/// extra top-level key is rejected. See the [module docs](self) for the
/// grammar, defaults, and the peer-string contract.
pub fn parse_swarm_config(value: &NixValue) -> Result<SwarmConfig, ExtosError> {
    let block = match value.get_path("swarm") {
        // Full-document shape: `swarm` is the grammar's only top-level key;
        // anything else is a typo that must not hide a declaration.
        Some(block) => {
            if let NixValue::AttrSet(top) = value {
                for key in top.keys() {
                    if key != "swarm" {
                        return Err(spec_err(format!(
                            "unknown top-level key: {key} (expected only 'swarm')"
                        )));
                    }
                }
            }
            block
        }
        // The inner `swarm` attribute set itself.
        None => value,
    };
    let table = block
        .as_attrset()
        .ok_or_else(|| spec_err("'swarm' must be an attribute set"))?;

    for key in table.keys() {
        if !matches!(key.as_str(), "enabled" | "listen" | "bootstrap") {
            return Err(spec_err(format!(
                "'swarm' has unknown key: {key} \
                 (expected 'enabled', 'listen', and/or 'bootstrap')"
            )));
        }
    }

    let enabled = match table.get("enabled") {
        Some(value) => value
            .as_bool()
            .ok_or_else(|| spec_err("'swarm.enabled' must be a boolean"))?,
        None => false,
    };

    let listen = match table.get("listen") {
        Some(value) => {
            let text = value
                .as_str()
                .ok_or_else(|| spec_err("'swarm.listen' must be a multiaddr string"))?;
            validate_peer("'swarm.listen'", text)?;
            text.to_string()
        }
        None => DEFAULT_LISTEN_MULTIADDR.to_string(),
    };

    let mut bootstrap = Vec::new();
    if let Some(value) = table.get("bootstrap") {
        let list = value.as_list().ok_or_else(|| {
            spec_err("'swarm.bootstrap' must be a list of multiaddr strings")
        })?;
        for item in list {
            let text = item.as_str().ok_or_else(|| {
                spec_err("'swarm.bootstrap' entries must be strings")
            })?;
            validate_peer("'swarm.bootstrap'", text)?;
            bootstrap.push(text.to_string());
        }
    }

    Ok(SwarmConfig {
        enabled,
        listen,
        bootstrap,
    })
}

/// Escape a string for a TOML basic (double-quoted) string.
///
/// Beyond `\` and `"`, every control character is escaped with its short
/// form (`\b`, `\t`, `\n`, `\f`, `\r`) or a `\u00XX` form, so a hand-built
/// [`SwarmConfig`] carrying a raw newline or tab still renders syntactically
/// valid TOML (the parser rejects control characters before this can ever
/// see one, so the escape forms are a renderer-level backstop).
fn toml_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\u{8}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            c if c.is_control() => out.push_str(&format!("\\u{:04X}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// Render the libp2p-compatible settings TOML the Phase 8.2 runtime will
/// consume (PLAN 7.3.2).
///
/// Shape (exact bytes, trailing newline included):
///
/// ```text
/// [swarm]
/// enabled = true
/// listen_multiaddr = "/ip4/0.0.0.0/tcp/4001"
/// bootstrap_peers = [ "p2p://swarm.extos.org" ]
/// ```
///
/// Bootstrap peers are sorted and deduplicated, so equal configurations
/// render byte-identical output on every run. Strings are TOML-escaped
/// (including control characters), so the output stays syntactically valid
/// TOML even for hand-constructed [`SwarmConfig`] values.
pub fn render_libp2p_settings(config: &SwarmConfig) -> String {
    let mut out = String::from("[swarm]\n");
    out.push_str("enabled = ");
    out.push_str(if config.enabled { "true" } else { "false" });
    out.push('\n');
    out.push_str("listen_multiaddr = \"");
    out.push_str(&toml_escape(&config.listen));
    out.push_str("\"\n");

    let peers: BTreeSet<&str> = config.bootstrap.iter().map(String::as_str).collect();
    if peers.is_empty() {
        out.push_str("bootstrap_peers = []\n");
    } else {
        let quoted: Vec<String> = peers
            .iter()
            .map(|peer| format!("\"{}\"", toml_escape(peer)))
            .collect();
        out.push_str(&format!("bootstrap_peers = [ {} ]\n", quoted.join(", ")));
    }
    out
}

// ─── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse_nix;

    fn parse_doc(text: &str) -> SwarmConfig {
        parse_swarm_config(&parse_nix(text).unwrap()).unwrap()
    }

    #[test]
    fn parses_full_document() {
        let config = parse_doc(
            r#"swarm = {
                enabled = true;
                listen = "/ip6/::/tcp/5001";
                bootstrap = [ "p2p://swarm.extos.org" "p2p://backup.extos.org" ];
            }"#,
        );
        assert!(config.enabled);
        assert_eq!(config.listen, "/ip6/::/tcp/5001");
        assert_eq!(
            config.bootstrap,
            vec!["p2p://swarm.extos.org", "p2p://backup.extos.org"]
        );
    }

    #[test]
    fn accepts_inner_block_and_applies_defaults() {
        // The inner `swarm` attribute set itself is accepted too.
        let config = parse_swarm_config(&parse_nix("{ enabled = true; }").unwrap()).unwrap();
        assert!(config.enabled);
        assert_eq!(config.listen, DEFAULT_LISTEN_MULTIADDR);
        assert!(config.bootstrap.is_empty());

        // Every key is optional.
        let defaults = parse_doc("swarm = {}");
        assert!(!defaults.enabled);
        assert_eq!(defaults.listen, DEFAULT_LISTEN_MULTIADDR);
        assert!(defaults.bootstrap.is_empty());

        let only_bootstrap = parse_doc(r#"swarm = { bootstrap = [ "p2p://x" ]; }"#);
        assert!(!only_bootstrap.enabled);
        assert_eq!(only_bootstrap.bootstrap, vec!["p2p://x"]);
    }

    #[test]
    fn renders_pinned_toml() {
        let config = parse_doc(
            r#"swarm = {
                enabled = true;
                listen = "/ip4/0.0.0.0/tcp/4001";
                bootstrap = [ "p2p://swarm.extos.org" ];
            }"#,
        );
        assert_eq!(
            render_libp2p_settings(&config),
            "[swarm]\nenabled = true\nlisten_multiaddr = \"/ip4/0.0.0.0/tcp/4001\"\nbootstrap_peers = [ \"p2p://swarm.extos.org\" ]\n"
        );
    }

    #[test]
    fn render_sorts_dedups_and_is_byte_identical() {
        let config = parse_doc(
            r#"swarm = { enabled = false; bootstrap = [ "z://b" "a://x" "z://b" ]; }"#,
        );
        let once = render_libp2p_settings(&config);
        assert_eq!(once, render_libp2p_settings(&config), "stable");
        assert!(
            once.contains("bootstrap_peers = [ \"a://x\", \"z://b\" ]\n"),
            "{once}"
        );
        assert!(!once.contains("\"z://b\", \"z://b\""), "duplicates collapse");

        let empty = render_libp2p_settings(&SwarmConfig {
            enabled: false,
            listen: DEFAULT_LISTEN_MULTIADDR.to_string(),
            bootstrap: Vec::new(),
        });
        assert_eq!(
            empty,
            "[swarm]\nenabled = false\nlisten_multiaddr = \"/ip4/0.0.0.0/tcp/4001\"\nbootstrap_peers = []\n"
        );
    }

    #[test]
    fn rejects_hostile_peer_strings() {
        for snippet in [
            r#"swarm = { listen = "has space"; }"#,
            r#"swarm = { listen = "quote\"inside"; }"#,
            r#"swarm = { listen = "back\\slash"; }"#,
            r#"swarm = { listen = "tab\there"; }"#,
            r#"swarm = { listen = ""; }"#,
            r#"swarm = { bootstrap = [ "multi\nline" ]; }"#,
            r#"swarm = { bootstrap = [ "" ]; }"#,
        ] {
            let doc = parse_nix(snippet).unwrap();
            let err = parse_swarm_config(&doc).unwrap_err();
            assert!(
                err.to_string()
                    .contains("must not contain whitespace, quotes, backslashes, or control characters")
                    || err.to_string().contains("must not be empty"),
                "{snippet}: {err}"
            );
        }
    }

    #[test]
    fn rejects_unknown_top_level_keys_in_full_document_shape() {
        // In the full-document shape `swarm` is the only top-level key; an
        // extra key is a typo that must not hide a declaration.
        let doc =
            parse_nix(r#"{ swarm = { enabled = true; }; swarmy = { enabled = false; }; }"#)
                .unwrap();
        let err = parse_swarm_config(&doc).unwrap_err();
        assert!(err.to_string().contains("unknown top-level key: swarmy"), "{err}");
    }

    #[test]
    fn render_escapes_control_characters_into_valid_toml() {
        // A hand-built value with a raw newline must not break out of the
        // TOML basic string — it is escaped with the short `\n` form; other
        // control characters take the `\u00XX` form. Parsed values can never
        // carry control characters, so the pinned byte shapes above are
        // untouched.
        let hostile = SwarmConfig {
            enabled: false,
            listen: "/ip4/0.0.0.0/tcp/4001\nEnabled=false".to_string(),
            bootstrap: vec!["p2p://x\u{1}".to_string()],
        };
        let toml = render_libp2p_settings(&hostile);
        assert_eq!(
            toml,
            "[swarm]\nenabled = false\nlisten_multiaddr = \"/ip4/0.0.0.0/tcp/4001\\nEnabled=false\"\nbootstrap_peers = [ \"p2p://x\\u0001\" ]\n",
            "raw newline/tab/control chars must be TOML-escaped"
        );
        assert_eq!(toml.lines().count(), 4, "no raw control character may add lines");

        // The backslash and quote escapes are unchanged for valid inputs.
        let escaped = render_libp2p_settings(&SwarmConfig {
            enabled: false,
            listen: "a\\b\"c".to_string(),
            bootstrap: Vec::new(),
        });
        assert_eq!(
            escaped,
            "[swarm]\nenabled = false\nlisten_multiaddr = \"a\\\\b\\\"c\"\nbootstrap_peers = []\n"
        );
    }

    #[test]
    fn rejects_unknown_keys_and_wrong_types() {
        for snippet in [
            r#"swarm = { enabeld = true; }"#,
            r#"swarm = { enabled = 1; }"#,
            r#"swarm = { listen = 42; }"#,
            r#"swarm = { bootstrap = "p2p://x"; }"#,
            r#"swarm = { bootstrap = [ 5 ]; }"#,
            r#"swarm = "on""#,
            r#"swarm = null"#,
        ] {
            let doc = parse_nix(snippet).unwrap();
            assert!(
                parse_swarm_config(&doc).is_err(),
                "must reject: {snippet}"
            );
        }
    }
}
