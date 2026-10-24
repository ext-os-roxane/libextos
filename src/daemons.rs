//! Declarative daemon management (PLAN 7.2.1 + 7.2.3, `design/ARCHITECTURE.md`
//! §15).
//!
//! # `daemons.nix` grammar (PLAN 7.2.1)
//!
//! ```nix
//! daemons = {
//!   pkt = {
//!     mirrors = [ "https://pkg.extos.org/tier1" "p2p://swarm.extos.org" ];
//!     strategy = "round-robin";
//!     decentralized = {
//!       enabled = true;
//!       upstream_mirrors = [ "https://github.com/extos-os/packages-index" ];
//!     };
//!   };
//!   instanz = {
//!     weaver_threads = 4;
//!   };
//! };
//! ```
//!
//! A daemon setting value is a string, an integer, a boolean, a list of
//! scalars, or a nested attribute set. Nested attribute sets are *flattened*
//! to dotted keys (`decentralized.enabled` = `"true"`); lists of scalars are
//! joined with single spaces. Attribute sets and lists inside lists, `null`
//! leaves, and keys outside `[a-z0-9._-]+` are rejected with typed
//! [`ExtosError::ConfigParse`] errors — nothing is ever silently dropped.
//!
//! [`parse_daemons_config`] accepts either the full document (a top-level
//! `daemons = { … };` binding, as written in `daemons.nix`) or the inner
//! `daemons` attribute set itself; a top-level `daemons` binding wins when
//! both are present, and an unknown extra top-level key is rejected so a
//! typo cannot hide a declaration.
//!
//! # systemd unit generation
//!
//! [`render_service_unit`] produces a deterministic `[Service]` unit whose
//! `Environment=` lines carry one `EXTOS_DAEMON_<UPPER_SNAKE_KEY>=<value>`
//! assignment per setting (sorted by key). In the environment key both dots
//! *and* hyphens map to underscores: systemd 262 (probed empirically on this
//! host with `systemd-analyze verify`) discards hyphenated environment
//! assignments as "invalid", so a dots-only mapping would silently drop
//! declared settings such as `mirror-fallback` from the daemon's
//! environment. That mapping is not injective (`a.b`, `a_b` and `a-b` all
//! become `A_B`), so settings that would collapse onto one
//! `EXTOS_DAEMON_*` variable — where one assignment would silently win —
//! are typed-rejected at parse *and* render time, naming every colliding
//! key. Values containing quotes, backslashes, newlines or control
//! characters are typed-rejected (systemd silently logs "Invalid syntax,
//! ignoring" and drops an assignment whose value carries a backslash, and
//! `\n` in a value is c-unescaped into a real newline), and `exec_start`
//! must not end with `\` (a systemd line continuation that swallows the
//! following line — `systemd.syntax(7)`) nor contain `;` (an unquoted
//! command separator). A rendered unit is therefore injection-proof: what
//! is declared is exactly what the unit carries.
//!
//! [`render_socket_unit`] renders the socket-activation unit for a daemon's
//! control socket (PLAN 7.2.3); [`DEFAULT_SOCKETS`] pins the design §15
//! control-plane sockets (`/run/extos/pkt.sock` for `wheel`,
//! `/run/extos/instanz.sock` for `extos-admin`).
//!
//! # Honest scope
//!
//! This module is pure generation: it never writes unit files nor talks to
//! PID 1. Materializing `/etc/systemd/system/<daemon>.service` (and the
//! enable/disable bookkeeping of PLAN 7.2.2) happens in the `instanz` apply
//! pipeline; hosts with `systemd-analyze` can validate the generated units
//! offline (see `tests/daemons_int.rs`).

use std::collections::BTreeMap;

use crate::config::NixValue;
use crate::error::ExtosError;

/// The design §15 control-plane sockets (PLAN 7.2.3): `(daemon, socket_path,
/// group)` triples. Socket permissions are tied to the `wheel` /
/// `extos-admin` groups; the gRPC servers themselves are PLAN 8.1.
pub const DEFAULT_SOCKETS: &[(&str, &str, &str)] = &[
    ("pkt", "/run/extos/pkt.sock", "wheel"),
    ("instanz", "/run/extos/instanz.sock", "extos-admin"),
];

/// A parsed `daemons.nix` document (PLAN 7.2.1): each daemon's flattened
/// settings, deterministically ordered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonConfig {
    /// Daemon name → flattened settings (dotted key → stringified value).
    pub daemons: BTreeMap<String, BTreeMap<String, String>>,
}

/// Build a `ConfigParse` error attributed to the `daemons.nix` grammar.
fn spec_err(message: impl Into<String>) -> ExtosError {
    ExtosError::ConfigParse {
        path: "daemons.nix".into(),
        line: 0,
        message: message.into(),
    }
}

/// Is `s` a non-empty run of `[a-z0-9._-]` (the unit/hostname-safe charset)?
fn is_safe_name(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-'))
}

/// Validate a whole name (daemon name, socket group) against
/// `[a-z0-9._-]+`, additionally rejecting the path-hostile `.` and `..`.
fn validate_name(name: &str, what: &str) -> Result<(), ExtosError> {
    if is_safe_name(name) && name != "." && name != ".." {
        Ok(())
    } else {
        Err(spec_err(format!(
            "invalid {what} {name:?}: expected non-empty [a-z0-9._-] (and not '.' or '..')"
        )))
    }
}

/// Validate a (possibly dotted) setting key: every dotted component must be
/// non-empty and unit/hostname-safe, so the flattened key and its derived
/// environment-variable name stay injective and injection-proof.
fn validate_setting_key(key: &str) -> Result<(), ExtosError> {
    for component in key.split('.') {
        if !is_safe_name(component) {
            return Err(spec_err(format!(
                "invalid setting key {key:?}: component {component:?} must be non-empty \
                 [a-z0-9._-]"
            )));
        }
    }
    Ok(())
}

/// Why `value` would corrupt a rendered `Environment=` assignment, if it
/// would (the assignment is emitted inside double quotes). A backslash is
/// rejected with the quotes: systemd 262 logs "Invalid syntax, ignoring"
/// and silently drops an assignment whose value carries one (probed
/// empirically on this host).
fn value_hostile_reason(value: &str) -> Option<&'static str> {
    if value
        .chars()
        .any(|c| c == '"' || c == '\\' || c.is_control())
    {
        Some("must not contain quotes, backslashes, newlines, or control characters")
    } else {
        None
    }
}

/// Why `exec_start` would corrupt the rendered `ExecStart=` line, if it
/// would. Quotes and spaces are legitimate systemd `ExecStart` syntax (the
/// value is emitted unquoted); line breaks, control characters, a trailing
/// `\` (systemd continues the line onto the next one, swallowing it —
/// `systemd.syntax(7)`; probed: `verify` exits 0 while the next `Environment=`
/// line becomes an `ExecStart` argument) and `;` (an unquoted command
/// separator that splits `ExecStart=` into multiple commands) are not.
fn exec_start_hostile_reason(exec_start: &str) -> Option<&'static str> {
    if exec_start.is_empty() {
        Some("must not be empty")
    } else if exec_start.chars().any(|c| c.is_control()) {
        Some("must not contain newlines or control characters")
    } else if exec_start.ends_with('\\') {
        Some(
            "must not end with a backslash (systemd continues the ExecStart= line onto \
             the next line, swallowing it)",
        )
    } else if exec_start.contains(';') {
        Some(
            "must not contain ';' (systemd splits ExecStart= on unquoted semicolons \
             into multiple commands)",
        )
    } else {
        None
    }
}

/// Stringify a scalar leaf (`string` / `integer` / `boolean`); `None` for
/// anything else (the grammar's non-scalars are typed-rejected by the
/// caller).
fn scalar_to_string(value: &NixValue) -> Option<String> {
    match value {
        NixValue::String(s) => Some(s.clone()),
        NixValue::Int(n) => Some(n.to_string()),
        NixValue::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// Flatten one setting (dotted-key recursion for nested attribute sets) into
/// `out`, validating keys and scalar leaves along the way.
fn flatten_setting(
    daemon: &str,
    key: &str,
    value: &NixValue,
    prefix: &str,
    out: &mut BTreeMap<String, String>,
) -> Result<(), ExtosError> {
    validate_setting_key(key)?;
    let dotted = if prefix.is_empty() {
        key.to_string()
    } else {
        format!("{prefix}.{key}")
    };
    match value {
        NixValue::AttrSet(inner) => {
            for (nested_key, nested_value) in inner {
                flatten_setting(daemon, nested_key, nested_value, &dotted, out)?;
            }
            Ok(())
        }
        NixValue::List(items) => {
            let mut parts = Vec::with_capacity(items.len());
            for item in items {
                let scalar = scalar_to_string(item).ok_or_else(|| {
                    spec_err(format!(
                        "'daemons.{daemon}.{dotted}' list entries must be scalars \
                         (string, integer or boolean), got {item}"
                    ))
                })?;
                if let Some(reason) = value_hostile_reason(&scalar) {
                    return Err(spec_err(format!(
                        "'daemons.{daemon}.{dotted}' list entries {reason}: {scalar:?}"
                    )));
                }
                parts.push(scalar);
            }
            out.insert(dotted, parts.join(" "));
            Ok(())
        }
        leaf => {
            let scalar = scalar_to_string(leaf).ok_or_else(|| {
                spec_err(format!(
                    "'daemons.{daemon}.{dotted}' must be a string, integer, boolean or \
                     list of scalars, got {leaf}"
                ))
            })?;
            if let Some(reason) = value_hostile_reason(&scalar) {
                return Err(spec_err(format!(
                    "'daemons.{daemon}.{dotted}' {reason}: {scalar:?}"
                )));
            }
            out.insert(dotted, scalar);
            Ok(())
        }
    }
}

/// The `daemons` block must be an attribute set of daemon declarations.
fn block_as_daemon_table(
    block: &NixValue,
) -> Result<&BTreeMap<String, NixValue>, ExtosError> {
    block
        .as_attrset()
        .ok_or_else(|| spec_err("'daemons' must be an attribute set of daemon declarations"))
}

/// Parse a `daemons.nix` document (PLAN 7.2.1).
///
/// Accepts either the full document (a top-level `daemons = { … };` binding,
/// as written in `daemons.nix`) or the inner `daemons` attribute set itself;
/// a top-level `daemons` binding wins when both are present, and an unknown
/// extra top-level key is rejected. See the module docs for the value
/// grammar and the flattening rules.
///
/// # Examples
///
/// ```
/// use libextos::config::parse_nix;
/// use libextos::daemons::{parse_daemons_config, render_service_unit};
///
/// let doc = parse_nix(
///     r#"daemons = {
///         pkt = {
///             strategy = "round-robin";
///             decentralized = { enabled = true; };
///         };
///     }"#,
/// )
/// .unwrap();
/// let config = parse_daemons_config(&doc).unwrap();
/// assert_eq!(config.daemons["pkt"]["decentralized.enabled"], "true");
///
/// let unit = render_service_unit("pkt", &config.daemons["pkt"], "/usr/bin/pkt daemon").unwrap();
/// assert!(unit.contains("Environment=\"EXTOS_DAEMON_DECENTRALIZED_ENABLED=true\"\n"));
/// ```
pub fn parse_daemons_config(value: &NixValue) -> Result<DaemonConfig, ExtosError> {
    let table = match value.get_path("daemons") {
        // Full-document shape: `daemons` is the grammar's only top-level
        // key; anything else is a typo that must not hide a declaration.
        Some(block) => {
            if let NixValue::AttrSet(top) = value {
                for key in top.keys() {
                    if key != "daemons" {
                        return Err(spec_err(format!(
                            "unknown top-level key: {key} (expected only 'daemons')"
                        )));
                    }
                }
            }
            block
        }
        // The inner `daemons` attribute set itself.
        None => value,
    };
    let table = block_as_daemon_table(table)?;

    let mut daemons = BTreeMap::new();
    for (name, decl) in table {
        validate_name(name, "daemon name")?;
        let settings_decl = decl.as_attrset().ok_or_else(|| {
            spec_err(format!(
                "'daemons.{name}' must be an attribute set of settings, got {decl}"
            ))
        })?;
        let mut settings = BTreeMap::new();
        for (key, setting) in settings_decl {
            flatten_setting(name, key, setting, "", &mut settings)?;
        }
        detect_env_name_collisions(name, &settings)?;
        daemons.insert(name.clone(), settings);
    }

    Ok(DaemonConfig { daemons })
}

/// Render the systemd service unit for one daemon (PLAN 7.2.1).
///
/// The output is deterministic and byte-identical for equal inputs: settings
/// are emitted in key order, one
/// `Environment="EXTOS_DAEMON_<UPPER_SNAKE_KEY>=<value>"` line per setting
/// (dots *and* hyphens map to underscores in the key — see the module docs
/// for the empirically-probed systemd 262 rationale). The daemon name, every
/// setting key and every setting value are validated first; `exec_start`
/// must be non-empty, free of newlines/control characters, must not end with
/// `\` and must not contain `;` (quotes and spaces are legitimate systemd
/// `ExecStart` syntax). Settings whose keys collapse onto one
/// `EXTOS_DAEMON_*` variable are rejected, naming every colliding key.
///
/// # Errors
///
/// [`ExtosError::ConfigParse`] naming the offending daemon, setting key or
/// value when validation fails.
pub fn render_service_unit(
    daemon: &str,
    settings: &BTreeMap<String, String>,
    exec_start: &str,
) -> Result<String, ExtosError> {
    validate_name(daemon, "daemon name")?;
    if let Some(reason) = exec_start_hostile_reason(exec_start) {
        return Err(spec_err(format!(
            "render_service_unit({daemon}): exec_start {reason}: {exec_start:?}"
        )));
    }
    for (key, value) in settings {
        validate_setting_key(key)?;
        if let Some(reason) = value_hostile_reason(value) {
            return Err(spec_err(format!(
                "render_service_unit({daemon}): setting {key:?} {reason}: {value:?}"
            )));
        }
    }
    detect_env_name_collisions(daemon, settings)?;

    let mut out = String::new();
    out.push_str("[Unit]\nDescription=ExtOS ");
    out.push_str(daemon);
    out.push_str(" daemon\nAfter=network-online.target\n\n[Service]\nType=exec\nExecStart=");
    out.push_str(exec_start);
    out.push('\n');
    for (key, value) in settings {
        out.push_str("Environment=\"EXTOS_DAEMON_");
        out.push_str(&env_var_name(key));
        out.push('=');
        out.push_str(value);
        out.push_str("\"\n");
    }
    out.push_str("\n[Install]\nWantedBy=multi-user.target\n");
    Ok(out)
}

/// The `EXTOS_DAEMON_*` environment-variable name for a flattened setting
/// key: dots *and* hyphens become underscores (systemd discards hyphenated
/// environment assignments), then the whole name is uppercased.
fn env_var_name(key: &str) -> String {
    key.replace(['.', '-'], "_").to_ascii_uppercase()
}

/// Reject settings whose environment-variable mapping collides (the
/// dots/hyphens → underscores mapping is not injective: `a.b`, `a_b` and
/// `a-b` all render `EXTOS_DAEMON_A_B=`, and one assignment would silently
/// win inside the unit). The typed error names *all* colliding keys per
/// group. Enforced at parse time (every daemon of a parsed config) and at
/// render time (hand-built maps included).
fn detect_env_name_collisions(
    daemon: &str,
    settings: &BTreeMap<String, String>,
) -> Result<(), ExtosError> {
    let mut by_env: BTreeMap<String, Vec<&str>> = BTreeMap::new();
    for key in settings.keys() {
        by_env.entry(env_var_name(key)).or_default().push(key);
    }
    let collisions: Vec<String> = by_env
        .into_iter()
        .filter_map(|(env, keys)| {
            (keys.len() > 1).then(|| format!("EXTOS_DAEMON_{env} ← [{}]", keys.join(", ")))
        })
        .collect();
    if collisions.is_empty() {
        return Ok(());
    }
    Err(spec_err(format!(
        "'daemons.{daemon}': settings that map to the same EXTOS_DAEMON_* environment \
         variable would silently overwrite each other: {}",
        collisions.join("; ")
    )))
}

/// Render the systemd socket-activation unit for a daemon's control socket
/// (PLAN 7.2.3).
///
/// The output is deterministic and byte-identical for equal inputs: a
/// `0660` socket owned by `group`, activated as `WantedBy=sockets.target`,
/// with the implied same-named `<daemon>.service` as its target (systemd
/// socket activation convention). The daemon name, `socket_path` (absolute;
/// every path component in `[a-z0-9._-]`, no `.`/`..`, no trailing slash)
/// and `group` are validated first.
///
/// # Errors
///
/// [`ExtosError::ConfigParse`] naming the offending argument when
/// validation fails.
pub fn render_socket_unit(
    daemon: &str,
    socket_path: &str,
    group: &str,
) -> Result<String, ExtosError> {
    validate_name(daemon, "daemon name")?;
    validate_socket_path(socket_path)?;
    validate_name(group, "socket group")?;

    let mut out = String::new();
    out.push_str("[Unit]\nDescription=ExtOS ");
    out.push_str(daemon);
    out.push_str(" control socket\n\n[Socket]\nListenStream=");
    out.push_str(socket_path);
    out.push_str("\nSocketMode=0660\nSocketGroup=");
    out.push_str(group);
    out.push_str("\n\n[Install]\nWantedBy=sockets.target\n");
    Ok(out)
}

/// Validate a `ListenStream` path: absolute, every component non-empty and
/// unit/hostname-safe (`[a-z0-9._-]`), no `.`/`..` components, no trailing
/// slash — the same charset law as daemon names, applied per component.
fn validate_socket_path(path: &str) -> Result<(), ExtosError> {
    let invalid = || {
        spec_err(format!(
            "invalid socket path {path:?}: expected an absolute path whose components are \
             non-empty [a-z0-9._-] (no '.', '..', or trailing '/')"
        ))
    };
    let Some(components) = path.strip_prefix('/') else {
        return Err(invalid());
    };
    if components.is_empty() {
        return Err(invalid());
    }
    for component in components.split('/') {
        if !is_safe_name(component) || component == "." || component == ".." {
            return Err(invalid());
        }
    }
    Ok(())
}

// ─── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// The shipped template (`config/daemons.nix`), verbatim including
    /// comments — the grammar this module must own.
    const TEMPLATE: &str = r#"{
  # ExtOS Daemon Configuration
  daemons = {
    pkt = {
      # Upstream mirrors for decentralized repository sync
      mirrors = [
        "https://pkg.extos.org/tier1"
        "https://mirror.extos.io"
        "p2p://swarm.extos.org"
      ];

      # Mirror priority and failover logic
      strategy = "round-robin"; # options: "latency", "round-robin", "priority"

      # Decentralized repository settings
      decentralized = {
        enabled = true;
        upstream_mirrors = [
          "https://github.com/extos-os/packages-index"
          "https://gitlab.com/extos-os/main-repo"
        ];
      };
    };

    instanz = {
      # Reserved for instanz daemon settings
      weaver_threads = 4;
    };
  };
}"#;

    fn parsed_template() -> DaemonConfig {
        let doc = crate::config::parse_nix(TEMPLATE).unwrap();
        parse_daemons_config(&doc).unwrap()
    }

    // ── 7.2.1: the parser ───────────────────────────────────────

    #[test]
    fn parses_template_shape_and_flattens_nested_attrsets() {
        let config = parsed_template();

        assert_eq!(config.daemons.len(), 2);
        let pkt = &config.daemons["pkt"];
        // Nested attrset flattened to dotted keys; booleans and integers
        // stringified; lists joined with single spaces.
        assert_eq!(
            pkt.get("mirrors").map(String::as_str),
            Some("https://pkg.extos.org/tier1 https://mirror.extos.io p2p://swarm.extos.org")
        );
        assert_eq!(pkt.get("strategy").map(String::as_str), Some("round-robin"));
        assert_eq!(
            pkt.get("decentralized.enabled").map(String::as_str),
            Some("true")
        );
        assert_eq!(
            pkt.get("decentralized.upstream_mirrors").map(String::as_str),
            Some("https://github.com/extos-os/packages-index https://gitlab.com/extos-os/main-repo")
        );
        assert_eq!(pkt.len(), 4);
        let instanz = &config.daemons["instanz"];
        assert_eq!(
            instanz.get("weaver_threads").map(String::as_str),
            Some("4")
        );
    }

    #[test]
    fn accepts_inner_daemons_attrset_and_rejects_unknown_top_level_keys() {
        // The inner `daemons` attribute set itself parses identically.
        let inner = crate::config::parse_nix(r#"{ pkt = { strategy = "latency"; }; }"#).unwrap();
        let config = parse_daemons_config(&inner).unwrap();
        assert_eq!(
            config.daemons["pkt"].get("strategy").map(String::as_str),
            Some("latency")
        );

        // In the full-document shape an unknown top-level key is a typo that
        // must not hide a declaration — typed rejection.
        let typo = crate::config::parse_nix(
            r#"{ daemons = { pkt = {}; }; daemonz = { pkt = {}; }; }"#,
        )
        .unwrap();
        let err = parse_daemons_config(&typo).unwrap_err();
        assert!(err.to_string().contains("unknown top-level key"), "{err}");
    }

    #[test]
    fn malformed_shapes_are_typed_rejected() {
        let reject = |input: &str, needle: &str| {
            let doc = crate::config::parse_nix(input).unwrap();
            let err = parse_daemons_config(&doc).unwrap_err();
            assert!(
                matches!(err, ExtosError::ConfigParse { .. }),
                "expected ConfigParse, got {err:?}"
            );
            assert!(err.to_string().contains(needle), "{err}");
        };

        // Top-level attrset expected at all.
        reject("null", "'daemons' must be an attribute set");
        reject(r#"{ daemons = 4; }"#, "'daemons' must be an attribute set");
        // A daemon declaration must be an attrset.
        reject(r#"{ daemons = { pkt = 4; }; }"#, "'daemons.pkt' must be an attribute set");
        // Non-scalar leaves: attrset lists, nested lists, null.
        reject(
            r#"{ daemons = { pkt = { bad = [ { nested = 1; } ]; }; }; }"#,
            "list entries must be scalars",
        );
        reject(
            r#"{ daemons = { pkt = { bad = [ [ "x" ] ]; }; }; }"#,
            "list entries must be scalars",
        );
        reject(
            r#"{ daemons = { pkt = { bad = null; }; }; }"#,
            "must be a string, integer, boolean or list of scalars",
        );
        reject(
            r#"{ daemons = { pkt = { bad = [ null ]; }; }; }"#,
            "list entries must be scalars",
        );
        // Hostile daemon names and setting keys.
        reject(r#"{ daemons = { "Pkt" = {}; }; }"#, "invalid daemon name");
        reject(r#"{ daemons = { "../escape" = {}; }; }"#, "invalid daemon name");
        reject(r#"{ daemons = { "." = {}; }; }"#, "invalid daemon name");
        reject(r#"{ daemons = { ".." = {}; }; }"#, "invalid daemon name");
        reject(r#"{ daemons = { pkt = { "Bad Key" = 1; }; }; }"#, "invalid setting key");
        reject(r#"{ daemons = { pkt = { "a..b" = 1; }; }; }"#, "invalid setting key");
        // Hostile string leaves (would corrupt a quoted Environment line).
        reject(
            r#"{ daemons = { pkt = { bad = "quoted \" inside"; }; }; }"#,
            "must not contain quotes",
        );
        reject(
            r#"{ daemons = { pkt = { bad = "line\nbreak"; }; }; }"#,
            "must not contain quotes",
        );
        // A backslash in a value makes systemd 262 silently drop the whole
        // assignment ("Invalid syntax, ignoring") — typed rejection.
        reject(
            r#"{ daemons = { pkt = { bad = "back\\slash"; }; }; }"#,
            "must not contain quotes",
        );
        // An empty daemon attrset contributes zero settings (legitimate).
        let empty = crate::config::parse_nix(r#"{ daemons = { idle = {}; }; }"#).unwrap();
        let config = parse_daemons_config(&empty).unwrap();
        assert!(config.daemons["idle"].is_empty());
        // An empty list is a legitimate (empty) value.
        let empty_list =
            crate::config::parse_nix(r#"{ daemons = { pkt = { mirrors = []; }; }; }"#).unwrap();
        let config = parse_daemons_config(&empty_list).unwrap();
        assert_eq!(config.daemons["pkt"].get("mirrors").map(String::as_str), Some(""));
    }

    #[test]
    fn env_name_collisions_are_typed_rejected_naming_all_keys() {
        // `a.b`, `a_b` and `a-b` all map to EXTOS_DAEMON_A_B (dots *and*
        // hyphens become underscores) — one assignment would silently win
        // inside the rendered unit, so all three keys must be named.
        let doc = crate::config::parse_nix(
            r#"{ daemons = { pkt = { "a.b" = 1; "a_b" = 2; "a-b" = 3; }; }; }"#,
        )
        .unwrap();
        let err = parse_daemons_config(&doc).unwrap_err();
        let text = err.to_string();
        assert!(text.contains("same EXTOS_DAEMON_* environment variable"), "{err}");
        for key in ["a.b", "a_b", "a-b"] {
            assert!(text.contains(key), "collision must name {key:?}: {err}");
        }
        assert!(text.contains("EXTOS_DAEMON_A_B"), "{err}");

        // A hand-built settings map gets the same rejection at render time.
        let settings: BTreeMap<String, String> = [
            ("a.b".to_string(), "1".to_string()),
            ("a_b".to_string(), "2".to_string()),
        ]
        .into_iter()
        .collect();
        let err = render_service_unit("pkt", &settings, "/usr/bin/true").unwrap_err();
        assert!(err.to_string().contains("a.b") && err.to_string().contains("a_b"), "{err}");

        // Distinct keys with distinct env names are untouched.
        let fine: BTreeMap<String, String> = [
            ("a.b".to_string(), "1".to_string()),
            ("a_c".to_string(), "2".to_string()),
        ]
        .into_iter()
        .collect();
        assert!(render_service_unit("pkt", &fine, "/usr/bin/true").is_ok());
    }

    // ── 7.2.1: the service unit renderer ────────────────────────

    #[test]
    fn service_unit_renders_byte_identical() {
        let settings: BTreeMap<String, String> = [
            ("strategy".to_string(), "round-robin".to_string()),
            ("decentralized.enabled".to_string(), "true".to_string()),
        ]
        .into_iter()
        .collect();

        let unit = render_service_unit("pkt", &settings, "/usr/bin/pkt daemon").unwrap();
        let expected = "[Unit]\n\
            Description=ExtOS pkt daemon\n\
            After=network-online.target\n\
            \n\
            [Service]\n\
            Type=exec\n\
            ExecStart=/usr/bin/pkt daemon\n\
            Environment=\"EXTOS_DAEMON_DECENTRALIZED_ENABLED=true\"\n\
            Environment=\"EXTOS_DAEMON_STRATEGY=round-robin\"\n\
            \n\
            [Install]\n\
            WantedBy=multi-user.target\n";
        assert_eq!(unit, expected);
        assert_eq!(render_service_unit("pkt", &settings, "/usr/bin/pkt daemon").unwrap(), unit,
            "rendering must be stable");
    }

    #[test]
    fn service_unit_without_settings_renders_byte_identical() {
        let unit = render_service_unit("solo", &BTreeMap::new(), "/usr/bin/true").unwrap();
        assert_eq!(
            unit,
            "[Unit]\n\
             Description=ExtOS solo daemon\n\
             After=network-online.target\n\
             \n\
             [Service]\n\
             Type=exec\n\
             ExecStart=/usr/bin/true\n\
             \n\
             [Install]\n\
             WantedBy=multi-user.target\n"
        );
    }

    #[test]
    fn service_unit_maps_dots_and_hyphens_to_underscores_in_env_keys() {
        // systemd 262 discards hyphenated environment assignments (probed
        // with systemd-analyze verify on this host), so both separators map
        // to underscores — a declared setting may never be silently dropped.
        let settings: BTreeMap<String, String> = [
            ("mirror-fallback".to_string(), "true".to_string()),
            ("decentralized.upstream_mirrors".to_string(), "https://a https://b".to_string()),
        ]
        .into_iter()
        .collect();
        let unit = render_service_unit("pkt", &settings, "/usr/bin/true").unwrap();
        assert!(unit.contains("Environment=\"EXTOS_DAEMON_MIRROR_FALLBACK=true\"\n"), "{unit}");
        assert!(
            unit.contains("Environment=\"EXTOS_DAEMON_DECENTRALIZED_UPSTREAM_MIRRORS=https://a https://b\"\n"),
            "{unit}"
        );
        // Exactly the two transformed assignments — no raw key may leak.
        assert_eq!(
            unit.lines().filter(|l| l.starts_with("Environment=")).count(),
            2,
            "{unit}"
        );
    }

    #[test]
    fn service_unit_rejects_hostile_inputs() {
        let ok: BTreeMap<String, String> =
            [("k".to_string(), "v".to_string())].into_iter().collect();

        // Daemon name escapes into Description=.
        for bad in ["../escape", "has space", "Pkt", "", ".", "..", "tab\there", "nl\nhere"] {
            let err = render_service_unit(bad, &ok, "/usr/bin/true").unwrap_err();
            assert!(err.to_string().contains("invalid daemon name"), "{err}");
        }
        // exec_start escapes into ExecStart=.
        for bad in [
            "",
            "/usr/bin/x\nWantedBy=evil.target",
            // systemd continues the ExecStart= line onto the next one
            // (systemd.syntax(7)); the following Environment= line would be
            // swallowed into an argument while verify exits 0.
            "/usr/bin/x \\",
            // an unquoted ';' splits ExecStart= into multiple commands.
            "/usr/bin/x; /usr/bin/evil",
        ] {
            let err = render_service_unit("pkt", &ok, bad).unwrap_err();
            assert!(
                err.to_string().contains("exec_start must not"),
                "exec_start {bad:?}: {err}"
            );
        }
        // Values escape into the quoted Environment= assignment.
        for bad_value in [
            "quote \" inside",
            "back\\slash inside",
            "newline\ninjected",
            "tab\tinside",
            "escape\u{1b}[31m",
        ] {
            let settings: BTreeMap<String, String> =
                [("key".to_string(), bad_value.to_string())].into_iter().collect();
            let err = render_service_unit("pkt", &settings, "/usr/bin/true").unwrap_err();
            assert!(
                err.to_string().contains(
                    "must not contain quotes, backslashes, newlines, or control characters"
                ),
                "value {bad_value:?}: {err}"
            );
        }
        // Setting keys escape into the env-var name.
        for bad_key in ["", "a..b", "Has Space", "UPPER", "x\ny"] {
            let settings: BTreeMap<String, String> =
                [(bad_key.to_string(), "v".to_string())].into_iter().collect();
            let err = render_service_unit("pkt", &settings, "/usr/bin/true").unwrap_err();
            assert!(err.to_string().contains("invalid setting key"), "key {bad_key:?}: {err}");
        }
    }

    // ── 7.2.3: the socket unit renderer ─────────────────────────

    #[test]
    fn socket_unit_renders_byte_identical() {
        let unit = render_socket_unit("pkt", "/run/extos/pkt.sock", "wheel").unwrap();
        let expected = "[Unit]\n\
            Description=ExtOS pkt control socket\n\
            \n\
            [Socket]\n\
            ListenStream=/run/extos/pkt.sock\n\
            SocketMode=0660\n\
            SocketGroup=wheel\n\
            \n\
            [Install]\n\
            WantedBy=sockets.target\n";
        assert_eq!(unit, expected);
        assert_eq!(
            render_socket_unit("pkt", "/run/extos/pkt.sock", "wheel").unwrap(),
            unit,
            "rendering must be stable"
        );
    }

    #[test]
    fn default_sockets_render_cleanly() {
        // The pinned design §15 pair must always survive its own validation.
        assert_eq!(DEFAULT_SOCKETS.len(), 2);
        for (daemon, path, group) in DEFAULT_SOCKETS {
            let unit = render_socket_unit(daemon, path, group)
                .unwrap_or_else(|err| panic!("DEFAULT_SOCKETS entry {daemon:?}: {err}"));
            assert!(unit.contains(&format!("ListenStream={path}\n")));
            assert!(unit.contains(&format!("SocketGroup={group}\n")));
        }
    }

    #[test]
    fn socket_unit_rejects_hostile_inputs() {
        for bad in ["../escape", "", ".", "..", "Instanz", "sock et", "nl\nhere"] {
            let err = render_socket_unit(bad, "/run/extos/x.sock", "wheel").unwrap_err();
            assert!(err.to_string().contains("invalid daemon name"), "{err}");
        }
        for bad in ["", "wheel:wheel", "WHEEL", "../wheel", "gr oup", "g\nroup"] {
            let err = render_socket_unit("pkt", "/run/extos/x.sock", bad).unwrap_err();
            assert!(err.to_string().contains("invalid socket group"), "{err}");
        }
        for bad in [
            "relative.sock",            // not absolute
            "",                         // empty
            "/",                        // no components
            "/run//x.sock",             // empty component
            "/run/extos/x.sock/",       // trailing slash
            "/run/../etc/host.sock",    // traversal
            "/run/./x.sock",            // dot component
            "/run/extos/x sock",        // space
            "/run/extos/X.SOCK",        // charset is lowercase
            "/run/extos/x\nsock",       // newline
        ] {
            let err = render_socket_unit("pkt", bad, "wheel").unwrap_err();
            assert!(err.to_string().contains("invalid socket path"), "path {bad:?}: {err}");
        }
    }
}
