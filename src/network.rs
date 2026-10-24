//! Declarative network configuration (PLAN 7.3.1) and the P2P swarm
//! declarative surface (PLAN 7.3.2, see [`swarm`]).
//!
//! # `network.nix` grammar
//!
//! ```nix
//! network = {
//!   hostname = "extos-box";            # optional; no whitespace/quotes/backslashes/control chars
//!   interfaces = {
//!     eth0 = { dhcp = true; };         # DHCP-managed interface (no static settings)
//!     wlan0 = {                        # statically addressed interface
//!       addresses = [ "10.0.0.5/24" ]; # CIDR: exactly one '/', prefix 0..=32
//!       gateway = "10.0.0.1";          # no whitespace/quotes/backslashes/control chars
//!       dns = [ "1.1.1.1" ];           # no whitespace/quotes/backslashes/control chars
//!     };
//!   };
//! };
//! ```
//!
//! [`parse_network_config`] accepts either the full document (a top-level
//! `network = { … };` binding, as written in `network.nix`) or the inner
//! `network` attribute set itself; a top-level `network` binding wins when
//! both are present, and an unknown extra top-level key is rejected so a
//! typo cannot hide a declaration.
//!
//! Validation is typed ([`ExtosError::ConfigParse`] with the offending field
//! addressed in the message):
//!
//! * interface names match `[a-z0-9._-]+` (lowercase; not `.` or `..`);
//! * `dhcp = true` XOR a non-empty `addresses` list — declaring both, or
//!   neither, is rejected;
//! * a DHCP interface takes no static settings: `gateway`/`dns` alongside
//!   `dhcp = true` are rejected, so what is declared is exactly what
//!   [`render_network_unit`] emits (no silent drops);
//! * every address contains exactly one `/` with a non-empty host part and a
//!   decimal prefix length `0..=32` (syntactic check only — no IP parsing
//!   dependency);
//! * hostname, gateway and DNS entries are non-empty and contain no
//!   whitespace, quotes, backslashes, or control characters (a trailing `\`
//!   would make systemd continue the line onto the next one, concatenating
//!   whatever follows into the value);
//! * unknown keys (top-level and per-interface) are rejected, so a typo
//!   cannot silently disable a setting.
//!
//! # `systemd-networkd` rendering (PLAN 7.3.1)
//!
//! [`render_network_unit`] produces one deterministic `.network` unit per
//! interface: `[Match]` with `Name=` from the interface name, then a
//! `[Network]` section — `DHCP=yes` for DHCP interfaces, or `Address=`
//! (sorted, duplicates collapse), `Gateway=` and `DNS=` (sorted, duplicates
//! collapse) for static ones. Rendering is pure; equal configurations render
//! byte-identical units on every run and every host.
//!
//! # Examples
//!
//! ```
//! use libextos::config::parse_nix;
//! use libextos::network::{parse_network_config, render_network_unit};
//!
//! let doc = parse_nix(
//!     r#"network = {
//!         hostname = "extos-box";
//!         interfaces = {
//!             eth0 = { dhcp = true; };
//!             wlan0 = {
//!                 addresses = [ "10.0.0.5/24" ];
//!                 gateway = "10.0.0.1";
//!                 dns = [ "1.1.1.1" ];
//!             };
//!         };
//!     }"#,
//! )
//! .unwrap();
//! let config = parse_network_config(&doc).unwrap();
//! assert_eq!(config.hostname.as_deref(), Some("extos-box"));
//! assert_eq!(config.interfaces.len(), 2);
//!
//! let unit = render_network_unit(&config.interfaces["wlan0"]).unwrap();
//! assert_eq!(
//!     unit,
//!     "[Match]\nName=wlan0\n\n[Network]\nAddress=10.0.0.5/24\nGateway=10.0.0.1\nDNS=1.1.1.1\n"
//! );
//! ```

use std::collections::{BTreeMap, BTreeSet};

use crate::config::NixValue;
use crate::error::ExtosError;

/// The P2P swarm declarative surface (PLAN 7.3.2).
///
/// The libp2p runtime itself is Phase 8.2 (PLAN 8.2.1); this module ships
/// only the typed `swarm.nix` configuration and the rendered
/// libp2p-compatible settings the future runtime will consume.
pub mod swarm;

// ─── 7.3.1: network.nix ─────────────────────────────────────────

/// A parsed `network.nix` document (PLAN 7.3.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkConfig {
    /// The optional `hostname` declaration.
    pub hostname: Option<String>,
    /// Interface declarations, keyed (and therefore iterated) by name.
    pub interfaces: BTreeMap<String, InterfaceConfig>,
}

/// One `network.interfaces.<name>` declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceConfig {
    /// Interface name (the `interfaces` key); matches `[a-z0-9._-]+`.
    pub name: String,
    /// Whether the interface is DHCP-managed (`dhcp = true`).
    pub dhcp: bool,
    /// Static CIDR addresses; empty for DHCP interfaces (the parser enforces
    /// `dhcp = true` XOR a non-empty list).
    pub addresses: Vec<String>,
    /// Static gateway; only valid on statically addressed interfaces.
    pub gateway: Option<String>,
    /// Static DNS resolvers; only valid on statically addressed interfaces.
    pub dns: Vec<String>,
}

/// Build a `ConfigParse` error attributed to the `network.nix` grammar.
fn spec_err(message: impl Into<String>) -> ExtosError {
    ExtosError::ConfigParse {
        path: "network.nix".into(),
        line: 0,
        message: message.into(),
    }
}

/// Why `value` would corrupt a rendered configuration value, if it would.
///
/// Shared with [`swarm`]: rendered unit/setting values are emitted verbatim
/// after quoting, so whitespace, quotes, backslashes, and control characters
/// are rejected at parse time instead. A backslash is hostile in its own
/// right: a trailing `\` makes systemd continue the line onto the next one
/// (`systemd.syntax(7)`), concatenating whatever follows into the value.
pub(crate) fn hostile_str_reason(value: &str) -> Option<String> {
    if value.is_empty() {
        return Some("must not be empty".to_string());
    }
    if value.chars().any(|c| {
        c.is_whitespace() || c.is_control() || matches!(c, '"' | '\'' | '\\')
    }) {
        return Some(
            "must not contain whitespace, quotes, backslashes, or control characters"
                .to_string(),
        );
    }
    None
}

/// Validate an interface name against `[a-z0-9._-]+`, additionally rejecting
/// the path-hostile `.` and `..` (lane L28 later emits `30-<name>.network`
/// filenames from these names, as `daemons.rs` does for unit names).
fn validate_interface_name(name: &str) -> Result<(), ExtosError> {
    let valid = !name.is_empty()
        && name != "."
        && name != ".."
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-'));
    if valid {
        Ok(())
    } else {
        Err(spec_err(format!(
            "interface name {name:?} is invalid (expected [a-z0-9._-]+ and not '.' or '..')"
        )))
    }
}

/// Syntactically validate one CIDR address: exactly one `/`, a non-empty
/// host part free of whitespace/quotes/control characters, and a decimal
/// prefix length `0..=32`. No IP parsing dependency (PLAN 7.3.1).
fn validate_address(field: &str, addr: &str) -> Result<(), ExtosError> {
    let Some((host, prefix)) = addr.split_once('/') else {
        return Err(spec_err(format!(
            "{field} must be a CIDR address with exactly one '/' (e.g. \"10.0.0.5/24\"), got {addr:?}"
        )));
    };
    if let Some(reason) = hostile_str_reason(host) {
        return Err(spec_err(format!("{field} host part {reason}: {addr:?}")));
    }
    let prefix_ok = !prefix.is_empty()
        && prefix.bytes().all(|b| b.is_ascii_digit())
        && prefix.parse::<u8>().is_ok_and(|p| p <= 32);
    if !prefix_ok {
        return Err(spec_err(format!(
            "{field} prefix length must be a decimal number 0..=32, got {prefix:?} in {addr:?}"
        )));
    }
    Ok(())
}

/// Enforce the full interface contract: name charset, per-value charsets,
/// and `dhcp = true` XOR static configuration.
fn validate_iface(iface: &InterfaceConfig) -> Result<(), ExtosError> {
    validate_interface_name(&iface.name)?;
    for addr in &iface.addresses {
        validate_address(&format!("network.interfaces.{}.addresses", iface.name), addr)?;
    }
    if let Some(gw) = &iface.gateway {
        if let Some(reason) = hostile_str_reason(gw) {
            return Err(spec_err(format!(
                "network.interfaces.{}.gateway {reason}",
                iface.name
            )));
        }
    }
    for entry in &iface.dns {
        if let Some(reason) = hostile_str_reason(entry) {
            return Err(spec_err(format!(
                "network.interfaces.{}.dns entry {reason}",
                iface.name
            )));
        }
    }
    if iface.dhcp {
        if !iface.addresses.is_empty() {
            return Err(spec_err(format!(
                "network.interfaces.{} declares both dhcp = true and static addresses; \
                 the two are mutually exclusive",
                iface.name
            )));
        }
        if iface.gateway.is_some() {
            return Err(spec_err(format!(
                "network.interfaces.{}.gateway is a static setting and conflicts with dhcp = true",
                iface.name
            )));
        }
        if !iface.dns.is_empty() {
            return Err(spec_err(format!(
                "network.interfaces.{}.dns is a static setting and conflicts with dhcp = true",
                iface.name
            )));
        }
    } else if iface.addresses.is_empty() {
        return Err(spec_err(format!(
            "network.interfaces.{} declares neither dhcp nor static addresses; \
             one of the two is required",
            iface.name
        )));
    }
    Ok(())
}

/// Parse a `network.nix` document (PLAN 7.3.1).
///
/// Accepts the full document (a top-level `network = { … };` binding) or the
/// inner `network` attribute set itself; in the full-document shape a
/// top-level `network` binding wins when both are present, and an unknown
/// extra top-level key is rejected so a typo cannot hide a declaration. See
/// the [module docs](self) for the grammar and the validation contract.
pub fn parse_network_config(value: &NixValue) -> Result<NetworkConfig, ExtosError> {
    let block = match value.get_path("network") {
        // Full-document shape: `network` is the grammar's only top-level key;
        // anything else is a typo that must not hide a declaration.
        Some(block) => {
            if let NixValue::AttrSet(top) = value {
                for key in top.keys() {
                    if key != "network" {
                        return Err(spec_err(format!(
                            "unknown top-level key: {key} (expected only 'network')"
                        )));
                    }
                }
            }
            block
        }
        // The inner `network` attribute set itself.
        None => value,
    };
    let table = block
        .as_attrset()
        .ok_or_else(|| spec_err("'network' must be an attribute set"))?;

    for key in table.keys() {
        if key != "hostname" && key != "interfaces" {
            return Err(spec_err(format!(
                "'network' has unknown key: {key} (expected 'hostname' and/or 'interfaces')"
            )));
        }
    }

    let mut hostname = None;
    if let Some(decl) = table.get("hostname") {
        let text = decl
            .as_str()
            .ok_or_else(|| spec_err("'network.hostname' must be a string"))?;
        if let Some(reason) = hostile_str_reason(text) {
            return Err(spec_err(format!("'network.hostname' {reason}")));
        }
        hostname = Some(text.to_string());
    }

    let mut interfaces = BTreeMap::new();
    if let Some(decl) = table.get("interfaces") {
        let map = decl.as_attrset().ok_or_else(|| {
            spec_err("'network.interfaces' must be an attribute set of interface declarations")
        })?;
        for (name, iface_decl) in map {
            validate_interface_name(name)?;
            interfaces.insert(name.clone(), parse_interface(name, iface_decl)?);
        }
    }

    Ok(NetworkConfig {
        hostname,
        interfaces,
    })
}

/// Parse one `network.interfaces.<name>` value.
fn parse_interface(name: &str, decl: &NixValue) -> Result<InterfaceConfig, ExtosError> {
    let table = decl.as_attrset().ok_or_else(|| {
        spec_err(format!("network.interfaces.{name} must be an attribute set"))
    })?;
    for key in table.keys() {
        if !matches!(key.as_str(), "dhcp" | "addresses" | "gateway" | "dns") {
            return Err(spec_err(format!(
                "network.interfaces.{name} has unknown key: {key} \
                 (expected 'dhcp', 'addresses', 'gateway', and/or 'dns')"
            )));
        }
    }

    let dhcp = match table.get("dhcp") {
        Some(value) => value
            .as_bool()
            .ok_or_else(|| spec_err(format!("network.interfaces.{name}.dhcp must be a boolean")))?,
        None => false,
    };

    let mut addresses = Vec::new();
    if let Some(value) = table.get("addresses") {
        let list = value.as_list().ok_or_else(|| {
            spec_err(format!(
                "network.interfaces.{name}.addresses must be a list of CIDR strings"
            ))
        })?;
        for item in list {
            let addr = item.as_str().ok_or_else(|| {
                spec_err(format!(
                    "network.interfaces.{name}.addresses entries must be strings"
                ))
            })?;
            addresses.push(addr.to_string());
        }
    }

    let mut gateway = None;
    if let Some(value) = table.get("gateway") {
        let text = value.as_str().ok_or_else(|| {
            spec_err(format!("network.interfaces.{name}.gateway must be a string"))
        })?;
        gateway = Some(text.to_string());
    }

    let mut dns = Vec::new();
    if let Some(value) = table.get("dns") {
        let list = value.as_list().ok_or_else(|| {
            spec_err(format!(
                "network.interfaces.{name}.dns must be a list of resolver addresses"
            ))
        })?;
        for item in list {
            let text = item.as_str().ok_or_else(|| {
                spec_err(format!(
                    "network.interfaces.{name}.dns entries must be strings"
                ))
            })?;
            dns.push(text.to_string());
        }
    }

    let iface = InterfaceConfig {
        name: name.to_string(),
        dhcp,
        addresses,
        gateway,
        dns,
    };
    validate_iface(&iface)?;
    Ok(iface)
}

/// Render one interface as a deterministic `systemd-networkd` `.network`
/// unit (PLAN 7.3.1).
///
/// Shape (exact bytes, trailing newline included):
///
/// ```text
/// [Match]
/// Name=wlan0
///
/// [Network]
/// Address=10.0.0.5/24
/// Gateway=10.0.0.1
/// DNS=1.1.1.1
/// ```
///
/// DHCP interfaces render `[Network]` with a single `DHCP=yes` line. Static
/// addresses and DNS entries are sorted (duplicates collapse), so equal
/// configurations render byte-identical units on every run. The same
/// contract [`parse_network_config`] enforces is re-checked here, so a
/// hand-constructed [`InterfaceConfig`] cannot render a unit that the
/// parser would have rejected.
pub fn render_network_unit(iface: &InterfaceConfig) -> Result<String, ExtosError> {
    validate_iface(iface)?;

    let mut out = String::new();
    out.push_str("[Match]\nName=");
    out.push_str(&iface.name);
    out.push_str("\n\n[Network]\n");
    if iface.dhcp {
        out.push_str("DHCP=yes\n");
        return Ok(out);
    }
    let addresses: BTreeSet<&str> = iface.addresses.iter().map(String::as_str).collect();
    for addr in addresses {
        out.push_str("Address=");
        out.push_str(addr);
        out.push('\n');
    }
    if let Some(gateway) = &iface.gateway {
        out.push_str("Gateway=");
        out.push_str(gateway);
        out.push('\n');
    }
    let dns: BTreeSet<&str> = iface.dns.iter().map(String::as_str).collect();
    for entry in dns {
        out.push_str("DNS=");
        out.push_str(entry);
        out.push('\n');
    }
    Ok(out)
}

// ─── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse_nix;

    fn parse_doc(text: &str) -> NetworkConfig {
        parse_network_config(&parse_nix(text).unwrap()).unwrap()
    }

    fn iface_dhcp(name: &str) -> InterfaceConfig {
        InterfaceConfig {
            name: name.to_string(),
            dhcp: true,
            addresses: Vec::new(),
            gateway: None,
            dns: Vec::new(),
        }
    }

    #[test]
    fn parses_full_document() {
        let config = parse_doc(
            r#"network = {
                hostname = "extos-box";
                interfaces = {
                    eth0 = { dhcp = true; };
                    wlan0 = {
                        addresses = [ "10.0.0.5/24" ];
                        gateway = "10.0.0.1";
                        dns = [ "1.1.1.1" ];
                    };
                };
            }"#,
        );
        assert_eq!(config.hostname.as_deref(), Some("extos-box"));
        assert_eq!(config.interfaces.len(), 2);
        assert!(config.interfaces["eth0"].dhcp);
        assert_eq!(config.interfaces["eth0"].addresses, Vec::<String>::new());
        assert!(!config.interfaces["wlan0"].dhcp);
        assert_eq!(config.interfaces["wlan0"].addresses, vec!["10.0.0.5/24"]);
        assert_eq!(config.interfaces["wlan0"].gateway.as_deref(), Some("10.0.0.1"));
        assert_eq!(config.interfaces["wlan0"].dns, vec!["1.1.1.1"]);
    }

    #[test]
    fn accepts_inner_block_and_optional_keys() {
        // The inner `network` attribute set itself is accepted too.
        let inner = parse_nix(
            r#"{ hostname = "box"; interfaces = { eth0 = { dhcp = true; }; }; }"#,
        )
        .unwrap();
        let config = parse_network_config(&inner).unwrap();
        assert_eq!(config.hostname.as_deref(), Some("box"));

        // Both top-level keys are optional.
        let empty = parse_doc("network = {}");
        assert_eq!(empty.hostname, None);
        assert!(empty.interfaces.is_empty());

        let no_hostname = parse_doc(r#"network = { interfaces = { eth0 = { dhcp = true; }; }; }"#);
        assert_eq!(no_hostname.hostname, None);
    }

    #[test]
    fn renders_dhcp_unit_pinned() {
        let iface = iface_dhcp("eth0");
        let unit = render_network_unit(&iface).unwrap();
        assert_eq!(unit, "[Match]\nName=eth0\n\n[Network]\nDHCP=yes\n");
        assert_eq!(unit, render_network_unit(&iface).unwrap(), "stable");
    }

    #[test]
    fn renders_static_unit_sorted_and_pinned() {
        let iface = InterfaceConfig {
            name: "wlan0".to_string(),
            dhcp: false,
            addresses: vec!["192.168.7.9/24".to_string(), "10.0.0.5/24".to_string()],
            gateway: Some("10.0.0.1".to_string()),
            dns: vec!["8.8.8.8".to_string(), "1.1.1.1".to_string()],
        };
        let unit = render_network_unit(&iface).unwrap();
        assert_eq!(
            unit,
            "[Match]\nName=wlan0\n\n[Network]\nAddress=10.0.0.5/24\nAddress=192.168.7.9/24\nGateway=10.0.0.1\nDNS=1.1.1.1\nDNS=8.8.8.8\n"
        );
        assert_eq!(unit, render_network_unit(&iface).unwrap(), "stable");
    }

    #[test]
    fn render_collapses_duplicate_addresses_and_dns() {
        let iface = InterfaceConfig {
            name: "eth1".to_string(),
            dhcp: false,
            addresses: vec!["10.0.0.5/24".to_string(), "10.0.0.5/24".to_string()],
            gateway: None,
            dns: vec!["1.1.1.1".to_string(), "1.1.1.1".to_string()],
        };
        let unit = render_network_unit(&iface).unwrap();
        assert_eq!(
            unit,
            "[Match]\nName=eth1\n\n[Network]\nAddress=10.0.0.5/24\nDNS=1.1.1.1\n"
        );
    }

    #[test]
    fn rejects_both_dhcp_and_addresses() {
        let doc = parse_nix(
            r#"network = { interfaces = { eth0 = { dhcp = true; addresses = [ "10.0.0.5/24" ]; }; }; }"#,
        )
        .unwrap();
        let err = parse_network_config(&doc).unwrap_err();
        assert!(err.to_string().contains("mutually exclusive"), "{err}");
        assert!(err.to_string().contains("eth0"), "{err}");
    }

    #[test]
    fn rejects_neither_dhcp_nor_addresses() {
        let doc = parse_nix(r#"network = { interfaces = { eth0 = {}; }; }"#).unwrap();
        let err = parse_network_config(&doc).unwrap_err();
        assert!(
            err.to_string().contains("neither dhcp nor static addresses"),
            "{err}"
        );
        // An explicit `dhcp = false` with no addresses is the same violation.
        let doc = parse_nix(r#"network = { interfaces = { eth0 = { dhcp = false; }; }; }"#).unwrap();
        assert!(parse_network_config(&doc).is_err());
    }

    #[test]
    fn rejects_static_settings_alongside_dhcp() {
        for snippet in [
            r#"network = { interfaces = { eth0 = { dhcp = true; gateway = "10.0.0.1"; }; }; }"#,
            r#"network = { interfaces = { eth0 = { dhcp = true; dns = [ "1.1.1.1" ]; }; }; }"#,
        ] {
            let doc = parse_nix(snippet).unwrap();
            let err = parse_network_config(&doc).unwrap_err();
            assert!(
                err.to_string().contains("conflicts with dhcp = true"),
                "{snippet}: {err}"
            );
        }
    }

    #[test]
    fn rejects_bad_interface_names() {
        for name in ["ETH0", "eth 0", "eth0!", "", "Wlan-1", "eth0\n", ".", ".."] {
            let doc = parse_nix(&format!(
                r#"network = {{ interfaces = {{ "{name}" = {{ dhcp = true; }}; }}; }}"#
            ))
            .unwrap();
            let err = parse_network_config(&doc).unwrap_err();
            assert!(
                err.to_string().contains("expected [a-z0-9._-]+"),
                "{name:?}: {err}"
            );
        }
    }

    #[test]
    fn rejects_unknown_top_level_keys_in_full_document_shape() {
        // In the full-document shape `network` is the only top-level key; an
        // extra key is a typo that must not hide a declaration.
        let doc = parse_nix(
            r#"{ network = { interfaces = { eth0 = { dhcp = true; }; }; }; netwrok = {}; }"#,
        )
        .unwrap();
        let err = parse_network_config(&doc).unwrap_err();
        assert!(err.to_string().contains("unknown top-level key: netwrok"), "{err}");
    }

    #[test]
    fn rejects_backslashes_in_rendered_values() {
        // A trailing `\` makes systemd continue the line onto the next one,
        // concatenating whatever follows into the value — typed rejection in
        // gateway, dns, and the host part of an address.
        for snippet in [
            r#"network = { interfaces = { eth0 = { addresses = [ "10.0.0.5/24" ]; gateway = "10.0.0.1\\"; }; }; }"#,
            r#"network = { interfaces = { eth0 = { addresses = [ "10.0.0.5/24" ]; dns = [ "1.1.1.1\\" ]; }; }; }"#,
            r#"network = { interfaces = { eth0 = { addresses = [ "10.0.0.5\\/24" ]; }; }; }"#,
            r#"network = { hostname = "extos\\box"; }"#,
        ] {
            let doc = parse_nix(snippet).unwrap();
            let err = parse_network_config(&doc).unwrap_err();
            assert!(
                err.to_string()
                    .contains("must not contain whitespace, quotes, backslashes, or control characters"),
                "{snippet}: {err}"
            );
        }
    }

    #[test]
    fn rejects_bad_cidr_addresses() {
        for addr in [
            "10.0.0.5",       // no '/'
            "10.0.0.5/24/8",  // more than one '/'
            "10.0.0.5/33",    // prefix out of range
            "10.0.0.5/abc",   // non-numeric prefix
            "10.0.0.5/",      // empty prefix
            "/24",            // empty host part
            "10.0.0.5/-1",    // negative prefix
            "10.0.0 5/24",    // whitespace in the host part
        ] {
            let doc = parse_nix(&format!(
                r#"network = {{ interfaces = {{ eth0 = {{ addresses = [ "{addr}" ]; }}; }}; }}"#
            ))
            .unwrap();
            let err = parse_network_config(&doc).unwrap_err();
            assert!(
                err.to_string().contains("addresses"),
                "{addr:?}: {err}"
            );
        }
    }

    #[test]
    fn rejects_hostile_gateway_and_dns_values() {
        for snippet in [
            r#"network = { interfaces = { eth0 = { addresses = [ "10.0.0.5/24" ]; gateway = "10.0.0.1 24"; }; }; }"#,
            r#"network = { interfaces = { eth0 = { addresses = [ "10.0.0.5/24" ]; gateway = "10\"0"; }; }; }"#,
            r#"network = { interfaces = { eth0 = { addresses = [ "10.0.0.5/24" ]; dns = [ "1.1.1.1\t2" ]; }; }; }"#,
            r#"network = { interfaces = { eth0 = { addresses = [ "10.0.0.5/24" ]; dns = [ "" ]; }; }; }"#,
        ] {
            let doc = parse_nix(snippet).unwrap();
            let err = parse_network_config(&doc).unwrap_err();
            assert!(
                err.to_string().contains("must not contain whitespace, quotes, backslashes, or control characters")
                    || err.to_string().contains("must not be empty"),
                "{snippet}: {err}"
            );
        }
    }

    #[test]
    fn rejects_unknown_keys() {
        let top = parse_nix(r#"network = { hostname = "x"; dns = [ "1.1.1.1" ]; }"#).unwrap();
        let err = parse_network_config(&top).unwrap_err();
        assert!(err.to_string().contains("unknown key: dns"), "{err}");

        let iface =
            parse_nix(r#"network = { interfaces = { eth0 = { dhcp = true; adresss = []; }; }; }"#)
                .unwrap();
        let err = parse_network_config(&iface).unwrap_err();
        assert!(err.to_string().contains("unknown key: adresss"), "{err}");
    }

    #[test]
    fn rejects_wrong_value_types() {
        for snippet in [
            r#"network = "eth0""#,
            r#"network = null"#,
            r#"network = { hostname = 5; }"#,
            r#"network = { hostname = ""; }"#,
            r#"network = { hostname = "ex tos"; }"#,
            r#"network = { interfaces = [ "eth0" ]; }"#,
            r#"network = { interfaces = { eth0 = "dhcp"; }; }"#,
            r#"network = { interfaces = { eth0 = { dhcp = "yes"; addresses = [ "10.0.0.5/24" ]; }; }; }"#,
            r#"network = { interfaces = { eth0 = { addresses = "10.0.0.5/24"; }; }; }"#,
            r#"network = { interfaces = { eth0 = { addresses = [ 5 ]; }; }; }"#,
            r#"network = { interfaces = { eth0 = { addresses = [ "10.0.0.5/24" ]; gateway = true; }; }; }"#,
            r#"network = { interfaces = { eth0 = { addresses = [ "10.0.0.5/24" ]; dns = [ 1 ]; }; }; }"#,
        ] {
            let doc = parse_nix(snippet).unwrap();
            assert!(
                parse_network_config(&doc).is_err(),
                "must reject: {snippet}"
            );
        }
    }

    #[test]
    fn render_rejects_hand_built_invalid_configs() {
        // Hand-constructed values get the same contract the parser enforces.
        let both = InterfaceConfig {
            name: "eth0".to_string(),
            dhcp: true,
            addresses: vec!["10.0.0.5/24".to_string()],
            gateway: None,
            dns: Vec::new(),
        };
        assert!(render_network_unit(&both).is_err());

        let neither = InterfaceConfig {
            name: "eth0".to_string(),
            dhcp: false,
            addresses: Vec::new(),
            gateway: None,
            dns: Vec::new(),
        };
        assert!(render_network_unit(&neither).is_err());

        let hostile_name = InterfaceConfig {
            name: "ETH0".to_string(),
            dhcp: true,
            addresses: Vec::new(),
            gateway: None,
            dns: Vec::new(),
        };
        assert!(render_network_unit(&hostile_name).is_err());

        // The path-hostile `.` / `..` names are rejected by the same contract
        // (lane L28 emits `30-<name>.network`-style filenames later).
        for name in [".", ".."] {
            let hostile = InterfaceConfig {
                name: name.to_string(),
                dhcp: true,
                addresses: Vec::new(),
                gateway: None,
                dns: Vec::new(),
            };
            assert!(render_network_unit(&hostile).is_err(), "{name:?}");
        }

        // A hand-built value carrying a backslash is rejected too: a trailing
        // `\` would make systemd concatenate the next line into the value.
        let backslash_gateway = InterfaceConfig {
            name: "eth0".to_string(),
            dhcp: false,
            addresses: vec!["10.0.0.5/24".to_string()],
            gateway: Some("10.0.0.1\\".to_string()),
            dns: Vec::new(),
        };
        assert!(render_network_unit(&backslash_gateway).is_err());

        let hostile_gateway = InterfaceConfig {
            name: "eth0".to_string(),
            dhcp: false,
            addresses: vec!["10.0.0.5/24".to_string()],
            gateway: Some("10.0.0.1 24".to_string()),
            dns: Vec::new(),
        };
        assert!(render_network_unit(&hostile_gateway).is_err());
    }
}
