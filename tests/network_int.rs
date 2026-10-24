//! Integration tests for lane L27 — PLAN Phase 7 sub-phases 7.3.1/7.3.2
//! (`network.nix` → `systemd-networkd` units, `swarm.nix` → libp2p settings).
//!
//! The `systemd-analyze verify` oracle is capability-probed before use: a
//! canonical, known-good control `.network` unit decides whether this host's
//! verifier can check network units at all. Hosts without the binary — and
//! hosts whose verifier refuses to *prepare* `.network` files (observed on
//! systemd 262, which answers "Failed to prepare filename …: Invalid
//! argument" even for its own `/usr/lib/systemd/network` builtins) — get an
//! honest `SKIP` with the verbatim output. Where the control unit passes, a
//! verification failure of a rendered unit is a real FAIL.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use libextos::config::parse_nix;
use libextos::network::swarm::{
    parse_swarm_config, render_libp2p_settings, DEFAULT_LISTEN_MULTIADDR,
};
use libextos::network::{parse_network_config, render_network_unit};

/// The declared `network.nix` document under test (runtime-synthesized;
/// there is no committed template for `network.nix` yet).
const NETWORK_DOC: &str = r#"network = {
    hostname = "extos-box";
    interfaces = {
        eth0 = { dhcp = true; };
        wlan0 = {
            addresses = [ "192.168.7.9/24" "10.0.0.5/24" ];
            gateway = "10.0.0.1";
            dns = [ "8.8.8.8" "1.1.1.1" ];
        };
    };
}"#;

// ─── 7.3.1: parse + render + write ──────────────────────────────

#[test]
fn parses_document_and_writes_units_to_scratch() {
    let doc = parse_nix(NETWORK_DOC).unwrap();
    let config = parse_network_config(&doc).unwrap();
    assert_eq!(config.hostname.as_deref(), Some("extos-box"));
    assert_eq!(config.interfaces.len(), 2);

    let dir = tempfile::tempdir().unwrap();
    for iface in config.interfaces.values() {
        let unit = render_network_unit(iface).expect("render unit");
        let path = dir.path().join(format!("30-{}.network", iface.name));
        fs::write(&path, &unit).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), unit, "written bytes");
    }

    let wlan = fs::read_to_string(dir.path().join("30-wlan0.network")).unwrap();
    assert_eq!(
        wlan,
        "[Match]\nName=wlan0\n\n[Network]\nAddress=10.0.0.5/24\nAddress=192.168.7.9/24\nGateway=10.0.0.1\nDNS=1.1.1.1\nDNS=8.8.8.8\n",
        "addresses and DNS render sorted regardless of declaration order"
    );
    let eth = fs::read_to_string(dir.path().join("30-eth0.network")).unwrap();
    assert_eq!(eth, "[Match]\nName=eth0\n\n[Network]\nDHCP=yes\n");
}

#[test]
fn rendering_is_byte_identical_and_order_insensitive() {
    let config_a = parse_network_config(&parse_nix(NETWORK_DOC).unwrap()).unwrap();
    let shuffled = NETWORK_DOC
        .replace("\"192.168.7.9/24\" \"10.0.0.5/24\"", "\"10.0.0.5/24\" \"192.168.7.9/24\"")
        .replace("\"8.8.8.8\" \"1.1.1.1\"", "\"1.1.1.1\" \"8.8.8.8\"");
    assert_ne!(shuffled, NETWORK_DOC, "shuffled document really differs");
    let config_b = parse_network_config(&parse_nix(&shuffled).unwrap()).unwrap();

    let unit_a = render_network_unit(&config_a.interfaces["wlan0"]).unwrap();
    let unit_b = render_network_unit(&config_b.interfaces["wlan0"]).unwrap();
    assert_eq!(unit_a, unit_b, "declaration order must not leak into units");
    assert_eq!(
        unit_a,
        render_network_unit(&config_a.interfaces["wlan0"]).unwrap(),
        "re-render is byte-identical"
    );
}

#[test]
fn hostile_network_declarations_are_typed_rejected() {
    for snippet in [
        // dhcp XOR addresses
        r#"network = { interfaces = { eth0 = { dhcp = true; addresses = [ "10.0.0.5/24" ]; }; }; }"#,
        r#"network = { interfaces = { eth0 = {}; }; }"#,
        // bad names / bad CIDR / hostile values
        r#"network = { interfaces = { "ETH0" = { dhcp = true; }; }; }"#,
        r#"network = { interfaces = { eth0 = { addresses = [ "10.0.0.5" ]; }; }; }"#,
        r#"network = { interfaces = { eth0 = { addresses = [ "10.0.0.5/33" ]; }; }; }"#,
        r#"network = { interfaces = { eth0 = { addresses = [ "10.0.0.5/24" ]; gateway = "10.0.0.1 24"; }; }; }"#,
        // typos must not silently disable a setting
        r#"network = { interfaces = { eth0 = { dhcp = true; adresss = []; }; }; }"#,
        r#"network = { hostnam = "extos-box"; }"#,
    ] {
        let doc = parse_nix(snippet).unwrap();
        let err = parse_network_config(&doc).expect_err(snippet);
        assert!(
            err.to_string().contains("Configuration parse error"),
            "typed ConfigParse expected: {err}"
        );
    }
}

// ─── 7.3.2: swarm declarative surface ───────────────────────────

#[test]
fn swarm_document_parses_and_renders_pinned_toml() {
    let doc = parse_nix(
        r#"swarm = {
            enabled = true;
            listen = "/ip4/0.0.0.0/tcp/4001";
            bootstrap = [ "p2p://backup.extos.org" "p2p://swarm.extos.org" "p2p://backup.extos.org" ];
        }"#,
    )
    .unwrap();
    let config = parse_swarm_config(&doc).unwrap();
    assert!(config.enabled);

    let toml = render_libp2p_settings(&config);
    assert_eq!(
        toml,
        "[swarm]\nenabled = true\nlisten_multiaddr = \"/ip4/0.0.0.0/tcp/4001\"\nbootstrap_peers = [ \"p2p://backup.extos.org\", \"p2p://swarm.extos.org\" ]\n",
        "peers sorted and deduplicated, byte-pinned"
    );
    assert_eq!(
        render_libp2p_settings(&config),
        toml,
        "re-render is byte-identical"
    );

    // A minimal declaration defaults to disabled with the canonical listen.
    let minimal = parse_swarm_config(&parse_nix(r#"swarm = { enabled = false; }"#).unwrap())
        .unwrap();
    assert_eq!(minimal.listen, DEFAULT_LISTEN_MULTIADDR);
    assert!(minimal.bootstrap.is_empty());
    assert!(
        render_libp2p_settings(&minimal).contains("enabled = false\n"),
        "{:?}",
        render_libp2p_settings(&minimal)
    );
}

// ─── Real-application probe (systemd-analyze verify) ────────────

/// Locate an executable on `PATH`, if present.
fn probe_tool(name: &str) -> Option<PathBuf> {
    for dir in std::env::split_paths(&std::env::var_os("PATH")?) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

#[test]
fn systemd_analyze_verifies_rendered_network_units() {
    let Some(analyze) = probe_tool("systemd-analyze") else {
        println!("SKIP systemd-analyze not available; rendered .network units are not verifier-proven");
        return;
    };

    let dir = tempfile::tempdir().unwrap();

    // Capability probe: can this systemd-analyze verify .network files at
    // all? A canonical, known-good control unit decides. systemd 262 (this
    // host) cannot prepare network units and answers "Failed to prepare
    // filename …: Invalid argument" — an honest skip, never a silent pass.
    let control = dir.path().join("extos-oracle-probe.network");
    fs::write(
        &control,
        "[Match]\nName=extos-oracle-probe\n\n[Network]\nDHCP=yes\n",
    )
    .unwrap();
    let out = Command::new(&analyze)
        .arg("verify")
        .arg(&control)
        .output()
        .expect("spawn systemd-analyze");
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        println!(
            "SKIP systemd-analyze cannot verify .network files on this host \
             (canonical control unit rejected, rc={:?}):\nstdout: {}\nstderr: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stdout).trim(),
            stderr.trim()
        );
        return;
    }

    // The oracle works here: render the real units and verify them. A
    // verification failure is a real FAIL.
    let config = parse_network_config(&parse_nix(NETWORK_DOC).unwrap()).unwrap();
    for iface in config.interfaces.values() {
        let unit = render_network_unit(iface).expect("render unit");
        let path = dir.path().join(format!("30-{}.network", iface.name));
        fs::write(&path, &unit).unwrap();

        let out = Command::new(&analyze)
            .arg("verify")
            .arg(&path)
            .output()
            .expect("spawn systemd-analyze");
        assert!(
            out.status.success(),
            "systemd-analyze rejected the rendered unit {}:\nunit:\n{unit}\nstdout: {}\nstderr: {}",
            path.display(),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
}
