//! Integration probe for PLAN 7.2.1 + 7.2.3 (`daemons.nix` → systemd units).
//!
//! The full parser → renderer chain is exercised on the shipped
//! `config/daemons.nix` shape: the template document is parsed with
//! [`libextos::daemons::parse_daemons_config`], and the design §15 control
//! plane (`pkt`, `instanz`) is rendered with
//! [`libextos::daemons::render_service_unit`] /
//! [`libextos::daemons::render_socket_unit`], including the design's
//! socket-activation pairs (`/run/extos/pkt.sock` for `wheel`,
//! `/run/extos/instanz.sock` for `extos-admin`).
//!
//! The generated units are then validated by the host's real
//! `systemd-analyze verify` (systemd 262 on this host). Two properties of
//! the tool were probed empirically before writing this test and shape the
//! procedure:
//!
//! * a `.socket` unit only verifies together with its implied same-named
//!   `.service` ("service not loaded, socket cannot be started" otherwise),
//!   so each daemon's pair is written under matching names into one scratch
//!   directory and verified in a single invocation;
//! * an unknown `SocketGroup` (`extos-admin` does not exist on dev hosts) is
//!   accepted by verify 262 — the socket is validated syntactically, group
//!   resolution is a runtime concern of PID 1.
//!
//! `exec_start` is substituted with `/usr/bin/true` (present on every host
//! with coreutils) for the verify run only: the real `pkt`/`instanz` daemon
//! binaries have no fixed install path on a development host, and verify
//! resolves `ExecStart=` against the filesystem. Everything else on the
//! units is exactly what the renderers emit.
//!
//! Honesty rules: if `systemd-analyze` is absent, or the *oracle control*
//! (a systemd-shipped unit) itself fails to verify, the probe prints an
//! honest `SKIP …` — the tool cannot arbitrate on this host. If the oracle
//! passes but a generated unit fails, that is a real `FAIL` (panic with the
//! tool output quoted verbatim), never papered over.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use libextos::config;
use libextos::daemons::{
    parse_daemons_config, render_service_unit, render_socket_unit, DaemonConfig, DEFAULT_SOCKETS,
};

/// The shipped template (`config/daemons.nix`), mirrored inline — the crate
/// must not reach outside its own directory at compile time.
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

/// The `ExecStart` substitution used for the verify run (see module docs).
const VERIFY_EXEC_START: &str = "/usr/bin/true";

fn parse_template() -> DaemonConfig {
    let doc = config::parse_nix(TEMPLATE).expect("template document parses");
    parse_daemons_config(&doc).expect("template shape parses")
}

/// Is `systemd-analyze` runnable at all?
fn systemd_analyze_available() -> bool {
    Command::new("systemd-analyze")
        .arg("--version")
        .output()
        .is_ok_and(|out| out.status.success())
}

/// Locate a systemd-shipped unit to serve as the oracle control: a unit the
/// distribution itself ships, so a verify failure indicts the tool, not the
/// generated output.
fn find_oracle_unit() -> Option<PathBuf> {
    let candidates = [
        "/usr/lib/systemd/system/dbus.service",
        "/usr/lib/systemd/system/systemd-journald.service",
        "/lib/systemd/system/dbus.service",
        "/usr/lib/systemd/system/ssh.service",
    ];
    for candidate in candidates {
        if Path::new(candidate).is_file() {
            return Some(PathBuf::from(candidate));
        }
    }
    // Fallback: first shipped .service in the primary unit directory.
    let dir = Path::new("/usr/lib/systemd/system");
    let entries = fs::read_dir(dir).ok()?;
    entries
        .flatten()
        .map(|entry| entry.path())
        .find(|path| path.extension().is_some_and(|ext| ext == "service"))
}

/// Run `systemd-analyze verify` on the given unit files; returns
/// `(exit_code, combined_output)`.
fn verify(units: &[&Path]) -> (Option<i32>, String) {
    let out = Command::new("systemd-analyze")
        .arg("verify")
        .args(units)
        .output()
        .expect("systemd-analyze spawn (availability probed)");
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status.code(), text)
}

#[test]
fn generated_units_pass_systemd_analyze_verify() {
    if !systemd_analyze_available() {
        println!("SKIP systemd-analyze not available; generated units not host-proven");
        return;
    }

    // Oracle control first: if the tool cannot verify a unit systemd itself
    // ships, it cannot arbitrate here (the .network lane precedent) — honest
    // skip with the oracle output quoted, never a pass.
    let Some(oracle) = find_oracle_unit() else {
        println!("SKIP no systemd-shipped unit found as oracle control; cannot arbitrate");
        return;
    };
    let (code, output) = verify(&[&oracle]);
    if code != Some(0) {
        println!(
            "SKIP oracle control {oracle:?} failed to verify (exit {code:?}); \
             systemd-analyze cannot arbitrate on this host. Output:\n{output}"
        );
        return;
    }
    println!("oracle control {oracle:?}: exit 0 (tool serviceable)");

    // The real chain: parse the template, render the design §15 pair.
    let parsed = parse_template();
    let dir = tempfile::tempdir().expect("scratch tmpdir");

    let mut pairs: Vec<(String, Vec<PathBuf>)> = Vec::new();
    for daemon in ["pkt", "instanz"] {
        let settings = parsed
            .daemons
            .get(daemon)
            .unwrap_or_else(|| panic!("template declares {daemon:?}"));
        let service = render_service_unit(daemon, settings, VERIFY_EXEC_START)
            .unwrap_or_else(|err| panic!("render {daemon}.service: {err}"));

        let (_, socket_path, group) = DEFAULT_SOCKETS
            .iter()
            .find(|(name, _, _)| *name == daemon)
            .unwrap_or_else(|| panic!("DEFAULT_SOCKETS pins {daemon:?}"));
        let socket = render_socket_unit(daemon, socket_path, group)
            .unwrap_or_else(|err| panic!("render {daemon}.socket: {err}"));

        let service_path = dir.path().join(format!("{daemon}.service"));
        let socket_path_buf = dir.path().join(format!("{daemon}.socket"));
        fs::write(&service_path, &service).expect("write service unit");
        fs::write(&socket_path_buf, &socket).expect("write socket unit");
        pairs.push((daemon.to_string(), vec![service_path, socket_path_buf]));
    }

    // One invocation per daemon pair: the .socket only verifies together
    // with its implied same-named .service (probed systemd 262 behavior).
    for (daemon, units) in &pairs {
        let unit_paths: Vec<&Path> = units.iter().map(Path::new).collect();
        let (code, output) = verify(&unit_paths);
        let rendered: String = units
            .iter()
            .map(|unit| {
                format!(
                    "--- {} ---\n{}",
                    unit.display(),
                    fs::read_to_string(unit).expect("read back written unit")
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        println!("rendered units:\n{rendered}");
        match code {
            Some(0) => println!(
                "PROVEN systemd-analyze verify exit 0 for {}:\n{}",
                unit_paths
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(" "),
                output
            ),
            code => panic!(
                "FAIL systemd-analyze verify rejected the generated {daemon} units \
                 (exit {code:?}). Output:\n{output}\nRendered units:\n{rendered}"
            ),
        }
    }
}
