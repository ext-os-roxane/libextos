//! Integration tests for PLAN sub-phase 4.4 — Runlevel 3 container runtime.
//!
//! Everything here runs unprivileged and without network access. Fixtures are
//! synthesized at test runtime (CAS objects, a `gcc -static` helper, a PTY); no
//! binary artifacts are committed.
//!
//! Coverage map:
//!
//! | Test | Task |
//! |------|------|
//! | `manifest_container_permissions_*` | 4.4.1 |
//! | `level1_container_runs_a_static_helper_under_a_pty` | 4.4.2, 4.4.3, 4.4.10 |
//! | `maximum_argv_is_delivered_without_truncation` | 4.4.2, 4.4.5 |
//! | `level0_isolated_container_has_no_pty_and_piped_stdio` | 4.4.2 |
//! | `level3_networked_container_inherits_the_host_network` | 4.4.5 |
//! | `privileged_launch_requires_explicit_opt_in` | 4.4.6 |
//! | `gui_spec_binds_real_sockets_into_the_container` | 4.4.4 |
//! | `rootfs_assembly_weaves_the_package_into_a_staging_tree` | 4.4.7 |
//! | `backend_matrix_and_probe_are_honest` | 4.4.9 |
//! | `child_setup_failure_is_a_typed_namespace_error` | 4.4.2 |
//! | `real_backend_runs_when_env_gated` | 4.4.9 |
//!
//! # Why a compiled helper
//!
//! The PLAN asks for "`uname -a` inside the container". Running the host
//! `/usr/bin/uname` inside a container would need the dynamic loader, libc and
//! their dependency closure staged in the rootfs. A statically linked helper
//! compiled by the test (`cc -static`) needs nothing but the kernel, which makes
//! the test hermetic and also lets it assert the *container's* view: hostname
//! (UTS namespace), `uid` (user namespace mapping), `/proc` (PID namespace) and
//! interface count (`/proc/net/dev` → network namespace).

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use libextos::cas::CasRepository;
use libextos::config::parse_nix;
use libextos::container::gui::assemble_gui_spec;
use libextos::container::{
    assemble_rootfs, launch, Backend, BackendProbe, ContainerError, GuiEnv, IsolationLevel,
    LaunchSpec, RootMode, RootfsRequest,
};
use libextos::manifest::{ContainerPermissions, ContainerSocket, PackageManifest};
use libextos::types::HashAlgorithm;
use libextos::weaver::CasRef;

// ─── Fixtures ──────────────────────────────────────────────────

/// C source of the in-container probe (`uname` + namespace evidence).
const PROBE_SOURCE: &str = r#"
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/utsname.h>
#include <unistd.h>

int main(int argc, char **argv) {
    struct utsname u;
    if (uname(&u) != 0) {
        return 2;
    }
    char host[65];
    memset(host, 0, sizeof host);
    if (gethostname(host, sizeof host - 1) != 0) {
        return 3;
    }
    printf("argc=%d\n", argc);
    if (argc > 63) {
        printf("argv63=%s\n", argv[63]);
    }
    printf("argv1=%s\n", argc > 1 ? argv[1] : "");
    printf("sysname=%s\n", u.sysname);
    printf("release=%s\n", u.release);
    printf("machine=%s\n", u.machine);
    printf("hostname=%s\n", host);
    printf("uid=%d\n", (int)getuid());

    FILE *interfaces = fopen("/proc/net/dev", "r");
    printf("proc-net-dev=%s\n", interfaces ? "present" : "absent");
    if (interfaces) {
        char line[512];
        int count = 0;
        while (fgets(line, sizeof line, interfaces) != NULL) {
            if (strchr(line, ':') != NULL) {
                count++;
            }
        }
        printf("ifaces=%d\n", count);
        fclose(interfaces);
    }

    // Writable /tmp (tmpfs) but read-only package tree (level 0/1).
    int tmp = open("/tmp/extos-probe", O_CREAT | O_WRONLY, 0600);
    printf("tmp-write=%s\n", tmp >= 0 ? "ok" : "denied");
    if (tmp >= 0) {
        close(tmp);
    }
    int usr = open("/usr/.extos-probe", O_CREAT | O_WRONLY, 0600);
    printf("usr-write=%s\n", usr >= 0 ? "ok" : "denied");
    if (usr >= 0) {
        close(usr);
    }
    return 0;
}
"#;

/// Compile the probe with `cc -static`, returning its bytes.
///
/// Returns `None` when no static toolchain is available so the affected tests can
/// print a skip instead of failing on a host without `libc.a`.
fn compile_probe(dir: &Path) -> Option<Vec<u8>> {
    let out = dir.join("extos-probe");
    let mut child = Command::new("cc")
        .args(["-static", "-O1", "-o"])
        .arg(&out)
        .args(["-x", "c", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;
    child
        .stdin
        .as_mut()
        .expect("probe compiler stdin")
        .write_all(PROBE_SOURCE.as_bytes())
        .ok()?;
    let status = child.wait().ok()?;
    if !status.success() {
        return None;
    }
    fs::read(&out).ok()
}

/// Manifest text for the containerised fixture package.
fn fixture_manifest(profile: &str) -> String {
    format!(
        r#"{{
  identity = {{
    origin = "scratch";
    name = "probe";
    version = "1.0.0";
  }};
  format = "extracted-tree";
  capabilities = {{ binaries = [ "usr/bin/extos-probe" ]; }};
  requires = [];
  containerPermissions = {profile};
}}"#
    )
}

struct Fixture {
    _tmp: tempfile::TempDir,
    repo: CasRepository,
    rootfs_stage: PathBuf,
    probe: Vec<u8>,
}

impl Fixture {
    /// Build a CAS with one package carrying the static probe, its
    /// `containerPermissions` block, and a `/usr` tree.
    fn build(profile: &str) -> Option<Self> {
        let tmp = tempfile::tempdir().ok()?;
        let work = tmp.path().to_path_buf();
        let probe = compile_probe(&work)?;

        let payload = work.join("payload");
        fs::create_dir_all(payload.join("usr/bin")).unwrap();
        fs::write(payload.join("usr/bin/extos-probe"), &probe).unwrap();
        fs::set_permissions(
            payload.join("usr/bin/extos-probe"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        fs::create_dir_all(payload.join("usr/share/extos")).unwrap();
        fs::write(payload.join("usr/share/extos/marker"), b"weaved\n").unwrap();

        let repo = CasRepository::open(work.join("repository"), HashAlgorithm::Blake3).unwrap();
        let hash = repo.store_directory(&payload).unwrap();
        repo.write_manifest(&hash, &fixture_manifest(profile))
            .unwrap();
        repo.create_ref("scratch", "probe", "1.0.0", &hash).unwrap();
        repo.update_current("scratch", "probe", "1.0.0").unwrap();

        Some(Self {
            _tmp: tmp,
            repo,
            rootfs_stage: work.join("rootfs"),
            probe,
        })
    }

    fn refs(&self) -> Vec<CasRef> {
        vec![CasRef::new("scratch", "probe", "1.0.0")]
    }

    /// Assemble the container rootfs from the fixture package.
    fn rootfs(&self, hostname: &str) -> libextos::container::Rootfs {
        assemble_rootfs(&RootfsRequest {
            repo: &self.repo,
            refs: &self.refs(),
            stage: &self.rootfs_stage,
            hostname,
        })
        .expect("rootfs assembly")
    }

    fn probe_bytes(&self) -> &[u8] {
        &self.probe
    }
}

fn userns_available() -> bool {
    BackendProbe::discover().native_userns
}

fn euid() -> u32 {
    // SAFETY: geteuid is always safe.
    unsafe { libc::geteuid() }
}

fn host_machine() -> String {
    unsafe {
        let mut info: libc::utsname = std::mem::zeroed();
        if libc::uname(&mut info) != 0 {
            return String::from("unknown");
        }
        std::ffi::CStr::from_ptr(info.machine.as_ptr())
            .to_string_lossy()
            .into_owned()
    }
}

// ─── 4.4.1: spec parser ────────────────────────────────────────

#[test]
fn manifest_container_permissions_parse_levels_and_sockets() {
    let nix = parse_nix(
        r#"{
            name = "browser";
            version = "1.0";
            origin = "scratch";
            containerPermissions = {
                level = "gui";
                sockets = [ "wayland" "pipewire" "dbus-session" ];
            };
        }"#,
    )
    .unwrap();
    let manifest = PackageManifest::from_nix(&nix).unwrap();
    let profile = manifest.container.expect("container block");
    assert_eq!(profile.level, IsolationLevel::Gui);
    assert!(profile.allows(ContainerSocket::Wayland));
    assert!(profile.allows(ContainerSocket::DbusSession));
    assert!(!profile.allows(ContainerSocket::X11));
    // Level defaults: all namespaces except cgroup.
    assert!(profile.namespaces.user && profile.namespaces.pid && profile.namespaces.net);
    assert!(!profile.namespaces.cgroup);
}

#[test]
fn manifest_container_permissions_accept_shorthand_and_overrides() {
    let shorthand = parse_nix(r#"{ name = "a"; containerPermissions = "networked"; }"#).unwrap();
    let manifest = PackageManifest::from_nix(&shorthand).unwrap();
    let profile = manifest.container.unwrap();
    assert_eq!(profile.level, IsolationLevel::Networked);
    assert!(!profile.namespaces.net, "level 3 keeps the host network");

    let numeric = parse_nix(
        r#"{ name = "a"; containerPermissions = { level = 2; namespaces = { net = true; }; }; }"#,
    )
    .unwrap();
    let manifest = PackageManifest::from_nix(&numeric).unwrap();
    let profile = manifest.container.unwrap();
    assert_eq!(profile.level, IsolationLevel::Gui);
    assert!(profile.namespaces.net, "manifest override wins over the default");
}

#[test]
fn manifest_without_container_block_is_unchanged() {
    let nix = parse_nix(r#"{ name = "htop"; version = "3"; origin = "archlinux"; }"#).unwrap();
    let manifest = PackageManifest::from_nix(&nix).unwrap();
    assert!(manifest.container.is_none());
}

#[test]
fn manifest_rejects_privileged_with_namespaces() {
    let nix = parse_nix(
        r#"{ name = "a"; containerPermissions = { level = "privileged"; namespaces = { net = true; }; }; }"#,
    )
    .unwrap();
    let err = PackageManifest::from_nix(&nix).unwrap_err();
    assert!(err.to_string().contains("privileged"));
}

#[test]
fn manifest_rejects_unknown_socket_and_level() {
    let bad_socket = parse_nix(
        r#"{ name = "a"; containerPermissions = { level = "gui"; sockets = [ "mir" ]; }; }"#,
    )
    .unwrap();
    assert!(PackageManifest::from_nix(&bad_socket).is_err());

    let bad_level = parse_nix(r#"{ name = "a"; containerPermissions = { level = 9; }; }"#).unwrap();
    assert!(PackageManifest::from_nix(&bad_level).is_err());
}

// ─── 4.4.7: rootfs weaving ─────────────────────────────────────

#[test]
fn rootfs_assembly_weaves_the_package_into_a_staging_tree() {
    let Some(fixture) = Fixture::build(r#"{ level = "cli"; }"#) else {
        eprintln!("skip: no static cc toolchain available");
        return;
    };
    let rootfs = fixture.rootfs("extos-rootfs-test");

    assert!(rootfs.has_program("/usr/bin/extos-probe"));
    assert_eq!(
        fs::read(rootfs.stage.join("usr/bin/extos-probe")).unwrap(),
        fixture.probe_bytes(),
        "the payload must be a byte-identical copy"
    );
    assert_eq!(
        fs::read_to_string(rootfs.stage.join("usr/share/extos/marker")).unwrap(),
        "weaved\n"
    );
    for dir in ["etc", "proc", "sys", "dev", "tmp", "run", "usr"] {
        assert!(
            rootfs.stage.join(dir).is_dir(),
            "system directory /{dir} missing from the staged rootfs"
        );
    }
    assert!(rootfs.top_level.contains(&"usr".to_string()));
    assert!(rootfs.top_level.contains(&"proc".to_string()));
    assert_eq!(
        fs::read_to_string(rootfs.stage.join("etc/hostname")).unwrap(),
        "extos-rootfs-test\n"
    );
    assert!(rootfs.files >= 2);
    assert!(rootfs.directories >= 10);

    // The staging directory is never reused: a stale root must not leak.
    let again = assemble_rootfs(&RootfsRequest {
        repo: &fixture.repo,
        refs: &fixture.refs(),
        stage: &fixture.rootfs_stage,
        hostname: "extos-rootfs-test",
    });
    assert!(again.is_err(), "assembling over a non-empty stage must fail");
}

// ─── 4.4.2 / 4.4.3 / 4.4.10: the real Level 1 run ──────────────

#[test]
fn level1_container_runs_a_static_helper_under_a_pty() {
    if !userns_available() {
        eprintln!("skip: unprivileged user namespaces are unavailable on this host");
        return;
    }
    let Some(fixture) = Fixture::build(r#"{ level = "cli"; }"#) else {
        eprintln!("skip: no static cc toolchain available");
        return;
    };
    let rootfs = fixture.rootfs("extos-cli");

    // Full chain: manifest → profile → LaunchSpec → rootfs → namespaces → PTY.
    let nix = parse_nix(&fixture_manifest(r#"{ level = "cli"; command = [ "/usr/bin/extos-probe" ]; }"#))
        .unwrap();
    let manifest = PackageManifest::from_nix(&nix).unwrap();
    let profile = manifest.container.expect("profile");
    let mut spec = LaunchSpec::from_profile(&profile, &rootfs.stage, None)
        .with_env("EXTOS_PROBE", "1")
        .with_privileged(false);
    spec.hostname = "extos-cli".into();
    assert_eq!(spec.program, "/usr/bin/extos-probe");

    let outcome = launch(&spec).expect("level 1 container launch");
    let text = outcome.text();
    eprintln!("── level 1 container output ──\n{text}\n──────────────────────────────");

    assert!(outcome.pty, "level 1 must wire stdio to a PTY");
    assert!(outcome.success(), "container exit status: {:?}", outcome.status);
    assert!(text.contains("sysname=Linux"), "output: {text}");
    assert!(
        text.contains(&format!("machine={}", host_machine())),
        "uname(2) inside the container must report the host kernel machine; output: {text}"
    );
    assert!(
        text.contains("hostname=extos-cli"),
        "the UTS namespace must give the container its own hostname; output: {text}"
    );
    assert!(
        text.contains("uid=0"),
        "the user namespace must map the caller to root; output: {text}"
    );
    assert!(
        text.contains("proc-net-dev=present"),
        "PID 1 must mount a private procfs; output: {text}"
    );
    assert!(
        text.contains("tmp-write=ok"),
        "the tmpfs /tmp must be writable; output: {text}"
    );
    assert!(
        text.contains("usr-write=denied"),
        "the package tree must be mounted read-only; output: {text}"
    );
}

#[test]
fn maximum_argv_is_delivered_without_truncation() {
    if !userns_available() {
        eprintln!("skip: unprivileged user namespaces are unavailable on this host");
        return;
    }
    let Some(fixture) = Fixture::build(r#"{ level = "cli"; }"#) else {
        eprintln!("skip: no static cc toolchain provided");
        return;
    };
    let rootfs = fixture.rootfs("extos-argv");

    // `program + 63 args` is exactly MAX_EXEC_VECTORS (64) argv entries. Before
    // the G-L15 fix the child copied only MAX_EXEC_VECTORS - 1 slots, so the
    // 64th entry became the NULL terminator (argc == 63).
    let args: Vec<String> = (0..63).map(|index| format!("arg-{index}")).collect();
    let spec = LaunchSpec::new(IsolationLevel::Cli, &rootfs.stage, "/usr/bin/extos-probe")
        .with_args(args);
    let outcome = launch(&spec).expect("level 1 container launch");
    let text = outcome.text();
    assert!(outcome.success(), "status {:?}: {text}", outcome.status);
    assert!(
        text.contains("argc=64"),
        "the payload must receive all 64 argv entries; output: {text}"
    );
    assert!(
        text.contains("argv63=arg-62"),
        "the 64th argument (argv[63]) must not be truncated; output: {text}"
    );
    assert!(
        text.contains("argv1=arg-0"),
        "argv[0] stays the program and argv[1] the first argument; output: {text}"
    );
}

#[test]
fn level0_isolated_container_has_no_pty_and_piped_stdio() {
    if !userns_available() {
        eprintln!("skip: unprivileged user namespaces are unavailable on this host");
        return;
    }
    let Some(fixture) = Fixture::build(r#"{ level = "isolated"; }"#) else {
        eprintln!("skip: no static cc toolchain available");
        return;
    };
    let rootfs = fixture.rootfs("extos-iso");
    let spec = LaunchSpec::new(IsolationLevel::Isolated, &rootfs.stage, "/usr/bin/extos-probe");
    assert!(!spec.level.needs_pty());

    let outcome = launch(&spec).expect("level 0 container launch");
    let text = outcome.text();
    eprintln!("── level 0 container output ──\n{text}\n──────────────────────────────");
    assert!(!outcome.pty);
    assert!(outcome.success(), "status {:?}: {text}", outcome.status);
    assert!(text.contains("sysname=Linux"));
    assert!(text.contains("hostname=extos"), "default hostname; output: {text}");
    assert!(text.contains("uid=0"));
    // A fresh network namespace has exactly one interface (`lo`).
    assert!(text.contains("ifaces=1"), "isolated netns; output: {text}");
}

// ─── 4.4.5: networked ──────────────────────────────────────────

#[test]
fn level3_networked_container_inherits_the_host_network() {
    if !userns_available() {
        eprintln!("skip: unprivileged user namespaces are unavailable on this host");
        return;
    }
    let Some(fixture) = Fixture::build(r#"{ level = "networked"; }"#) else {
        eprintln!("skip: no static cc toolchain available");
        return;
    };
    let rootfs = fixture.rootfs("extos-net");
    let mut spec = LaunchSpec::new(
        IsolationLevel::Networked,
        &rootfs.stage,
        "/usr/bin/extos-probe",
    );
    spec.hostname = "extos-net".into();
    assert!(!spec.effective_namespaces().net, "level 3 keeps host netns");

    let outcome = launch(&spec).expect("level 3 container launch");
    let text = outcome.text();
    eprintln!("── level 3 container output ──\n{text}\n──────────────────────────────");
    assert!(outcome.success(), "status {:?}: {text}", outcome.status);
    assert!(text.contains("hostname=extos-net"));
    // The host network namespace always has more than the isolated `lo`.
    let host_ifaces: usize = fs::read_to_string("/proc/net/dev")
        .map(|text| {
            text.lines()
                .filter(|line| line.contains(':'))
                .count()
        })
        .unwrap_or(0);
    let inside = text
        .lines()
        .find_map(|line| line.strip_prefix("ifaces="))
        .and_then(|value| value.trim().parse::<usize>().ok())
        .unwrap_or(0);
    assert_eq!(
        inside, host_ifaces,
        "a networked container must see the host interface set; output: {text}"
    );
}

// ─── 4.4.4: GUI socket assembly ────────────────────────────────

#[test]
fn gui_spec_binds_real_sockets_into_the_container() {
    let tmp = tempfile::tempdir().unwrap();
    let runtime = tmp.path().join("runtime");
    fs::create_dir_all(runtime.join("pulse")).unwrap();
    let wayland = runtime.join("wayland-7");
    let pipewire = runtime.join("pipewire-0");
    let pulse = runtime.join("pulse/native");
    let bus = runtime.join("bus");
    let _listeners = [
        std::os::unix::net::UnixListener::bind(&wayland).unwrap(),
        std::os::unix::net::UnixListener::bind(&pipewire).unwrap(),
        std::os::unix::net::UnixListener::bind(&pulse).unwrap(),
        std::os::unix::net::UnixListener::bind(&bus).unwrap(),
    ];

    let env = GuiEnv {
        xdg_runtime_dir: Some(runtime.clone()),
        wayland_display: Some("wayland-7".into()),
        dbus_session_address: Some(format!("unix:path={}", bus.display())),
        display: Some(":0".into()),
        xauthority: Some(tmp.path().join("Xauthority")),
        system_bus: tmp.path().join("absent-system-bus"),
    };
    let spec = assemble_gui_spec(
        &[
            ContainerSocket::Wayland,
            ContainerSocket::Pipewire,
            ContainerSocket::PulseAudio,
            ContainerSocket::DbusSession,
        ],
        &env,
    );

    assert_eq!(spec.mounts.len(), 4);
    assert!(spec.missing().is_empty(), "missing: {:?}", spec.missing());
    for mount in &spec.mounts {
        assert!(
            mount.target.starts_with("/run/user/0"),
            "socket target {} escapes the container runtime dir",
            mount.target.display()
        );
        assert!(mount.is_available());
    }
    assert_eq!(spec.env_var("WAYLAND_DISPLAY"), Some("wayland-7"));
    assert_eq!(spec.env_var("XDG_RUNTIME_DIR"), Some("/run/user/0"));
    assert_eq!(spec.env_var("PULSE_SERVER"), Some("unix:/run/user/0/pulse/native"));
    assert_eq!(
        spec.env_var("DBUS_SESSION_BUS_ADDRESS"),
        Some("unix:path=/run/user/0/bus")
    );
    assert!(spec.unset.contains(&"XAUTHORITY".to_string()));
    spec.clone().require_all().validate(true).unwrap();

    // The binds reach the child program's mount table, not the host's.
    let rootfs = tmp.path().join("rootfs");
    fs::create_dir_all(rootfs.join("usr/bin")).unwrap();
    fs::write(rootfs.join("usr/bin/app"), b"#!/bin/sh\n").unwrap();
    fs::set_permissions(
        rootfs.join("usr/bin/app"),
        std::os::unix::fs::PermissionsExt::from_mode(0o755),
    )
    .unwrap();
    let mut launch_spec = LaunchSpec::new(IsolationLevel::Gui, &rootfs, "/usr/bin/app");
    launch_spec.gui = Some(spec);
    let table = libextos::container::MountPlan::for_level(
        IsolationLevel::Gui,
        &libextos::container::HostPaths::from_env(),
        4096,
    );
    assert!(table.mounts_proc());
}

// ─── 4.4.6: privileged guard ───────────────────────────────────

#[test]
fn privileged_launch_requires_explicit_opt_in() {
    let Some(fixture) = Fixture::build(r#"{ level = "privileged"; }"#) else {
        eprintln!("skip: no static cc toolchain available");
        return;
    };
    let rootfs = fixture.rootfs("extos-priv");
    let spec = LaunchSpec::new(
        IsolationLevel::Privileged,
        &rootfs.stage,
        "/usr/bin/extos-probe",
    );
    let err = launch(&spec).unwrap_err();
    assert!(
        matches!(err, ContainerError::PrivilegedNotAllowed),
        "expected PrivilegedNotAllowed, got {err:?}"
    );

    // The guard is not an artefact of a missing rootfs: the same spec with the
    // opt-in passes validation and only fails later if the host refuses chroot.
    let allowed = spec.with_privileged(true);
    assert!(allowed.allow_privileged);
    assert_eq!(allowed.effective_root_mode(), RootMode::Direct);
    assert!(allowed.effective_namespaces().user, "chroot capability shim");
    match launch(&allowed) {
        Ok(outcome) => {
            eprintln!("privileged container ran: {}", outcome.text());
        }
        Err(err) => {
            // Unprivileged hosts get a typed setup failure — never a panic or a
            // silently unconfined process.
            eprintln!("privileged container refused by the host: {err}");
            assert!(
                matches!(
                    err,
                    ContainerError::Namespace { .. } | ContainerError::Rootfs(_)
                ),
                "unexpected error kind: {err:?}"
            );
        }
    }
}

// ─── 4.4.9: backend matrix ─────────────────────────────────────

#[test]
fn backend_matrix_and_probe_are_honest() {
    let probe = BackendProbe::discover();
    let report = probe.report();
    eprintln!("── container backend probe ──\n{report}─────────────────────────────");

    assert!(report.contains("native user namespaces:"));
    assert!(report.contains("systemd-nsresourced:"));
    assert_eq!(report.contains("systemd-nsresourced: yes"), probe.nsresourced);
    // The absent list must name every backend whose binary is not on PATH.
    if probe.nspawn.is_none() {
        assert!(probe.absent.contains(&"nspawn"));
    }
    if probe.crun.is_none() {
        assert!(probe.absent.contains(&"crun"));
    }

    // Combination guards are typed and mention both sides.
    let nspawn = Backend::Nspawn("systemd-nspawn".into());
    let err = nspawn.supports(IsolationLevel::Privileged).unwrap_err();
    assert!(err.to_string().contains("nspawn"));
    assert!(err.to_string().contains("privileged"));

    let runc = Backend::Runc("runc".into());
    assert!(runc.supports(IsolationLevel::Gui).is_ok());
    assert!(runc.supports(IsolationLevel::Privileged).is_err());

    let chroot = Backend::Chroot("chroot".into());
    assert!(chroot.supports(IsolationLevel::Cli).is_err());
    assert!(chroot.supports(IsolationLevel::Privileged).is_ok());

    assert_eq!(Backend::from_env().unwrap_or(Backend::Native), Backend::Native);
}

#[test]
fn typed_failure_matrix() {
    // 1. Missing rootfs.
    let spec = LaunchSpec::new(IsolationLevel::Cli, "/definitely/not/a/rootfs", "/bin/sh");
    assert!(matches!(launch(&spec).unwrap_err(), ContainerError::Rootfs(_)));

    // 2. Missing program inside an existing rootfs.
    let tmp = tempfile::tempdir().unwrap();
    fs::create_dir_all(tmp.path().join("usr/bin")).unwrap();
    let spec = LaunchSpec::new(IsolationLevel::Cli, tmp.path(), "/usr/bin/absent");
    match launch(&spec).unwrap_err() {
        ContainerError::ProgramNotFound(name) => assert!(name.contains("absent")),
        other => panic!("unexpected error: {other:?}"),
    }

    // 3. Unsupported level/backend combination.
    let spec = LaunchSpec::new(IsolationLevel::Networked, tmp.path(), "/usr/bin/absent")
        .with_backend(Backend::Chroot("chroot".into()));
    assert!(matches!(
        launch(&spec).unwrap_err(),
        ContainerError::UnsupportedLevel { .. }
    ));

    // 4. Numeric / textual level parsing round-trips.
    for level in IsolationLevel::ALL {
        assert_eq!(
            level.as_str().parse::<IsolationLevel>().unwrap(),
            level,
            "round-trip through the manifest spelling"
        );
        assert_eq!(
            level.as_u8().to_string().parse::<IsolationLevel>().unwrap(),
            level
        );
    }
}

#[test]
fn child_setup_failure_is_a_typed_namespace_error() {
    if euid() == 0 {
        eprintln!("skip: running as root, unshare(CLONE_NEWNS) would succeed");
        return;
    }
    if !userns_available() {
        eprintln!("skip: unprivileged user namespaces are unavailable on this host");
        return;
    }
    let Some(fixture) = Fixture::build(r#"{ level = "cli"; }"#) else {
        eprintln!("skip: no static cc toolchain available");
        return;
    };
    let rootfs = fixture.rootfs("extos-fail");

    // A mount namespace without a user namespace cannot be created unprivileged:
    // the child reports `unshare` and exits 120, the parent turns that into a
    // typed error instead of a mysterious exit status.
    let mut spec = LaunchSpec::new(IsolationLevel::Cli, &rootfs.stage, "/usr/bin/extos-probe");
    spec.namespaces = libextos::manifest::NamespaceToggles {
        user: false,
        mount: true,
        pid: false,
        ipc: false,
        uts: false,
        net: false,
        cgroup: false,
    };
    let err = launch(&spec).unwrap_err();
    match err {
        ContainerError::Namespace { op, message } => {
            assert_eq!(op, "unshare");
            assert!(!message.is_empty());
        }
        other => panic!("expected a typed namespace error, got {other:?}"),
    }
}

// ─── Env-gated real backend runs ───────────────────────────────

#[test]
fn real_backend_runs_when_env_gated() {
    let requested = std::env::var("EXTOS_TEST_CONTAINER_BACKEND").unwrap_or_default();
    if requested.is_empty() {
        eprintln!(
            "skip: set EXTOS_TEST_CONTAINER_BACKEND=nspawn|runc to exercise an external backend"
        );
        return;
    }
    let Some(fixture) = Fixture::build(r#"{ level = "cli"; }"#) else {
        eprintln!("skip: no static cc toolchain available");
        return;
    };
    let rootfs = fixture.rootfs("extos-ext");

    let backend = match Backend::from_name(requested.trim()) {
        Ok(backend) => backend,
        Err(err) => {
            eprintln!("skip: backend {requested:?} unavailable: {err}");
            return;
        }
    };
    if let Err(err) = backend.supports(IsolationLevel::Cli) {
        eprintln!("skip: {err}");
        return;
    }

    let spec = LaunchSpec::new(IsolationLevel::Cli, &rootfs.stage, "/usr/bin/extos-probe")
        .with_backend(backend);
    match launch(&spec) {
        Ok(outcome) => {
            eprintln!("── external backend output ──\n{}", outcome.text());
            assert!(outcome.success(), "external backend exit: {:?}", outcome.status);
            assert!(outcome.text().contains("sysname=Linux"));
        }
        Err(err) => {
            // Env-gated real runs are best effort: a host without delegated
            // cgroups or with a restricted kernel prints the reason and passes.
            eprintln!("external backend could not run on this host: {err}");
        }
    }
}

// ─── RootfsSpec sanity (no launch) ─────────────────────────────

#[test]
fn container_env_and_socket_defaults_are_explicit() {
    let env: BTreeMap<String, String> = BTreeMap::new();
    assert!(env.is_empty());
    let profile = ContainerPermissions::new(IsolationLevel::Networked);
    assert!(profile.allows(ContainerSocket::Wayland));
    assert!(!profile.namespaces.net);
    let spec = LaunchSpec::from_profile(&profile, "/tmp/rootfs", Some("/usr/bin/app"));
    assert_eq!(spec.sockets().len(), 3);
    assert!(spec.container_env().contains_key("XDG_RUNTIME_DIR"));
}
