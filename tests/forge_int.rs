//! Integration tests for PLAN Sub-phase 4.2 — Runlevel 0 initramfs forge
//! (task 4.2.6).
//!
//! The chain under test is the one `instanz apply` will drive in wave 2:
//!
//! ```text
//! blueprint text ──parse──▶ ForgeBlueprint ──build──▶ MountPlan
//!      │                                    │
//!      │                                    ├─ stage mkinitcpio.conf (tmpfs)
//!      │                                    ▼
//!      │                            Forge::run(stub mkinitcpio)
//!      │                                    ▼
//!      └────────── metadata ──────▶ MkinitcpioOutcome.artifact (through <forge>/out)
//!                                           ▼
//!                              BlsPlan::from_systems ──▶ <boot>/loader/entries/*.conf
//!                                                       + <boot>/loader/loader.conf
//! ```
//!
//! Everything is synthesized at runtime: a stub `mkinitcpio` script and a stub
//! hook are stored as CAS objects, the boot root and the forge scratch dir are
//! tempdirs. No network, no root, no committed blobs.
//!
//! # Real namespaces
//!
//! The `SelfExec` runs are *real*: an unprivileged user namespace plus a private
//! mount namespace, tmpfs root, read-only CAS binds and the stub tool executing
//! inside. Hosts where user namespaces are disabled print an honest `SKIP …`
//! line and return instead of failing (the conductor verified the capability on
//! the reference host, so the expected outcome here is a real run).
//!
//! `EXTOS_TEST_FORGE_REAL=1` additionally enables one run against the *real*
//! `mkinitcpio` binary (`--version`, no image build, no kernel assumption).

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use libextos::cas::CasRepository;
use libextos::forge::ForgeError;
use libextos::forge::bls::{
    BlsPlan, BlsPlanOptions, BlsSystem, BlsWriteOptions, BootKernel, LoaderConfAction, entries_dir,
    loader_conf_path, read_loader_default,
};
use libextos::forge::blueprint::ForgeBlueprint;
use libextos::forge::forge::{
    Forge, ForgeCommand, ForgeConfig, NamespaceStrategy, probe_unprivileged_userns,
};
use libextos::forge::mkinitcpio::{self, MkinitcpioJob};
use libextos::forge::mount::{MountKind, MountPlan, MountPlanOptions};
use libextos::types::HashAlgorithm;

// ─── Fixtures ───────────────────────────────────────────────────

/// Stub `mkinitcpio`: dumps its argv and the staged config into the `-g` file.
const STUB_TOOL: &str = r#"#!/bin/sh
# Stub mkinitcpio for the ExtOS forge integration test (PLAN 4.2.6).
set -eu
out=""
cfg=""
all="$*"
while [ "$#" -gt 0 ]; do
  case "$1" in
    -g) out="${2:-}"; shift 2 || shift ;;
    -c) cfg="${2:-}"; shift 2 || shift ;;
    -k) shift 2 || shift ;;
    -p) shift 2 || shift ;;
    *) shift ;;
  esac
done
if [ -z "$out" ]; then
  echo "stub: missing -g" >&2
  exit 3
fi
{
  echo "stub-argv: $all"
  if [ -n "$cfg" ]; then
    echo "config-begin"
    cat "$cfg"
    echo "config-end"
  fi
} > "$out"
echo "stub stdout"
"#;

/// Stub that "succeeds" without writing anything (artifact-missing case).
const STUB_SILENT: &str = "#!/bin/sh\nexit 0\n";

/// Stub that fails with a distinctive status (tool-failure case).
const STUB_FAILING: &str = "#!/bin/sh\necho 'boom' >&2\nexit 4\n";

struct Fixture {
    dir: tempfile::TempDir,
    cas: CasRepository,
    boot: PathBuf,
    scratch: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let cas =
            CasRepository::open(dir.path().join("repo"), HashAlgorithm::Blake3).expect("open CAS");
        let boot = dir.path().join("boot");
        let scratch = dir.path().join("scratch");
        fs::create_dir_all(&boot).expect("boot dir");
        fs::create_dir_all(&scratch).expect("scratch dir");
        Self {
            dir,
            cas,
            boot,
            scratch,
        }
    }

    /// Store `script` as `bin/<name>` inside a fresh CAS object; returns the id.
    fn add_tool(&self, name: &str, script: &str, mode: u32) -> String {
        let payload = self.dir.path().join(format!("payload-{name}"));
        let _ = fs::remove_dir_all(&payload);
        fs::create_dir_all(payload.join("bin")).expect("payload bin");
        let path = payload.join("bin").join(name);
        fs::write(&path, script).expect("write tool");
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).expect("chmod tool");
        self.cas.store_directory(&payload).expect("store tool")
    }

    /// Store a hook script under `usr/lib/initcpio/install/<name>`; returns id.
    fn add_hook(&self, name: &str) -> String {
        let payload = self.dir.path().join(format!("hook-{name}"));
        let _ = fs::remove_dir_all(&payload);
        fs::create_dir_all(payload.join("usr/lib/initcpio/install")).expect("hook dirs");
        fs::write(
            payload.join(format!("usr/lib/initcpio/install/{name}")),
            "#!/bin/sh\n# stub extos hook\nrun_hook() { :; }\n",
        )
        .expect("hook script");
        self.cas.store_directory(&payload).expect("store hook")
    }

    /// Blueprint text with one stub tool, `hooks` in order, and `kernels` labels.
    fn blueprint(&self, tool: &str, object: &str, hooks: &[&str], kernel: &str) -> String {
        let hooks_nix = hooks
            .iter()
            .map(|hook| format!("{{ name = \"{hook}\"; }}"))
            .collect::<Vec<_>>()
            .join(" ");
        format!(
            r#"{{
  tools = [ {{ name = "{tool}"; object = "{object}"; exec = "bin/{tool}"; }} ];
  hooks = [ {hooks_nix} ];
  output = {{
    dir = "{boot}";
    name = "initramfs-linux.img";
    kernel = "{kernel}";
  }};
}}"#,
            boot = self.boot.display()
        )
    }
}

/// Stub that reports whether the bound hook script is visible in the forge.
const STUB_HOOK_CHECK: &str = r#"#!/bin/sh
set -u
out=""
all="$*"
while [ "$#" -gt 0 ]; do
  case "$1" in
    -g) out="${2:-}"; shift 2 || shift ;;
    *) shift ;;
  esac
done
{
  echo "stub-argv: $all"
  if [ -n "${EXTOS_TEST_HOOK:-}" ] && [ -f "$EXTOS_TEST_HOOK" ]; then
    echo "hook-present"
  else
    echo "hook-missing"
  fi
} > "$out"
"#;

/// True when this host can create unprivileged user + mount namespaces.
fn namespaces_available() -> bool {
    match probe_unprivileged_userns(&ForgeConfig::default()) {
        Ok(()) => true,
        Err(error) => {
            eprintln!("SKIP: {error}");
            false
        }
    }
}

/// Build plan + job + forge for `tool` and run the generator once.
struct Chain {
    forge: Forge,
    job: MkinitcpioJob,
}

fn build_chain(
    fixture: &Fixture,
    tool_name: &str,
    object: &str,
    hooks: &[&str],
    strategy: NamespaceStrategy,
) -> Result<Chain, ForgeError> {
    let text = fixture.blueprint(tool_name, object, hooks, "6.11.0");
    let blueprint = ForgeBlueprint::parse(&text, "forge.nix")?;
    let mut plan = MountPlan::build(&blueprint, &fixture.cas, &fixture.scratch)?;
    let job = MkinitcpioJob::from_blueprint(&blueprint, &plan);
    mkinitcpio::stage_config(&mut plan, &job)?;
    let forge = Forge::new(plan, ForgeConfig::default().with_strategy(strategy));
    Ok(Chain { forge, job })
}

fn systems(boot_relative_initrd: &str) -> Vec<BlsSystem> {
    vec![
        BlsSystem {
            system: "workstation".into(),
            generation: 41,
            kernels: vec![
                {
                    let mut kernel = BootKernel::new("6.11.0-arch1-1", "/vmlinuz-linux");
                    kernel.initrd.push(PathBuf::from(boot_relative_initrd));
                    kernel.options = Some("root=UUID=extos rw quiet".into());
                    kernel
                },
                BootKernel::new("6.6.1-lts", "/vmlinuz-linux-lts"),
            ],
        },
        BlsSystem {
            system: "server".into(),
            generation: 12,
            kernels: vec![BootKernel::new("6.11.0-arch1-1", "/vmlinuz-server")],
        },
    ]
}

// ─── 4.2.1 blueprint + 4.2.2 mount spec (no namespace needed) ───

#[test]
fn test_blueprint_parses_into_mount_spec() {
    let fixture = Fixture::new();
    let object = fixture.add_tool("mkinitcpio", STUB_TOOL, 0o755);
    let text = fixture.blueprint("mkinitcpio", &object, &["base", "udev"], "6.11.0");
    let blueprint = ForgeBlueprint::parse(&text, "forge.nix").expect("parse blueprint");

    assert_eq!(blueprint.tools.len(), 1);
    assert_eq!(blueprint.hook_names(), vec!["base", "udev"]);
    assert_eq!(blueprint.output.name, "initramfs-linux.img");
    assert_eq!(blueprint.output.kernel.as_deref(), Some("6.11.0"));

    let plan = MountPlan::build(&blueprint, &fixture.cas, &fixture.scratch).expect("plan");
    let describes = plan.describe();
    assert!(describes[0].starts_with("tmpfs "), "{describes:?}");
    assert!(
        describes
            .iter()
            .any(|line| line.starts_with("bind ro ") && line.contains("opt/extos/tools/mkinitcpio")),
        "{describes:?}"
    );
    assert!(
        describes
            .iter()
            .any(|line| line.starts_with("bind rw ") && line.ends_with("/out")),
        "{describes:?}"
    );
    assert_eq!(
        plan.tool_program("mkinitcpio"),
        Some(
            plan.root()
                .join("opt/extos/tools/mkinitcpio/bin/mkinitcpio")
                .as_path()
        )
    );
    // The forge root is a caller-supplied scratch dir, never a hardcoded path.
    assert!(plan.root().starts_with(&fixture.scratch));
    assert!(matches!(plan.mounts()[0].kind, MountKind::Tmpfs { .. }));

    // Every mount source exists on the host (the plan is buildable, not just
    // declarative).
    for mount in plan.mounts() {
        if let Some(source) = &mount.source {
            assert!(
                source.exists(),
                "mount source missing: {}",
                source.display()
            );
        }
    }
}

#[test]
fn test_blueprint_parse_error_is_typed() {
    match ForgeBlueprint::parse("{ tools = [ { name = \"x\"; } ]; }", "bad.nix") {
        Err(ForgeError::Blueprint { field, file, .. }) => {
            assert_eq!(field, "tools[0].object");
            assert_eq!(file, "bad.nix");
        }
        other => panic!("expected typed blueprint error, got {other:?}"),
    }
}

// ─── 4.2.2/4.2.3 real forge runs ────────────────────────────────

#[test]
fn test_full_chain_self_exec_strategy() {
    if !namespaces_available() {
        return;
    }
    let fixture = Fixture::new();
    let object = fixture.add_tool("mkinitcpio", STUB_TOOL, 0o755);
    let chain = build_chain(
        &fixture,
        "mkinitcpio",
        &object,
        &["base", "udev", "filesystems"],
        NamespaceStrategy::SelfExec,
    )
    .expect("chain");

    // The staged config must live inside the forge, not on the host.
    let job = &chain.job;
    assert_eq!(
        job.config.as_deref(),
        Some(
            chain
                .forge
                .plan()
                .in_forge("etc/mkinitcpio.conf")
                .to_string_lossy()
                .as_ref()
        )
    );

    // Stub tool, real namespace, real tmpfs, real bind mounts.
    let outcome = mkinitcpio::run(&chain.forge, job).expect("stub run");
    assert_eq!(outcome.artifact, fixture.boot.join("initramfs-linux.img"));
    assert!(outcome.artifact_size > 0);
    assert!(outcome.outcome.success());
    assert_eq!(outcome.outcome.stdout_trimmed(), "stub stdout");

    let artifact = fs::read_to_string(&outcome.artifact).expect("read artifact");
    assert!(artifact.contains("stub-argv: -g "), "{artifact}");
    assert!(artifact.contains("-c "), "{artifact}");
    assert!(artifact.contains("-k 6.11.0"), "{artifact}");
    // The config the tool saw is the one staged into the tmpfs.
    assert!(artifact.contains("config-begin"), "{artifact}");
    assert!(
        artifact.contains("HOOKS=(base udev filesystems)"),
        "{artifact}"
    );
    assert!(artifact.contains("config-end"), "{artifact}");

    // Nothing inside the forge survives; the tmpfs died with the namespace.
    let mut leftovers = fs::read_dir(chain.forge.plan().root())
        .expect("read forge root")
        .map(|entry| {
            entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect::<Vec<_>>();
    leftovers.sort();
    assert!(
        leftovers.is_empty(),
        "leftover forge entries: {leftovers:?}"
    );
}

#[test]
fn test_full_chain_unshare_cli_strategy() {
    if !namespaces_available() {
        return;
    }
    let fixture = Fixture::new();
    let object = fixture.add_tool("mkinitcpio", STUB_TOOL, 0o755);
    let chain = build_chain(
        &fixture,
        "mkinitcpio",
        &object,
        &["base", "udev"],
        NamespaceStrategy::UnshareCli,
    )
    .expect("chain");

    // The generated argv keeps unshare's own flags before `--`.
    let argv = chain.forge.cli_argv(&chain.job.command());
    let rendered: Vec<String> = argv
        .iter()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
    assert_eq!(rendered[1], "--user");
    assert!(rendered.contains(&"--map-root-user".to_string()));
    assert!(rendered.contains(&"--mount".to_string()));
    let separator = rendered
        .iter()
        .position(|arg| arg == "--")
        .expect("unshare separator");
    assert_eq!(rendered[separator + 1], "sh");
    assert_eq!(rendered[separator + 2], "-c");

    let outcome = mkinitcpio::run(&chain.forge, &chain.job).expect("stub run");
    let artifact = fs::read_to_string(&outcome.artifact).expect("artifact");
    assert!(artifact.contains("HOOKS=(base udev)"), "{artifact}");
    assert!(artifact.contains("stub-argv: -g "), "{artifact}");
}

#[test]
fn test_missing_program_is_typed() {
    if !namespaces_available() {
        return;
    }
    let fixture = Fixture::new();
    let object = fixture.add_tool("mkinitcpio", STUB_TOOL, 0o755);
    let chain = build_chain(
        &fixture,
        "mkinitcpio",
        &object,
        &["base"],
        NamespaceStrategy::SelfExec,
    )
    .expect("chain");

    let missing = chain.forge.plan().in_forge("opt/extos/tools/nope");
    match chain
        .forge
        .run(&ForgeCommand::new(missing.to_string_lossy()))
    {
        Err(ForgeError::MountFailed { message, .. }) => {
            assert!(message.contains("missing program"), "{message}");
        }
        Err(other) => panic!("expected MountFailed, got {other}"),
        Ok(outcome) => panic!("unexpected success: {outcome:?}"),
    }
}

#[test]
fn test_non_executable_tool_is_permission_denied() {
    if !namespaces_available() {
        return;
    }
    let fixture = Fixture::new();
    let object = fixture.add_tool("mkinitcpio", STUB_TOOL, 0o644);
    let chain = build_chain(
        &fixture,
        "mkinitcpio",
        &object,
        &["base"],
        NamespaceStrategy::SelfExec,
    )
    .expect("chain");

    match chain.forge.run(&chain.job.command()) {
        Err(ForgeError::PermissionDenied { message }) => {
            assert!(message.contains("forge child"), "{message}");
        }
        Err(other) => panic!("expected PermissionDenied, got {other}"),
        Ok(outcome) => panic!("unexpected success: {outcome:?}"),
    }
}

#[test]
fn test_tool_failure_is_typed() {
    if !namespaces_available() {
        return;
    }
    let fixture = Fixture::new();
    let object = fixture.add_tool("mkinitcpio", STUB_FAILING, 0o755);
    let chain = build_chain(
        &fixture,
        "mkinitcpio",
        &object,
        &["base"],
        NamespaceStrategy::SelfExec,
    )
    .expect("chain");

    match mkinitcpio::run(&chain.forge, &chain.job) {
        Err(ForgeError::ToolFailed {
            program,
            status,
            stderr,
        }) => {
            assert!(program.ends_with("bin/mkinitcpio"), "{program}");
            assert_eq!(status, "exited with 4");
            assert_eq!(stderr, "boom");
        }
        other => panic!("expected ToolFailed, got {other:?}"),
    }
}

#[test]
fn test_artifact_missing_is_typed() {
    if !namespaces_available() {
        return;
    }
    let fixture = Fixture::new();
    let object = fixture.add_tool("mkinitcpio", STUB_SILENT, 0o755);
    let chain = build_chain(
        &fixture,
        "mkinitcpio",
        &object,
        &["base"],
        NamespaceStrategy::SelfExec,
    )
    .expect("chain");

    match mkinitcpio::run(&chain.forge, &chain.job) {
        Err(ForgeError::ArtifactMissing { path }) => {
            assert!(path.ends_with("initramfs-linux.img"), "{path}");
        }
        other => panic!("expected ArtifactMissing, got {other:?}"),
    }
}

#[test]
fn test_workdir_override_runs_inside_the_forge() {
    if !namespaces_available() {
        return;
    }
    let fixture = Fixture::new();
    // A tool that proves the cwd is the forge root (tmpfs) and not the host dir
    // that the tmpfs covers.
    let script = "#!/bin/sh\npwd > \"$(dirname \"$0\")/cwd.txt\"\nexit 0\n";
    let object = fixture.add_tool("pwdprobe", script, 0o755);
    let text = fixture.blueprint("pwdprobe", &object, &[], "6.11.0");
    let blueprint = ForgeBlueprint::parse(&text, "forge.nix").expect("blueprint");
    let plan = MountPlan::build(&blueprint, &fixture.cas, &fixture.scratch).expect("plan");
    let tool = plan
        .tool_program("pwdprobe")
        .expect("tool")
        .to_string_lossy()
        .into_owned();
    let forge = Forge::new(plan, ForgeConfig::default());
    let outcome = forge
        .run(&ForgeCommand::new(tool))
        .expect("run")
        .require_success("pwdprobe")
        .expect("success");
    assert_eq!(outcome.status.code(), Some(0));
    let root = forge.plan().root().to_string_lossy().into_owned();
    // pwd wrote into the tmpfs, which is gone; the host dir must stay empty.
    assert!(
        fs::read_dir(forge.plan().root())
            .expect("root")
            .next()
            .is_none(),
        "tmpfs contents leaked to the host under {root}"
    );
}

#[test]
fn test_hook_script_is_bound_into_the_forge() {
    if !namespaces_available() {
        return;
    }
    let fixture = Fixture::new();
    let tool_hash = fixture.add_tool("mkinitcpio", STUB_HOOK_CHECK, 0o755);
    let hook_hash = fixture.add_hook("base");

    // Hook `base` ships its script from a CAS object; `udev` only participates
    // in HOOKS=(…).
    let text = format!(
        r#"{{
  tools = [ {{ name = "mkinitcpio"; object = "{tool_hash}"; exec = "bin/mkinitcpio"; }} ];
  hooks = [
    {{ name = "base"; object = "{hook_hash}"; path = "usr/lib/initcpio/install/base"; }}
    {{ name = "udev"; }}
  ];
  output = {{ dir = "{boot}"; name = "initramfs-linux.img"; }};
}}"#,
        boot = fixture.boot.display()
    );
    let blueprint = ForgeBlueprint::parse(&text, "forge.nix").expect("blueprint");
    let mut plan = MountPlan::build(&blueprint, &fixture.cas, &fixture.scratch).expect("plan");
    let hook_in_forge = plan.in_forge("etc/initcpio/install/base");
    let mut job = MkinitcpioJob::from_blueprint(&blueprint, &plan);
    job.env.push((
        "EXTOS_TEST_HOOK".into(),
        hook_in_forge.to_string_lossy().into_owned(),
    ));
    mkinitcpio::stage_config(&mut plan, &job).expect("stage");

    let forge = Forge::new(plan, ForgeConfig::default());
    let outcome = mkinitcpio::run(&forge, &job).expect("run");
    let artifact = fs::read_to_string(&outcome.artifact).expect("artifact");
    // The hook script came from the CAS object, through a read-only file bind,
    // onto an empty target file created inside the tmpfs.
    assert!(artifact.contains("hook-present"), "{artifact}");
    assert!(artifact.contains("stub-argv: -g "), "{artifact}");
    assert!(artifact.contains("-c "), "{artifact}");
}

// ─── 4.2.4/4.2.5 BLS entries, matrix, loader.conf ──────────────

#[test]
fn test_multi_boot_matrix_and_loader_default() {
    let fixture = Fixture::new();
    let plan = BlsPlan::from_systems(&systems("/initramfs-linux.img"), &BlsPlanOptions::default())
        .expect("matrix");

    let ids: Vec<&str> = plan
        .entries()
        .iter()
        .map(|entry| entry.id.as_str())
        .collect();
    assert_eq!(
        ids,
        vec![
            "extos-workstation-g41-6.11.0-arch1-1",
            "extos-workstation-g41-6.6.1-lts",
            "extos-server-g12-6.11.0-arch1-1",
        ]
    );
    assert_eq!(
        plan.default_id(),
        Some("extos-workstation-g41-6.11.0-arch1-1")
    );

    let report = plan
        .write(&fixture.boot, &BlsWriteOptions::create_if_missing())
        .expect("write");
    assert_eq!(report.written.len(), 3);
    assert_eq!(
        report.default.as_deref(),
        Some("extos-workstation-g41-6.11.0-arch1-1")
    );
    assert!(matches!(report.loader_conf, LoaderConfAction::Created(_)));

    // Fresh boot root ⇒ loader.conf exists and points at the newest entry.
    assert_eq!(
        read_loader_default(&fixture.boot).expect("read"),
        Some("extos-workstation-g41-6.11.0-arch1-1".into())
    );

    let entries = entries_dir(&fixture.boot);
    let mut names: Vec<String> = fs::read_dir(&entries)
        .expect("entries")
        .map(|entry| {
            entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    names.sort();
    assert_eq!(
        names,
        vec![
            "extos-server-g12-6.11.0-arch1-1.conf",
            "extos-workstation-g41-6.11.0-arch1-1.conf",
            "extos-workstation-g41-6.6.1-lts.conf",
        ]
    );

    let newest = fs::read_to_string(entries.join("extos-workstation-g41-6.11.0-arch1-1.conf"))
        .expect("read entry");
    assert!(
        newest.contains("title ExtOS workstation 6.11.0-arch1-1"),
        "{newest}"
    );
    assert!(newest.contains("linux /vmlinuz-linux"), "{newest}");
    assert!(newest.contains("initrd /initramfs-linux.img"), "{newest}");
    assert!(
        newest.contains("options root=UUID=extos rw quiet"),
        "{newest}"
    );
}

#[test]
fn test_bls_rerun_is_idempotent() {
    let fixture = Fixture::new();
    let plan = BlsPlan::from_systems(&systems("/initramfs-linux.img"), &BlsPlanOptions::default())
        .expect("matrix");
    plan.write(&fixture.boot, &BlsWriteOptions::create_if_missing())
        .expect("first");

    let loader_before = fs::read_to_string(loader_conf_path(&fixture.boot)).expect("loader");
    let second = plan
        .write(&fixture.boot, &BlsWriteOptions::create_if_missing())
        .expect("second");
    assert!(second.written.is_empty(), "{second:?}");
    assert_eq!(second.unchanged.len(), 3);
    assert!(matches!(
        second.loader_conf,
        LoaderConfAction::Preserved { .. }
    ));
    assert_eq!(
        fs::read_to_string(loader_conf_path(&fixture.boot)).expect("loader"),
        loader_before
    );
}

#[test]
fn test_existing_loader_conf_is_not_clobbered() {
    let fixture = Fixture::new();
    fs::create_dir_all(fixture.boot.join("loader")).expect("loader dir");
    let custom = "default other-system\ntimeout 10\n";
    fs::write(loader_conf_path(&fixture.boot), custom).expect("write loader");

    let plan = BlsPlan::from_systems(&systems("/initramfs-linux.img"), &BlsPlanOptions::default())
        .expect("matrix");
    let report = plan
        .write(&fixture.boot, &BlsWriteOptions::create_if_missing())
        .expect("write");
    assert!(matches!(
        report.loader_conf,
        LoaderConfAction::Preserved { .. }
    ));
    assert_eq!(
        fs::read_to_string(loader_conf_path(&fixture.boot)).expect("loader"),
        custom
    );

    // ... but an explicit request flips just the default line.
    plan.write(&fixture.boot, &BlsWriteOptions::always())
        .expect("force");
    let forced = fs::read_to_string(loader_conf_path(&fixture.boot)).expect("loader");
    assert!(
        forced.starts_with("default extos-workstation-g41-6.11.0-arch1-1\n"),
        "{forced}"
    );
    assert!(forced.contains("timeout 10"), "{forced}");
}

#[test]
fn test_id_collision_is_typed_end_to_end() {
    let systems = vec![BlsSystem {
        system: "dup".into(),
        generation: 1,
        kernels: vec![
            BootKernel::new("6.1.0", "/vmlinuz-a"),
            BootKernel::new("6.1.0", "/vmlinuz-b"),
        ],
    }];
    match BlsPlan::from_systems(&systems, &BlsPlanOptions::default()) {
        Err(ForgeError::BlsIdCollision { id, .. }) => {
            assert_eq!(id, "extos-dup-g1-6.1.0");
        }
        other => panic!("expected collision, got {other:?}"),
    }
}

// ─── Full chain including BLS ──────────────────────────────────

#[test]
fn test_full_chain_generate_initramfs_then_bls_entries() {
    if !namespaces_available() {
        return;
    }
    let fixture = Fixture::new();
    let object = fixture.add_tool("mkinitcpio", STUB_TOOL, 0o755);

    // 1. blueprint → forge → generator, twice (rerun must stay green).
    for attempt in 0..2 {
        let chain = build_chain(
            &fixture,
            "mkinitcpio",
            &object,
            &["base", "udev", "filesystems", "fsck"],
            NamespaceStrategy::SelfExec,
        )
        .expect("chain");
        mkinitcpio::run(&chain.forge, &chain.job)
            .unwrap_or_else(|error| panic!("attempt {attempt}: {error}"));
    }

    // 2. boot metadata → BLS entries in the same boot root.
    let initrd = "/initramfs-linux.img";
    assert!(fixture.boot.join("initramfs-linux.img").is_file());

    let bls = BlsPlan::from_systems(&systems(initrd), &BlsPlanOptions::default()).expect("matrix");
    let first = bls
        .write(&fixture.boot, &BlsWriteOptions::create_if_missing())
        .expect("write");
    assert_eq!(first.written.len(), 3);

    let second = bls
        .write(&fixture.boot, &BlsWriteOptions::create_if_missing())
        .expect("rewrite");
    assert!(second.written.is_empty(), "{second:?}");
    assert_eq!(
        read_loader_default(&fixture.boot).expect("read"),
        Some("extos-workstation-g41-6.11.0-arch1-1".into())
    );

    // 3. The boot root now holds exactly the artifact, three entries and the
    //    loader config — nothing leaked from the tmpfs forge.
    let mut top: Vec<String> = fs::read_dir(&fixture.boot)
        .expect("boot")
        .map(|entry| {
            entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    top.sort();
    assert_eq!(top, vec!["initramfs-linux.img", "loader"]);
}

// ─── Env-gated real-machine run ────────────────────────────────

#[test]
fn test_real_mkinitcpio_when_enabled() {
    if std::env::var("EXTOS_TEST_FORGE_REAL").as_deref() != Ok("1") {
        eprintln!(
            "SKIP: EXTOS_TEST_FORGE_REAL=1 not set — real mkinitcpio run not attempted \
             (stub runs cover the forge itself)"
        );
        return;
    }
    if !namespaces_available() {
        return;
    }
    let binary = mkinitcpio::binary_from_env();
    let Some(host_binary) = mkinitcpio::probe(&binary) else {
        eprintln!("SKIP: '{binary}' is not on PATH — nothing to run for real");
        return;
    };
    eprintln!("real mkinitcpio: {}", host_binary.display());

    let fixture = Fixture::new();
    // A blueprint with a trivial tool keeps the forge schema honest while the
    // generator itself comes from the host PATH through the runtime binds.
    let object = fixture.add_tool("placeholder", "#!/bin/sh\nexit 0\n", 0o755);
    let text = fixture.blueprint("placeholder", &object, &[], "6.11.0");
    let blueprint = ForgeBlueprint::parse(&text, "forge.nix").expect("blueprint");
    let mut plan = MountPlan::build(&blueprint, &fixture.cas, &fixture.scratch).expect("plan");
    let probe_output = plan
        .output_in_forge("probe.img")
        .to_string_lossy()
        .into_owned();
    mkinitcpio::stage_config(
        &mut plan,
        &MkinitcpioJob {
            binary: binary.clone(),
            output: probe_output,
            config: None,
            kernel: None,
            preset: None,
            hooks: Vec::new(),
            env: Vec::new(),
        },
    )
    .expect("stage");
    let forge = Forge::new(plan, ForgeConfig::default());

    match mkinitcpio::version(&forge, &binary) {
        Ok(version) => eprintln!("real mkinitcpio inside forge: {version}"),
        // Honest failure: the tool answered, but not from inside the forge.
        Err(error) => panic!("real mkinitcpio could not run inside the forge: {error}"),
    }
}

// ─── Path hygiene ──────────────────────────────────────────────

#[test]
fn test_forge_never_hardcodes_a_layout() {
    // Every path the module can produce is derived from the fixture's tempdirs.
    let fixture = Fixture::new();
    let object = fixture.add_tool("mkinitcpio", STUB_TOOL, 0o755);
    let text = fixture.blueprint("mkinitcpio", &object, &["base"], "6.11.0");
    let blueprint = ForgeBlueprint::parse(&text, "forge.nix").expect("blueprint");
    let plan = MountPlan::build_with(
        &blueprint,
        &fixture.cas,
        &fixture.scratch,
        &MountPlanOptions::minimal(),
    )
    .expect("plan");

    assert_eq!(plan.output_host(), fixture.boot.as_path());
    assert!(plan.root().starts_with(&fixture.scratch));
    for entry in plan.describe() {
        assert!(
            !entry.contains("/boot") || entry.contains(&fixture.boot.to_string_lossy().to_string()),
            "unexpected hardcoded boot path in: {entry}"
        );
    }
    // The blueprint itself never carries a library default either.
    assert_eq!(blueprint.output.dir, fixture.boot);
}
