//! End-to-end weaver tests for PLAN Sub-phase 2.4 (tasks 2.4.1 – 2.4.7).
//!
//! Fixtures are synthesized at test runtime: three tiny synthetic packages are
//! written into a tempdir, stored with `CasRepository::store_directory`, given a
//! hand-written `manifest.nix` and committed as refs. No archive, no network, no
//! root, and no committed blobs.
//!
//! Covered here:
//! * 2.4.1 `plan_from_refs` — DAG → toposort → VFS → plan, dependency order.
//! * 2.4.2 `execute_plan` — symlink / hardlink / reflink application + idempotency.
//! * 2.4.3 Tier-2 → Tier-3 collision escalation (execute order + alternatives).
//! * 2.4.4 `generate_wrapper` — self-locating `LD_LIBRARY_PATH`/`PATH` wrapper.
//! * 2.4.5 / 2.4.6 `run_ldconfig` / `run_depmod` — explicit, chroot-scoped tools.

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

use libextos::cas::CasRepository;
use libextos::error::ExtosError;
use libextos::types::HashAlgorithm;
use libextos::weaver::{
    execute_plan, generate_wrapper, plan_from_refs, plan_from_refs_with, run_depmod, run_ldconfig,
    CasRef, JournalAction, LinkStrategy, OriginPriority, PlanOp, WrapperAlternative, WrapperSpec,
};

// ─── Fixtures ───────────────────────────────────────────────────

/// A synthetic package: identity, payload files (`rel path → contents`) and an
/// optional `requires` fragment for the manifest.
struct Fixture<'a> {
    origin: &'a str,
    name: &'a str,
    version: &'a str,
    files: Vec<(&'a str, &'a str)>,
    requires: &'a str,
}

impl Fixture<'_> {
    fn manifest(&self) -> String {
        format!(
            r#"{{
  identity = {{
    origin = "{origin}";
    name = "{name}";
    version = "{version}";
  }};
  format = "extracted-tree";
  capabilities = {{ binaries = [ "{name}" ]; }};
  requires = [ {requires} ];
}}"#,
            origin = self.origin,
            name = self.name,
            version = self.version,
            requires = self.requires,
        )
    }
}

/// Materialize a fixture into `repo` and commit `refs/<origin>/<name>/<version>`.
///
/// Returns the object hash. The payload is written to a staging dir first so the
/// CAS hash is a pure function of the fixture contents.
fn publish(repo: &CasRepository, fixture: &Fixture<'_>, staging: &Path) -> String {
    let src = staging.join(format!("{}-{}", fixture.origin, fixture.name));
    for (rel, contents) in &fixture.files {
        let path = src.join(rel);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&path, contents).unwrap();
        // `fs::copy` (used by `store_directory`) preserves the mode, so marking
        // payload binaries executable here keeps them executable in the CAS.
        if rel.starts_with("usr/bin/") {
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        }
    }
    // `store_directory` requires the source to exist even for empty packages.
    fs::create_dir_all(&src).unwrap();

    let hash = repo.store_directory(&src).unwrap();
    repo.write_manifest(&hash, &fixture.manifest()).unwrap();
    repo.create_ref(fixture.origin, fixture.name, fixture.version, &hash)
        .unwrap();
    repo.update_current(fixture.origin, fixture.name, fixture.version)
        .unwrap();
    hash
}

/// Add an in-package symlink straight into the stored object.
///
/// `store_directory` copies by value (`fs::copy` follows links), so link fixtures
/// are injected afterwards. This mirrors what an extraction pipeline that
/// preserves links would have produced.
fn add_symlink(repo: &CasRepository, hash: &str, rel: &str, target: &str) {
    let path = repo.object_path(hash).join("content").join(rel);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    std::os::unix::fs::symlink(target, &path).unwrap();
}

fn open_repo(dir: &Path) -> CasRepository {
    CasRepository::open(dir, HashAlgorithm::Blake3).unwrap()
}

/// Three packages:
/// * `distro-a/alpha` — `usr/bin/tool` (content A), `usr/lib/libalpha.so{,.1}`,
///   `usr/lib/libshared.so.1` (A), `usr/bin/alpha-only`
/// * `distro-b/beta`  — `usr/bin/tool` (content B), `usr/lib/libbeta.so.1`,
///   `usr/lib/libshared.so.1` (B)
/// * `debian/gamma`   — `usr/bin/delta`, `usr/lib/libshared.so.1` (C), requires
///   `distro-a/alpha` exactly
///
/// `usr/bin/tool` is a same-priority (Tier 3) conflict between distro-a and
/// distro-b; `usr/lib/libshared.so.1` is a three-way conflict that debian wins on
/// origin priority (Tier 2).
struct World {
    _tmp: tempfile::TempDir,
    repo: CasRepository,
    refs: Vec<CasRef>,
    hashes: Vec<String>,
}

fn build_world() -> World {
    let tmp = tempfile::tempdir().unwrap();
    let repo = open_repo(&tmp.path().join("repository"));
    let staging = tmp.path().join("staging");
    fs::create_dir_all(&staging).unwrap();

    let alpha = Fixture {
        origin: "distro-a",
        name: "alpha",
        version: "1.0.0",
        files: vec![
            ("usr/bin/tool", "#!/bin/sh\necho A\n"),
            ("usr/bin/alpha-only", "#!/bin/sh\necho alpha\n"),
            ("usr/lib/libalpha.so.1", "ALPHA-SO-1"),
            ("usr/lib/libshared.so.1", "SHARED-FROM-A"),
        ],
        requires: "",
    };
    let beta = Fixture {
        origin: "distro-b",
        name: "beta",
        version: "1.0.0",
        files: vec![
            ("usr/bin/tool", "#!/bin/sh\necho B\n"),
            ("usr/lib/libbeta.so.1", "BETA-SO-1"),
            ("usr/lib/libshared.so.1", "SHARED-FROM-B"),
        ],
        requires: "",
    };
    let gamma = Fixture {
        origin: "debian",
        name: "gamma",
        version: "1.0.0",
        files: vec![
            ("usr/bin/delta", "#!/bin/sh\necho D\n"),
            ("usr/lib/libshared.so.1", "SHARED-FROM-G"),
        ],
        requires: r#"{ origin = "distro-a"; name = "alpha"; version = "1.0.0"; }"#,
    };

    let mut hashes = Vec::new();
    let mut refs = Vec::new();
    for fixture in [&alpha, &beta, &gamma] {
        hashes.push(publish(&repo, fixture, &staging));
        refs.push(CasRef::new(fixture.origin, fixture.name, fixture.version));
    }

    // alpha ships `usr/lib/libalpha.so -> libalpha.so.1`.
    add_symlink(&repo, &hashes[0], "usr/lib/libalpha.so", "libalpha.so.1");

    World {
        _tmp: tmp,
        repo,
        refs,
        hashes,
    }
}

fn is_file_op(op: &PlanOp) -> bool {
    matches!(op, PlanOp::Link { .. })
}

// ─── 2.4.1 Planning ─────────────────────────────────────────────

#[test]
fn plan_covers_all_providers_before_touching_disk() {
    let world = build_world();
    let plan = plan_from_refs(&world.repo, &world.refs).unwrap();

    assert_eq!(
        plan.providers(),
        vec!["debian/gamma", "distro-a/alpha", "distro-b/beta"]
    );
    assert!(plan.directory_ops() >= 2, "usr/bin and usr/lib must be planned");
    assert!(plan.file_ops() > 0);

    // The shipped symlink is carried as a symlink op, target verbatim.
    let link = plan
        .entries()
        .iter()
        .find(|e| e.rel_path() == Path::new("usr/lib/libalpha.so"))
        .expect("libalpha.so planned");
    match &link.op {
        PlanOp::Symlink { target, .. } => assert_eq!(target, &PathBuf::from("libalpha.so.1")),
        other => panic!("expected Symlink, got {other:?}"),
    }

    // `usr/bin/alpha-only` is a plain file op with the planned strategy.
    let file = plan
        .entries()
        .iter()
        .find(|e| e.rel_path() == Path::new("usr/bin/alpha-only"))
        .expect("alpha-only planned");
    match &file.op {
        PlanOp::Link { strategy, source, .. } => {
            assert_eq!(*strategy, LinkStrategy::Symlink);
            assert!(source.is_file(), "CAS payload must exist: {}", source.display());
        }
        other => panic!("expected Link, got {other:?}"),
    }
}

#[test]
fn plan_respects_dependency_order() {
    let world = build_world();
    let plan = plan_from_refs(&world.repo, &world.refs).unwrap();

    let position = |needle: &str| {
        plan.entries()
            .iter()
            .position(|e| e.rel_path() == Path::new(needle))
            .unwrap_or_else(|| panic!("{needle} missing from plan"))
    };
    // gamma requires alpha → alpha's payload must be emitted first.
    assert!(position("usr/bin/alpha-only") < position("usr/bin/delta"));
}

#[test]
fn unresolved_ref_is_a_hard_error() {
    let world = build_world();
    let err = plan_from_refs(
        &world.repo,
        &[CasRef::new("distro-a", "does-not-exist", "1.0.0")],
    )
    .unwrap_err();
    assert!(matches!(err, ExtosError::PackageNotFound { .. }), "{err}");
}

#[test]
fn empty_ref_list_produces_an_empty_plan() {
    let world = build_world();
    let plan = plan_from_refs(&world.repo, &[]).unwrap();
    assert!(plan.is_empty());
}

// ─── 2.4.3 / 2.4.4 Collision escalation & wrappers ──────────────

#[test]
fn collision_escalates_to_tier3_and_priority_wins_otherwise() {
    let world = build_world();
    let plan = plan_from_refs(&world.repo, &world.refs).unwrap();

    assert_eq!(plan.collisions().len(), 2, "{:?}", plan.collisions());

    let tool = plan
        .collisions()
        .iter()
        .find(|c| c.path == Path::new("usr/bin/tool"))
        .expect("usr/bin/tool collision");
    match &tool.resolution {
        libextos::weaver::CollisionResolution::Tier3Wrapper { alternatives, .. } => {
            assert_eq!(
                alternatives,
                &vec!["distro-a-alpha".to_string(), "distro-b-beta".to_string()]
            );
        }
        other => panic!("expected Tier3Wrapper, got {other:?}"),
    }

    let shared = plan
        .collisions()
        .iter()
        .find(|c| c.path == Path::new("usr/lib/libshared.so.1"))
        .expect("libshared collision");
    match &shared.resolution {
        libextos::weaver::CollisionResolution::PriorityWin { winner, loser } => {
            assert_eq!(winner, "debian/gamma");
            assert!(loser.contains("distro-a/alpha"), "{loser}");
            assert!(loser.contains("distro-b/beta"), "{loser}");
        }
        other => panic!("expected PriorityWin, got {other:?}"),
    }

    // Tier 3 keeps both payloads under the alternatives tree…
    for slug in ["distro-a-alpha", "distro-b-beta"] {
        let rel = format!("usr/lib/extos/alternatives/{slug}/usr/bin/tool");
        let entry = plan
            .entries()
            .iter()
            .find(|e| e.rel_path() == Path::new(&rel))
            .unwrap_or_else(|| panic!("{rel} planned"));
        assert!(is_file_op(&entry.op), "{rel} must be a file op");
    }
    // …and installs exactly one dispatch wrapper at the contested path.
    assert_eq!(plan.wrapper_ops(), 1);
    let wrapper = plan
        .entries()
        .iter()
        .find(|e| e.rel_path() == Path::new("usr/bin/tool"))
        .expect("wrapper planned");
    assert_eq!(wrapper.provider, "extos/weaver");
    match &wrapper.op {
        PlanOp::Wrapper { script, .. } => {
            assert!(script.contains("EXTOS_ALT_TOOL"), "{script}");
            assert!(script.contains("distro-a-alpha"), "{script}");
        }
        other => panic!("expected Wrapper, got {other:?}"),
    }

    // The uncontested binary from the Tier-2 loser survives.
    assert!(plan
        .entries()
        .iter()
        .any(|e| e.rel_path() == Path::new("usr/bin/alpha-only")));
}

#[test]
fn generate_wrapper_is_self_locating_and_executable() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("roof");
    fs::create_dir_all(&root).unwrap();

    let spec = WrapperSpec::new("distro-a/alpha", "tool").with_alternatives(vec![
        WrapperAlternative::new(
            "distro-a/alpha",
            "distro-a-alpha",
            "usr/lib/extos/alternatives/distro-a-alpha/usr/bin/tool",
        ),
        WrapperAlternative::new(
            "distro-b/beta",
            "distro-b-beta",
            "usr/lib/extos/alternatives/distro-b-beta/usr/bin/tool",
        ),
    ])
    .with_lib_dirs(vec![PathBuf::from("opt/alpha/lib")]);

    let path = generate_wrapper(&spec, "libalpha.so.1", &root).unwrap();
    assert_eq!(path, root.join("usr/bin/tool"));

    let script = fs::read_to_string(&path).unwrap();
    assert!(script.contains("LD_LIBRARY_PATH="), "{script}");
    assert!(script.contains("PATH=\"$extos_root/usr/bin"), "{script}");
    assert!(script.contains("$extos_root/opt/alpha/lib"), "{script}");
    assert!(script.contains("libalpha.so.1"), "{script}");
    assert!(script.contains("#!/bin/sh"), "{script}");
    assert!(script.contains("exec "), "{script}");
    // Never bake host paths into a generated rootfs file.
    let root_str = root.to_string_lossy().to_string();
    assert!(!script.contains(&root_str), "absolute root leaked: {script}");
    assert!(!script.contains("/repository"), "{script}");

    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o755
    );
}

// ─── 2.4.2 Execution ────────────────────────────────────────────

#[test]
fn execute_plan_builds_a_coherent_roof() {
    let world = build_world();
    let plan = plan_from_refs(&world.repo, &world.refs).unwrap();
    let roof = world._tmp.path().join("roof");

    let run = execute_plan(&plan, &roof).unwrap();
    assert_eq!(run.files_linked, plan.file_ops());
    assert_eq!(run.symlinks_created, 1, "the only shipped link is libalpha.so");
    assert_eq!(run.wrappers_written, 1);

    // Plain files are symlinks into the CAS.
    let alpha_only = roof.join("usr/bin/alpha-only");
    assert!(alpha_only.symlink_metadata().unwrap().file_type().is_symlink());
    assert_eq!(fs::read_to_string(&alpha_only).unwrap(), "#!/bin/sh\necho alpha\n");

    // Shipped symlink is recreated verbatim and resolves inside the roof.
    let libalpha = roof.join("usr/lib/libalpha.so");
    assert_eq!(fs::read_link(&libalpha).unwrap(), PathBuf::from("libalpha.so.1"));
    assert_eq!(fs::read_to_string(&libalpha).unwrap(), "ALPHA-SO-1");

    // Tier-3: both real payloads survive, wrapper dispatches to the default one.
    assert_eq!(
        fs::read_to_string(roof.join(
            "usr/lib/extos/alternatives/distro-a-alpha/usr/bin/tool"
        ))
        .unwrap(),
        "#!/bin/sh\necho A\n"
    );
    assert_eq!(
        fs::read_to_string(roof.join(
            "usr/lib/extos/alternatives/distro-b-beta/usr/bin/tool"
        ))
        .unwrap(),
        "#!/bin/sh\necho B\n"
    );
    let wrapper = roof.join("usr/bin/tool");
    assert!(wrapper.is_file() && !wrapper.symlink_metadata().unwrap().file_type().is_symlink());
    assert_eq!(
        fs::metadata(&wrapper).unwrap().permissions().mode() & 0o777,
        0o755
    );
    let wrapper_body = fs::read_to_string(&wrapper).unwrap();
    assert!(wrapper_body.contains(":-distro-a-alpha"), "{wrapper_body}");

    // Tier-2 winner owns the contested library; the losers are gone.
    assert_eq!(
        fs::read_to_string(roof.join("usr/lib/libshared.so.1")).unwrap(),
        "SHARED-FROM-G"
    );

    // Journal is complete and ordered by operation.
    assert_eq!(run.journal.len(), plan.len());
    assert!(run
        .journal
        .iter()
        .any(|j| j.action == JournalAction::WrapperWritten));
}

#[test]
fn tier3_wrapper_dispatches_to_the_selected_alternative() {
    let world = build_world();
    let plan = plan_from_refs(&world.repo, &world.refs).unwrap();
    let roof = world._tmp.path().join("roof");
    execute_plan(&plan, &roof).unwrap();

    let run = |extra: Option<(&str, &str)>| {
        let mut cmd = Command::new(roof.join("usr/bin/tool"));
        if let Some((key, value)) = extra {
            cmd.env(key, value);
        }
        let output = cmd.output().expect("execute generated wrapper");
        assert!(
            output.status.success(),
            "wrapper failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).to_string()
    };

    // Default selection is the first alternative (distro-a/alpha).
    assert_eq!(run(None), "A\n");
    // The selector variable switches to the other claimant's real payload.
    assert_eq!(run(Some(("EXTOS_ALT_TOOL", "distro-b-beta"))), "B\n");
}

#[test]
fn execute_plan_is_idempotent() {
    let world = build_world();
    let plan = plan_from_refs(&world.repo, &world.refs).unwrap();
    let roof = world._tmp.path().join("roof");

    execute_plan(&plan, &roof).unwrap();
    let second = execute_plan(&plan, &roof).unwrap();

    assert_eq!(second.directories_created, 0);
    assert_eq!(second.files_linked, 0);
    assert_eq!(second.symlinks_created, 0);
    assert_eq!(second.wrappers_written, 0);
    assert_eq!(second.reused, plan.len() - plan.directory_ops());
    assert!(second
        .journal
        .iter()
        .all(|j| matches!(j.action, JournalAction::DirectoryCreated) || second.reused > 0));
}

#[test]
fn execute_plan_replaces_wrong_links() {
    let world = build_world();
    let plan = plan_from_refs(&world.repo, &world.refs).unwrap();
    let roof = world._tmp.path().join("roof");
    execute_plan(&plan, &roof).unwrap();

    // Corrupt an existing symlink and a wrapper, re-run, expect repair.
    fs::remove_file(roof.join("usr/lib/libalpha.so")).unwrap();
    std::os::unix::fs::symlink("somewhere-else.so", roof.join("usr/lib/libalpha.so")).unwrap();
    fs::write(roof.join("usr/bin/tool"), "stale wrapper").unwrap();

    let repaired = execute_plan(&plan, &roof).unwrap();
    assert_eq!(
        fs::read_link(roof.join("usr/lib/libalpha.so")).unwrap(),
        PathBuf::from("libalpha.so.1")
    );
    assert_eq!(repaired.wrappers_written, 1);
    assert!(fs::read_to_string(roof.join("usr/bin/tool"))
        .unwrap()
        .contains("EXTOS_ALT_TOOL"));
}

#[test]
fn hardlink_strategy_shares_the_cas_inode() {
    let world = build_world();
    let plan = plan_from_refs_with(
        &world.repo,
        &world.refs,
        LinkStrategy::Hardlink,
        &OriginPriority::new(),
    )
    .unwrap();
    let roof = world._tmp.path().join("roof-hardlink");

    let run = execute_plan(&plan, &roof).unwrap();
    assert!(run.files_linked > 0);

    let roof_file = fs::metadata(roof.join("usr/bin/alpha-only")).unwrap();
    let cas_file =
        fs::metadata(world.repo.object_path(&world.hashes[0]).join("content/usr/bin/alpha-only"))
            .unwrap();
    assert_eq!(roof_file.dev(), cas_file.dev());
    assert_eq!(roof_file.ino(), cas_file.ino());
    // Same filesystem ⇒ no fallback needed on a normal tempdir.
    assert_eq!(run.fallbacks, 0);
}

#[test]
fn reflink_strategy_falls_back_without_data_loss() {
    let world = build_world();
    let plan = plan_from_refs_with(
        &world.repo,
        &world.refs,
        LinkStrategy::Reflink,
        &OriginPriority::new(),
    )
    .unwrap();
    let roof = world._tmp.path().join("roof-reflink");

    let run = execute_plan(&plan, &roof).unwrap();
    assert!(run.files_linked > 0);

    let copied = roof.join("usr/bin/delta");
    // Whatever strategy won, the payload must be a readable regular file.
    assert!(!copied.symlink_metadata().unwrap().file_type().is_symlink());
    assert_eq!(fs::read_to_string(&copied).unwrap(), "#!/bin/sh\necho D\n");

    // Reflink on a non-CoW fs (tmpfs, ext4) legitimately falls back to hardlink.
    let effective = run
        .journal
        .iter()
        .find_map(|j| match j.action {
            JournalAction::FileLinked(strategy) => Some(strategy),
            _ => None,
        })
        .expect("at least one file linked");
    assert!(matches!(
        effective,
        LinkStrategy::Reflink | LinkStrategy::Hardlink | LinkStrategy::Symlink
    ));
}

// ─── 2.4.5 / 2.4.6 Post-weave tools ────────────────────────────

#[test]
fn ldconfig_is_scoped_to_the_roof_and_never_silent() {
    let world = build_world();
    let roof = world._tmp.path().join("roof");
    let plan = plan_from_refs(&world.repo, &world.refs).unwrap();
    execute_plan(&plan, &roof).unwrap();
    // A woven root always carries /etc; ldconfig writes its cache there.
    fs::create_dir_all(roof.join("etc")).unwrap();

    let available = Command::new("ldconfig").arg("-p").output().is_ok();
    match run_ldconfig(&roof) {
        Ok(outcome) => {
            assert_eq!(outcome.program, "ldconfig");
            assert_eq!(outcome.arguments[0], "-r");
            assert_eq!(outcome.arguments[1], roof.display().to_string());
            assert!(available, "reported success without an ldconfig on PATH");
            // Scoped: the host cache is untouched, the roof cache is our own.
            assert!(roof.join("etc/ld.so.cache").exists());
        }
        Err(err) => {
            // Either "not found" or a real tool failure — but always *named*,
            // never a silent success.
            let message = err.to_string();
            assert!(message.contains("ldconfig"), "{message}");
            assert!(matches!(err, ExtosError::Weave(_)), "{message}");
        }
    }
}

#[test]
fn ldconfig_rejects_a_missing_roof() {
    let tmp = tempfile::tempdir().unwrap();
    let err = run_ldconfig(&tmp.path().join("no-such-roof")).unwrap_err();
    assert!(err.to_string().contains("rootfs root"), "{err}");
}

#[test]
fn depmod_is_scoped_and_validates_the_kernel_version() {
    let world = build_world();
    let roof = world._tmp.path().join("roof");
    // `depmod -b <root>` looks under `<root>/lib/modules`, like a real rootfs.
    fs::create_dir_all(roof.join("lib/modules/6.8.2-extos")).unwrap();

    // Traversal in the kernel version must never reach the host.
    for bad in ["../../etc", "a/b", ""] {
        let err = run_depmod(&roof, bad).unwrap_err();
        assert!(
            matches!(err, ExtosError::Weave(_)),
            "{bad}: expected a weave error, got {err}"
        );
    }

    let available = Command::new("depmod").arg("--version").output().is_ok();
    match run_depmod(&roof, "6.8.2-extos") {
        Ok(outcome) => {
            assert_eq!(outcome.arguments[0], "-b");
            assert_eq!(outcome.arguments[1], roof.display().to_string());
            assert_eq!(outcome.arguments[2], "6.8.2-extos");
            assert!(available, "reported success without a depmod on PATH");
        }
        Err(err) => {
            let message = err.to_string();
            assert!(message.contains("depmod"), "{message}");
            assert!(matches!(err, ExtosError::Weave(_)), "{message}");
            let _ = available;
        }
    }
}
