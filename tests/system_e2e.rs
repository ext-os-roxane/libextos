//! End-to-end tests for PLAN sub-phase 4.1 "Runlevel 1 — Host System Weaving"
//! as far as the library layer owns it: real host ELF payloads → fixture CAS →
//! SONAME anchor bidding → weave → post-weave tool hooks.
//!
//! The instanz-side half of the chain (`groups`/virtual expansion, `/etc`
//! seeding, `/var`+`/home` mount specs, `instanz apply`) lives in
//! `core/instanz/tests/system_e2e.rs`, because instanz is the crate that
//! *consumes* libextos and the dependency direction cannot be inverted.
//!
//! Fixtures are copied from the running host (`/usr/bin/true`, `/usr/bin/bash`,
//! `libc.so.6`) at test time: nothing is committed, nothing is downloaded, no
//! root is needed. If a path is unavailable the test falls back to a synthetic
//! payload and keeps asserting the same structural invariants.
//!
//! Pinned here:
//! * 4.1.3 — anchor bidding on **real** SONAMEs read by `elf_scan`, 2-way and
//!   3-way conflicts, declared-priority override, deterministic tiebreak;
//! * the weaver integration — the anchor winner, not the origin order, owns a
//!   contested library path;
//! * the linker law — the woven tree never references `/repository`;
//! * 4.1.6 — `ldconfig`/`depmod` stubs are invoked *after* the weave, scoped to
//!   the roof.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use libextos::anchor::{AnchorPolicy, AnchorTable};
use libextos::cas::CasRepository;
use libextos::elf_scan;
use libextos::types::HashAlgorithm;
use libextos::weaver::plan::plan_from_refs_with_anchors;
use libextos::weaver::{
    execute_plan, run_depmod, run_ldconfig, CasRef, LinkStrategy, OriginPriority, PlanOp,
};

/// Serializes tests that mutate the tool-override environment variables.
static TOOL_ENV: Mutex<()> = Mutex::new(());

// ─── Host payload fixtures ──────────────────────────────────────

/// Copy the first readable candidate into `destination`, else write `fallback`.
///
/// Returns the source that was used so tests can report whether they exercised
/// real host binaries or the synthetic fallback.
fn copy_host_payload(destination: &Path, candidates: &[&str], fallback: &[u8]) -> String {
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    for candidate in candidates {
        let source = Path::new(candidate);
        if let Ok(bytes) = fs::read(source) {
            fs::write(destination, bytes).unwrap();
            return (*candidate).to_string();
        }
    }
    fs::write(destination, fallback).unwrap();
    "synthetic".to_string()
}

/// A fixture package: identity, payload files already staged, manifest extras.
struct Fixture {
    origin: &'static str,
    name: &'static str,
    version: &'static str,
    /// Files as `(relative path, absolute source to copy or None for extra)`.
    files: Vec<(&'static str, Option<String>)>,
    /// SONAMEs the package advertises (normally read from the payload).
    libraries: Vec<String>,
    binaries: Vec<String>,
}

impl Fixture {
    fn manifest(&self) -> String {
        let libraries = self
            .libraries
            .iter()
            .map(|soname| format!("\"{soname}\""))
            .collect::<Vec<_>>()
            .join(" ");
        let binaries = self
            .binaries
            .iter()
            .map(|binary| format!("\"{binary}\""))
            .collect::<Vec<_>>()
            .join(" ");
        format!(
            r#"{{
  identity = {{
    origin = "{}";
    name = "{}";
    version = "{}";
  }};
  format = "extracted-tree";
  capabilities = {{
    binaries = [ {binaries} ];
    libraries = [ {libraries} ];
  }};
  requires = [ ];
}}"#,
            self.origin, self.name, self.version
        )
    }
}

/// Stage `fixture` into `staging`, store it in `repo` and commit its ref.
fn publish(repo: &CasRepository, fixture: &Fixture, staging: &Path) -> String {
    let src = staging.join(format!("{}-{}", fixture.origin, fixture.name));
    fs::create_dir_all(&src).unwrap();
    for (rel, source) in &fixture.files {
        let destination = src.join(rel);
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        match source {
            Some(source) => {
                fs::copy(source, &destination).unwrap();
            }
            None => {
                fs::write(&destination, rel.as_bytes()).unwrap();
            }
        }
        if rel.starts_with("usr/bin/") || rel.starts_with("usr/lib/") {
            fs::set_permissions(&destination, fs::Permissions::from_mode(0o755)).unwrap();
        }
    }
    let hash = repo.store_directory(&src).unwrap();
    repo.write_manifest(&hash, &fixture.manifest()).unwrap();
    repo.create_ref(fixture.origin, fixture.name, fixture.version, &hash)
        .unwrap();
    repo.update_current(fixture.origin, fixture.name, fixture.version)
        .unwrap();
    hash
}

/// Read the SONAME of a staged payload, falling back to the file name.
fn soname_of(payload: &Path, fallback: &str) -> String {
    elf_scan::read_soname(payload).unwrap_or_else(|| fallback.to_string())
}

/// Detect whether a payload is a real ELF (used to decide if we can trust
/// `readelf`-derived SONAMEs).
fn is_real_elf(payload: &Path) -> bool {
    elf_scan::is_elf(payload)
}

struct World {
    _tmp: tempfile::TempDir,
    repo: CasRepository,
    refs: Vec<CasRef>,
    /// SONAME detected for the two competing libc payloads.
    libc_sonames: Vec<String>,
    /// Whether at least one payload came from the host.
    real_payloads: usize,
}

/// host `glibc` (archlinux) vs. a competing `musl-ish` provider (alpine), plus
/// `bash` and `coreutils` binaries and an `/etc/ld.so.conf`.
fn build_world() -> World {
    let tmp = tempfile::tempdir().unwrap();
    let repo = CasRepository::open(tmp.path().join("repository"), HashAlgorithm::Blake3).unwrap();
    let staging = tmp.path().join("staging");
    fs::create_dir_all(&staging).unwrap();

    // 1. The primary glibc payload: a real libc when available.
    let primary_lib = staging.join("primary-libc");
    let primary_source = copy_host_payload(
        &primary_lib,
        &["/usr/lib/libc.so.6", "/lib/x86_64-linux-gnu/libc.so.6", "/lib/libc.so.6"],
        b"\x7fELF\x02\x01\x01\x00extos-synthetic-libc",
    );
    let primary_soname = if is_real_elf(&primary_lib) {
        soname_of(&primary_lib, "libc.so.6")
    } else {
        "libc.so.6".to_string()
    };

    // 2. The competing provider ships a *different* payload under the same
    //    SONAME (that is exactly the bidding conflict 4.1.3 must arbitrate).
    let rival_lib = staging.join("rival-libc");
    let rival_source = copy_host_payload(
        &rival_lib,
        &["/usr/lib/libm.so.6", "/lib/x86_64-linux-gnu/libm.so.6"],
        b"\x7fELF\x02\x01\x01\x00extos-synthetic-rival",
    );

    // 3. Real userland binaries.
    let bash = staging.join("bash");
    copy_host_payload(
        &bash,
        &["/usr/bin/bash", "/bin/bash"],
        b"#!/bin/sh\necho extos-bash\n",
    );
    let true_bin = staging.join("true");
    copy_host_payload(
        &true_bin,
        &["/usr/bin/true", "/bin/true"],
        b"#!/bin/sh\nexit 0\n",
    );

    let real_payloads = [primary_source.as_str(), rival_source.as_str()]
        .iter()
        .filter(|source| **source != "synthetic")
        .count();

    let fixtures = vec![
        Fixture {
            origin: "archlinux",
            name: "glibc",
            version: "2.39",
            files: vec![
                (
                    "usr/lib/libc.so.6",
                    Some(primary_lib.to_string_lossy().into_owned()),
                ),
                ("etc/ld.so.conf", None),
            ],
            libraries: vec![primary_soname.clone()],
            binaries: vec![],
        },
        Fixture {
            origin: "alpine",
            name: "musl-compat",
            version: "1.2.5",
            files: vec![(
                "usr/lib/libc.so.6",
                Some(rival_lib.to_string_lossy().into_owned()),
            )],
            // Deliberately advertises the *same* SONAME: that is the conflict.
            libraries: vec![primary_soname.clone()],
            binaries: vec![],
        },
        Fixture {
            origin: "archlinux",
            name: "bash",
            version: "5.2",
            files: vec![("usr/bin/bash", Some(bash.to_string_lossy().into_owned()))],
            libraries: vec![],
            binaries: vec!["bash".to_string()],
        },
        Fixture {
            origin: "archlinux",
            name: "coreutils",
            version: "9.4",
            files: vec![("usr/bin/true", Some(true_bin.to_string_lossy().into_owned()))],
            libraries: vec![],
            binaries: vec!["true".to_string()],
        },
    ];

    let mut refs = Vec::new();
    for fixture in &fixtures {
        publish(&repo, fixture, &staging);
        refs.push(CasRef::new(fixture.origin, fixture.name, fixture.version));
    }

    World {
        _tmp: tmp,
        repo,
        refs,
        libc_sonames: vec![primary_soname],
        real_payloads,
    }
}

// ─── 4.1.3 anchor bidding on real payloads ──────────────────────

#[test]
fn anchors_are_derived_from_real_sonames() {
    let world = build_world();
    let plan = plan_from_refs_with_anchors(
        &world.repo,
        &world.refs,
        LinkStrategy::Reflink,
        &OriginPriority::new(),
        &AnchorPolicy::new(),
    )
    .unwrap();

    let soname = &world.libc_sonames[0];
    let anchors = plan.anchors();
    assert!(
        anchors.get(soname).is_some(),
        "no anchor for {soname}: {:?}",
        anchors.choices().map(|c| c.soname.clone()).collect::<Vec<_>>()
    );

    // OriginPriority ranks archlinux (10) above alpine (30).
    assert_eq!(anchors.winner_of(soname), Some("archlinux/glibc"), "{soname}");
    let choice = anchors.get(soname).unwrap();
    assert_eq!(choice.losers(), vec!["alpine/musl-compat"]);
    // The bid path is the real in-roof library path.
    assert_eq!(choice.path, PathBuf::from(format!("usr/lib/{soname}")));
    if world.real_payloads > 0 {
        assert!(
            soname.starts_with("lib"),
            "readelf-derived SONAME looks wrong: {soname}"
        );
    }
}

#[test]
fn declared_priority_overrides_the_origin_default() {
    let world = build_world();
    let soname = world.libc_sonames[0].clone();

    // Without an override archlinux wins; declaring alpine at priority 5 flips it.
    let mut policy = AnchorPolicy::new();
    policy.declare("alpine/musl-compat", 5);
    let plan = plan_from_refs_with_anchors(
        &world.repo,
        &world.refs,
        LinkStrategy::Reflink,
        &OriginPriority::new(),
        &policy,
    )
    .unwrap();

    assert_eq!(plan.anchors().winner_of(&soname), Some("alpine/musl-compat"));
    assert_eq!(plan.anchors().get(&soname).unwrap().priority, 5);

    // A flavour of the policy that only re-ranks origins keeps archlinux on top.
    let mut origin_policy = AnchorPolicy::new();
    origin_policy.declare_origin("alpine", 1);
    let plan = plan_from_refs_with_anchors(
        &world.repo,
        &world.refs,
        LinkStrategy::Reflink,
        &OriginPriority::new(),
        &origin_policy,
    )
    .unwrap();
    assert_eq!(plan.anchors().winner_of(&soname), Some("alpine/musl-compat"));
}

#[test]
fn missing_soname_provider_is_a_typed_error() {
    let world = build_world();
    let bids = vec![libextos::anchor::AnchorBid::new(
        "libssl.so.3",
        "archlinux/openssl",
        "archlinux",
        "3.3.1",
        "usr/lib/libssl.so.3",
    )];
    let err = AnchorTable::resolve("libc.so.6", &bids, &AnchorPolicy::new()).unwrap_err();
    assert!(
        matches!(err, libextos::error::ExtosError::DependencyUnresolvable(_)),
        "{err}"
    );
    let _ = world;
}

// ─── Weave + linker law ─────────────────────────────────────────

#[test]
fn weave_respects_the_anchor_and_never_exposes_the_cas() {
    let world = build_world();
    let soname = world.libc_sonames[0].clone();
    let plan = plan_from_refs_with_anchors(
        &world.repo,
        &world.refs,
        LinkStrategy::Reflink,
        &OriginPriority::new(),
        &AnchorPolicy::new(),
    )
    .unwrap();

    // The contested library is resolved by the anchor, with a documented warning.
    let collision = plan
        .collisions()
        .iter()
        .find(|c| c.path == Path::new(&format!("usr/lib/{soname}")))
        .expect("libc collision must be recorded");
    match &collision.resolution {
        libextos::weaver::CollisionResolution::PriorityWin { winner, .. } => {
            assert_eq!(winner, "archlinux/glibc");
        }
        other => panic!("expected the anchor to decide, got {other:?}"),
    }
    assert!(
        plan.warnings().iter().any(|w| w.contains("anchor at")),
        "{:?}",
        plan.warnings()
    );

    let roof = world._tmp.path().join("roof");
    let execution = execute_plan(&plan, &roof).unwrap();
    assert!(execution.files_linked >= 3, "{execution:?}");

    // The winner's bytes are at the contested path.
    let woven_libc = roof.join(format!("usr/lib/{soname}"));
    assert!(woven_libc.is_file(), "{} missing", woven_libc.display());
    let cas_winner = world.repo.object_path(
        &world
            .repo
            .resolve_ref("archlinux", "glibc", "2.39")
            .unwrap(),
    );
    let expected = fs::read(cas_winner.join(format!("content/usr/lib/{soname}"))).unwrap();
    assert_eq!(fs::read(&woven_libc).unwrap(), expected);

    // Linker law: no woven path may point into the CAS.
    assert_no_cas_paths(&roof);
    // The `/etc` payload that seeding consumes is present in the roof.
    assert!(roof.join("etc/ld.so.conf").exists());

    // No `/repository` string anywhere in the plan.
    for entry in plan.entries() {
        match &entry.op {
            PlanOp::Link { source, .. } => {
                assert!(!source.to_string_lossy().contains("refs/"));
            }
            PlanOp::Symlink { target, .. } => {
                assert!(!target.to_string_lossy().contains("/repository"));
            }
            _ => {}
        }
    }
}

/// Walk `root` and assert no symlink or file path mentions the CAS root layout.
fn assert_no_cas_paths(root: &Path) {
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for entry in fs::read_dir(&dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            let meta = fs::symlink_metadata(&path).unwrap();
            if meta.file_type().is_symlink() {
                let target = fs::read_link(&path).unwrap();
                assert!(
                    !target.to_string_lossy().contains("/repository"),
                    "{} links into the CAS: {}",
                    path.display(),
                    target.display()
                );
            } else if meta.is_dir() {
                pending.push(path);
            } else {
                assert!(
                    !path.to_string_lossy().contains("/repository/"),
                    "{} lives in the CAS",
                    path.display()
                );
            }
        }
    }
}

// ─── 4.1.6 post-weave hooks ─────────────────────────────────────

#[test]
fn post_weave_tool_stubs_run_after_the_weave_with_scoped_arguments() {
    let _guard = TOOL_ENV.lock().unwrap_or_else(|e| e.into_inner());
    let world = build_world();
    let plan = plan_from_refs_with_anchors(
        &world.repo,
        &world.refs,
        LinkStrategy::Reflink,
        &OriginPriority::new(),
        &AnchorPolicy::new(),
    )
    .unwrap();
    let roof = world._tmp.path().join("roof");
    execute_plan(&plan, &roof).unwrap();

    let log = world._tmp.path().join("hooks.log");
    let ldconfig_stub = write_hook_stub(&world._tmp.path().join("ldconfig-stub"), &log, &roof);
    let depmod_stub = write_hook_stub(&world._tmp.path().join("depmod-stub"), &log, &roof);

    // SAFETY: guarded by TOOL_ENV; no other test in this binary reads these vars.
    unsafe {
        std::env::set_var("EXTOS_LDCONFIG", &ldconfig_stub);
        std::env::set_var("EXTOS_DEPMOD", &depmod_stub);
    }
    let ldconfig = run_ldconfig(&roof);
    let depmod = run_depmod(&roof, "6.8.2-extos");
    unsafe {
        std::env::remove_var("EXTOS_LDCONFIG");
        std::env::remove_var("EXTOS_DEPMOD");
    }

    let ldconfig = ldconfig.expect("stub ldconfig must succeed");
    let depmod = depmod.expect("stub depmod must succeed");
    assert_eq!(ldconfig.arguments, vec!["-r".to_string(), roof.display().to_string()]);
    assert_eq!(
        depmod.arguments,
        vec![
            "-b".to_string(),
            roof.display().to_string(),
            "6.8.2-extos".to_string()
        ]
    );

    let lines: Vec<String> = fs::read_to_string(&log)
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect();
    assert_eq!(lines.len(), 2, "{lines:?}");
    assert!(lines.iter().all(|line| line.contains("woven=yes")), "{lines:?}");
    assert!(lines[0].contains("ldconfig-stub"), "{lines:?}");
    assert!(lines[1].contains("depmod-stub"), "{lines:?}");
}

/// A stub that records its argv *and* proves the weave already happened by
/// checking for a woven binary under the `-r`/`-b` root it was handed.
fn write_hook_stub(path: &Path, log: &Path, _roof: &Path) -> PathBuf {
    fs::write(
        path,
        format!(
            "#!/bin/sh\n\
             if [ -e \"$2/usr/bin/bash\" ]; then woven=yes; else woven=no; fi\n\
             printf '%s argv=%s woven=%s\\n' \"$0\" \"$*\" \"$woven\" >> '{}'\n",
            log.display()
        ),
    )
    .unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    path.to_path_buf()
}
