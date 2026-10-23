//! Integration tests for PLAN Sub-phase 4.3 — Runlevel 2 AppDirs (`/opt`).
//!
//! Two synthetic packages each ship a *different* `usr/lib/libfoo.so.1`
//! (the same SONAME, incompatible payloads). Equal origin priority forces the
//! collision engine into Tier 3; the AppDir fallback then provisions
//! `<root>/<app>/{bin,lib,share,meta}`, links the CAS payloads into `lib/` and
//! writes a launcher script whose `LD_LIBRARY_PATH` puts the AppDir's own
//! library first.
//!
//! Everything is hermetic: fixtures live in a `tempfile::tempdir()` and no
//! network, root, or committed blob is involved.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use libextos::appdir::{
    normalize_app_id, AppDirLayout, AppDirWrapperSpec, APPDIR_SUBDIRS, DEFAULT_APPDIR_ROOT,
};
use libextos::appdir::CasLibraryRef;
use libextos::cas::CasRepository;
use libextos::error::ExtosError;
use libextos::types::HashAlgorithm;
use libextos::weaver::collision::AppDirFallback;
use libextos::weaver::{
    CollisionResolution, CollisionResolver, OriginPriority,
};
use libextos::weaver::vfs::Collision;

// ─── Fixtures ───────────────────────────────────────────────────

struct Fixture {
    origin: &'static str,
    name: &'static str,
    version: &'static str,
    lib_bytes: &'static [u8],
}

struct World {
    repo: CasRepository,
    appdir_root: PathBuf,
    alpha_hash: String,
    beta_hash: String,
    _tmp: tempfile::TempDir,
}

/// Store one fixture package (payload + ref) and return its object hash.
fn store_fixture(repo: &CasRepository, tmp: &Path, fx: &Fixture) -> String {
    let src = tmp.join(format!("src-{}-{}", fx.origin, fx.name));
    let lib_dir = src.join("usr/lib");
    fs::create_dir_all(&lib_dir).unwrap();
    fs::write(lib_dir.join("libfoo.so.1"), fx.lib_bytes).unwrap();

    let hash = repo.store_directory(&src).unwrap();
    repo.create_ref(fx.origin, fx.name, fx.version, &hash).unwrap();
    hash
}

fn build_world() -> World {
    let tmp = tempfile::tempdir().unwrap();
    let repo = CasRepository::open(tmp.path().join("repository"), HashAlgorithm::Blake3).unwrap();
    let alpha = Fixture {
        origin: "distro-a",
        name: "alpha",
        version: "1.0.0",
        lib_bytes: b"ELF-alpha-libfoo-1",
    };
    let beta = Fixture {
        origin: "distro-b",
        name: "beta",
        version: "2.0.0",
        lib_bytes: b"ELF-beta-libfoo-2",
    };
    let alpha_hash = store_fixture(&repo, tmp.path(), &alpha);
    let beta_hash = store_fixture(&repo, tmp.path(), &beta);

    World {
        repo,
        appdir_root: tmp.path().join("runlevel/2"),
        alpha_hash,
        beta_hash,
        _tmp: tmp,
    }
}

fn soname_collision() -> Collision {
    Collision {
        path: PathBuf::from("usr/lib/libfoo.so.1"),
        claimant_a: "distro-a/alpha".into(),
        claimant_b: "distro-b/beta".into(),
    }
}

fn equal_priority() -> OriginPriority {
    let mut prio = OriginPriority::new();
    prio.set("distro-a", 10);
    prio.set("distro-b", 10);
    prio
}

// ─── 4.3.1 / 4.3.2 / 4.3.3 / 4.3.4 ─────────────────────────────

#[test]
fn tier3_soname_conflict_provisions_appdir_and_wrapper() {
    let world = build_world();
    let resolver = CollisionResolver::new(equal_priority());
    let fallback = AppDirFallback::new(&world.appdir_root);

    let resolved = resolver
        .resolve_all_with_appdirs(&[soname_collision()], Some(&fallback), &HashMap::new())
        .unwrap();
    assert_eq!(resolved.len(), 1);

    let appdir = resolved[0].appdir.as_ref().expect("AppDir provisioned");
    assert_eq!(appdir.app_id, "distro-a-alpha");
    assert!(appdir.created);
    for sub in APPDIR_SUBDIRS {
        assert!(
            appdir.app_root.join(sub).is_dir(),
            "AppDir layout missing {sub}"
        );
    }

    let wrapper = match &resolved[0].resolved.resolution {
        CollisionResolution::Tier3Wrapper {
            wrapper_path,
            alternatives,
        } => {
            assert_eq!(alternatives.len(), 2);
            assert_eq!(
                alternatives,
                &vec!["distro-a/alpha".to_string(), "distro-b/beta".to_string()]
            );
            assert!(
                wrapper_path.starts_with(&appdir.app_root),
                "wrapper must live inside the AppDir: {}",
                wrapper_path.display()
            );
            wrapper_path.clone()
        }
        other => panic!("expected Tier3Wrapper, got {other:?}"),
    };
    assert!(wrapper.is_file());
    assert_eq!(wrapper, appdir.app_root.join("bin/distro-a-alpha-env"));

    // The AppDir's own package's library comes first in LD_LIBRARY_PATH, then
    // the woven-tree fallback, then the AppDir data directory.
    let script = fs::read_to_string(&wrapper).unwrap();
    assert!(script.starts_with("#!/bin/sh\n"));
    assert!(script.contains("# Shared library hint: libfoo.so.1"));
    let lib_pos = script
        .find("LD_LIBRARY_PATH=\"$extos_appdir/lib:$extos_appdir/usr/lib")
        .expect("AppDir lib must precede the woven /usr/lib");
    assert!(script.contains("XDG_DATA_DIRS=\"$extos_appdir/share:$extos_appdir/usr/share"));
    assert!(script.find("LD_LIBRARY_PATH").unwrap() < script.find("XDG_DATA_DIRS").unwrap());
    assert!(lib_pos > 0);
    // Self-locating and hermetic: no host paths baked in.
    assert!(script.contains("$self_dir/.."));
    assert!(!script.contains(world.appdir_root.to_str().unwrap()));
    assert!(!script.contains("/repository"));

    // 4.3.2: CAS payloads are linked into <app>/lib, targets inside objects/.
    let layout = AppDirLayout::new(&world.appdir_root, "distro-a-alpha").unwrap();
    let linked = layout
        .link_libraries(
            &world.repo,
            &[
                CasLibraryRef::new(&world.alpha_hash, "usr/lib/libfoo.so.1", "libfoo.so.1"),
                CasLibraryRef::from_ref(
                    &world.repo,
                    "distro-b",
                    "beta",
                    "2.0.0",
                    "usr/lib/libfoo.so.1",
                    "libfoo-beta.so.1",
                )
                .unwrap(),
            ],
        )
        .unwrap();
    assert_eq!(linked.len(), 2);
    for link in &linked {
        let target = fs::read_link(link).unwrap();
        assert!(
            target.starts_with(world.repo.object_path(
                if link.ends_with("libfoo-beta.so.1") {
                    &world.beta_hash
                } else {
                    &world.alpha_hash
                }
            )),
            "link must point into the CAS object store: {}",
            target.display()
        );
        assert!(!target.starts_with(world.repo.root.join("refs")));
    }
    assert_eq!(
        fs::read(layout.app_root().join("lib/libfoo.so.1")).unwrap(),
        b"ELF-alpha-libfoo-1"
    );
}

#[test]
fn wrapper_executes_with_expected_environment_precedence() {
    let world = build_world();
    let resolver = CollisionResolver::new(equal_priority());
    let fallback = AppDirFallback::new(&world.appdir_root);
    let resolved = resolver
        .resolve_all_with_appdirs(&[soname_collision()], Some(&fallback), &HashMap::new())
        .unwrap();
    let appdir = resolved[0].appdir.as_ref().unwrap();
    let wrapper = match &resolved[0].resolved.resolution {
        CollisionResolution::Tier3Wrapper { wrapper_path, .. } => wrapper_path.clone(),
        other => panic!("expected Tier3Wrapper, got {other:?}"),
    };

    let probe = "printf '%s\\n' \"$LD_LIBRARY_PATH\"; printf '%s\\n' \"$XDG_DATA_DIRS\"";
    let canonical_app = fs::canonicalize(&appdir.app_root).unwrap();
    let expected_lib = canonical_app.join("lib");
    let expected_share = canonical_app.join("share");

    for shell in ["sh", "bash"] {
        if Command::new(shell).arg("-c").arg("exit 0").status().is_err() {
            continue; // shell not installed on this host
        }
        let out = Command::new(shell)
            .arg(&wrapper)
            .arg(shell)
            .arg("-c")
            .arg(probe)
            .output()
            .unwrap_or_else(|e| panic!("failed to execute wrapper via {shell}: {e}"));
        assert!(
            out.status.success(),
            "{shell} wrapper exit: {:?} / stderr: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
        let text = String::from_utf8_lossy(&out.stdout);
        let mut lines = text.lines();
        let lib_path = lines.next().expect("LD_LIBRARY_PATH line");
        let data_path = lines.next().expect("XDG_DATA_DIRS line");

        let lib_segments: Vec<&str> = lib_path.split(':').collect();
        assert_eq!(
            Path::new(lib_segments[0]),
            expected_lib,
            "{shell}: AppDir lib must be first in LD_LIBRARY_PATH: {lib_path}"
        );
        assert!(
            lib_segments
                .iter()
                .any(|s| *s == canonical_app.join("usr/lib").to_string_lossy()),
            "{shell}: woven /usr/lib fallback missing: {lib_path}"
        );
        assert_eq!(
            Path::new(data_path.split(':').next().unwrap()),
            expected_share,
            "{shell}: AppDir share must be first in XDG_DATA_DIRS: {data_path}"
        );
    }
}

#[test]
fn reprovisioning_is_idempotent() {
    let world = build_world();
    let resolver = CollisionResolver::new(equal_priority());
    let fallback = AppDirFallback::new(&world.appdir_root);

    let first = resolver
        .resolve_all_with_appdirs(&[soname_collision()], Some(&fallback), &HashMap::new())
        .unwrap();
    let first_appdir = first[0].appdir.clone().unwrap();
    let first_wrapper = match &first[0].resolved.resolution {
        CollisionResolution::Tier3Wrapper { wrapper_path, .. } => wrapper_path.clone(),
        other => panic!("expected Tier3Wrapper, got {other:?}"),
    };
    let first_script = fs::read_to_string(&first_wrapper).unwrap();

    let second = resolver
        .resolve_all_with_appdirs(&[soname_collision()], Some(&fallback), &HashMap::new())
        .unwrap();
    let second_appdir = second[0].appdir.as_ref().unwrap();
    assert!(!second_appdir.created, "second provision must be a no-op");
    assert_eq!(second_appdir.app_root, first_appdir.app_root);
    match &second[0].resolved.resolution {
        CollisionResolution::Tier3Wrapper { wrapper_path, .. } => {
            assert_eq!(wrapper_path, &first_wrapper);
            assert_eq!(fs::read_to_string(wrapper_path).unwrap(), first_script);
        }
        other => panic!("expected Tier3Wrapper, got {other:?}"),
    }

    // Direct provisioner re-run is equally idempotent.
    let layout = AppDirLayout::new(&world.appdir_root, "distro-a-alpha").unwrap();
    let third = layout.provision().unwrap();
    assert!(!third.created);
    assert_eq!(third.app_root, first_appdir.app_root);
}

#[test]
fn priority_wins_are_untouched_by_the_fallback() {
    let world = build_world();
    // Different priorities: Tier 2 decides, no AppDir may appear.
    let mut prio = OriginPriority::new();
    prio.set("distro-a", 10);
    prio.set("distro-b", 30);
    let resolver = CollisionResolver::new(prio);
    let fallback = AppDirFallback::new(&world.appdir_root);
    let resolved = resolver
        .resolve_all_with_appdirs(&[soname_collision()], Some(&fallback), &HashMap::new())
        .unwrap();

    assert!(resolved[0].appdir.is_none());
    assert!(!fallback.root().exists());
    match &resolved[0].resolved.resolution {
        CollisionResolution::PriorityWin { winner, loser } => {
            assert_eq!(winner, "distro-a/alpha");
            assert_eq!(loser, "distro-b/beta");
        }
        other => panic!("expected PriorityWin, got {other:?}"),
    }
}

// ─── Hostile inputs ────────────────────────────────────────────

#[test]
fn hostile_extra_dirs_are_rejected_before_a_wrapper_is_written() {
    // G-L14 N1, pinned: the extras are interpolated inside double quotes, so
    // `$(id -u)` would execute at wrapper runtime. It must be a typed error at
    // build time instead of a "working" launcher.
    let tmp = tempfile::tempdir().unwrap();
    let layout = AppDirLayout::new(tmp.path().join("runlevel/2"), "distro-a-alpha").unwrap();
    let spec = AppDirWrapperSpec::new("tool-env")
        .with_lib_dir("$(id -u)")
        .with_data_dir("`id -u`");
    let err = layout.write_wrapper(&spec).unwrap_err();
    assert!(matches!(err, ExtosError::Weave(_)), "got {err:?}");
    assert!(
        !layout.app_root().exists(),
        "validation must run before the AppDir is provisioned"
    );

    // A lone hostile dir is rejected on its own as well.
    let single = AppDirWrapperSpec::new("tool-env").with_lib_dir("lib/$(id -u)");
    assert!(matches!(
        layout.write_wrapper(&single),
        Err(ExtosError::Weave(_))
    ));
}

#[test]
fn hostile_inputs_yield_typed_errors() {
    let world = build_world();

    // Bad AppDir ids (path traversal, separators, hidden names).
    for bad in ["../etc", "a/b", ".hidden", "-rf", ""] {
        assert!(
            matches!(
                AppDirLayout::new(&world.appdir_root, bad).unwrap_err(),
                ExtosError::Weave(_)
            ),
            "AppDir id {bad:?} must be rejected"
        );
    }
    assert_eq!(normalize_app_id("DistroA").unwrap(), "distroa");
    assert_eq!(DEFAULT_APPDIR_ROOT, "/runlevel/2");

    // Missing CAS object → typed PackageNotFound.
    let layout = AppDirLayout::new(&world.appdir_root, "distro-a-alpha").unwrap();
    layout.provision().unwrap();
    let missing = CasLibraryRef::new("blake3-not-present", "usr/lib/libfoo.so.1", "libfoo.so.1");
    assert!(matches!(
        layout.link_library(&world.repo, &missing).unwrap_err(),
        ExtosError::PackageNotFound { .. }
    ));

    // Payload path escaping the object / hostile link name → typed Weave error.
    let escape = CasLibraryRef::new(&world.alpha_hash, "../metadata/cache.bin", "x.so");
    assert!(matches!(
        layout.link_library(&world.repo, &escape).unwrap_err(),
        ExtosError::Weave(_)
    ));
    let hostile_name = CasLibraryRef::new(&world.alpha_hash, "usr/lib/libfoo.so.1", "../x.so");
    assert!(matches!(
        layout.link_library(&world.repo, &hostile_name).unwrap_err(),
        ExtosError::Weave(_)
    ));

    // Existing planned wrapper: preserved verbatim, no AppDir provisioned.
    let resolver = CollisionResolver::new(equal_priority());
    let planned = world.appdir_root.join("planned/usr/bin/tool");
    let mut overrides = HashMap::new();
    overrides.insert(PathBuf::from("usr/lib/libfoo.so.1"), planned.clone());
    let kept = resolver
        .resolve_all_with_appdirs(
            &[soname_collision()],
            Some(&AppDirFallback::new(world.appdir_root.join("never"))),
            &overrides,
        )
        .unwrap();
    assert!(kept[0].kept_existing_wrapper);
    assert!(kept[0].appdir.is_none());
    match &kept[0].resolved.resolution {
        CollisionResolution::Tier3Wrapper { wrapper_path, .. } => {
            assert_eq!(wrapper_path, &planned);
        }
        other => panic!("expected Tier3Wrapper, got {other:?}"),
    }
    assert!(!world.appdir_root.join("never").exists());
}
