//! Integration test for the `libexpr-extos` evaluator bridge (PLAN 3.1.7).
//!
//! The test is **honest-skip**: it only runs when `EXTOS_NIX_EVAL_LIB` points
//! at a built bridge (`libnixexprc.so` from the `libexpr-extos` fork). Without
//! it the test prints a skip reason and returns success — the Rust-side
//! parsing/serde tests live in `src/nix_eval/mod.rs` and always run.
//!
//! Golden rules honoured here: no network, no root, nothing outside a
//! `tempfile::TempDir`.
//!
//! All bridge assertions are confined to two `#[test]`s that share a static
//! mutex: the fixture test needs `std::env::set_var`, and mutating the process
//! environment while another test thread evaluates would be a data race. The
//! remaining tests never touch the bridge. (The bridge itself also serialises
//! evaluations internally; that is what the concurrency test checks.)

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use libextos::error::ExtosError;
use libextos::nix_eval::{DagNodeKind, EvalDag, LIB_ENV, NixEvalLib, StoreDirSource};

/// Serialises the bridge-backed tests: the fixture test mutates
/// `EXTOS_REPOSITORY`, and a `setenv` racing a concurrent evaluation in another
/// test thread would be undefined behaviour of the process environment itself
/// (independent of the bridge's own serialisation).
static ENV_LOCK: Mutex<()> = Mutex::new(());

/// Acquire [`ENV_LOCK`], ignoring poisoning: a failed sibling test must not
/// cascade into "lock poisoned" noise.
fn env_lock() -> MutexGuard<'static, ()> {
    ENV_LOCK.lock().unwrap_or_else(|error| error.into_inner())
}

/// Fixture checked in next to this test.
fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/nix_eval/system.nix")
}

/// Load the bridge, or explain why the bridge-backed tests are skipped.
fn bridge() -> Option<NixEvalLib> {
    let Some(path) = std::env::var_os(LIB_ENV) else {
        eprintln!(
            "SKIP nix_eval_int: {LIB_ENV} is not set; build the fork with \
             `meson setup build src/nix-functional-tests=disabled` (any \
             configuration including libexpr-c) and point {LIB_ENV} at \
             `build/src/libexpr-c/libnixexprc.so`"
        );
        return None;
    };
    let path = PathBuf::from(path);
    match NixEvalLib::open(&path) {
        Ok(lib) => Some(lib),
        Err(err) => {
            eprintln!("SKIP nix_eval_int: cannot load bridge at {}: {err}", path.display());
            None
        }
    }
}

/// Copy the fixture into a tempdir so the test never depends on (or writes to)
/// the checkout.
fn stage_config(dir: &Path) -> PathBuf {
    let target = dir.join("system.nix");
    fs::copy(fixture_path(), &target).expect("copy fixture");
    target
}

#[test]
fn evaluates_system_fixture_into_a_dag() {
    let Some(lib) = bridge() else {
        return;
    };
    let _env = env_lock();

    let tmp = tempfile::tempdir().expect("tempdir");
    let repository = tmp.path().join("repository");
    let config = stage_config(tmp.path());

    // --- 1. upstream default (only when the operator left the env clean) ----
    if std::env::var_os("EXTOS_REPOSITORY").is_none() {
        let dag = lib
            .evaluate(&config, &serde_json::json!({}))
            .expect("evaluation must succeed");
        assert_eq!(
            dag.store_dir, "/nix/store",
            "PLAN 3.1.2: without EXTOS_REPOSITORY the upstream default must be preserved"
        );
        assert_eq!(dag.store_dir_source, StoreDirSource::Upstream);
    }

    // --- 2. with the ExtOS override ---------------------------------------
    // `set_var` is `unsafe` in edition 2024 because other threads may read the
    // environment concurrently; this is the only bridge-facing test in the
    // binary, so nothing else observes the change.
    unsafe { std::env::set_var("EXTOS_REPOSITORY", &repository) };

    let dag = lib
        .evaluate(&config, &serde_json::json!({}))
        .expect("evaluation must succeed");

    assert!(dag.version.starts_with("2.35"), "version: {}", dag.version);
    assert_eq!(
        dag.store_dir,
        repository.join("store").display().to_string(),
        "PLAN 3.1.2: EXTOS_REPOSITORY must relocate the store directory"
    );
    assert_eq!(dag.store_dir_source, StoreDirSource::ExtosRepository);

    // --- system block -----------------------------------------------------
    assert_eq!(dag.system.name, "workstation");
    assert_eq!(dag.system.native_pm.as_deref(), Some("debian"));
    assert_eq!(dag.system.kernel.as_deref(), Some("6.8.2-extos"));
    assert_eq!(dag.system.services, ["sshd", "chronyd", "networkd"]);

    // --- packages ---------------------------------------------------------
    let refs: Vec<&str> = dag.packages.iter().map(|p| p.id.as_str()).collect();
    assert_eq!(
        refs,
        [
            "archlinux/htop/3.3.0-1",
            "debian/bash/current",
            "archlinux/ripgrep/14.1.0",
            "alpine/musl/1.2.5-r0",
            "archlinux/glibc/current",
        ]
    );

    // PLAN 3.1.3: `<repo>/store/<origin>/<name>/<version>`.
    let expected_layouts: Vec<String> = dag
        .packages
        .iter()
        .map(|p| {
            repository
                .join("store")
                .join(&p.origin)
                .join(&p.name)
                .join(&p.version)
                .display()
                .to_string()
        })
        .collect();
    assert_eq!(
        dag.layout_paths(),
        expected_layouts.iter().map(String::as_str).collect::<Vec<_>>()
    );

    // --- dag --------------------------------------------------------------
    assert_eq!(dag.dag.nodes.len(), 6, "one system node + five packages");
    assert_eq!(dag.dag.nodes[0].kind, DagNodeKind::System);
    assert_eq!(dag.dag.nodes[0].id, "system:workstation");
    assert_eq!(dag.dag.edges.len(), 5);
    assert!(dag.dag.edges.iter().all(|e| e.kind == "weave"));
    assert!(
        dag.dag
            .edges
            .iter()
            .all(|e| e.from == "system:workstation" && refs.contains(&e.to.as_str())),
        "every weave edge must originate at the system node and target a package"
    );

    // --- 3. missing config --------------------------------------------------
    let missing = tmp.path().join("does-not-exist.nix");
    let err = lib
        .evaluate(&missing, &serde_json::json!({}))
        .expect_err("missing config must fail");
    assert!(matches!(err, ExtosError::Io(_)), "unexpected error kind: {err}");
}

/// Four threads evaluating at once must not corrupt the evaluator
/// (auditor G-L8 must-fix #1): the bridge serialises internally, so every call
/// either succeeds or fails with a typed error — never a panic or an abort.
#[test]
fn concurrent_evaluations_are_serialized_by_the_bridge() {
    use std::sync::Arc;

    const THREADS: usize = 4;
    const EVALS_PER_THREAD: usize = 4;

    let Some(lib) = bridge() else {
        return;
    };
    let _env = env_lock();

    let tmp = tempfile::tempdir().expect("tempdir");
    let config = stage_config(tmp.path());
    let lib = Arc::new(lib);
    let config = Arc::new(config);

    let mut handles = Vec::with_capacity(THREADS);
    for worker in 0..THREADS {
        let lib = Arc::clone(&lib);
        let config = Arc::clone(&config);
        handles.push(std::thread::spawn(move || {
            let mut failures = Vec::new();
            for round in 0..EVALS_PER_THREAD {
                match lib.evaluate(&config, &serde_json::json!({})) {
                    Ok(dag) => {
                        assert_eq!(
                            dag.system.name, "workstation",
                            "worker {worker} round {round}: a serialised evaluation must \
                             still produce the fixture's DAG"
                        );
                        assert_eq!(dag.packages.len(), 5, "worker {worker} round {round}");
                    }
                    Err(err) => failures.push(format!("worker {worker} round {round}: {err}")),
                }
            }
            failures
        }));
    }

    let mut failures = Vec::new();
    for handle in handles {
        // A panic or abort inside Nix would surface here as a failed join.
        let joined = handle.join().expect("no evaluation may panic or abort");
        failures.extend(joined);
    }
    assert!(
        failures.is_empty(),
        "concurrent evaluations must not fail once serialised: {failures:?}"
    );
}

/// The parser/serde path always runs, with or without the shared library.
#[test]
fn dag_model_round_trips() {
    let dag = EvalDag::from_json(
        r#"{
          "version": "2.35.0-extos.1",
          "config_path": "system.nix",
          "store_dir": "/repo/store",
          "store_dir_source": "extos_repository",
          "store_uri": "auto",
          "system": {"name": "default", "native_pm": null, "kernel": null,
                     "root": null, "linux": null, "services": []},
          "packages": [],
          "dag": {"nodes": [], "edges": []}
        }"#,
    )
    .expect("minimal DAG must parse");
    assert!(dag.packages.is_empty());
    assert!(dag.weave_targets().is_empty());
    assert!(dag.layout_paths().is_empty());
}
