//! Integration tests for PLAN Sub-phase 5.1 — Virtual Anchor Map
//! (tasks 5.1.1–5.1.5).
//!
//! The chain exercised end to end is the one `instanz apply` will drive:
//!
//! ```text
//! anchors.nix ──parse──▶ AnchorsMap ──bid against the CAS──▶ AnchorResolution
//!                                                              │        │
//!                                    anchors_map::apply ◀─────┘        └─────▶ AnchorLock
//!                                    refs/virtual/<name>                  anchors.lock
//!                                            │                              │
//!                    resolve_virtual_object ◀┘                  parse/verify┘
//! ```
//!
//! Everything is hermetic: two synthetic packages each ship a *different*
//! `usr/lib/libssl.so.3`, stored through the real CAS ingest primitives in a
//! `tempfile::tempdir()`. No network, no root, no committed blobs.

use std::fs;
use std::path::{Path, PathBuf};

use libextos::anchor::compare_versions;
use libextos::anchors_map::{self, AnchorsMap};
use libextos::cas::{CasRepository, RefEntry};
use libextos::error::ExtosError;
use libextos::types::HashAlgorithm;
use libextos::vlock::AnchorLock;

// ─── Fixtures ───────────────────────────────────────────────────

/// `fedora` ships the *older* SONAME payload; the map declares it higher.
const ANCHORS_NIX: &str = r#"{
    # One virtual name, two allowed providers. Priorities are declared per
    # origin: lower wins, so fedora (5) beats archlinux (10) even though its
    # concrete version is older.
    anchors = {
        "libssl.so.3" = [
            { origin = "archlinux"; package = "openssl"; }
            { origin = "fedora"; package = "openssl"; }
        ];
    };
    priorities = {
        fedora = 5;
        archlinux = 10;
    };
}"#;

struct World {
    _tmp: tempfile::TempDir,
    repo: CasRepository,
    fedora: String,
    arch: String,
    lock_path: PathBuf,
}

/// Store one fixture package (payload + concrete ref) and return its object id.
fn store_package(
    repo: &CasRepository,
    tmp: &Path,
    origin: &str,
    name: &str,
    version: &str,
    soname: &str,
    payload: &[u8],
) -> String {
    let src = tmp.join(format!("src-{origin}-{name}-{version}"));
    fs::create_dir_all(src.join("usr/lib")).unwrap();
    fs::write(src.join("usr/lib").join(soname), payload).unwrap();
    let hash = repo.store_directory(&src).unwrap();
    repo.create_ref(origin, name, version, &hash).unwrap();
    hash
}

fn build_world() -> World {
    let tmp = tempfile::tempdir().unwrap();
    let repo = CasRepository::open(tmp.path().join("repository"), HashAlgorithm::Blake3).unwrap();
    let fedora = store_package(
        &repo,
        tmp.path(),
        "fedora",
        "openssl",
        "3.0.11",
        "libssl.so.3",
        b"ELF-fedora-libssl.so.3",
    );
    let arch = store_package(
        &repo,
        tmp.path(),
        "archlinux",
        "openssl",
        "3.3.1",
        "libssl.so.3",
        b"ELF-archlinux-libssl.so.3",
    );
    let lock_path = tmp.path().join("locks").join("anchors.lock");
    World {
        _tmp: tmp,
        repo,
        fedora,
        arch,
        lock_path,
    }
}

// ─── 5.1.1 / 5.1.2 / 5.1.3 / 5.1.4: the full chain ──────────────

#[test]
fn full_chain_parses_bids_links_and_locks_the_priority_winner() {
    let world = build_world();

    // 5.1.1 — parse the declarative map.
    let map = AnchorsMap::parse(ANCHORS_NIX, "config/anchors.nix").unwrap();
    assert_eq!(map.len(), 1);
    assert_eq!(map.providers_of("libssl.so.3").unwrap().len(), 2);

    // 5.1.3 — bid every provider against the CAS.
    let resolution = anchors_map::resolve(&world.repo, &map).unwrap();
    assert_eq!(resolution.len(), 1);
    let anchor = resolution.get("libssl.so.3").unwrap();
    assert_eq!(anchor.provider(), "fedora/openssl");
    assert_eq!(anchor.version, "3.0.11");
    assert_eq!(anchor.object, world.fedora);
    assert_eq!(
        resolution.table.winner_of("libssl.so.3"),
        Some("fedora/openssl")
    );

    // 5.1.2 — the refs/virtual chain points at the winning concrete ref.
    assert_eq!(resolution.apply(&world.repo).unwrap(), 1);
    let link = world.repo.virtual_ref_path("libssl.so.3");
    assert!(link.symlink_metadata().unwrap().file_type().is_symlink());
    assert_eq!(
        fs::read_link(&link).unwrap(),
        PathBuf::from("../fedora/openssl/3.0.11")
    );
    // Absolute-target safety: the link resolves inside this repository only.
    let root = fs::canonicalize(&world.repo.root).unwrap();
    assert!(fs::canonicalize(&link).unwrap().starts_with(&root));

    // Resolving back through the virtual name lands on the chosen ref.
    assert_eq!(
        world.repo.resolve_virtual("libssl.so.3").unwrap(),
        RefEntry {
            origin: "fedora".into(),
            name: "openssl".into(),
            version: "3.0.11".into(),
        }
    );
    let (entry, object) = world.repo.resolve_virtual_object("libssl.so.3").unwrap();
    assert_eq!(entry.origin, "fedora");
    assert_eq!(object, world.fedora);
    assert_eq!(
        world
            .repo
            .resolve_ref(&entry.origin, &entry.name, &entry.version)
            .unwrap(),
        world.fedora
    );
    // Re-applying is a no-op for an already-correct chain.
    assert_eq!(resolution.apply(&world.repo).unwrap(), 0);

    // 5.1.4 — the lock pins the same outcome, byte-identically.
    let lock = AnchorLock::from_resolution(&resolution).unwrap();
    assert_eq!(lock.len(), 1);
    let pinned = lock.get("libssl.so.3").unwrap();
    assert_eq!(pinned.provider(), "fedora/openssl");
    assert_eq!(pinned.version, "3.0.11");
    // The object id is the CAS object of *fedora's* content, not a new digest.
    assert_eq!(pinned.object, world.fedora);
    assert_eq!(pinned.link, "refs/virtual/libssl.so.3");

    assert!(lock.write(&world.lock_path).unwrap());
    let bytes = fs::read_to_string(&world.lock_path).unwrap();
    assert!(bytes.contains(&world.fedora), "{bytes}");
    assert!(!bytes.contains(&world.arch), "{bytes}");
    assert!(bytes.starts_with("# ExtOS virtual anchor lock"));

    // Byte-identical rerun: same resolution, same file, no rewrite.
    let again = anchors_map::resolve(&world.repo, &AnchorsMap::parse(ANCHORS_NIX, "a").unwrap())
        .unwrap();
    assert_eq!(
        AnchorLock::from_resolution(&again).unwrap().render(),
        lock.render()
    );
    assert!(!lock.write(&world.lock_path).unwrap());

    // Round-trip read-back and drift check.
    assert_eq!(AnchorLock::parse_file(&world.lock_path).unwrap(), lock);
    lock.verify(&world.repo).unwrap();
}

// ─── Priority override semantics ────────────────────────────────

#[test]
fn priority_override_wins_over_a_numerically_higher_version() {
    let world = build_world();
    // Sanity: the loser really is the newer version.
    assert_eq!(
        compare_versions("3.0.11", "3.3.1"),
        std::cmp::Ordering::Less
    );
    let map = AnchorsMap::parse(ANCHORS_NIX, "anchors.nix").unwrap();
    let resolution = anchors_map::resolve(&world.repo, &map).unwrap();
    let winner = &resolution.anchors[0];
    assert_eq!(winner.version, "3.0.11", "priority must beat version order");
    assert_eq!(resolution.table.get("libssl.so.3").unwrap().losers(), vec![
        "archlinux/openssl"
    ]);
    assert_eq!(
        resolution.table.get("libssl.so.3").unwrap().priority,
        5,
        "the winner's priority is the declared origin priority"
    );

    // Without the priorities block the implicit origin order flips the winner:
    // archlinux (10) beats an unknown fedora (50).
    let implicit = AnchorsMap::parse(
        r#"{ anchors = { "libssl.so.3" = [
            { origin = "archlinux"; package = "openssl"; }
            { origin = "fedora"; package = "openssl"; }
        ]; }; }"#,
        "anchors.nix",
    )
    .unwrap();
    let flipped = anchors_map::resolve(&world.repo, &implicit).unwrap();
    assert_eq!(flipped.anchors[0].provider(), "archlinux/openssl");
    assert_eq!(flipped.anchors[0].object, world.arch);

    // A per-provider priority beats the origin priority.
    let per_provider = AnchorsMap::parse(
        r#"{
            anchors = { "libssl.so.3" = [
                { origin = "archlinux"; package = "openssl"; priority = 1; }
                { origin = "fedora"; package = "openssl"; }
            ]; };
            priorities = { fedora = 5; archlinux = 10; };
        }"#,
        "anchors.nix",
    )
    .unwrap();
    let resolution = anchors_map::resolve(&world.repo, &per_provider).unwrap();
    assert_eq!(resolution.anchors[0].provider(), "archlinux/openssl");
    assert_eq!(resolution.anchors[0].version, "3.3.1");
}

// ─── Determinism ────────────────────────────────────────────────

#[test]
fn reruns_and_declaration_order_do_not_change_bytes() {
    let world = build_world();
    let reordered = ANCHORS_NIX.replace(
        r#"{ origin = "archlinux"; package = "openssl"; }
            { origin = "fedora"; package = "openssl"; }"#,
        r#"{ origin = "fedora"; package = "openssl"; }
            { origin = "archlinux"; package = "openssl"; }"#,
    );
    assert_ne!(reordered, ANCHORS_NIX, "fixture must actually reorder");

    let first = anchors_map::resolve(
        &world.repo,
        &AnchorsMap::parse(ANCHORS_NIX, "anchors.nix").unwrap(),
    )
    .unwrap();
    let second = anchors_map::resolve(
        &world.repo,
        &AnchorsMap::parse(&reordered, "anchors.nix").unwrap(),
    )
    .unwrap();
    assert_eq!(first.anchors, second.anchors);

    first.apply(&world.repo).unwrap();
    let lock_a = AnchorLock::from_resolution(&first).unwrap();
    let lock_b = AnchorLock::from_resolution(&second).unwrap();
    assert_eq!(lock_a.render(), lock_b.render());
    assert!(lock_a.write(&world.lock_path).unwrap());
    let bytes = fs::read(&world.lock_path).unwrap();
    assert!(!lock_b.write(&world.lock_path).unwrap());
    assert_eq!(fs::read(&world.lock_path).unwrap(), bytes);

    // Re-running the whole pipeline a third time is still a no-op.
    let third = anchors_map::resolve(
        &world.repo,
        &AnchorsMap::parse(ANCHORS_NIX, "anchors.nix").unwrap(),
    )
    .unwrap();
    assert_eq!(third.apply(&world.repo).unwrap(), 0);
    assert!(!AnchorLock::from_resolution(&third)
        .unwrap()
        .write(&world.lock_path)
        .unwrap());
}

// ─── Failure modes ─────────────────────────────────────────────

#[test]
fn missing_provider_is_a_typed_error() {
    let world = build_world();
    let map = AnchorsMap::parse(
        r#"{ anchors = { "libssl.so.3" = [
            { origin = "nixos"; package = "openssl"; }
        ]; }; }"#,
        "anchors.nix",
    )
    .unwrap();
    let err = anchors_map::resolve(&world.repo, &map).unwrap_err();
    assert!(matches!(err, ExtosError::DependencyUnresolvable(_)), "{err}");
    assert!(err.to_string().contains("nixos/openssl"), "{err}");
    // Nothing was created by the failed resolution.
    assert!(world
        .repo
        .virtual_ref_path("libssl.so.3")
        .symlink_metadata()
        .is_err());

    // A partially available list is not an error: unavailable providers are
    // skipped, available ones still bid.
    let map = AnchorsMap::parse(
        r#"{ anchors = { "libssl.so.3" = [
            { origin = "nixos"; package = "openssl"; }
            { origin = "fedora"; package = "openssl"; }
        ]; }; }"#,
        "anchors.nix",
    )
    .unwrap();
    let resolution = anchors_map::resolve(&world.repo, &map).unwrap();
    assert_eq!(resolution.anchors[0].provider(), "fedora/openssl");
}

#[test]
fn hostile_virtual_names_are_rejected_everywhere() {
    // Parse time: schema-level rejection with a field-addressed error.
    for name in ["../libssl.so.3", "lib/ssl.so.3", "lib ssl.so.3", "-libssl"] {
        let source = format!(
            "{{ anchors = {{ \"{name}\" = [ {{ origin = \"fedora\"; package = \"openssl\"; }} ]; }}; }}"
        );
        let err = AnchorsMap::parse(&source, "anchors.nix").unwrap_err();
        assert!(matches!(err, ExtosError::ConfigParse { .. }), "{name} -> {err}");
        assert!(err.to_string().contains("invalid virtual name"), "{err}");
    }

    // CAS API: defense in depth, even when a caller skips the parser.
    let world = build_world();
    for name in ["../evil", "..", "a/b", ""] {
        let err = world
            .repo
            .create_virtual_link(name, "fedora", "openssl", "3.0.11")
            .unwrap_err();
        assert!(matches!(err, ExtosError::Weave(_)), "{name:?} -> {err}");
    }
    // No link escaped refs/virtual: the directory does not even exist yet.
    assert!(
        world
            .repo
            .root
            .join("refs")
            .join("virtual")
            .symlink_metadata()
            .is_err()
    );
    assert!(world
        .repo
        .resolve_virtual("../evil")
        .is_err());
}

#[test]
fn drifted_lock_and_chain_are_typed_errors() {
    let world = build_world();
    let map = AnchorsMap::parse(ANCHORS_NIX, "anchors.nix").unwrap();
    let resolution = anchors_map::resolve(&world.repo, &map).unwrap();
    resolution.apply(&world.repo).unwrap();
    let lock = AnchorLock::from_resolution(&resolution).unwrap();
    lock.write(&world.lock_path).unwrap();

    // A lock from another format version is refused, never guessed at.
    let text = fs::read_to_string(&world.lock_path).unwrap();
    fs::write(
        &world.lock_path,
        text.replace("format 1", "format 2"),
    )
    .unwrap();
    let err = AnchorLock::parse_file(&world.lock_path).unwrap_err();
    assert!(err.to_string().contains("unsupported lock format"), "{err}");

    // A count that disagrees with the body is drift.
    fs::write(&world.lock_path, text.replace("count 1", "count 2")).unwrap();
    let err = AnchorLock::parse_file(&world.lock_path).unwrap_err();
    assert!(err.to_string().contains("count says 2"), "{err}");

    // Retargeting the chain behind a valid lock makes verify() fail.
    world
        .repo
        .create_virtual_link("libssl.so.3", "archlinux", "openssl", "3.3.1")
        .unwrap();
    let err = lock.verify(&world.repo).unwrap_err();
    assert!(matches!(err, ExtosError::CasIntegrity { .. }), "{err}");

    // Re-applying the resolution repairs the chain, and verify() passes again.
    assert_eq!(resolution.apply(&world.repo).unwrap(), 1);
    lock.verify(&world.repo).unwrap();
}

#[test]
fn lock_sorts_by_virtual_name_and_round_trips_multiple_entries() {
    let world = build_world();
    // Two virtuals, declared in reverse order on purpose; fedora has a second
    // package so the second anchor resolves too.
    let libcrypto = store_package(
        &world.repo,
        world._tmp.path(),
        "fedora",
        "openssl-libs",
        "3.0.11",
        "libcrypto.so.3",
        b"ELF-fedora-libcrypto.so.3",
    );
    let map = AnchorsMap::parse(
        r#"{
            anchors = {
                "libssl.so.3" = [ { origin = "fedora"; package = "openssl"; } ];
                "libcrypto.so.3" = [ { origin = "fedora"; package = "openssl-libs"; } ];
            };
            priorities = { fedora = 5; };
        }"#,
        "anchors.nix",
    )
    .unwrap();
    let resolution = anchors_map::resolve(&world.repo, &map).unwrap();
    assert_eq!(
        resolution
            .anchors
            .iter()
            .map(|a| a.virtual_name.as_str())
            .collect::<Vec<_>>(),
        vec!["libcrypto.so.3", "libssl.so.3"]
    );
    resolution.apply(&world.repo).unwrap();
    assert_eq!(
        world.repo.resolve_virtual_object("libcrypto.so.3").unwrap().1,
        libcrypto
    );
    assert_eq!(
        world.repo.resolve_virtual_object("libssl.so.3").unwrap().1,
        world.fedora
    );

    let lock = AnchorLock::from_resolution(&resolution).unwrap();
    lock.write(&world.lock_path).unwrap();
    let parsed = AnchorLock::parse_file(&world.lock_path).unwrap();
    assert_eq!(parsed, lock);
    assert_eq!(parsed.entries()[0].virtual_name, "libcrypto.so.3");
    parsed.verify(&world.repo).unwrap();

    // The rendered body is strictly sorted by virtual name.
    let text = lock.render();
    let names: Vec<&str> = text
        .lines()
        .filter(|line| line.starts_with("virtual "))
        .map(|line| line.split('"').nth(1).unwrap())
        .collect();
    assert_eq!(names, vec!["libcrypto.so.3", "libssl.so.3"]);
}
