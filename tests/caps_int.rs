//! Integration tests for PLAN Sub-phase 5.2 — Capability Index (5.2.1-5.2.5).
//!
//! The fixture is a real CAS: package trees are hashed into
//! `<tmp>/repository/objects`, their `manifest.nix` carries a
//! `capabilities.libraries` block exactly the way `ingest` writes it
//! (`src/ingest.rs:252`), and `refs/<origin>/<name>/<version>` are created with
//! [`CasRepository::create_ref`]. Everything is hermetic — `tempfile` fixture, no
//! network, no root, no committed blob.
//!
//! Coverage:
//! * 5.2.1 — exact-SONAME lookup, deterministic ordering, hostile input rejection;
//! * 5.2.2 — population from CAS manifests, structured warnings on corrupt rows;
//! * 5.2.3 — Tier-3 resolution through the index, in-plan precedence;
//! * 5.2.5 — `libssl.so.3 → archlinux/openssl`, `libssl.so.10 → rpm/openssl`,
//!   absent → unresolved, warning path, repeatable determinism.
//!
//! The `pkt -F --soname` CLI half of 5.2.4 lives in `core/pkt/tests/caps_cli.rs`,
//! where `CARGO_BIN_EXE_pkt` is available.

use std::fs;
use std::path::Path;

use libextos::caps::{
    validate_soname, CapabilityIndex, CapabilityProvider, MAX_SONAME_LEN,
};
use libextos::cas::CasRepository;
use libextos::dependency::{
    resolve_capability, CapabilityCandidate, CapabilityRequest, CapabilitySource,
};
use libextos::error::ExtosError;
use libextos::manifest::Capabilities;
use libextos::types::HashAlgorithm;

// ─── Fixture ────────────────────────────────────────────────────

/// One fixture package: identity + the SONAMEs its manifest declares.
struct Fixture<'a> {
    origin: &'a str,
    name: &'a str,
    version: &'a str,
    /// Manifest `capabilities.libraries`.
    libraries: &'a [&'a str],
    /// Payload files written into `content/` (`(relative path, bytes)`).
    files: &'a [(&'a str, &'a [u8])],
}

/// A populated repository plus the paths the tests need.
struct World {
    repo: CasRepository,
    _tmp: tempfile::TempDir,
}

impl World {
    fn object_of(&self, origin: &str, name: &str, version: &str) -> String {
        self.repo.resolve_ref(origin, name, version).unwrap()
    }
}

/// The manifest body `ingest` would have committed for this fixture.
fn manifest_nix(fixture: &Fixture<'_>) -> String {
    let libraries = fixture
        .libraries
        .iter()
        .map(|soname| format!("\"{soname}\""))
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        r#"{{
  identity = {{
    origin = "{origin}";
    name = "{name}";
    version = "{version}";
  }};
  format = "extracted-tree";
  capabilities = {{ libraries = [ {libraries} ]; }};
}}"#,
        origin = fixture.origin,
        name = fixture.name,
        version = fixture.version,
        libraries = libraries,
    )
}

/// Store one fixture into `repo` and commit its ref. Returns the object hash.
fn publish(repo: &CasRepository, staging: &Path, fixture: &Fixture<'_>) -> String {
    let src = staging.join(format!("{}-{}", fixture.origin, fixture.name));
    // A per-version marker so two versions of the same package never collapse
    // onto one object (`store_directory` hashes the tree, and an empty tree
    // would hash identically for every version).
    let marker = src.join(format!("usr/share/doc/{}-{}", fixture.name, fixture.version));
    fs::create_dir_all(&marker).unwrap();
    fs::write(marker.join("version"), fixture.version).unwrap();
    for (rel, bytes) in fixture.files {
        let path = src.join(rel);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&path, bytes).unwrap();
    }
    // `store_directory` needs the source to exist even for payload-less fixtures.
    fs::create_dir_all(&src).unwrap();

    let hash = repo.store_directory(&src).unwrap();
    repo.write_manifest(&hash, &manifest_nix(fixture)).unwrap();
    repo.create_ref(fixture.origin, fixture.name, fixture.version, &hash)
        .unwrap();
    repo.update_current(fixture.origin, fixture.name, fixture.version)
        .unwrap();
    hash
}

const LIBSSL3: &[u8] = b"ELF-archlinux-libssl.so.3";
const LIBCRYPTO3: &[u8] = b"ELF-archlinux-libcrypto.so.3";
const LIBSSL10: &[u8] = b"ELF-rpm-libssl.so.10";
const HTOP: &[u8] = b"#!/bin/sh\necho htop\n";

/// Two `openssl` packages from different origins, one `htop` with no libraries,
/// plus one corrupt and one dangling ref for the warning path.
///
/// * `archlinux/openssl 3.3.1-1` → `libssl.so.3`, `libcrypto.so.3`
/// * `rpm/openssl 3.0.13` → `libssl.so.10`
/// * `archlinux/htop 3.3.0` → no libraries
fn build_world() -> World {
    let tmp = tempfile::tempdir().unwrap();
    let repo = CasRepository::open(tmp.path().join("repository"), HashAlgorithm::Blake3).unwrap();

    publish(
        &repo,
        tmp.path(),
        &Fixture {
            origin: "archlinux",
            name: "openssl",
            version: "3.3.1-1",
            libraries: &["libssl.so.3", "libcrypto.so.3"],
            files: &[
                ("usr/lib/libssl.so.3", LIBSSL3),
                ("usr/lib/libcrypto.so.3", LIBCRYPTO3),
            ],
        },
    );
    publish(
        &repo,
        tmp.path(),
        &Fixture {
            origin: "rpm",
            name: "openssl",
            version: "3.0.13",
            libraries: &["libssl.so.10"],
            files: &[("usr/lib64/libssl.so.10", LIBSSL10)],
        },
    );
    publish(
        &repo,
        tmp.path(),
        &Fixture {
            origin: "archlinux",
            name: "htop",
            version: "3.3.0",
            libraries: &[],
            files: &[("usr/bin/htop", HTOP)],
        },
    );

    World { repo, _tmp: tmp }
}

// ─── 5.2.1 / 5.2.5: lookup ─────────────────────────────────────

#[test]
fn populate_then_query_libssl_so_3_finds_archlinux_openssl() {
    let world = build_world();
    let populated = CapabilityIndex::populate(&world.repo).unwrap();

    assert!(
        populated.summary.is_clean(),
        "unexpected warnings: {:?}",
        populated.summary.warnings
    );
    assert_eq!(populated.summary.refs_scanned, 3);
    assert_eq!(populated.summary.packages, 2, "htop declares no libraries");
    assert_eq!(populated.summary.sonames, 3);
    assert_eq!(populated.summary.entries, 3);

    let providers = populated.index.query("libssl.so.3").unwrap();
    assert_eq!(providers.len(), 1);
    let provider = &providers[0];
    assert_eq!(provider.origin, "archlinux");
    assert_eq!(provider.name, "openssl");
    assert_eq!(provider.version, "3.3.1-1");
    assert_eq!(provider.ref_id(), "archlinux/openssl/3.3.1-1");
    assert_eq!(provider.label(), "archlinux/openssl");
    assert_eq!(
        provider.object.as_deref(),
        Some(world.object_of("archlinux", "openssl", "3.3.1-1").as_str())
    );
    // The ref id round-trips through the CAS.
    assert_eq!(
        world
            .repo
            .resolve_ref("archlinux", "openssl", "3.3.1-1")
            .unwrap(),
        provider.object.clone().unwrap()
    );

    // The other SONAME of the same package resolves to it as well.
    assert_eq!(
        populated.index.providers_of("libcrypto.so.3")[0].label(),
        "archlinux/openssl"
    );
}

#[test]
fn negative_case_libssl_so_10_resolves_only_to_rpm_openssl() {
    let world = build_world();
    let populated = CapabilityIndex::populate(&world.repo).unwrap();

    let providers = populated.index.query("libssl.so.10").unwrap();
    assert_eq!(providers.len(), 1);
    assert_eq!(providers[0].label(), "rpm/openssl");
    assert_eq!(providers[0].version, "3.0.13");

    // The two SONAMEs never cross-resolve.
    assert!(
        !populated
            .index
            .providers_of("libssl.so.3")
            .iter()
            .any(|p| p.origin == "rpm")
    );
    assert!(
        !populated
            .index
            .providers_of("libssl.so.10")
            .iter()
            .any(|p| p.origin == "archlinux")
    );
}

#[test]
fn absent_soname_is_unresolved_and_not_an_error() {
    let world = build_world();
    let populated = CapabilityIndex::populate(&world.repo).unwrap();

    assert!(populated.index.query("libnope.so.9").unwrap().is_empty());
    assert!(populated.index.providers_of("libssl").is_empty());
    assert!(populated.index.providers_of("libssl.so.30").is_empty());

    let resolved = resolve_capability(
        &CapabilityRequest::Provides("libnope.so.9".into()),
        &[],
        Some(&populated.index),
    );
    assert!(!resolved.is_resolved());
    assert_eq!(resolved.source, None);
}

#[test]
fn exact_lookup_rejects_hostile_query_strings() {
    let world = build_world();
    let populated = CapabilityIndex::populate(&world.repo).unwrap();

    for hostile in [
        "",
        "..",
        "../../etc/passwd",
        "usr/lib/libssl.so.3",
        "libssl.so.3\0",
        "lib ssl.so.3",
    ] {
        let err = populated.index.query(hostile).expect_err(hostile);
        assert!(
            matches!(err, ExtosError::ConfigParse { .. }),
            "{hostile}: {err}"
        );
    }
    assert!(validate_soname("libssl.so.3").is_ok());
    assert!(validate_soname(&"x".repeat(MAX_SONAME_LEN)).is_ok());
    assert!(validate_soname(&"x".repeat(MAX_SONAME_LEN + 1)).is_err());
}

// ─── 5.2.1: ordering determinism ───────────────────────────────

#[test]
fn ordering_is_origin_then_name_then_newest_version_and_repeatable() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = CasRepository::open(tmp.path().join("repository"), HashAlgorithm::Blake3).unwrap();

    // Insertion order is deliberately hostile to the expected output order.
    for (origin, name, version) in [
        ("rpm", "openssl", "3.0.13"),
        ("archlinux", "openssl", "3.9"),
        ("archlinux", "openssl", "3.10"),
        ("archlinux", "libressl", "4.1"),
        ("debian", "openssl", "3.0.13"),
    ] {
        publish(
            &repo,
            tmp.path(),
            &Fixture {
                origin,
                name,
                version,
                libraries: &["libssl.so.3"],
                files: &[],
            },
        );
    }

    let first = CapabilityIndex::populate(&repo).unwrap();
    let refs: Vec<String> = first
        .index
        .providers_of("libssl.so.3")
        .iter()
        .map(CapabilityProvider::ref_id)
        .collect();
    assert_eq!(
        refs,
        vec![
            // origin asc …
            "archlinux/libressl/4.1",
            // … name asc, newest version first (3.10 outranks 3.9 numerically) …
            "archlinux/openssl/3.10",
            "archlinux/openssl/3.9",
            "debian/openssl/3.0.13",
            "rpm/openssl/3.0.13",
        ]
    );

    // Same repository, second run: byte-identical outcome.
    let second = CapabilityIndex::populate(&repo).unwrap();
    assert_eq!(first.index, second.index);
    assert_eq!(
        first.index.provider_count(),
        second.index.provider_count(),
        "population is idempotent"
    );

    // The key enumeration is BTree order as well.
    assert_eq!(
        first.index.sonames().collect::<Vec<_>>(),
        vec!["libssl.so.3"]
    );
}

// ─── 5.2.2: warning path ───────────────────────────────────────

#[test]
fn corrupt_rows_are_skipped_and_recorded_in_the_summary() {
    let world = build_world();
    let repo = &world.repo;

    // A ref whose object carries no manifest at all (metadata absent).
    let manifestless = repo.store_bytes(b"no metadata").unwrap();
    repo.create_ref("debian", "libssl", "3.0.13", &manifestless)
        .unwrap();

    // A ref whose manifest is unparsable.
    let broken = repo.store_bytes(b"broken manifest").unwrap();
    repo.write_manifest(&broken, "{ name = ").unwrap();
    repo.create_ref("alpine", "libssl3", "3.1.4", &broken)
        .unwrap();

    // A dangling ref (target object does not exist).
    repo.create_ref("void", "libressl", "4.0", "BLAKE3-0123456789abcdef")
        .unwrap();

    // A manifest declaring a path-traversing "SONAME".
    let hostile = repo.store_bytes(b"hostile").unwrap();
    repo.write_manifest(
        &hostile,
        "{ identity = { origin = \"rpm\"; name = \"evil\"; version = \"1.0\"; };\n\
          capabilities = { libraries = [ \"../../../etc/passwd\" ]; }; }",
    )
    .unwrap();
    repo.create_ref("rpm", "evil", "1.0", &hostile).unwrap();

    let populated = CapabilityIndex::populate(repo).unwrap();

    // The healthy rows are still there...
    assert_eq!(
        populated.index.providers_of("libssl.so.3")[0].label(),
        "archlinux/openssl"
    );
    assert_eq!(
        populated.index.providers_of("libssl.so.10")[0].label(),
        "rpm/openssl"
    );
    // ...and the hostile row contributed nothing.
    assert_eq!(populated.index.len(), 3);
    assert!(populated.index.providers_of("../../../etc/passwd").is_empty());

    // Nothing was skipped silently.
    assert_eq!(populated.summary.refs_scanned, 7);
    assert_eq!(populated.summary.packages, 2);
    assert_eq!(populated.summary.warnings.len(), 4);
    assert!(!populated.summary.is_clean());
    let ref_ids: Vec<&str> = populated
        .summary
        .warnings
        .iter()
        .map(|warning| warning.ref_id.as_str())
        .collect();
    assert!(ref_ids.contains(&"debian/libssl/3.0.13"), "{ref_ids:?}");
    assert!(ref_ids.contains(&"alpine/libssl3/3.1.4"), "{ref_ids:?}");
    assert!(ref_ids.contains(&"void/libressl/4.0"), "{ref_ids:?}");
    assert!(ref_ids.contains(&"rpm/evil/1.0"), "{ref_ids:?}");
}

// ─── 5.2.3: resolver wiring ───────────────────────────────────

#[test]
fn tier3_resolution_uses_the_index_and_prefers_in_plan_providers() {
    let world = build_world();
    let populated = CapabilityIndex::populate(&world.repo).unwrap();
    let request = CapabilityRequest::Provides("libssl.so.3".into());

    // No in-plan source: the index answers.
    let from_index = resolve_capability(&request, &[], Some(&populated.index));
    assert_eq!(from_index.source, Some(CapabilitySource::CapabilityIndex));
    assert_eq!(
        from_index.winner().unwrap().label(),
        "archlinux/openssl",
        "the only libssl.so.3 provider"
    );

    // In-plan package satisfying the request wins outright.
    let plan = vec![CapabilityCandidate::from_plan(
        "debian",
        "libssl3",
        "3.0.13",
        Some("BLAKE3-plan-provider".into()),
        Capabilities {
            libraries: vec!["libssl.so.3".into()],
            ..Capabilities::default()
        },
    )];
    let from_plan = resolve_capability(&request, &plan, Some(&populated.index));
    assert_eq!(from_plan.source, Some(CapabilitySource::Plan));
    assert_eq!(from_plan.providers.len(), 1);
    assert_eq!(from_plan.winner().unwrap().label(), "debian/libssl3");

    // The in-plan source is honoured even without any index at all.
    let plan_only = resolve_capability(&request, &plan, None);
    assert_eq!(plan_only.source, Some(CapabilitySource::Plan));

    // A package that is in the plan but does not provide the SONAME is not a
    // provider: the index still gets consulted.
    let unrelated = vec![CapabilityCandidate::from_plan(
        "archlinux",
        "htop",
        "3.3.0",
        None,
        Capabilities {
            binaries: vec!["htop".into()],
            ..Capabilities::default()
        },
    )];
    let mixed = resolve_capability(&request, &unrelated, Some(&populated.index));
    assert_eq!(mixed.source, Some(CapabilitySource::CapabilityIndex));
    assert_eq!(mixed.winner().unwrap().label(), "archlinux/openssl");
}

// ─── 5.2.2: virtual refs are not packages (G-L19 MF-1) ────────

#[test]
fn virtual_ref_rows_are_skipped_without_fabricating_providers() {
    let world = build_world();

    // Auditor repro, structural variant 1: the real API creates
    // `refs/virtual/<name> -> ../<origin>/<pkg>/<version>`, which the Phase-2
    // listing walk reports as `virtual/<name>/{content,metadata}`.
    world
        .repo
        .create_virtual_link("desktop-monitor", "archlinux", "htop", "3.3.0")
        .unwrap();
    // Structural variant 2: a raw per-version alias
    // (`refs/virtual/<name>/<ver> -> ../../<origin>/<pkg>/<ver>`) resolves to a
    // real object, which used to be indexed as an `origin == "virtual"` provider.
    world
        .repo
        .create_virtual_ref("system-monitor", "3.3.1-1", "archlinux", "openssl")
        .unwrap();

    let populated = CapabilityIndex::populate(&world.repo).unwrap();

    // Only the three concrete refs are scanned; the pseudo-rows are invisible.
    assert_eq!(populated.summary.refs_scanned, 3);
    assert!(
        populated.summary.is_clean(),
        "virtual rows must not warn: {:?}",
        populated.summary.warnings
    );

    // No fabricated provider, on either SONAME, from a virtual origin.
    assert_eq!(
        populated.index.providers_of("libssl.so.3")[0].ref_id(),
        "archlinux/openssl/3.3.1-1"
    );
    assert!(
        !populated
            .index
            .providers_of("libssl.so.3")
            .iter()
            .any(|provider| provider.origin == "virtual"),
        "{:?}",
        populated.index.providers_of("libssl.so.3")
    );
    assert!(
        !populated
            .index
            .providers_of("libcrypto.so.3")
            .iter()
            .any(|provider| provider.origin == "virtual")
    );
    for (_, providers) in populated.index.entries() {
        for provider in providers {
            assert_ne!(provider.origin, "virtual", "{provider}");
        }
    }
    assert!(
        populated
            .index
            .provider_refs()
            .iter()
            .all(|ref_id| !ref_id.starts_with("virtual/")),
        "{:?}",
        populated.index.provider_refs()
    );
    // `virtual/system-monitor` never became a package.
    assert!(populated.index.providers_of("virtual/system-monitor").is_empty());
}

#[test]
fn manifest_without_a_name_is_a_recorded_warning() {
    let world = build_world();
    // Parses as nix, but `identity` lacks the required `name` field.
    let nameless = world.repo.store_bytes(b"nameless manifest").unwrap();
    world
        .repo
        .write_manifest(
            &nameless,
            "{ identity = { origin = \"archlinux\"; version = \"9.9\"; };\n\
              capabilities = { libraries = [ \"libnameless.so.9\" ]; }; }",
        )
        .unwrap();
    world
        .repo
        .create_ref("archlinux", "nameless", "9.9", &nameless)
        .unwrap();

    let populated = CapabilityIndex::populate(&world.repo).unwrap();
    assert_eq!(populated.summary.refs_scanned, 4);
    assert_eq!(populated.summary.warnings.len(), 1);
    let warning = &populated.summary.warnings[0];
    assert_eq!(warning.ref_id, "archlinux/nameless/9.9");
    assert!(
        warning.message.contains("not a valid package manifest"),
        "{warning}"
    );
    assert!(populated.index.providers_of("libnameless.so.9").is_empty());
}

// ─── 5.2.2: empty repository ───────────────────────────────────

#[test]
fn empty_repository_populates_to_an_empty_index() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = CasRepository::open(tmp.path(), HashAlgorithm::Blake3).unwrap();

    let populated = CapabilityIndex::populate(&repo).unwrap();
    assert!(populated.index.is_empty());
    assert_eq!(populated.index.len(), 0);
    assert_eq!(populated.index.provider_count(), 0);
    assert_eq!(populated.summary.refs_scanned, 0);
    assert_eq!(populated.summary.entries, 0);
    assert!(populated.summary.is_clean());

    // A ref table with a namespace but no version rows is equally clean.
    repo.create_namespace("scratch").unwrap();
    let populated = CapabilityIndex::populate(&repo).unwrap();
    assert!(populated.index.is_empty());
    assert!(populated.summary.is_clean());
}
