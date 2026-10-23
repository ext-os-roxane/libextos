//! Integration tests for the PLAN 5.2.3 consumer: capability-index promotion in
//! the weave planner.
//!
//! The entry point under test is
//! [`plan_from_refs_with_anchors_and_index`](libextos::weaver::plan::plan_from_refs_with_anchors_and_index).
//! The fixture is a real CAS: every package is a stored directory with a
//! committed `manifest.nix` and a concrete ref, exactly like `ingest` produces.
//! The index is populated from that repository ([`CapabilityIndex::populate`]),
//! so these tests exercise the same code path `pkt -F --soname` uses.
//!
//! Coverage:
//! * an index winner is promoted, gets the CAS object (not the ref id) and lands
//!   at the roof (VirtualFhs / plan entries / anchor bids see it);
//! * in-plan providers still outrank the index (no promotion on satisfaction);
//! * a promoted package's own requirements fan out on the next pass;
//! * a dependency cycle among promoted packages is the typed toposort error,
//!   bounded (never a hang);
//! * repeated requests never promote the same `origin/name` twice;
//! * promotion happens before the virtual FHS is built;
//! * anchor interplay: an unrelated promotion cannot steal an anchored SONAME,
//!   while a promoted *library bidder* competes and the anchor policy decides
//!   over the final node set;
//! * the no-index delegate (`plan_from_refs_with_anchors`) still behaves exactly
//!   as before — the path `instanz::orchestrate` uses.

use std::fs;
use std::path::{Path, PathBuf};

use libextos::anchor::AnchorPolicy;
use libextos::caps::CapabilityIndex;
use libextos::cas::CasRepository;
use libextos::error::ExtosError;
use libextos::types::HashAlgorithm;
use libextos::weaver::plan::{
    plan_from_refs_with_anchors, plan_from_refs_with_anchors_and_index, CasRef, VfsPlan,
};
use libextos::weaver::{LinkStrategy, OriginPriority};

// ─── Fixture ────────────────────────────────────────────────────

/// One fixture package.
struct Pkg<'a> {
    origin: &'a str,
    name: &'a str,
    version: &'a str,
    /// Manifest `capabilities.libraries`.
    libraries: &'a [&'a str],
    /// Manifest `requires`, expressed as SONAME capability requests.
    requires: &'a [&'a str],
    /// Payload files written into `content/`.
    files: &'a [(&'a str, &'a [u8])],
}

struct World {
    repo: CasRepository,
    staging: PathBuf,
    _tmp: tempfile::TempDir,
}

impl World {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let repo =
            CasRepository::open(tmp.path().join("repository"), HashAlgorithm::Blake3).unwrap();
        Self {
            repo,
            staging: tmp.path().to_path_buf(),
            _tmp: tmp,
        }
    }

    /// Store `pkg`, commit its manifest and create its concrete ref.
    fn publish(&self, pkg: &Pkg<'_>) -> String {
        let src = self
            .staging
            .join(format!("{}-{}-{}", pkg.origin, pkg.name, pkg.version));
        // Version marker so two versions never hash to the same object.
        let marker = src.join(format!("usr/share/doc/{}/{}/version", pkg.name, pkg.version));
        fs::create_dir_all(&marker).unwrap();
        fs::write(marker.join("version"), pkg.version).unwrap();
        for (rel, bytes) in pkg.files {
            let path = src.join(rel);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(&path, bytes).unwrap();
        }
        fs::create_dir_all(&src).unwrap();

        let hash = self.repo.store_directory(&src).unwrap();
        let libraries = pkg
            .libraries
            .iter()
            .map(|soname| format!("\"{soname}\""))
            .collect::<Vec<_>>()
            .join(" ");
        let requires = pkg
            .requires
            .iter()
            .map(|soname| format!("{{ provides = \"{soname}\"; }}"))
            .collect::<Vec<_>>()
            .join(" ");
        let manifest = format!(
            r#"{{
  identity = {{ origin = "{origin}"; name = "{name}"; version = "{version}"; }};
  format = "extracted-tree";
  capabilities = {{ libraries = [ {libraries} ]; }};
  requires = [ {requires} ];
}}"#,
            origin = pkg.origin,
            name = pkg.name,
            version = pkg.version,
        );
        self.repo.write_manifest(&hash, &manifest).unwrap();
        self.repo
            .create_ref(pkg.origin, pkg.name, pkg.version, &hash)
            .unwrap();
        self.repo
            .update_current(pkg.origin, pkg.name, pkg.version)
            .unwrap();
        hash
    }

    fn index(&self) -> CapabilityIndex {
        let populated = CapabilityIndex::populate(&self.repo).unwrap();
        assert!(
            populated.summary.is_clean(),
            "unexpected fixture warnings: {:?}",
            populated.summary.warnings
        );
        populated.index
    }
}

const APP: &[u8] = b"#!/bin/sh\necho app\n";
const LIBSSL: &[u8] = b"ELF-archlinux-libssl.so.3";
const LIBSSL_ALT: &[u8] = b"ELF-debian-libssl.so.3";
const LIBCRYPTO: &[u8] = b"ELF-archlinux-libcrypto.so.3";
const SHIM_SSL: &[u8] = b"ELF-shim-libssl.so.3";

fn plan_with(
    world: &World,
    refs: &[CasRef],
    index: &CapabilityIndex,
    policy: &AnchorPolicy,
) -> Result<VfsPlan, ExtosError> {
    plan_from_refs_with_anchors_and_index(
        &world.repo,
        refs,
        LinkStrategy::Symlink,
        &OriginPriority::new(),
        policy,
        Some(index),
    )
}

fn labels(plan: &VfsPlan) -> Vec<String> {
    plan.promoted()
        .iter()
        .map(|candidate| candidate.label())
        .collect()
}

/// The single plan entry at `rel`, if any.
fn entry_at<'a>(plan: &'a VfsPlan, rel: &str) -> Option<&'a libextos::weaver::PlanEntry> {
    plan.entries()
        .iter()
        .find(|entry| entry.rel_path() == Path::new(rel))
}

// ─── Promotion basics ──────────────────────────────────────────

#[test]
fn index_winner_is_promoted_with_the_cas_object_and_lands_at_the_roof() {
    let world = World::new();
    world.publish(&Pkg {
        origin: "scratch",
        name: "app",
        version: "1.0",
        libraries: &[],
        requires: &["libssl.so.3"],
        files: &[("usr/bin/app", APP)],
    });
    let openssl_object = world.publish(&Pkg {
        origin: "archlinux",
        name: "openssl",
        version: "3.3.1",
        libraries: &["libssl.so.3"],
        requires: &[],
        files: &[("usr/lib/libssl.so.3", LIBSSL)],
    });

    let index = world.index();
    let plan = plan_with(
        &world,
        &[CasRef::new("scratch", "app", "1.0")],
        &index,
        &AnchorPolicy::new(),
    )
    .unwrap();

    // The winner was promoted exactly once, with the real CAS object — never a
    // re-resolved ref id (PLAN 5.2.3 MF-2 consequence).
    assert_eq!(labels(&plan), vec!["archlinux/openssl"]);
    assert_eq!(
        plan.promoted()[0].object.as_deref(),
        Some(openssl_object.as_str())
    );

    // ...and it is a normal plan package: at the roof, with the library file.
    assert!(plan.providers().iter().any(|p| p == "archlinux/openssl"));
    let lib_entry = entry_at(&plan, "usr/lib/libssl.so.3").expect("promoted library at the roof");
    assert_eq!(lib_entry.provider, "archlinux/openssl");

    // The anchor stage saw the promoted node (bids are derived after promotion).
    assert_eq!(
        plan.anchors().winner_of("libssl.so.3"),
        Some("archlinux/openssl")
    );

    // The promotion is announced, and the request is no longer unresolved.
    assert!(
        plan.warnings().iter().any(|warning| warning
            == "promoted archlinux/openssl 3.3.1 from the capability index for libssl.so.3"),
        "warnings: {:?}",
        plan.warnings()
    );
    assert!(
        !plan
            .warnings()
            .iter()
            .any(|warning| warning.contains("unresolved dependency")),
        "promotion must satisfy the request: {:?}",
        plan.warnings()
    );
}

#[test]
fn in_plan_provider_outranks_the_index_and_promotes_nothing() {
    let world = World::new();
    world.publish(&Pkg {
        origin: "scratch",
        name: "app",
        version: "1.0",
        libraries: &[],
        requires: &["libssl.so.3"],
        files: &[("usr/bin/app", APP)],
    });
    world.publish(&Pkg {
        origin: "archlinux",
        name: "openssl",
        version: "3.3.1",
        libraries: &["libssl.so.3"],
        requires: &[],
        files: &[("usr/lib/libssl.so.3", LIBSSL)],
    });

    let index = world.index();
    let plan = plan_with(
        &world,
        &[
            CasRef::new("scratch", "app", "1.0"),
            CasRef::new("archlinux", "openssl", "3.3.1"),
        ],
        &index,
        &AnchorPolicy::new(),
    )
    .unwrap();

    assert!(
        plan.promoted().is_empty(),
        "an in-plan provider must never bounce the index: {:?}",
        labels(&plan)
    );
    assert!(!plan.warnings().iter().any(|w| w.starts_with("promoted ")));
    // One claim for the library: the in-plan node's, not a duplicate promotion.
    assert_eq!(
        plan.entries()
            .iter()
            .filter(|entry| entry.rel_path() == Path::new("usr/lib/libssl.so.3"))
            .count(),
        1
    );
}

#[test]
fn promoted_packages_own_requirements_resolve_on_the_next_pass() {
    let world = World::new();
    world.publish(&Pkg {
        origin: "scratch",
        name: "app",
        version: "1.0",
        libraries: &[],
        requires: &["libssl.so.3"],
        files: &[("usr/bin/app", APP)],
    });
    world.publish(&Pkg {
        origin: "archlinux",
        name: "openssl",
        version: "3.3.1",
        libraries: &["libssl.so.3"],
        requires: &["libcrypto.so.3"],
        files: &[("usr/lib/libssl.so.3", LIBSSL)],
    });
    world.publish(&Pkg {
        origin: "archlinux",
        name: "cryptolib",
        version: "3.3.1",
        libraries: &["libcrypto.so.3"],
        requires: &[],
        files: &[("usr/lib/libcrypto.so.3", LIBCRYPTO)],
    });

    let index = world.index();
    let plan = plan_with(
        &world,
        &[CasRef::new("scratch", "app", "1.0")],
        &index,
        &AnchorPolicy::new(),
    )
    .unwrap();

    // Pass 1 promotes openssl (app's requirement); pass 2 promotes cryptolib
    // (the promoted node's own requirement) — deterministic order.
    assert_eq!(
        labels(&plan),
        vec!["archlinux/openssl", "archlinux/cryptolib"]
    );
    assert_eq!(
        entry_at(&plan, "usr/lib/libcrypto.so.3")
            .expect("transitive promoted library at the roof")
            .provider,
        "archlinux/cryptolib"
    );
    assert!(
        !plan
            .warnings()
            .iter()
            .any(|warning| warning.contains("unresolved dependency")),
        "warnings: {:?}",
        plan.warnings()
    );
}

#[test]
fn repeated_requests_promote_one_node_per_origin_name() {
    let world = World::new();
    // Duplicate request inside one manifest plus a second app asking for the
    // same SONAME: the dedup law must still yield exactly one promotion.
    world.publish(&Pkg {
        origin: "scratch",
        name: "app-one",
        version: "1.0",
        libraries: &[],
        requires: &["libssl.so.3", "libssl.so.3"],
        files: &[("usr/bin/app-one", APP)],
    });
    world.publish(&Pkg {
        origin: "scratch",
        name: "app-two",
        version: "1.0",
        libraries: &[],
        requires: &["libssl.so.3"],
        files: &[("usr/bin/app-two", APP)],
    });
    world.publish(&Pkg {
        origin: "archlinux",
        name: "openssl",
        version: "3.3.1",
        libraries: &["libssl.so.3"],
        requires: &[],
        files: &[("usr/lib/libssl.so.3", LIBSSL)],
    });

    let index = world.index();
    let refs = [
        CasRef::new("scratch", "app-one", "1.0"),
        CasRef::new("scratch", "app-two", "1.0"),
    ];
    let plan = plan_with(&world, &refs, &index, &AnchorPolicy::new()).unwrap();

    assert_eq!(labels(&plan), vec!["archlinux/openssl"]);
    assert_eq!(
        plan.warnings()
            .iter()
            .filter(|warning| warning.starts_with("promoted "))
            .count(),
        1
    );
    assert_eq!(
        plan.entries()
            .iter()
            .filter(|entry| entry.rel_path() == Path::new("usr/lib/libssl.so.3"))
            .count(),
        1,
        "a promoted node is inserted once, so its payload is claimed once"
    );

    // Re-planning the same inputs is byte-for-byte stable.
    let again = plan_with(&world, &refs, &index, &AnchorPolicy::new()).unwrap();
    assert_eq!(labels(&again), labels(&plan));
}

#[test]
fn promotion_precedes_the_virtual_fhs_so_the_roof_contains_the_library() {
    let world = World::new();
    world.publish(&Pkg {
        origin: "scratch",
        name: "app",
        version: "1.0",
        libraries: &[],
        requires: &["libssl.so.3"],
        files: &[("usr/bin/app", APP)],
    });
    world.publish(&Pkg {
        origin: "archlinux",
        name: "openssl",
        version: "3.3.1",
        libraries: &["libssl.so.3"],
        requires: &[],
        files: &[
            ("usr/lib/libssl.so.3", LIBSSL),
            ("usr/bin/openssl", b"#!/bin/sh\necho openssl\n"),
        ],
    });

    let index = world.index();
    let plan = plan_with(
        &world,
        &[CasRef::new("scratch", "app", "1.0")],
        &index,
        &AnchorPolicy::new(),
    )
    .unwrap();

    // Directory + both promoted files are materialized: proof the promoted node
    // existed when `VirtualFhs::build` ran (step order, not a post-pass).
    assert!(entry_at(&plan, "usr/lib").is_some(), "{:?}", plan.entries());
    assert!(entry_at(&plan, "usr/lib/libssl.so.3").is_some());
    assert!(entry_at(&plan, "usr/bin/openssl").is_some());
    assert!(plan.file_ops() >= 3);
}

// ─── Failure modes ─────────────────────────────────────────────

#[test]
fn a_cycle_among_promoted_packages_is_a_typed_bounded_error() {
    let world = World::new();
    world.publish(&Pkg {
        origin: "scratch",
        name: "app",
        version: "1.0",
        libraries: &[],
        requires: &["liba.so.1"],
        files: &[("usr/bin/app", APP)],
    });
    world.publish(&Pkg {
        origin: "cycle",
        name: "a",
        version: "1.0",
        libraries: &["liba.so.1"],
        requires: &["libb.so.1"],
        files: &[("usr/lib/liba.so.1", b"ELF-cycle-a")],
    });
    world.publish(&Pkg {
        origin: "cycle",
        name: "b",
        version: "1.0",
        libraries: &["libb.so.1"],
        requires: &["liba.so.1"],
        files: &[("usr/lib/libb.so.1", b"ELF-cycle-b")],
    });

    let index = world.index();
    // Returns (bounded), with the topological-sort cycle error — never a hang.
    let err = plan_with(
        &world,
        &[CasRef::new("scratch", "app", "1.0")],
        &index,
        &AnchorPolicy::new(),
    )
    .expect_err("a promoted dependency cycle must fail");

    match err {
        ExtosError::Weave(message) => {
            assert!(message.contains("cycle"), "{message}");
            assert!(message.contains("cycle/a"), "{message}");
            assert!(message.contains("cycle/b"), "{message}");
        }
        other => panic!("expected ExtosError::Weave, got {other:?}"),
    }
}

// ─── Anchor interplay (PLAN 5.2.3 doc contract) ────────────────

#[test]
fn unrelated_promotion_does_not_steal_an_anchored_soname() {
    let world = World::new();
    world.publish(&Pkg {
        origin: "scratch",
        name: "app",
        version: "1.0",
        libraries: &[],
        requires: &["libneeded.so.1"],
        files: &[("usr/bin/app", APP)],
    });
    world.publish(&Pkg {
        origin: "archlinux",
        name: "openssl",
        version: "3.3.1",
        libraries: &["libssl.so.3"],
        requires: &[],
        files: &[("usr/lib/libssl.so.3", LIBSSL)],
    });
    world.publish(&Pkg {
        origin: "debian",
        name: "libressl",
        version: "4.1",
        libraries: &["libssl.so.3"],
        requires: &[],
        files: &[("usr/lib/libssl.so.3", LIBSSL_ALT)],
    });
    // The helper answers the *unrelated* request and bids on no anchored SONAME.
    world.publish(&Pkg {
        origin: "shim",
        name: "needed",
        version: "1.0",
        libraries: &["libneeded.so.1"],
        requires: &[],
        files: &[("usr/share/shim/needed.txt", b"needed shim")],
    });

    let mut policy = AnchorPolicy::new();
    policy.declare("archlinux/openssl", 1);

    let refs = [
        CasRef::new("scratch", "app", "1.0"),
        CasRef::new("archlinux", "openssl", "3.3.1"),
        CasRef::new("debian", "libressl", "4.1"),
    ];
    let baseline = plan_from_refs_with_anchors(
        &world.repo,
        &refs,
        LinkStrategy::Symlink,
        &OriginPriority::new(),
        &policy,
    )
    .unwrap();
    let index = world.index();
    let promoted = plan_with(&world, &refs, &index, &policy).unwrap();

    // The index never decides a roof collision: the promoted helper adds no bid
    // for the anchored SONAME, so the anchor outcome is unchanged.
    assert_eq!(
        baseline.anchors().winner_of("libssl.so.3"),
        Some("archlinux/openssl")
    );
    assert_eq!(
        promoted.anchors().winner_of("libssl.so.3"),
        Some("archlinux/openssl")
    );
    assert!(labels(&promoted).iter().any(|label| label == "shim/needed"));
}

#[test]
fn a_promoted_library_bidder_competes_and_policy_decides_the_final_set() {
    let world = World::new();
    world.publish(&Pkg {
        origin: "scratch",
        name: "app",
        version: "1.0",
        libraries: &[],
        requires: &["libneeded.so.1"],
        files: &[("usr/bin/app", APP)],
    });
    world.publish(&Pkg {
        origin: "archlinux",
        name: "openssl",
        version: "3.3.1",
        libraries: &["libssl.so.3"],
        requires: &[],
        files: &[("usr/lib/libssl.so.3", LIBSSL)],
    });
    // Promoted because of `libneeded.so.1`, but it also ships libssl.so.3.
    world.publish(&Pkg {
        origin: "shim",
        name: "ssl-shim",
        version: "1.0",
        libraries: &["libneeded.so.1", "libssl.so.3"],
        requires: &[],
        files: &[
            ("usr/lib/libssl.so.3", SHIM_SSL),
            ("usr/share/shim/marker.txt", b"shim marker"),
        ],
    });

    let mut policy = AnchorPolicy::new();
    // Policy must beat the default archlinux (10) bid of openssl.
    policy.declare("shim/ssl-shim", 1);

    let index = world.index();
    let plan = plan_with(
        &world,
        &[
            CasRef::new("scratch", "app", "1.0"),
            CasRef::new("archlinux", "openssl", "3.3.1"),
        ],
        &index,
        &policy,
    )
    .unwrap();

    assert_eq!(labels(&plan), vec!["shim/ssl-shim"]);
    // Promotion added a bidder; the anchor policy — not the index — decided.
    assert_eq!(
        plan.anchors().winner_of("libssl.so.3"),
        Some("shim/ssl-shim"),
        "the anchor stage is authoritative over the final (enlarged) bid set"
    );
    assert!(
        plan.anchors().chose("libssl.so.3", "shim/ssl-shim"),
        "promoted provider must own the anchored library"
    );
    assert_eq!(
        entry_at(&plan, "usr/lib/libssl.so.3")
            .expect("anchored library at the roof")
            .provider,
        "shim/ssl-shim"
    );
    assert!(
        plan.warnings().iter().any(|warning| warning
            .contains("anchor at usr/lib/libssl.so.3 won by shim/ssl-shim")),
        "warnings: {:?}",
        plan.warnings()
    );
}

// ─── Delegate path (instanz::orchestrate) ──────────────────────

#[test]
fn no_index_delegate_promotes_nothing_and_keeps_the_old_warnings() {
    let world = World::new();
    world.publish(&Pkg {
        origin: "scratch",
        name: "app",
        version: "1.0",
        libraries: &[],
        requires: &["libssl.so.3"],
        files: &[("usr/bin/app", APP)],
    });
    world.publish(&Pkg {
        origin: "archlinux",
        name: "openssl",
        version: "3.3.1",
        libraries: &["libssl.so.3"],
        requires: &[],
        files: &[("usr/lib/libssl.so.3", LIBSSL)],
    });

    // `plan_from_refs_with_anchors` is a one-line delegate with `None`: the
    // index is never consulted even though the repository could answer.
    let plan = plan_from_refs_with_anchors(
        &world.repo,
        &[CasRef::new("scratch", "app", "1.0")],
        LinkStrategy::Symlink,
        &OriginPriority::new(),
        &AnchorPolicy::new(),
    )
    .unwrap();

    assert!(plan.promoted().is_empty());
    assert!(!plan.providers().iter().any(|p| p == "archlinux/openssl"));
    // The pre-5.2.3 behaviour is preserved: unresolved is a warning.
    assert!(
        plan.warnings()
            .iter()
            .any(|warning| warning.contains("unresolved dependency") && warning.contains("libssl.so.3")),
        "warnings: {:?}",
        plan.warnings()
    );
}
