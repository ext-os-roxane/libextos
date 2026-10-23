//! Collision resolution protocol (M6.5).
//!
//! When two packages claim the same path, the collision protocol decides:
//! 1. **Priority**: Higher-priority origin wins (configurable)
//! 2. **Tier 3 wrapper**: Generate a shim binary that selects at runtime
//! 3. **Tier 4 escalation**: Isolate into separate containers
//!
//! This module handles cases 1 and 2 (Tier 4 is deferred to M10).
//!
//! # AppDir fallback (PLAN 4.3.4)
//!
//! [`CollisionResolver::resolve_all`] is the pure, filesystem-free protocol. On
//! top of it, [`CollisionResolver::resolve_all_with_appdirs`] optionally
//! engages the Runlevel-2 AppDir provisioner (`crate::appdir`): every Tier-3
//! verdict is materialized as `<root>/<app>/{bin,lib,share,meta}` plus a
//! launcher script, and the returned [`CollisionResolution::Tier3Wrapper`] now
//! carries that real wrapper path. The hook is strictly additive — priority
//! wins, identical content and Tier-4 deferrals are passed through untouched,
//! and an already-planned wrapper for the contested path is preserved.
//!
//! # Anchor-safe replay (G-L14 N2)
//!
//! [`VfsPlan`](crate::weaver::plan::VfsPlan) exposes its collisions as
//! [`ResolvedCollision`] values, not as raw [`Collision`]s. Feeding those back
//! through [`CollisionResolver::resolve_all_with_appdirs`] would re-run
//! `CollisionResolver::resolve_one` **without** the anchor table the planner
//! used, so an anchor-decided priority win could be overwritten by a fresh
//! Tier-3 class. [`CollisionResolver::resolve_resolved_with_appdirs`] exists
//! for exactly that seam: it never re-resolves, it only materializes Tier-3
//! verdicts and passes every other verdict through verbatim.

use std::collections::HashMap;
use std::path::PathBuf;

use crate::appdir::{AppDirLayout, AppDirWrapperSpec, ProvisionedAppDir};
use crate::error::ExtosError;
use crate::weaver::vfs::Collision;

/// How a collision was resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CollisionResolution {
    /// Higher-priority origin wins; loser is dropped
    PriorityWin {
        winner: String,
        loser: String,
    },
    /// Both kept via Tier 3 wrapper shim
    Tier3Wrapper {
        wrapper_path: PathBuf,
        alternatives: Vec<String>,
    },
    /// Deferred to Tier 4 container isolation
    Tier4Deferred {
        path: PathBuf,
        claimants: Vec<String>,
    },
    /// Identical content (same hash) — no real conflict
    IdenticalContent,
}

/// Resolved collision record.
#[derive(Debug, Clone)]
pub struct ResolvedCollision {
    pub path: PathBuf,
    pub resolution: CollisionResolution,
}

/// Origin priority map: lower number = higher priority.
///
/// Default priorities:
/// - `pkt` (native ExtOS): 0
/// - `archlinux`: 10
/// - `debian`: 20
/// - `alpine`: 30
/// - everything else: 50
#[derive(Debug, Clone)]
pub struct OriginPriority {
    priorities: HashMap<String, u32>,
    default_priority: u32,
}

impl OriginPriority {
    pub fn new() -> Self {
        let mut priorities = HashMap::new();
        priorities.insert("pkt".into(), 0);
        priorities.insert("scratch".into(), 0);
        priorities.insert("archlinux".into(), 10);
        priorities.insert("arch".into(), 10);
        priorities.insert("debian".into(), 20);
        priorities.insert("ubuntu".into(), 20);
        priorities.insert("alpine".into(), 30);
        Self {
            priorities,
            default_priority: 50,
        }
    }

    /// Set priority for an origin (lower = higher priority).
    pub fn set(&mut self, origin: &str, priority: u32) {
        self.priorities.insert(origin.to_string(), priority);
    }

    /// Get priority for an origin.
    pub fn get(&self, origin: &str) -> u32 {
        // Extract origin from "origin/name" format
        let origin_part = origin.split('/').next().unwrap_or(origin);
        *self.priorities.get(origin_part).unwrap_or(&self.default_priority)
    }

    /// Compare two providers: returns the winner (lower priority number).
    pub fn winner<'a>(&self, a: &'a str, b: &'a str) -> &'a str {
        if self.get(a) <= self.get(b) { a } else { b }
    }
}

impl Default for OriginPriority {
    fn default() -> Self {
        Self::new()
    }
}

/// Collision resolver using the priority protocol.
pub struct CollisionResolver {
    priority: OriginPriority,
    /// Whether to generate Tier 3 wrappers for same-priority collisions
    enable_tier3: bool,
}

impl CollisionResolver {
    pub fn new(priority: OriginPriority) -> Self {
        Self {
            priority,
            enable_tier3: true,
        }
    }

    /// Disable Tier 3 wrapper generation (priority-only mode).
    pub fn priority_only(mut self) -> Self {
        self.enable_tier3 = false;
        self
    }

    /// Resolve all collisions in a VirtualFhs.
    pub fn resolve_all(&self, collisions: &[Collision]) -> Vec<ResolvedCollision> {
        collisions.iter().map(|c| self.resolve_one(c)).collect()
    }

    /// Resolve a single collision.
    fn resolve_one(&self, collision: &Collision) -> ResolvedCollision {
        let pri_a = self.priority.get(&collision.claimant_a);
        let pri_b = self.priority.get(&collision.claimant_b);

        let resolution = if pri_a != pri_b {
            // Different priorities: higher priority wins
            let (winner, loser) = if pri_a < pri_b {
                (collision.claimant_a.clone(), collision.claimant_b.clone())
            } else {
                (collision.claimant_b.clone(), collision.claimant_a.clone())
            };
            CollisionResolution::PriorityWin { winner, loser }
        } else if self.enable_tier3 {
            // Same priority: Tier 3 wrapper
            let wrapper_path = collision.path.with_extension("extos-wrapper");
            CollisionResolution::Tier3Wrapper {
                wrapper_path,
                alternatives: vec![
                    collision.claimant_a.clone(),
                    collision.claimant_b.clone(),
                ],
            }
        } else {
            // Tier 3 disabled: defer to container isolation
            CollisionResolution::Tier4Deferred {
                path: collision.path.clone(),
                claimants: vec![
                    collision.claimant_a.clone(),
                    collision.claimant_b.clone(),
                ],
            }
        };

        ResolvedCollision {
            path: collision.path.clone(),
            resolution,
        }
    }
}

/// Tier-3 AppDir fallback configuration (PLAN 4.3.4).
///
/// The root is caller-supplied (config, CLI or
/// [`crate::appdir::appdir_root_from_env`]); the resolver never hardcodes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppDirFallback {
    root: PathBuf,
}

impl AppDirFallback {
    /// Use `root` as the AppDir root (`<root>/<app>/...`).
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Resolve the root from `EXTOS_APPDIR_ROOT`, falling back to the
    /// documented default [`crate::appdir::DEFAULT_APPDIR_ROOT`].
    pub fn from_env() -> Self {
        Self::new(crate::appdir::appdir_root_from_env())
    }

    /// The configured AppDir root.
    pub fn root(&self) -> &std::path::Path {
        &self.root
    }
}

/// One collision resolved with the AppDir fallback engaged (PLAN 4.3.4).
#[derive(Debug, Clone)]
pub struct AppDirResolution {
    /// The protocol verdict. For materialized Tier-3 fallbacks the
    /// [`CollisionResolution::Tier3Wrapper::wrapper_path`] is the real
    /// `<root>/<app>/bin/<program>` script, not the synthetic
    /// `.extos-wrapper` placeholder.
    pub resolved: ResolvedCollision,
    /// The AppDir provisioned for this collision, if any.
    pub appdir: Option<ProvisionedAppDir>,
    /// `true` when a pre-existing wrapper for the path was honored instead of
    /// provisioning a new AppDir.
    pub kept_existing_wrapper: bool,
}

impl CollisionResolver {
    /// Resolve collisions, materializing Tier-3 verdicts as AppDirs.
    ///
    /// Semantics per contested path:
    /// 1. `resolve_one` runs first, unchanged. Non-Tier-3 verdicts are
    ///    returned verbatim — the fallback never weakens a priority win.
    /// 2. If the path has an entry in `existing_wrappers`, that wrapper path is
    ///    kept and no AppDir is provisioned (additive override).
    /// 3. Otherwise, when `fallback` is `Some`, an AppDir is provisioned for the
    ///    first claimant and a launcher is written to `<app>/bin/`. The
    ///    Tier-3 verdict's `wrapper_path` is replaced by the real script path.
    ///
    /// Provisioning is idempotent; a second run reuses the same tree and
    /// reports `created == false`.
    pub fn resolve_all_with_appdirs(
        &self,
        collisions: &[Collision],
        fallback: Option<&AppDirFallback>,
        existing_wrappers: &HashMap<PathBuf, PathBuf>,
    ) -> Result<Vec<AppDirResolution>, ExtosError> {
        let mut out = Vec::with_capacity(collisions.len());
        for collision in collisions {
            let mut resolved = self.resolve_one(collision);
            let mut appdir = None;
            let mut kept_existing_wrapper = false;

            if let CollisionResolution::Tier3Wrapper { wrapper_path, .. } =
                &mut resolved.resolution
            {
                if let Some(existing) = existing_wrappers.get(&collision.path) {
                    *wrapper_path = existing.clone();
                    kept_existing_wrapper = true;
                } else if let Some(fallback) = fallback {
                    let (provisioned, script) = provision_appdir(fallback, collision)?;
                    *wrapper_path = script;
                    appdir = Some(provisioned);
                }
            }

            out.push(AppDirResolution {
                resolved,
                appdir,
                kept_existing_wrapper,
            });
        }
        Ok(out)
    }

    /// Materialize the AppDir fallback for an **already resolved** collision
    /// list (PLAN 4.3.4; G-L14 N2).
    ///
    /// # Why this variant exists
    ///
    /// [`crate::weaver::plan::VfsPlan`] carries [`ResolvedCollision`] values. A
    /// future wiring that called [`CollisionResolver::resolve_all_with_appdirs`]
    /// on them would have to rebuild raw [`Collision`]s, and that re-runs
    /// `CollisionResolver::resolve_one` with *this* resolver's priority map —
    /// which does not know the planner's anchor table. An anchor-decided
    /// [`CollisionResolution::PriorityWin`] could silently be replaced by a
    /// fresh Tier-3 class. This entry point therefore never resolves again:
    ///
    /// 1. `PriorityWin`, `IdenticalContent` and `Tier4Deferred` verdicts are
    ///    returned untouched, and no AppDir is created for them.
    /// 2. A `Tier3Wrapper` verdict keeps its existing wrapper when
    ///    `existing_wrappers` has one for the path (the same override
    ///    semantics as [`CollisionResolver::resolve_all_with_appdirs`]).
    /// 3. Otherwise, when `fallback` is `Some`, the AppDir is provisioned from
    ///    the verdict's `alternatives` (first claimant owns it) and the
    ///    verdict's `wrapper_path` is replaced by the real launcher.
    ///
    /// The structural binding is deliberate: a Tier-3 verdict already names
    /// both claimants in `alternatives`, so the fallback inputs needed to
    /// provision are recoverable without re-running the protocol.
    pub fn resolve_resolved_with_appdirs(
        &self,
        existing: &[ResolvedCollision],
        fallback: Option<&AppDirFallback>,
        existing_wrappers: &HashMap<PathBuf, PathBuf>,
    ) -> Result<Vec<AppDirResolution>, ExtosError> {
        let mut out = Vec::with_capacity(existing.len());
        for entry in existing {
            let mut resolved = entry.clone();
            let mut appdir = None;
            let mut kept_existing_wrapper = false;

            if let CollisionResolution::Tier3Wrapper {
                wrapper_path,
                alternatives,
            } = &mut resolved.resolution
            {
                if let Some(existing_wrapper) = existing_wrappers.get(&entry.path) {
                    *wrapper_path = existing_wrapper.clone();
                    kept_existing_wrapper = true;
                } else if let Some(fallback) = fallback {
                    let collision = tier3_inputs(entry, alternatives)?;
                    let (provisioned, script) = provision_appdir(fallback, &collision)?;
                    *wrapper_path = script;
                    appdir = Some(provisioned);
                }
            }

            out.push(AppDirResolution {
                resolved,
                appdir,
                kept_existing_wrapper,
            });
        }
        Ok(out)
    }
}

/// Recover the two claimants a [`CollisionResolution::Tier3Wrapper`] verdict
/// still names, so the AppDir provisioner can run without re-resolving.
///
/// The alternatives vector is written by [`CollisionResolver::resolve_one`] in
/// claimant order (`a` then `b`), which is exactly what
/// [`provision_appdir`] expects (the first claimant owns the AppDir).
fn tier3_inputs(
    resolved: &ResolvedCollision,
    alternatives: &[String],
) -> Result<Collision, ExtosError> {
    let (claimant_a, claimant_b) = match alternatives {
        [a, b, ..] => (a.clone(), b.clone()),
        _ => {
            return Err(ExtosError::Weave(format!(
                "Tier-3 verdict for {} carries fewer than two alternatives",
                resolved.path.display()
            )));
        }
    };
    Ok(Collision {
        path: resolved.path.clone(),
        claimant_a,
        claimant_b,
    })
}

/// Provision the AppDir for a Tier-3 collision and write its launcher.
///
/// The first claimant owns the AppDir. Executable collisions (`usr/bin/<x>`,
/// single component) get a launcher that `exec`s the AppDir-local
/// `bin/<program>`; every other path (typically a conflicting SONAME under
/// `usr/lib/`) gets an environment-only launcher (`<app>/bin/<app>-env <cmd>`)
/// so the AppDir libraries win over the woven tree at runtime.
fn provision_appdir(
    fallback: &AppDirFallback,
    collision: &Collision,
) -> Result<(ProvisionedAppDir, PathBuf), ExtosError> {
    let owner = &collision.claimant_a;
    let app_id = crate::weaver::wrapper::provider_slug(owner);
    let layout = AppDirLayout::new(fallback.root(), &app_id)?;
    let provisioned = layout.provision()?;

    let is_bin_executable = collision
        .path
        .strip_prefix("usr/bin")
        .map(|rest| rest.components().count() == 1)
        .unwrap_or(false);

    let file_name = collision
        .path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| app_id.clone());

    let mut spec = if is_bin_executable {
        let program = crate::weaver::wrapper::sanitize_wrapper_name(&file_name);
        AppDirWrapperSpec::new(program.clone())
            .exec(PathBuf::from("bin").join(program))
    } else {
        AppDirWrapperSpec::new(format!("{app_id}-env"))
    };

    if file_name.contains(".so") {
        spec = spec.with_soname(file_name);
    }

    let script = layout.write_wrapper(&spec)?;
    Ok((provisioned, script))
}

// ─── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn collision(path: &str, a: &str, b: &str) -> Collision {
        Collision {
            path: PathBuf::from(path),
            claimant_a: a.into(),
            claimant_b: b.into(),
        }
    }

    #[test]
    fn test_priority_win() {
        let resolver = CollisionResolver::new(OriginPriority::new());
        let c = collision("usr/lib/libfoo.so", "archlinux/foo", "debian/foo");
        let resolved = resolver.resolve_all(&[c]);
        assert_eq!(resolved.len(), 1);
        match &resolved[0].resolution {
            CollisionResolution::PriorityWin { winner, loser } => {
                assert_eq!(winner, "archlinux/foo"); // arch=10 < debian=20
                assert_eq!(loser, "debian/foo");
            }
            _ => panic!("expected PriorityWin"),
        }
    }

    #[test]
    fn test_native_always_wins() {
        let resolver = CollisionResolver::new(OriginPriority::new());
        let c = collision("usr/bin/tool", "pkt/tool", "archlinux/tool");
        let resolved = resolver.resolve_all(&[c]);
        match &resolved[0].resolution {
            CollisionResolution::PriorityWin { winner, .. } => {
                assert_eq!(winner, "pkt/tool"); // pkt=0 < arch=10
            }
            _ => panic!("expected PriorityWin"),
        }
    }

    #[test]
    fn test_same_priority_tier3() {
        let mut prio = OriginPriority::new();
        prio.set("distro-a", 10);
        prio.set("distro-b", 10);
        let resolver = CollisionResolver::new(prio);
        let c = collision("usr/bin/tool", "distro-a/pkg", "distro-b/pkg");
        let resolved = resolver.resolve_all(&[c]);
        assert!(matches!(
            &resolved[0].resolution,
            CollisionResolution::Tier3Wrapper { .. }
        ));
    }

    #[test]
    fn test_priority_only_defers() {
        let mut prio = OriginPriority::new();
        prio.set("distro-a", 10);
        prio.set("distro-b", 10);
        let resolver = CollisionResolver::new(prio).priority_only();
        let c = collision("usr/bin/tool", "distro-a/pkg", "distro-b/pkg");
        let resolved = resolver.resolve_all(&[c]);
        assert!(matches!(
            &resolved[0].resolution,
            CollisionResolution::Tier4Deferred { .. }
        ));
    }

    #[test]
    fn test_custom_priority() {
        let mut prio = OriginPriority::new();
        prio.set("debian", 5); // promote debian above arch
        let resolver = CollisionResolver::new(prio);
        let c = collision("usr/lib/libfoo.so", "archlinux/foo", "debian/foo");
        let resolved = resolver.resolve_all(&[c]);
        match &resolved[0].resolution {
            CollisionResolution::PriorityWin { winner, .. } => {
                assert_eq!(winner, "debian/foo"); // debian=5 < arch=10
            }
            _ => panic!("expected PriorityWin"),
        }
    }

    // ─── PLAN 4.3.4: AppDir fallback ────────────────────────────

    fn same_priority_resolver() -> CollisionResolver {
        let mut prio = OriginPriority::new();
        prio.set("distro-a", 10);
        prio.set("distro-b", 10);
        CollisionResolver::new(prio)
    }

    #[test]
    fn tier3_fallback_provisions_appdir_and_returns_wrapper() {
        let tmp = tempfile::tempdir().unwrap();
        let fallback = AppDirFallback::new(tmp.path().join("runlevel/2"));
        let resolver = same_priority_resolver();
        let c = collision(
            "usr/lib/libfoo.so.1",
            "distro-a/alpha",
            "distro-b/beta",
        );

        let out = resolver
            .resolve_all_with_appdirs(&[c], Some(&fallback), &HashMap::new())
            .unwrap();
        assert_eq!(out.len(), 1);
        let appdir = out[0].appdir.as_ref().expect("AppDir provisioned");
        assert_eq!(appdir.app_id, "distro-a-alpha");
        assert!(appdir.created);
        for sub in crate::appdir::APPDIR_SUBDIRS {
            assert!(appdir.app_root.join(sub).is_dir(), "missing {sub}");
        }
        match &out[0].resolved.resolution {
            CollisionResolution::Tier3Wrapper {
                wrapper_path,
                alternatives,
            } => {
                assert_eq!(
                    wrapper_path,
                    &appdir.app_root.join("bin/distro-a-alpha-env")
                );
                assert!(wrapper_path.is_file());
                assert_eq!(alternatives.len(), 2);
            }
            other => panic!("expected Tier3Wrapper, got {other:?}"),
        }
        assert!(!out[0].kept_existing_wrapper);

        // Idempotent reprovisioning: same script path, created == false.
        let c = collision("usr/lib/libfoo.so.1", "distro-a/alpha", "distro-b/beta");
        let again = resolver
            .resolve_all_with_appdirs(&[c], Some(&fallback), &HashMap::new())
            .unwrap();
        let again_appdir = again[0].appdir.as_ref().unwrap();
        assert!(!again_appdir.created);
        assert_eq!(again_appdir.app_root, appdir.app_root);
    }

    #[test]
    fn fallback_never_touches_priority_wins() {
        let tmp = tempfile::tempdir().unwrap();
        let fallback = AppDirFallback::new(tmp.path().join("runlevel/2"));
        let resolver = CollisionResolver::new(OriginPriority::new());
        let c = collision("usr/lib/libssl.so.3", "archlinux/openssl", "debian/openssl");

        let out = resolver
            .resolve_all_with_appdirs(&[c], Some(&fallback), &HashMap::new())
            .unwrap();
        assert!(out[0].appdir.is_none());
        assert!(matches!(
            out[0].resolved.resolution,
            CollisionResolution::PriorityWin { .. }
        ));
        // No tree was created anywhere below the fallback root.
        assert!(!fallback.root().exists());
    }

    #[test]
    fn existing_wrapper_override_is_honored() {
        let tmp = tempfile::tempdir().unwrap();
        let fallback = AppDirFallback::new(tmp.path().join("runlevel/2"));
        let resolver = same_priority_resolver();
        let c = collision("usr/bin/tool", "distro-a/alpha", "distro-b/beta");
        let planned = tmp.path().join("planned/usr/bin/tool");
        let mut overrides = HashMap::new();
        overrides.insert(PathBuf::from("usr/bin/tool"), planned.clone());

        let out = resolver
            .resolve_all_with_appdirs(&[c], Some(&fallback), &overrides)
            .unwrap();
        assert!(out[0].kept_existing_wrapper);
        assert!(out[0].appdir.is_none());
        assert!(!fallback.root().exists());
        match &out[0].resolved.resolution {
            CollisionResolution::Tier3Wrapper { wrapper_path, .. } => {
                assert_eq!(wrapper_path, &planned);
            }
            other => panic!("expected Tier3Wrapper, got {other:?}"),
        }
    }

    #[test]
    fn resolved_replay_is_anchor_safe_and_only_provisions_tier3() {
        let tmp = tempfile::tempdir().unwrap();
        let fallback = AppDirFallback::new(tmp.path().join("runlevel/2"));

        // Simulates the planner output: an anchor-decided win for libA (pkt
        // beats debian) and an unresolved same-SONAME Tier-3 for libB.
        let existing = vec![
            ResolvedCollision {
                path: PathBuf::from("usr/lib/libA.so.1"),
                resolution: CollisionResolution::PriorityWin {
                    winner: "pkt/alpha".into(),
                    loser: "debian/alpha".into(),
                },
            },
            ResolvedCollision {
                path: PathBuf::from("usr/lib/libB.so.1"),
                resolution: CollisionResolution::Tier3Wrapper {
                    wrapper_path: PathBuf::from("usr/lib/libB.so.1.extos-wrapper"),
                    alternatives: vec!["distro-a/beta".into(), "distro-b/beta".into()],
                },
            },
            ResolvedCollision {
                path: PathBuf::from("usr/lib/libC.so.1"),
                resolution: CollisionResolution::IdenticalContent,
            },
        ];

        let resolver = CollisionResolver::new(OriginPriority::new());
        let out = resolver
            .resolve_resolved_with_appdirs(&existing, Some(&fallback), &HashMap::new())
            .unwrap();
        assert_eq!(out.len(), 3);

        // G-L14 N2: the anchor-decided verdict is replayed verbatim and no
        // AppDir is ever created for it (a re-resolution would know nothing
        // about the anchor).
        assert!(out[0].appdir.is_none());
        assert!(!out[0].kept_existing_wrapper);
        assert_eq!(out[0].resolved.resolution, existing[0].resolution);
        assert!(!fallback.root().join("pkt-alpha").exists());

        // Identical content passes through untouched as well.
        assert!(out[2].appdir.is_none());
        assert_eq!(out[2].resolved.resolution, CollisionResolution::IdenticalContent);

        // The unresolved Tier-3 collision is materialized exactly like
        // `resolve_all_with_appdirs` would.
        let appdir = out[1].appdir.as_ref().expect("Tier-3 AppDir provisioned");
        assert_eq!(appdir.app_id, "distro-a-beta");
        match &out[1].resolved.resolution {
            CollisionResolution::Tier3Wrapper {
                wrapper_path,
                alternatives,
            } => {
                assert_eq!(wrapper_path, &appdir.app_root.join("bin/distro-a-beta-env"));
                assert!(wrapper_path.is_file());
                assert_eq!(alternatives.len(), 2);
            }
            other => panic!("expected Tier3Wrapper, got {other:?}"),
        }

        // Only the Tier-3 appdir exists below the fallback root.
        let mut names: Vec<String> = std::fs::read_dir(fallback.root())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(names, vec!["distro-a-beta".to_string()]);
    }

    #[test]
    fn priority_only_mode_still_defers_without_provisioning() {
        let tmp = tempfile::tempdir().unwrap();
        let fallback = AppDirFallback::new(tmp.path().join("runlevel/2"));
        let resolver = same_priority_resolver().priority_only();
        let c = collision("usr/bin/tool", "distro-a/pkg", "distro-b/pkg");
        let out = resolver
            .resolve_all_with_appdirs(&[c], Some(&fallback), &HashMap::new())
            .unwrap();
        assert!(out[0].appdir.is_none());
        assert!(!fallback.root().exists());
        assert!(matches!(
            out[0].resolved.resolution,
            CollisionResolution::Tier4Deferred { .. }
        ));
    }
}
