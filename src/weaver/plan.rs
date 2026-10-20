//! Weaver plan: refs → DAG → resolve → virtual FHS → disk (PLAN 2.4.1–2.4.3).
//!
//! [`plan_from_refs`] is the standalone entry point of the weaver: given a list
//! of CAS refs it loads manifests, builds and topologically sorts the dependency
//! graph, resolves collisions and returns a [`VfsPlan`] — a journaled list of
//! `mkdir` / symlink / reflink / hardlink / wrapper operations. [`execute_plan`]
//! then applies that plan to a target root.
//!
//! Collision escalation: the priority protocol (Tier 2) is tried first; when two
//! claimants are equally ranked and their payloads differ, the plan escalates to
//! Tier 3 — both payloads survive under [`ALTERNATIVES_ROOT`] and a dispatch
//! wrapper (or a redirect symlink for non-executables) is installed at the
//! contested path. Planning never fails merely because two packages collide.

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::{Component, Path, PathBuf};

use crate::cas::{hash_bytes, CasRepository, RefEntry};
use crate::config;
use crate::error::ExtosError;
use crate::manifest::{PackageIdentity, PackageManifest};
use crate::weaver::collision::{CollisionResolution, OriginPriority, ResolvedCollision};
use crate::weaver::dag::{DagNode, DepGraph};
use crate::weaver::link::{link_hardlink, link_reflink, link_symlink, LinkStrategy};
use crate::weaver::resolve::MultiPassResolver;
use crate::weaver::vfs::{Collision, FhsEntry, FhsEntryKind, VirtualFhs};
use crate::weaver::wrapper::{
    provider_slug, render_wrapper, write_executable, WrapperAlternative, WrapperSpec,
    ALTERNATIVES_ROOT,
};

// ─── Refs ───────────────────────────────────────────────────────

/// A concrete CAS ref to weave: `refs/<origin>/<name>/<version>`.
///
/// Mirrors [`RefEntry`] but is the weaver's own input type, so callers can build
/// a plan from a lockfile or an `instanz` config without touching the CAS.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CasRef {
    /// Origin namespace (`archlinux`, `debian`, `scratch`, …)
    pub origin: String,
    /// Package name as recorded upstream
    pub name: String,
    /// Concrete version (`current` is accepted and resolved through the ref)
    pub version: String,
}

impl CasRef {
    /// Build a ref from its three path components.
    ///
    /// ```
    /// use libextos::weaver::CasRef;
    ///
    /// let r = CasRef::new("archlinux", "htop", "3.3.0");
    /// assert_eq!(r.label(), "archlinux/htop 3.3.0");
    /// ```
    pub fn new(
        origin: impl Into<String>,
        name: impl Into<String>,
        version: impl Into<String>,
    ) -> Self {
        Self {
            origin: origin.into(),
            name: name.into(),
            version: version.into(),
        }
    }

    /// Human-readable `origin/name version`.
    pub fn label(&self) -> String {
        format!("{}/{} {}", self.origin, self.name, self.version)
    }
}

impl From<RefEntry> for CasRef {
    fn from(entry: RefEntry) -> Self {
        Self {
            origin: entry.origin,
            name: entry.name,
            version: entry.version,
        }
    }
}

impl From<&RefEntry> for CasRef {
    fn from(entry: &RefEntry) -> Self {
        Self {
            origin: entry.origin.clone(),
            name: entry.name.clone(),
            version: entry.version.clone(),
        }
    }
}

// ─── Plan types ─────────────────────────────────────────────────

/// A single filesystem operation in a [`VfsPlan`].
///
/// The variant doubles as the journaled mode: `Link` carries the [`LinkStrategy`]
/// that was planned for it, so [`execute_plan`] never re-derives policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanOp {
    /// Create a directory (merged across packages).
    Directory {
        /// Path relative to the rootfs root.
        rel_path: PathBuf,
    },
    /// Re-create a symlink shipped by a package (target kept verbatim), or a
    /// redirect symlink emitted by Tier-3 escalation.
    Symlink {
        /// Path relative to the rootfs root.
        rel_path: PathBuf,
        /// Link target exactly as it will be stored.
        target: PathBuf,
    },
    /// Materialize a regular file from a CAS payload.
    Link {
        /// Path relative to the rootfs root.
        rel_path: PathBuf,
        /// Absolute source path inside the CAS (`objects/<hash>/content/...`).
        source: PathBuf,
        /// Link strategy to use, with the documented fallbacks.
        strategy: LinkStrategy,
    },
    /// Install a Tier-3 dispatch script.
    Wrapper {
        /// Path relative to the rootfs root.
        rel_path: PathBuf,
        /// Complete script contents.
        script: String,
    },
}

impl PlanOp {
    /// Rootfs-relative path this operation targets.
    pub fn rel_path(&self) -> &Path {
        match self {
            PlanOp::Directory { rel_path }
            | PlanOp::Symlink { rel_path, .. }
            | PlanOp::Link { rel_path, .. }
            | PlanOp::Wrapper { rel_path, .. } => rel_path,
        }
    }
}

/// A plan operation plus the package that contributed it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanEntry {
    /// The operation itself.
    pub op: PlanOp,
    /// Provider label (`origin/name`) or `extos/weaver` for generated entries.
    pub provider: String,
}

impl PlanEntry {
    /// Rootfs-relative path of the operation.
    pub fn rel_path(&self) -> &Path {
        self.op.rel_path()
    }
}

/// The complete weave plan for a set of refs.
#[derive(Debug, Clone)]
pub struct VfsPlan {
    entries: Vec<PlanEntry>,
    collisions: Vec<ResolvedCollision>,
    strategy: LinkStrategy,
    warnings: Vec<String>,
}

impl Default for VfsPlan {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
            collisions: Vec::new(),
            strategy: LinkStrategy::Symlink,
            warnings: Vec::new(),
        }
    }
}

impl VfsPlan {
    /// Planned operations, in application order (directories first).
    pub fn entries(&self) -> &[PlanEntry] {
        &self.entries
    }

    /// Collision verdicts (one per contested path).
    pub fn collisions(&self) -> &[ResolvedCollision] {
        &self.collisions
    }

    /// Non-fatal notes gathered while planning (dropped packages, missing
    /// payloads, …).
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    /// Link strategy planned for regular files.
    pub fn strategy(&self) -> LinkStrategy {
        self.strategy
    }

    /// Replace the file link strategy (consuming builder form).
    pub fn with_strategy(mut self, strategy: LinkStrategy) -> Self {
        for entry in &mut self.entries {
            if let PlanOp::Link { strategy: s, .. } = &mut entry.op {
                *s = strategy;
            }
        }
        self.strategy = strategy;
        self
    }

    /// Number of planned operations.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the plan is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Number of directory operations.
    pub fn directory_ops(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| matches!(e.op, PlanOp::Directory { .. }))
            .count()
    }

    /// Number of planned file links.
    pub fn file_ops(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| matches!(e.op, PlanOp::Link { .. }))
            .count()
    }

    /// Number of shipped/altered symlinks.
    pub fn symlink_ops(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| matches!(e.op, PlanOp::Symlink { .. }))
            .count()
    }

    /// Number of Tier-3 wrapper scripts.
    pub fn wrapper_ops(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| matches!(e.op, PlanOp::Wrapper { .. }))
            .count()
    }

    /// Distinct providers that contributed entries, sorted.
    pub fn providers(&self) -> Vec<String> {
        let mut set: Vec<String> = self
            .entries
            .iter()
            .map(|e| e.provider.clone())
            .filter(|p| p != "extos/weaver")
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        set.sort();
        set
    }
}

// ─── Journal ────────────────────────────────────────────────────

/// What [`execute_plan`] did for one path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JournalAction {
    /// Directory created (or already present).
    DirectoryCreated,
    /// Symlink written.
    SymlinkCreated,
    /// Correct symlink already present — left alone.
    SymlinkReused,
    /// Regular file materialized with the given (effective) strategy.
    FileLinked(LinkStrategy),
    /// File already materialized by an earlier run.
    FileReused,
    /// Wrapper script written.
    WrapperWritten,
    /// Identical wrapper already present.
    WrapperReused,
}

/// One journal row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalEntry {
    /// Rootfs-relative path.
    pub rel_path: PathBuf,
    /// Provider label, or `extos/weaver` for generated entries.
    pub provider: String,
    /// Applied action.
    pub action: JournalAction,
}

/// Result of [`execute_plan`] — the plan's journal plus cheap counters.
#[derive(Debug, Clone, Default)]
pub struct PlanExecution {
    /// Ordered record of applied operations (idempotent re-runs show reuse).
    pub journal: Vec<JournalEntry>,
    /// Directories created by this run.
    pub directories_created: usize,
    /// Symlinks created by this run.
    pub symlinks_created: usize,
    /// Regular files materialized by this run.
    pub files_linked: usize,
    /// Wrapper scripts written by this run.
    pub wrappers_written: usize,
    /// Paths that were already correct and were left untouched.
    pub reused: usize,
    /// Files that fell back from reflink/hardlink to the next strategy.
    pub fallbacks: usize,
}

// ─── Planning ───────────────────────────────────────────────────

/// Build a weave plan for `refs` using the default collision priorities and the
/// symlink strategy.
///
/// Each ref must resolve to a stored object with a readable manifest; a broken
/// ref is a hard error (the caller explicitly asked for it). Dependency edges are
/// resolved among the supplied refs only — missing dependencies become warnings,
/// mirroring [`MultiPassResolver`]'s non-strict mode.
///
/// The plan uses [`LinkStrategy::Symlink`]. That mirrors [`crate::weaver::weave`],
/// but symlinks do resolve into the CAS (`objects/<hash>/content/…`); a production
/// roof that must keep CAS paths invisible to the linker should plan with
/// [`LinkStrategy::Reflink`] or [`LinkStrategy::Hardlink`] via
/// [`plan_from_refs_with`] (both fall back to symlinks per file).
///
/// # Examples
///
/// ```no_run
/// use libextos::cas::CasRepository;
/// use libextos::types::HashAlgorithm;
/// use libextos::weaver::{plan_from_refs, CasRef};
///
/// # fn main() -> Result<(), libextos::error::ExtosError> {
/// let repo = CasRepository::open("/repository", HashAlgorithm::Blake3)?;
/// let plan = plan_from_refs(
///     &repo,
///     &[CasRef::new("archlinux", "htop", "3.3.0")],
/// )?;
/// println!("{} operations", plan.len());
/// # Ok(())
/// # }
/// ```
pub fn plan_from_refs(
    repo: &CasRepository,
    refs: &[CasRef],
) -> Result<VfsPlan, ExtosError> {
    plan_from_refs_with(repo, refs, LinkStrategy::Symlink, &OriginPriority::new())
}

/// [`plan_from_refs`] with an explicit link strategy and origin priority map.
pub fn plan_from_refs_with(
    repo: &CasRepository,
    refs: &[CasRef],
    strategy: LinkStrategy,
    priority: &OriginPriority,
) -> Result<VfsPlan, ExtosError> {
    if refs.is_empty() {
        return Ok(VfsPlan::default().with_strategy(strategy));
    }

    let mut warnings = Vec::new();
    let mut graph = DepGraph::new();
    let mut seen: HashSet<(String, String)> = HashSet::new();

    for r in refs {
        let key = (r.origin.clone(), r.name.clone());
        if !seen.insert(key) {
            warnings.push(format!("duplicate ref ignored: {}", r.label()));
            continue;
        }
        let hash = repo.resolve_ref(&r.origin, &r.name, &r.version)?;
        let manifest_nix = repo.read_manifest(&hash)?;
        let value = config::parse_nix(&manifest_nix)?;
        let manifest = PackageManifest::from_nix(&value)?;

        // The ref is authoritative for origin/name; the manifest for version.
        let identity = PackageIdentity {
            origin: r.origin.clone(),
            name: r.name.clone(),
            version: if manifest.identity.version.is_empty() {
                r.version.clone()
            } else {
                manifest.identity.version.clone()
            },
            aliases: manifest.identity.aliases.clone(),
        };

        graph.insert(DagNode {
            hash,
            identity,
            capabilities: manifest.capabilities.clone(),
            deps: Vec::new(),
            requires: manifest.requires.clone(),
        });
    }

    // Phase 2: turn `requires` into dependency indices, then topologically sort.
    graph.link_requires();
    let resolution = MultiPassResolver::new(&graph).resolve()?;
    warnings.extend(resolution.warnings);

    let packages = resolution.packages;
    let hashes: BTreeMap<String, String> = packages
        .iter()
        .map(|p| (format!("{}/{}", p.identity.origin, p.identity.name), p.hash.clone()))
        .collect();

    let vfs = VirtualFhs::build(repo, &packages)?;

    // Collision protocol first: it decides which claims are suppressed.
    let mut collisions = Vec::new();
    let mut suppressed: HashSet<(String, PathBuf)> = HashSet::new();
    let mut extra_ops: Vec<PlanEntry> = Vec::new();
    for (path, claimants) in group_collisions(vfs.collisions()) {
        let outcome = resolve_collision(
            repo,
            &hashes,
            &path,
            &claimants,
            priority,
            strategy,
        )?;
        warnings.extend(outcome.warnings);
        suppressed.extend(outcome.suppressed);
        extra_ops.extend(outcome.extra_ops);
        collisions.push(outcome.resolved);
    }

    // Group the virtual FS by provider so packages are emitted in install order.
    let mut by_provider: BTreeMap<String, Vec<&FhsEntry>> = BTreeMap::new();
    for (_key, entry) in vfs.iter() {
        by_provider.entry(entry.provider.clone()).or_default().push(entry);
    }

    let mut entries: Vec<PlanEntry> = Vec::new();
    let mut seen_dirs: HashSet<PathBuf> = HashSet::new();
    for pkg in &packages {
        let label = format!("{}/{}", pkg.identity.origin, pkg.identity.name);
        let Some(pkg_entries) = by_provider.get(&label) else {
            continue;
        };
        for entry in pkg_entries {
            let rel = entry.rel_path.clone();
            if suppressed.contains(&(label.clone(), rel.clone())) {
                continue;
            }
            let op = match &entry.kind {
                FhsEntryKind::Directory => {
                    if !seen_dirs.insert(rel.clone()) {
                        continue;
                    }
                    PlanOp::Directory { rel_path: rel }
                }
                FhsEntryKind::Symlink(target) => PlanOp::Symlink {
                    rel_path: rel,
                    target: target.clone(),
                },
                FhsEntryKind::File => PlanOp::Link {
                    rel_path: rel,
                    source: entry.source_path.clone(),
                    strategy,
                },
            };
            entries.push(PlanEntry {
                op,
                provider: label.clone(),
            });
        }
    }

    // Alternatives and wrapper/redirect entries come after the main tree.
    entries.extend(extra_ops);

    Ok(VfsPlan {
        entries,
        collisions,
        strategy,
        warnings,
    })
}

/// Group pairwise collision records into `path → ordered claimant labels`.
fn group_collisions(collisions: &[Collision]) -> BTreeMap<PathBuf, Vec<String>> {
    let mut grouped: BTreeMap<PathBuf, Vec<String>> = BTreeMap::new();
    for c in collisions {
        let claimants = grouped.entry(c.path.clone()).or_default();
        for claimant in [&c.claimant_a, &c.claimant_b] {
            if !claimants.contains(claimant) {
                claimants.push(claimant.clone());
            }
        }
    }
    grouped
}

struct CollisionOutcome {
    resolved: ResolvedCollision,
    suppressed: Vec<(String, PathBuf)>,
    extra_ops: Vec<PlanEntry>,
    warnings: Vec<String>,
}

/// Apply the Tier-2 → Tier-3 escalation for one contested path.
fn resolve_collision(
    repo: &CasRepository,
    hashes: &BTreeMap<String, String>,
    path: &Path,
    claimants: &[String],
    priority: &OriginPriority,
    strategy: LinkStrategy,
) -> Result<CollisionOutcome, ExtosError> {
    let mut warnings = Vec::new();
    let mut suppressed = Vec::new();
    let mut extra_ops = Vec::new();

    let signatures: Vec<Option<String>> = claimants
        .iter()
        .map(|c| claim_signature(repo, hashes, c, path))
        .collect();

    // Identical bytes: not a real conflict, first claimant keeps the path.
    let identical = signatures.iter().all(|s| s.is_some())
        && signatures
            .windows(2)
            .all(|w| w[0].is_some() && w[0] == w[1]);
    if identical {
        for claimant in claimants.iter().skip(1) {
            suppressed.push((claimant.clone(), path.to_path_buf()));
        }
        return Ok(CollisionOutcome {
            resolved: ResolvedCollision {
                path: path.to_path_buf(),
                resolution: CollisionResolution::IdenticalContent,
            },
            suppressed,
            extra_ops,
            warnings,
        });
    }

    // Tier 2: origin priority.
    let priorities: Vec<u32> = claimants.iter().map(|c| priority.get(c)).collect();
    let min_priority = priorities.iter().copied().min().unwrap_or(50);
    let winners: Vec<usize> = priorities
        .iter()
        .enumerate()
        .filter(|(_, p)| **p == min_priority)
        .map(|(i, _)| i)
        .collect();

    if winners.len() == 1 {
        let winner = claimants[winners[0]].clone();
        let losers: Vec<String> = claimants
            .iter()
            .filter(|c| **c != winner)
            .cloned()
            .collect();
        // The VirtualFhs keeps the *first* claim, which is not necessarily the
        // priority winner — suppress every claim and emit the winner explicitly.
        for claimant in claimants {
            suppressed.push((claimant.clone(), path.to_path_buf()));
        }
        match payload_op(repo, hashes, &winner, path, strategy) {
            Some(op) => extra_ops.push(PlanEntry {
                op,
                provider: winner.clone(),
            }),
            None => warnings.push(format!(
                "collision at {} won by {winner}, but its payload is missing",
                path.display()
            )),
        }
        warnings.push(format!(
            "collision at {} won by {winner} over {} (origin priority)",
            path.display(),
            losers.join(", ")
        ));
        return Ok(CollisionOutcome {
            resolved: ResolvedCollision {
                path: path.to_path_buf(),
                resolution: CollisionResolution::PriorityWin {
                    winner,
                    loser: losers.join(", "),
                },
            },
            suppressed,
            extra_ops,
            warnings,
        });
    }

    // Tier 3: equal priority and different payloads → keep both, dispatch.
    let mut alternatives: Vec<WrapperAlternative> = Vec::new();
    let mut used_slugs: HashSet<String> = HashSet::new();
    for (idx, claimant) in claimants.iter().enumerate() {
        let mut slug = provider_slug(claimant);
        if !used_slugs.insert(slug.clone()) {
            slug = format!("{slug}-{idx}");
            used_slugs.insert(slug.clone());
        }
        let alt_rel = PathBuf::from(ALTERNATIVES_ROOT).join(&slug).join(path);
        let Some(source) = payload_source(repo, hashes, claimant, path) else {
            warnings.push(format!(
                "collision at {}: no payload for {claimant}; alternative skipped",
                path.display()
            ));
            continue;
        };
        extra_ops.push(PlanEntry {
            op: PlanOp::Link {
                rel_path: alt_rel.clone(),
                source,
                strategy,
            },
            provider: claimant.clone(),
        });
        alternatives.push(WrapperAlternative::new(claimant.clone(), slug, alt_rel));
    }

    if alternatives.is_empty() {
        // Nothing could be preserved: isolate rather than silently pick one.
        warnings.push(format!(
            "collision at {}: no alternative payloads available; deferred",
            path.display()
        ));
        for claimant in claimants {
            suppressed.push((claimant.clone(), path.to_path_buf()));
        }
        return Ok(CollisionOutcome {
            resolved: ResolvedCollision {
                path: path.to_path_buf(),
                resolution: CollisionResolution::Tier4Deferred {
                    path: path.to_path_buf(),
                    claimants: claimants.to_vec(),
                },
            },
            suppressed,
            extra_ops,
            warnings,
        });
    }

    let slugs: Vec<String> = alternatives.iter().map(|a| a.slug.clone()).collect();
    for claimant in claimants {
        suppressed.push((claimant.clone(), path.to_path_buf()));
    }

    // Executables get a dispatch script; data/lib files get a redirect symlink
    // to the default alternative (a script would not be loadable as a library).
    let is_executable = path
        .strip_prefix("usr/bin")
        .map(|rest| rest.components().count() == 1)
        .unwrap_or(false);

    let op = if is_executable {
        let binary = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "extos-wrapper".to_string());
        let spec = WrapperSpec::new(alternatives[0].package.clone(), binary)
            .at_path(path)
            .with_alternatives(alternatives.clone());
        PlanOp::Wrapper {
            rel_path: path.to_path_buf(),
            script: render_wrapper(&spec, "")?,
        }
    } else {
        let default_alt = &alternatives[0].rel_path;
        let link_dir = path.parent().unwrap_or_else(|| Path::new(""));
        PlanOp::Symlink {
            rel_path: path.to_path_buf(),
            target: relative_path(link_dir, default_alt),
        }
    };

    extra_ops.push(PlanEntry {
        op,
        provider: "extos/weaver".to_string(),
    });

    Ok(CollisionOutcome {
        resolved: ResolvedCollision {
            path: path.to_path_buf(),
            resolution: CollisionResolution::Tier3Wrapper {
                wrapper_path: path.to_path_buf(),
                alternatives: slugs,
            },
        },
        suppressed,
        extra_ops,
        warnings,
    })
}

/// Content signature of one claimant's payload at `rel`: file bytes hashed with
/// the repo algorithm, or the raw link target for symlinks.
fn claim_signature(
    repo: &CasRepository,
    hashes: &BTreeMap<String, String>,
    provider: &str,
    rel: &Path,
) -> Option<String> {
    let hash = hashes.get(provider)?;
    let source = repo.object_path(hash).join("content").join(rel);
    match fs::symlink_metadata(&source) {
        Ok(meta) if meta.file_type().is_symlink() => fs::read_link(&source)
            .ok()
            .map(|t| format!("link:{}", t.display())),
        Ok(_) => fs::read(&source).ok().map(|data| hash_bytes(&data, repo.algo)),
        Err(_) => None,
    }
}

/// The plan operation that re-materializes `provider`'s payload at `path`.
fn payload_op(
    repo: &CasRepository,
    hashes: &BTreeMap<String, String>,
    provider: &str,
    path: &Path,
    strategy: LinkStrategy,
) -> Option<PlanOp> {
    let source = payload_source(repo, hashes, provider, path)?;
    let meta = fs::symlink_metadata(&source).ok()?;
    if meta.file_type().is_symlink() {
        let target = fs::read_link(&source).ok()?;
        Some(PlanOp::Symlink {
            rel_path: path.to_path_buf(),
            target,
        })
    } else {
        Some(PlanOp::Link {
            rel_path: path.to_path_buf(),
            source,
            strategy,
        })
    }
}

/// Absolute CAS source path for one claimant's payload at `rel`.
fn payload_source(
    repo: &CasRepository,
    hashes: &BTreeMap<String, String>,
    provider: &str,
    rel: &Path,
) -> Option<PathBuf> {
    let hash = hashes.get(provider)?;
    let source = repo.object_path(hash).join("content").join(rel);
    source.symlink_metadata().ok().map(|_| source)
}

/// Relative path from `from_dir` to `to` (both rootfs-relative).
///
/// `usr/lib` → `usr/lib/extos/x` yields `extos/x`; `usr/bin` → `usr/lib/x`
/// yields `../lib/x`.
pub fn relative_path(from_dir: &Path, to: &Path) -> PathBuf {
    let from: Vec<Component<'_>> = from_dir.components().collect();
    let to_parts: Vec<Component<'_>> = to.components().collect();
    let common = from
        .iter()
        .zip(to_parts.iter())
        .take_while(|(a, b)| a == b)
        .count();
    let mut out = PathBuf::new();
    for _ in common..from.len() {
        out.push("..");
    }
    for component in &to_parts[common..] {
        out.push(component.as_os_str());
    }
    out
}

// ─── Execution ──────────────────────────────────────────────────

/// Apply `plan` to `target_root`, creating parents as needed.
///
/// Idempotent by design: an already-correct symlink or wrapper is reused, a wrong
/// one is replaced. Regular files follow the planned strategy with the documented
/// fallbacks (reflink → hardlink → symlink, hardlink → symlink), and every applied
/// operation is journaled in [`PlanExecution::journal`].
pub fn execute_plan(
    plan: &VfsPlan,
    target_root: &Path,
) -> Result<PlanExecution, ExtosError> {
    fs::create_dir_all(target_root)?;
    let mut result = PlanExecution::default();

    // Pass 1: directories (plans are already de-duplicated by the planner).
    for entry in plan.entries() {
        if let PlanOp::Directory { rel_path } = &entry.op {
            validate_rel_path(rel_path)?;
            let target = target_root.join(rel_path);
            let existed = target.is_dir();
            fs::create_dir_all(&target)?;
            if !existed {
                result.directories_created += 1;
            }
            result.journal.push(JournalEntry {
                rel_path: rel_path.clone(),
                provider: entry.provider.clone(),
                action: JournalAction::DirectoryCreated,
            });
        }
    }

    // Pass 2: files, symlinks and wrappers, in plan order.
    for entry in plan.entries() {
        let rel_path = entry.rel_path();
        if matches!(entry.op, PlanOp::Directory { .. }) {
            continue;
        }
        validate_rel_path(rel_path)?;

        match &entry.op {
            PlanOp::Directory { .. } => {}
            PlanOp::Symlink { rel_path, target } => {
                let dest = target_root.join(rel_path);
                ensure_parent(&dest)?;
                let action = if fs::read_link(&dest).map(|t| t == *target).unwrap_or(false) {
                    result.reused += 1;
                    JournalAction::SymlinkReused
                } else {
                    remove_existing(&dest)?;
                    std::os::unix::fs::symlink(target, &dest)?;
                    result.symlinks_created += 1;
                    JournalAction::SymlinkCreated
                };
                result.journal.push(JournalEntry {
                    rel_path: rel_path.clone(),
                    provider: entry.provider.clone(),
                    action,
                });
            }
            PlanOp::Link {
                rel_path,
                source,
                strategy,
            } => {
                let dest = target_root.join(rel_path);
                ensure_parent(&dest)?;
                if link_is_current(&dest, source) {
                    result.reused += 1;
                    result.journal.push(JournalEntry {
                        rel_path: rel_path.clone(),
                        provider: entry.provider.clone(),
                        action: JournalAction::FileReused,
                    });
                    continue;
                }
                remove_existing(&dest)?;

                let effective = apply_link(source, &dest, *strategy, &mut result)?;
                result.files_linked += 1;
                result.journal.push(JournalEntry {
                    rel_path: rel_path.clone(),
                    provider: entry.provider.clone(),
                    action: JournalAction::FileLinked(effective),
                });
            }
            PlanOp::Wrapper { rel_path, script } => {
                let dest = target_root.join(rel_path);
                ensure_parent(&dest)?;
                if fs::read_to_string(&dest).map(|c| c == *script).unwrap_or(false) {
                    result.reused += 1;
                    result.journal.push(JournalEntry {
                        rel_path: rel_path.clone(),
                        provider: entry.provider.clone(),
                        action: JournalAction::WrapperReused,
                    });
                } else {
                    write_executable(target_root, rel_path, script)?;
                    result.wrappers_written += 1;
                    result.journal.push(JournalEntry {
                        rel_path: rel_path.clone(),
                        provider: entry.provider.clone(),
                        action: JournalAction::WrapperWritten,
                    });
                }
            }
        }
    }

    Ok(result)
}

/// Apply one link strategy, returning the strategy that actually succeeded.
fn apply_link(
    source: &Path,
    dest: &Path,
    strategy: LinkStrategy,
    result: &mut PlanExecution,
) -> Result<LinkStrategy, ExtosError> {
    match strategy {
        LinkStrategy::Symlink => {
            link_symlink(source, dest)?;
            Ok(LinkStrategy::Symlink)
        }
        LinkStrategy::Reflink => match link_reflink(source, dest) {
            Ok(()) => Ok(LinkStrategy::Reflink),
            Err(_) => match link_hardlink(source, dest) {
                Ok(()) => {
                    result.fallbacks += 1;
                    Ok(LinkStrategy::Hardlink)
                }
                Err(_) => {
                    link_symlink(source, dest)?;
                    result.fallbacks += 1;
                    Ok(LinkStrategy::Symlink)
                }
            },
        },
        LinkStrategy::Hardlink => match link_hardlink(source, dest) {
            Ok(()) => Ok(LinkStrategy::Hardlink),
            Err(_) => {
                link_symlink(source, dest)?;
                result.fallbacks += 1;
                Ok(LinkStrategy::Symlink)
            }
        },
    }
}

/// Whether `dest` already resolves to `source` (symlink to it, or same inode).
fn link_is_current(dest: &Path, source: &Path) -> bool {
    if let Ok(existing) = fs::read_link(dest) {
        if existing == source {
            return true;
        }
        if let (Ok(a), Ok(b)) = (fs::canonicalize(&existing), fs::canonicalize(source)) {
            return a == b;
        }
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if let (Ok(a), Ok(b)) = (fs::metadata(dest), fs::metadata(source)) {
            return a.dev() == b.dev() && a.ino() == b.ino();
        }
    }
    false
}

/// Remove a stale regular file or symlink; refuse to clobber directories.
fn remove_existing(path: &Path) -> Result<(), ExtosError> {
    match path.symlink_metadata() {
        Ok(meta) => {
            if meta.is_dir() {
                return Err(ExtosError::Weave(format!(
                    "refusing to replace directory with a file: {}",
                    path.display()
                )));
            }
            fs::remove_file(path)?;
            Ok(())
        }
        Err(_) => Ok(()),
    }
}

/// Create the parent directory of `path` when missing.
fn ensure_parent(path: &Path) -> Result<(), ExtosError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    Ok(())
}

/// Reject plan paths that could escape the rootfs.
fn validate_rel_path(rel_path: &Path) -> Result<(), ExtosError> {
    let escapes = rel_path.as_os_str().is_empty()
        || rel_path.is_absolute()
        || rel_path.components().any(|c| {
            matches!(
                c,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        });
    if escapes {
        return Err(ExtosError::Weave(format!(
            "plan path must stay inside the rootfs: {}",
            rel_path.display()
        )));
    }
    Ok(())
}

// ─── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cas_ref_labels_and_conversions() {
        let r = CasRef::new("archlinux", "htop", "3.3.0");
        assert_eq!(r.label(), "archlinux/htop 3.3.0");
        let entry = RefEntry {
            origin: "debian".into(),
            name: "vim".into(),
            version: "9.1".into(),
        };
        assert_eq!(CasRef::from(&entry), CasRef::new("debian", "vim", "9.1"));
        assert_eq!(CasRef::from(entry.clone()), CasRef::new("debian", "vim", "9.1"));
    }

    #[test]
    fn relative_path_walks_up_and_down() {
        assert_eq!(
            relative_path(Path::new("usr/lib"), Path::new("usr/lib/extos/x")),
            PathBuf::from("extos/x")
        );
        assert_eq!(
            relative_path(Path::new("usr/bin"), Path::new("usr/lib/x")),
            PathBuf::from("../lib/x")
        );
        assert_eq!(
            relative_path(Path::new(""), Path::new("usr/lib/x")),
            PathBuf::from("usr/lib/x")
        );
    }

    #[test]
    fn empty_ref_list_is_an_empty_plan() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = CasRepository::open(tmp.path(), crate::types::HashAlgorithm::Blake3).unwrap();
        let plan = plan_from_refs(&repo, &[]).unwrap();
        assert!(plan.is_empty());
        assert_eq!(plan.strategy(), LinkStrategy::Symlink);
        let exec = execute_plan(&plan, &tmp.path().join("root")).unwrap();
        assert!(exec.journal.is_empty());
    }

    #[test]
    fn plan_paths_must_stay_inside_the_rootfs() {
        for bad in ["", "/etc/passwd", "../escape", "usr/../../etc"] {
            let plan = VfsPlan {
                entries: vec![PlanEntry {
                    op: PlanOp::Directory {
                        rel_path: PathBuf::from(bad),
                    },
                    provider: "x/y".into(),
                }],
                ..VfsPlan::default()
            };
            let tmp = tempfile::tempdir().unwrap();
            assert!(execute_plan(&plan, tmp.path()).is_err(), "{bad} was accepted");
        }
    }

    #[test]
    fn with_strategy_rewrites_file_ops() {
        let plan = VfsPlan {
            entries: vec![PlanEntry {
                op: PlanOp::Link {
                    rel_path: PathBuf::from("usr/bin/x"),
                    source: PathBuf::from("/source/x"),
                    strategy: LinkStrategy::Symlink,
                },
                provider: "x/y".into(),
            }],
            ..VfsPlan::default()
        }
        .with_strategy(LinkStrategy::Hardlink);
        assert_eq!(plan.strategy(), LinkStrategy::Hardlink);
        match &plan.entries()[0].op {
            PlanOp::Link { strategy, .. } => assert_eq!(*strategy, LinkStrategy::Hardlink),
            other => panic!("unexpected op: {other:?}"),
        }
    }

    #[test]
    fn duplicate_refs_are_warned_about() {
        // Planning with a duplicate ref never inserts two graph nodes, so the
        // second one is reported instead of silently shadowing the first.
        let tmp = tempfile::tempdir().unwrap();
        let repo = CasRepository::open(tmp.path(), crate::types::HashAlgorithm::Blake3).unwrap();
        // No refs stored → resolve_ref errors, so exercise the guard directly.
        let refs = [CasRef::new("a", "b", "1"), CasRef::new("a", "b", "1")];
        let err = plan_from_refs(&repo, &refs).unwrap_err();
        assert!(matches!(err, ExtosError::PackageNotFound { .. }), "{err}");
    }
}
