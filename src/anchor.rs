//! SONAME anchor bidding for weave planning (PLAN task 4.1.3).
//!
//! Several CAS packages can provide the same shared-object name (`SONAME`): an
//! Arch `glibc`, a Debian `libc6`, a `scratch` compatibility shim. A woven roof
//! must resolve that file to exactly one of them, deterministically, so the
//! linker sees a stable provider across generations.
//!
//! # Bidding model
//!
//! Each planned provider *bids* for a SONAME it ships. A bid carries:
//!
//! * the SONAME (e.g. `libssl.so.3`),
//! * the provider label (`origin/name`),
//! * the provider's origin and the concrete ref version,
//! * the in-roof path of the library file,
//! * a priority (`u32`, lower wins — the same polarity as
//!   [`crate::weaver::OriginPriority`]).
//!
//! [`AnchorPolicy`] declares priorities: per-provider overrides first, then the
//! origin defaults from [`OriginPriority`]. The winner is the lowest-ranked bid
//! under the following total order (all steps documented, all deterministic):
//!
//! 1. **priority** — lower number wins;
//! 2. **origin** — ascending lexicographic origin name;
//! 3. **version** — descending [`compare_versions`] order: the newest ref wins,
//!    compared numerically so `2.10` outranks `2.9`;
//! 4. **provider** — ascending label, then path, which makes the order total
//!    even for pathological duplicate bids.
//!
//! # Scope boundary (Phase 5)
//!
//! This module is *in-plan* bidding only: it never reads or writes a `.lock`
//! file and it has no memory across `instanz apply` runs. Phase 5.1 formalizes
//! the lockfile that pins these outcomes for reproducibility; until then the
//! bidding inputs are exactly "the refs being woven + the capabilities their
//! manifests declare", as required by PLAN 4.1.3.
//!
//! # Examples
//!
//! ```
//! use libextos::anchor::{AnchorBid, AnchorPolicy, AnchorTable};
//!
//! let bids = vec![
//!     AnchorBid::new("libssl.so.3", "debian/openssl", "debian", "3.0.13", "usr/lib/libssl.so.3"),
//!     AnchorBid::new("libssl.so.3", "archlinux/openssl", "archlinux", "3.3.1", "usr/lib/libssl.so.3"),
//! ];
//! let table = AnchorTable::from_bids(&bids, &AnchorPolicy::new());
//! // OriginPriority ranks archlinux (10) above debian (20).
//! assert_eq!(table.winner_of("libssl.so.3"), Some("archlinux/openssl"));
//! ```

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::error::ExtosError;
use crate::manifest::Capabilities;
use crate::weaver::OriginPriority;

/// Priority assumed when a policy declares nothing for a provider/origin.
///
/// `50` matches [`OriginPriority`]'s default for unknown origins.
pub const DEFAULT_PRIORITY: u32 = 50;

/// In-roof directory scanned for anchored libraries.
const LIB_PREFIX: &str = "usr/lib/";

// ─── Bids ───────────────────────────────────────────────────────

/// One bid by one provider for one SONAME.
///
/// Bids are values: they can be built from manifests (see
/// [`AnchorBid::from_capabilities`]) or injected by a caller that knows the
/// exact in-roof path of a library file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorBid {
    /// Shared-object name being claimed (`libssl.so.3`).
    pub soname: String,
    /// Provider label, `origin/name`.
    pub provider: String,
    /// Origin namespace of the provider.
    pub origin: String,
    /// Concrete ref version of the provider (never `current` in a bid).
    pub version: String,
    /// Path of the library file relative to the roof root.
    pub path: PathBuf,
    /// Priority: lower wins. Use [`AnchorPolicy::priority_of`] to derive it.
    pub priority: u32,
}

impl AnchorBid {
    /// A bid at [`DEFAULT_PRIORITY`].
    pub fn new(
        soname: impl Into<String>,
        provider: impl Into<String>,
        origin: impl Into<String>,
        version: impl Into<String>,
        path: impl Into<PathBuf>,
    ) -> Self {
        Self {
            soname: soname.into(),
            provider: provider.into(),
            origin: origin.into(),
            version: version.into(),
            path: path.into(),
            priority: DEFAULT_PRIORITY,
        }
    }

    /// Same bid at an explicit priority (lower wins).
    pub fn with_priority(mut self, priority: u32) -> Self {
        self.priority = priority;
        self
    }

    /// Convenience: the usual in-roof location of a SONAME.
    pub fn default_path(soname: &str) -> PathBuf {
        PathBuf::from(format!("{LIB_PREFIX}{soname}"))
    }

    /// Build one bid per declared library capability of a package.
    ///
    /// The path is [`AnchorBid::default_path`]: manifests declare SONAMEs, not
    /// file locations, so the conventional `usr/lib/<soname>` is assumed. A
    /// planner that knows the real location (e.g. from the virtual FHS) should
    /// override [`AnchorBid::path`] before bidding.
    pub fn from_capabilities(
        provider: &str,
        origin: &str,
        version: &str,
        capabilities: &Capabilities,
    ) -> Vec<Self> {
        capabilities
            .libraries
            .iter()
            .map(|soname| {
                Self::new(
                    soname,
                    provider,
                    origin,
                    version,
                    Self::default_path(soname),
                )
            })
            .collect()
    }
}

// ─── Policy ─────────────────────────────────────────────────────

/// Declared priorities for anchor bidding.
///
/// A per-provider override (`"debian/openssl" → 5`) beats the origin default
/// taken from [`OriginPriority`] (`debian → 20`), which beats
/// [`DEFAULT_PRIORITY`] (`50`).
#[derive(Debug, Clone)]
pub struct AnchorPolicy {
    origins: OriginPriority,
    overrides: BTreeMap<String, u32>,
}

impl Default for AnchorPolicy {
    fn default() -> Self {
        Self::new()
    }
}

impl AnchorPolicy {
    /// Policy with the standard origin priorities and no overrides.
    pub fn new() -> Self {
        Self {
            origins: OriginPriority::new(),
            overrides: BTreeMap::new(),
        }
    }

    /// Policy wrapping a caller-provided origin priority map.
    pub fn with_origin_priority(origins: OriginPriority) -> Self {
        Self {
            origins,
            overrides: BTreeMap::new(),
        }
    }

    /// Declare a priority for one provider label (`origin/name`); lower wins.
    pub fn declare(&mut self, provider: impl Into<String>, priority: u32) -> &mut Self {
        self.overrides.insert(provider.into(), priority);
        self
    }

    /// Declare a default priority for an origin; lower wins.
    pub fn declare_origin(&mut self, origin: impl Into<String>, priority: u32) -> &mut Self {
        self.origins.set(&origin.into(), priority);
        self
    }

    /// Priority for a provider: override → origin default → 50.
    pub fn priority_of(&self, provider: &str) -> u32 {
        if let Some(priority) = self.overrides.get(provider) {
            return *priority;
        }
        let origin = provider.split('/').next().unwrap_or(provider);
        self.origins.get(origin)
    }

    /// Apply this policy to `bids`, rewriting every bid's priority.
    pub fn apply(&self, bids: &mut [AnchorBid]) {
        for bid in bids.iter_mut() {
            bid.priority = self.priority_of(&bid.provider);
        }
    }
}

// ─── Choices ────────────────────────────────────────────────────

/// The winning bid for one SONAME, plus the bids that lost.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorChoice {
    /// SONAME that was bid for.
    pub soname: String,
    /// Winning provider label.
    pub winner: String,
    /// Winning priority.
    pub priority: u32,
    /// Winning library path (roof-relative).
    pub path: PathBuf,
    /// Every bid for this SONAME, best-ranked first.
    pub bids: Vec<AnchorBid>,
}

impl AnchorChoice {
    /// Labels of the bids that lost, in ranked order.
    pub fn losers(&self) -> Vec<String> {
        self.bids
            .iter()
            .skip(1)
            .map(|bid| bid.provider.clone())
            .collect()
    }

    /// Whether `provider` is the anchored winner.
    pub fn is_winner(&self, provider: &str) -> bool {
        self.provider_of_winner() == provider
    }

    fn provider_of_winner(&self) -> &str {
        &self.bids[0].provider
    }
}

/// All anchor decisions made for one weave plan.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AnchorTable {
    choices: BTreeMap<String, AnchorChoice>,
}

impl AnchorTable {
    /// An empty table (a plan with no library capabilities).
    pub fn empty() -> Self {
        Self::default()
    }

    /// Bid for a set of SONAMEs and keep the winners.
    ///
    /// Priorities are taken from each bid's `priority` field; use
    /// [`AnchorPolicy::apply`] first to derive them from a policy. This never
    /// fails: ties are broken by the documented total order, and a SONAME with
    /// a single bid is simply anchored to it.
    pub fn from_bids(bids: &[AnchorBid], _policy: &AnchorPolicy) -> Self {
        let mut grouped: BTreeMap<&str, Vec<AnchorBid>> = BTreeMap::new();
        for bid in bids {
            if bid.soname.trim().is_empty() || bid.provider.trim().is_empty() {
                continue;
            }
            grouped.entry(bid.soname.as_str()).or_default().push(bid.clone());
        }

        let mut choices = BTreeMap::new();
        for (soname, mut bids) in grouped {
            sort_bids(&mut bids);
            let winner = bids[0].clone();
            choices.insert(
                soname.to_string(),
                AnchorChoice {
                    soname: soname.to_string(),
                    winner: winner.provider.clone(),
                    priority: winner.priority,
                    path: winner.path.clone(),
                    bids,
                },
            );
        }
        Self { choices }
    }

    /// Resolve one SONAME against `bids`; a missing provider is a typed error.
    ///
    /// `Err(ExtosError::DependencyUnresolvable)` is returned when no bid carries
    /// `soname`, so a caller that *requires* the anchor never silently proceeds
    /// with an unanchored library.
    pub fn resolve(
        soname: &str,
        bids: &[AnchorBid],
        _policy: &AnchorPolicy,
    ) -> Result<AnchorChoice, ExtosError> {
        let mut matching: Vec<AnchorBid> = bids
            .iter()
            .filter(|bid| bid.soname == soname)
            .cloned()
            .collect();
        if matching.is_empty() {
            return Err(ExtosError::DependencyUnresolvable(format!(
                "anchor: no provider bids for SONAME {soname}"
            )));
        }
        sort_bids(&mut matching);
        let winner = matching[0].clone();
        Ok(AnchorChoice {
            soname: soname.to_string(),
            winner: winner.provider,
            priority: winner.priority,
            path: winner.path,
            bids: matching,
        })
    }

    /// Decision for `soname`, if anything bid for it.
    pub fn get(&self, soname: &str) -> Option<&AnchorChoice> {
        self.choices.get(soname)
    }

    /// Winning provider label for `soname`.
    pub fn winner_of(&self, soname: &str) -> Option<&str> {
        self.choices.get(soname).map(|c| c.winner.as_str())
    }

    /// Winning path for `soname`.
    pub fn path_of(&self, soname: &str) -> Option<&Path> {
        self.choices.get(soname).map(|c| c.path.as_path())
    }

    /// Whether `provider` won the anchor for `soname`.
    pub fn chose(&self, soname: &str, provider: &str) -> bool {
        self.winner_of(soname) == Some(provider)
    }

    /// Anchor decision covering the file name of `rel_path`, if any.
    ///
    /// This is the lookup the weaver uses to detect that a contested path is a
    /// library with a declared anchor: `usr/lib/libssl.so.3` asks for the
    /// `libssl.so.3` decision.
    pub fn for_library_path(&self, rel_path: &Path) -> Option<&AnchorChoice> {
        let name = rel_path.file_name()?.to_str()?;
        self.choices.get(name)
    }

    /// Number of anchored SONAMEs.
    pub fn len(&self) -> usize {
        self.choices.len()
    }

    /// Whether no SONAME was bid for.
    pub fn is_empty(&self) -> bool {
        self.choices.is_empty()
    }

    /// Decisions in SONAME order.
    pub fn choices(&self) -> impl Iterator<Item = &AnchorChoice> {
        self.choices.values()
    }
}

// ─── Ranking ────────────────────────────────────────────────────

/// Sort bids best-first by the documented total order.
fn sort_bids(bids: &mut [AnchorBid]) {
    bids.sort_by(|a, b| {
        a.priority
            .cmp(&b.priority)
            .then_with(|| a.origin.cmp(&b.origin))
            // Newest version wins: reverse the numeric-aware comparison.
            .then_with(|| compare_versions(&b.version, &a.version))
            .then_with(|| a.provider.cmp(&b.provider))
            .then_with(|| a.path.cmp(&b.path))
    });
}

/// Compare two version strings with digit runs compared numerically.
///
/// `2.9 < 2.10`, `1.0 == 1.0`, `1.0~rc1 < 1.0` is **not** modelled (no tilde
/// handling; the strings are only a tiebreak, never a dependency decision).
/// Numeric runs are compared as unbounded decimal integers so long upstream
/// versions cannot overflow.
pub fn compare_versions(a: &str, b: &str) -> std::cmp::Ordering {
    use std::cmp::Ordering;

    let a_tokens = tokenize_version(a);
    let b_tokens = tokenize_version(b);
    for (left, right) in a_tokens.iter().zip(b_tokens.iter()) {
        let ordering = match (left, right) {
            (VersionToken::Number(x), VersionToken::Number(y)) => compare_numeric(x, y),
            (VersionToken::Text(x), VersionToken::Text(y)) => x.cmp(y),
            // A numeric run sorts after text so `a1` < `a.b` is stable anyway.
            (VersionToken::Number(_), VersionToken::Text(_)) => Ordering::Greater,
            (VersionToken::Text(_), VersionToken::Number(_)) => Ordering::Less,
        };
        if ordering != Ordering::Equal {
            return ordering;
        }
    }
    a_tokens.len().cmp(&b_tokens.len())
}

#[derive(Debug, PartialEq, Eq)]
enum VersionToken {
    Number(String),
    Text(String),
}

fn tokenize_version(version: &str) -> Vec<VersionToken> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut numeric = None::<bool>;
    for ch in version.chars() {
        let is_digit = ch.is_ascii_digit();
        if numeric == Some(is_digit) {
            current.push(ch);
            continue;
        }
        if let Some(was_numeric) = numeric {
            tokens.push(if was_numeric {
                VersionToken::Number(std::mem::take(&mut current))
            } else {
                VersionToken::Text(std::mem::take(&mut current))
            });
        }
        numeric = Some(is_digit);
        current.push(ch);
    }
    if let Some(was_numeric) = numeric {
        tokens.push(if was_numeric {
            VersionToken::Number(current)
        } else {
            VersionToken::Text(current)
        });
    }
    tokens
}

/// Compare two decimal strings of arbitrary length without parsing them.
fn compare_numeric(a: &str, b: &str) -> std::cmp::Ordering {
    let a = a.trim_start_matches('0');
    let b = b.trim_start_matches('0');
    a.len().cmp(&b.len()).then_with(|| a.cmp(b))
}

// ─── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::Capabilities;

    fn bid(soname: &str, provider: &str, version: &str, priority: u32) -> AnchorBid {
        let origin = provider.split('/').next().unwrap_or(provider).to_string();
        AnchorBid::new(
            soname,
            provider,
            origin,
            version,
            AnchorBid::default_path(soname),
        )
        .with_priority(priority)
    }

    #[test]
    fn two_way_conflict_highest_bid_wins() {
        let bids = vec![
            bid("libc.so.6", "debian/glibc", "2.39", 40),
            bid("libc.so.6", "archlinux/glibc", "2.39", 10),
        ];
        let table = AnchorTable::from_bids(&bids, &AnchorPolicy::new());
        assert_eq!(table.winner_of("libc.so.6"), Some("archlinux/glibc"));
        let choice = table.get("libc.so.6").unwrap();
        assert_eq!(choice.losers(), vec!["debian/glibc"]);
        assert!(choice.is_winner("archlinux/glibc"));
        assert!(!choice.is_winner("debian/glibc"));
    }

    #[test]
    fn three_way_conflict_orders_all_losers() {
        let bids = vec![
            bid("libssl.so.3", "alpine/openssl", "3.3.1", 30),
            bid("libssl.so.3", "debian/openssl", "3.0.13", 20),
            bid("libssl.so.3", "scratch/openssl-compat", "3.0.0", 0),
        ];
        let choice = AnchorTable::resolve("libssl.so.3", &bids, &AnchorPolicy::new()).unwrap();
        assert_eq!(choice.winner, "scratch/openssl-compat");
        assert_eq!(
            choice.losers(),
            vec!["debian/openssl", "alpine/openssl"]
        );
    }

    #[test]
    fn priority_ties_break_by_origin_then_version() {
        // Same priority, different origins: lexicographic origin wins.
        let bids = vec![
            bid("libz.so.1", "debian/zlib", "1.3", 50),
            bid("libz.so.1", "alpine/zlib", "1.3", 50),
        ];
        let table = AnchorTable::from_bids(&bids, &AnchorPolicy::new());
        assert_eq!(table.winner_of("libz.so.1"), Some("alpine/zlib"));

        // Same origin: the higher version wins, numerically (1.10 > 1.9).
        let bids = vec![
            bid("libz.so.1", "debian/zlib", "1.9", 50),
            bid("libz.so.1", "debian/zlib", "1.10", 50),
        ];
        let table = AnchorTable::from_bids(&bids, &AnchorPolicy::new());
        assert_eq!(table.get("libz.so.1").unwrap().bids[0].version, "1.10");
    }

    #[test]
    fn policy_overrides_origin_defaults() {
        let mut policy = AnchorPolicy::new();
        // debian normally loses to archlinux (20 vs 10); the override flips it.
        policy.declare("debian/openssl", 5);
        let mut bids = vec![
            bid("libssl.so.3", "debian/openssl", "3.0.13", 0),
            bid("libssl.so.3", "archlinux/openssl", "3.3.1", 0),
        ];
        policy.apply(&mut bids);
        let table = AnchorTable::from_bids(&bids, &policy);
        assert_eq!(table.winner_of("libssl.so.3"), Some("debian/openssl"));
        assert_eq!(policy.priority_of("debian/openssl"), 5);
        assert_eq!(policy.priority_of("debian/other"), 20);
        assert_eq!(policy.priority_of("nixos/other"), DEFAULT_PRIORITY);
    }

    #[test]
    fn missing_provider_is_a_typed_error() {
        let bids = vec![bid("libc.so.6", "debian/glibc", "2.39", 20)];
        let err = AnchorTable::resolve("libssl.so.3", &bids, &AnchorPolicy::new()).unwrap_err();
        assert!(
            matches!(err, ExtosError::DependencyUnresolvable(_)),
            "{err}"
        );
        assert!(err.to_string().contains("libssl.so.3"), "{err}");
        // An entirely empty bid list is the same error, not a panic.
        assert!(AnchorTable::resolve("libc.so.6", &[], &AnchorPolicy::new()).is_err());
    }

    #[test]
    fn single_bid_is_anchored_without_competition() {
        let bids = vec![bid("libm.so.6", "archlinux/glibc", "2.39", 10)];
        let table = AnchorTable::from_bids(&bids, &AnchorPolicy::new());
        assert_eq!(table.len(), 1);
        assert!(!table.is_empty());
        let choice = table.get("libm.so.6").unwrap();
        assert!(choice.losers().is_empty());
        assert_eq!(table.path_of("libm.so.6"), Some(Path::new("usr/lib/libm.so.6")));
    }

    #[test]
    fn library_path_lookup_finds_the_anchor() {
        let bids = vec![bid("libssl.so.3", "archlinux/openssl", "3.3.1", 10)];
        let table = AnchorTable::from_bids(&bids, &AnchorPolicy::new());
        assert!(table
            .for_library_path(Path::new("usr/lib/libssl.so.3"))
            .is_some());
        assert!(table
            .for_library_path(Path::new("usr/bin/openssl"))
            .is_none());
        assert_eq!(table.choices().count(), 1);
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn bids_are_derived_from_capabilities() {
        let capabilities = Capabilities {
            libraries: vec!["libssl.so.3".into(), "libcrypto.so.3".into()],
            ..Capabilities::default()
        };
        let bids =
            AnchorBid::from_capabilities("archlinux/openssl", "archlinux", "3.3.1", &capabilities);
        assert_eq!(bids.len(), 2);
        assert_eq!(bids[0].soname, "libssl.so.3");
        assert_eq!(bids[0].provider, "archlinux/openssl");
        assert_eq!(bids[0].path, PathBuf::from("usr/lib/libssl.so.3"));

        let table = AnchorTable::from_bids(&bids, &AnchorPolicy::new());
        assert_eq!(table.len(), 2);
        assert!(table.chose("libcrypto.so.3", "archlinux/openssl"));
    }

    #[test]
    fn version_comparison_is_numeric_aware() {
        use std::cmp::Ordering;
        assert_eq!(compare_versions("2.9", "2.10"), Ordering::Less);
        assert_eq!(compare_versions("2.10", "2.9"), Ordering::Greater);
        assert_eq!(compare_versions("3.0.0", "3.0.0"), Ordering::Equal);
        assert_eq!(compare_versions("2026.1", "2026.01"), Ordering::Equal);
        assert_eq!(compare_versions("1.0", "1.0.1"), Ordering::Less);
    }

    #[test]
    fn empty_bids_are_skipped_not_anchored() {
        let bids = vec![bid("", "archlinux/x", "1", 10), bid("libx.so.1", "", "1", 10)];
        let table = AnchorTable::from_bids(&bids, &AnchorPolicy::new());
        assert!(table.is_empty());
        assert!(table.get("").is_none());
    }
}
