//! Dependency specification types.
//!
//! Models the three-tier resolution hierarchy:
//! - **Tier 1 (Strict Pin):** Exact origin + name + version
//! - **Tier 2 (Loose Ecosystem):** Origin + name, any compatible version
//! - **Tier 3 (Capability / Duck-Typing):** SONAME, binary, resource, or virtual

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::caps::{CapabilityIndex, CapabilityProvider};
use crate::manifest::Capabilities;

/// A dependency requirement in the ExtOS DAG.
///
/// Represents exactly one edge in the dependency graph.
/// The collision engine resolves these in order: Tier 1 → Tier 2 → Tier 3.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DependencySpec {
    /// Tier 1: Exact origin + name + version pin.
    StrictPin {
        origin: String,
        name: String,
        version: String,
    },

    /// Tier 2: Origin + name, but any compatible version.
    LooseEcosystem {
        origin: String,
        name: String,
        version_constraint: Option<String>,
    },

    /// Tier 3: Capability duck-typing.
    Capability(CapabilityRequest),
}

impl fmt::Display for DependencySpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DependencySpec::StrictPin {
                origin,
                name,
                version,
            } => write!(f, "{origin}/{name}={version}"),
            DependencySpec::LooseEcosystem {
                origin,
                name,
                version_constraint,
            } => match version_constraint {
                Some(vc) => write!(f, "{origin}/{name} ({vc})"),
                None => write!(f, "{origin}/{name}"),
            },
            DependencySpec::Capability(cap) => write!(f, "{cap}"),
        }
    }
}

/// A Tier 3 capability request — what does the package *need*?
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CapabilityRequest {
    /// Requires a shared library SONAME (e.g., `libssl.so.3`)
    Provides(String),

    /// Requires an executable binary in `$PATH` (e.g., `python3`)
    Executable {
        name: String,
        version: Option<String>,
    },

    /// Requires a filesystem resource (e.g., `/usr/share/hwdata/pci.ids`)
    Resource(String),

    /// Requires a virtual capability (e.g., `system-monitor`, `modules/6.8.2-zen`)
    Virtual(String),
}

impl fmt::Display for CapabilityRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CapabilityRequest::Provides(soname) => write!(f, "provides:{soname}"),
            CapabilityRequest::Executable { name, version } => match version {
                Some(v) => write!(f, "executable:{name} ({v})"),
                None => write!(f, "executable:{name}"),
            },
            CapabilityRequest::Resource(path) => write!(f, "resource:{path}"),
            CapabilityRequest::Virtual(cap) => write!(f, "virtual:{cap}"),
        }
    }
}

// ─── Tier 3 resolution through the CAS capability index (PLAN 5.2.3) ──
//
// The resolver seam is deliberately *additive*: nothing above this block
// changes, and the weaver can adopt the new entry point without touching any
// existing call site. The contract below is the whole of the Phase-5.2.3
// wiring decision; the code flow it mirrors lives in
// `weaver/resolve.rs::MultiPassResolver::resolve_single` (Tier 3 arm) and
// `weaver/dag.rs::DepGraph::resolve_spec`, and the plan-level consumer is
// `weaver/plan.rs::plan_from_refs_with_anchors_and_index`.

/// Where a Tier-3 provider candidate came from.
///
/// The variant is part of the precedence contract: [`CapabilitySource::Plan`]
/// candidates always outrank [`CapabilitySource::CapabilityIndex`] ones, because
/// a package that is already in the plan is the one whose payload will actually
/// be woven.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CapabilitySource {
    /// A package already selected for weaving (a `DepGraph` node).
    Plan,
    /// A CAS-wide hit supplied by [`CapabilityIndex`] (PLAN 5.2.1/5.2.3).
    CapabilityIndex,
}

impl fmt::Display for CapabilitySource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CapabilitySource::Plan => f.write_str("plan"),
            CapabilitySource::CapabilityIndex => f.write_str("capability-index"),
        }
    }
}

/// One Tier-3 provider candidate, whether it came from the plan or the index.
///
/// `capabilities` is the manifest's declared capability block, so a candidate's
/// match against a [`CapabilityRequest`] is decided by exactly the data
/// [`CapabilityRequest::is_satisfied_by`] reads.
#[derive(Debug, Clone)]
pub struct CapabilityCandidate {
    /// Origin namespace of the candidate.
    pub origin: String,
    /// Package name.
    pub name: String,
    /// Concrete version (PLAN 5.2.3).
    ///
    /// For a plan candidate this is the `DagNode` identity version. For an index
    /// hit it is [`CapabilityProvider::version`](crate::caps::CapabilityProvider::version),
    /// i.e. the human-readable manifest version, which may carry a `pkgrel`
    /// (`3.3.1-1`) even when the ref component is `3.3.1`. The plan keys nodes on
    /// `origin/name`, so this is the version shown in warnings; weaving consumes
    /// [`CapabilityCandidate::object`], never a re-resolved ref.
    pub version: String,
    /// CAS object hash, when known.
    pub object: Option<String>,
    /// Declared capabilities of the candidate.
    pub capabilities: Capabilities,
    /// Which source produced this candidate.
    pub source: CapabilitySource,
}

impl CapabilityCandidate {
    /// Build a candidate from an in-plan package.
    ///
    /// `capabilities` is the same block the planner put into the `DagNode`, so
    /// the plan and the resolver cannot disagree about what a package provides.
    pub fn from_plan(
        origin: impl Into<String>,
        name: impl Into<String>,
        version: impl Into<String>,
        object: Option<String>,
        capabilities: Capabilities,
    ) -> Self {
        Self {
            origin: origin.into(),
            name: name.into(),
            version: version.into(),
            object,
            capabilities,
            source: CapabilitySource::Plan,
        }
    }

    /// Build a candidate from a [`CapabilityProvider`] index hit.
    ///
    /// The index carries SONAMEs only, so the resulting candidate advertises
    /// `provides` as its `capabilities.libraries` and nothing else. Its
    /// [`version`](CapabilityCandidate::version) is the provider's manifest
    /// version (possibly with a `pkgrel`); the round-trippable ref component
    /// stays on the provider, while planning uses
    /// [`object`](CapabilityCandidate::object) directly.
    pub fn from_index_provider(provider: &CapabilityProvider) -> Self {
        Self {
            origin: provider.origin.clone(),
            name: provider.name.clone(),
            version: provider.version.clone(),
            object: provider.object.clone(),
            capabilities: Capabilities {
                libraries: provider.provides.clone(),
                ..Capabilities::default()
            },
            source: CapabilitySource::CapabilityIndex,
        }
    }

    /// Provider label (`origin/name`), the weaver's package identity.
    pub fn label(&self) -> String {
        format!("{}/{}", self.origin, self.name)
    }

    /// Semantic ref id (`origin/name/version`).
    ///
    /// This is a display/grouping identity, **not** necessarily a resolve
    /// triple. A candidate built by
    /// [`CapabilityCandidate::from_index_provider`] carries the provider's
    /// human-readable version (the manifest `identity.version`, possibly with a
    /// `pkgrel` such as `3.3.1-1`), whereas
    /// [`crate::cas::CasRepository::resolve_ref`] takes the concrete ref
    /// component (`3.3.1`). Use
    /// [`CapabilityProvider::ref_id`](crate::caps::CapabilityProvider::ref_id)
    /// when a round-trippable id is required, or
    /// [`CapabilityCandidate::object`] — which is what capability promotion feeds
    /// into the plan (PLAN 5.2.3).
    pub fn ref_id(&self) -> String {
        format!("{}/{}/{}", self.origin, self.name, self.version)
    }
}

/// Outcome of one Tier-3 resolution attempt (PLAN 5.2.3).
#[derive(Debug, Clone)]
pub struct CapabilityResolution {
    /// The request that was resolved.
    pub request: CapabilityRequest,
    /// Every satisfying candidate, best-first (empty when unresolved).
    pub providers: Vec<CapabilityCandidate>,
    /// Source that produced [`CapabilityResolution::providers`]; `None` when
    /// nothing satisfied the request.
    pub source: Option<CapabilitySource>,
}

impl CapabilityResolution {
    /// Whether any provider satisfied the request.
    pub fn is_resolved(&self) -> bool {
        !self.providers.is_empty()
    }

    /// The preferred provider (the one the resolver would link/weave first).
    pub fn winner(&self) -> Option<&CapabilityCandidate> {
        self.providers.first()
    }

    /// Ref ids of all providers, best-first.
    pub fn provider_ref_ids(&self) -> Vec<String> {
        self.providers.iter().map(CapabilityCandidate::ref_id).collect()
    }
}

impl CapabilityRequest {
    /// Whether `capabilities` satisfies this request (Tier-3 duck typing).
    ///
    /// This is the in-plan half of the resolver: it answers "does *this* package
    /// provide what the spec needs" without consulting any index, which is what
    /// `weaver/resolve.rs` does today through `DepGraph::providers_of_*`.
    pub fn is_satisfied_by(&self, capabilities: &Capabilities) -> bool {
        match self {
            CapabilityRequest::Provides(soname) => {
                capabilities.libraries.iter().any(|library| library == soname)
            }
            CapabilityRequest::Executable { name, .. } => {
                capabilities.binaries.iter().any(|binary| binary == name)
            }
            CapabilityRequest::Resource(path) => {
                capabilities.resources.iter().any(|resource| resource == path)
            }
            CapabilityRequest::Virtual(capability) => capabilities
                .virtual_caps
                .iter()
                .any(|declared| declared == capability),
        }
    }
}

/// Index hits for a Tier-3 request, as candidates (empty for non-SONAME kinds).
///
/// Exposed so a caller that already knows which index rows it wants can build
/// candidates without reaching into [`CapabilityIndex`]'s layout.
pub fn index_candidates(
    index: &CapabilityIndex,
    request: &CapabilityRequest,
) -> Vec<CapabilityCandidate> {
    index
        .providers_for(request)
        .iter()
        .map(CapabilityCandidate::from_index_provider)
        .collect()
}

/// Resolve a Tier-3 capability: in-plan providers first, CAS index as fallback
/// (PLAN 5.2.3).
///
/// # Precedence (decoded from the Phase-2/4 code, not assumed)
///
/// 1. **In-plan wins.** Every candidate in `in_plan` whose
///    [`CapabilityRequest::is_satisfied_by`] holds is a provider, in the order
///    the plan listed them (the plan's order is itself deterministic: it comes
///    from `MultiPassResolver`'s topological order). The index is **not**
///    consulted at all when at least one in-plan package satisfies the request.
///    This mirrors the existing Tier-3 arm of
///    `weaver/resolve.rs::MultiPassResolver::resolve_single`, which only ever
///    looks at `DepGraph::providers_of_*`, i.e. at in-plan nodes.
/// 2. **Index only fills gaps.** When no in-plan package satisfies the request,
///    `index` (when supplied) contributes its rows, already ordered by
///    [`CapabilityIndex`]'s documented rule (origin asc, name asc, newest
///    version first) — the same newest-first polarity anchor bidding uses. A
///    row from the index is a *candidate for the next plan*, not an automatic
///    weave decision.
/// 3. **The anchor stage is authoritative over the final node set.** Roof-level
///    provider choice is decided by `anchor::AnchorTable` in
///    `weaver/plan.rs::resolve_collision`, *after* resolution and *before*
///    origin priority; that stage is untouched here and is never bypassed by an
///    index hit. The **stage order** is what keeps the index safe: an index hit
///    can never decide a roof collision directly — it can only be promoted into
///    the plan and become one more *bidder*. Promotion therefore adds bids, and
///    the anchor/policy winner is re-derived over the final bid set: if a
///    promoted package also ships a library covered by an anchored SONAME, the
///    contest is settled by the anchor policy (per-provider override → origin
///    priority), not by which package arrived from the index. This function
///    itself never changes an anchor outcome; it only supplies candidates
///    upstream of that final decision (PLAN 5.2.3).
///
/// # Non-SONAME requests
///
/// [`CapabilityRequest::Provides`] is the only kind the CAS index covers
/// (PLAN 5.2.1). Executable / resource / virtual requests still honour the
/// in-plan stage; the index contributes nothing to them, so an unresolved
/// non-SONAME request stays unresolved unless `in_plan` satisfies it.
///
/// # Examples
///
/// ```
/// use libextos::caps::{CapabilityIndex, CapabilityProvider};
/// use libextos::dependency::{resolve_capability, CapabilityRequest, CapabilitySource};
///
/// let mut index = CapabilityIndex::new();
/// index
///     .insert(CapabilityProvider::new(
///         "archlinux",
///         "openssl",
///         "3.3.1",
///         None,
///         vec!["libssl.so.3".to_string()],
///     ))
///     .unwrap();
///
/// let request = CapabilityRequest::Provides("libssl.so.3".to_string());
/// let resolved = resolve_capability(&request, &[], Some(&index));
/// assert_eq!(resolved.source, Some(CapabilitySource::CapabilityIndex));
/// assert_eq!(resolved.winner().unwrap().label(), "archlinux/openssl");
/// ```
pub fn resolve_capability(
    request: &CapabilityRequest,
    in_plan: &[CapabilityCandidate],
    index: Option<&CapabilityIndex>,
) -> CapabilityResolution {
    let providers: Vec<CapabilityCandidate> = in_plan
        .iter()
        .filter(|candidate| request.is_satisfied_by(&candidate.capabilities))
        .cloned()
        .collect();

    if !providers.is_empty() {
        return CapabilityResolution {
            request: request.clone(),
            providers,
            source: Some(CapabilitySource::Plan),
        };
    }

    match index {
        Some(index) => {
            let providers = index_candidates(index, request);
            let source = if providers.is_empty() {
                None
            } else {
                Some(CapabilitySource::CapabilityIndex)
            };
            CapabilityResolution {
                request: request.clone(),
                providers,
                source,
            }
        }
        None => CapabilityResolution {
            request: request.clone(),
            providers: Vec::new(),
            source: None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_display_strict_pin() {
        let dep = DependencySpec::StrictPin {
            origin: "archlinux".into(),
            name: "glibc".into(),
            version: "2.38".into(),
        };
        assert_eq!(dep.to_string(), "archlinux/glibc=2.38");
    }

    #[test]
    fn test_display_loose() {
        let dep = DependencySpec::LooseEcosystem {
            origin: "debian".into(),
            name: "openssl".into(),
            version_constraint: Some(">=3.0".into()),
        };
        assert_eq!(dep.to_string(), "debian/openssl (>=3.0)");
    }

    #[test]
    fn test_display_capability() {
        let dep = DependencySpec::Capability(CapabilityRequest::Provides("libssl.so.3".into()));
        assert_eq!(dep.to_string(), "provides:libssl.so.3");
    }

    #[test]
    fn test_display_executable() {
        let dep = DependencySpec::Capability(CapabilityRequest::Executable {
            name: "python3".into(),
            version: Some(">=3.11".into()),
        });
        assert_eq!(dep.to_string(), "executable:python3 (>=3.11)");
    }
}

/// Tier-3 resolution through the capability index (PLAN 5.2.3).
#[cfg(test)]
mod cap_index_tests {
    use super::*;
    use crate::caps::CapabilityProvider;

    fn index_with(rows: &[(&str, &str, &str, &str)]) -> CapabilityIndex {
        let mut index = CapabilityIndex::new();
        for (origin, name, version, soname) in rows {
            index
                .insert(CapabilityProvider::new(
                    *origin,
                    *name,
                    *version,
                    Some(format!("BLAKE3-{name}-{version}")),
                    vec![(*soname).to_string()],
                ))
                .unwrap();
        }
        index
    }

    #[test]
    fn test_request_satisfaction_per_kind() {
        let caps = Capabilities {
            binaries: vec!["htop".into()],
            libraries: vec!["libssl.so.3".into()],
            virtual_caps: vec!["system-monitor".into()],
            resources: vec!["/usr/share/hwdata/pci.ids".into()],
        };
        assert!(CapabilityRequest::Provides("libssl.so.3".into()).is_satisfied_by(&caps));
        assert!(!CapabilityRequest::Provides("libssl.so.10".into()).is_satisfied_by(&caps));
        assert!(
            CapabilityRequest::Executable {
                name: "htop".into(),
                version: None
            }
            .is_satisfied_by(&caps)
        );
        assert!(CapabilityRequest::Virtual("system-monitor".into()).is_satisfied_by(&caps));
        assert!(
            CapabilityRequest::Resource("/usr/share/hwdata/pci.ids".into())
                .is_satisfied_by(&caps)
        );
        assert!(!CapabilityRequest::Resource("/etc/shadow".into()).is_satisfied_by(&caps));
    }

    #[test]
    fn test_index_resolves_when_plan_is_silent() {
        let index = index_with(&[
            ("archlinux", "openssl", "3.9", "libssl.so.3"),
            ("archlinux", "openssl", "3.10", "libssl.so.3"),
        ]);
        let request = CapabilityRequest::Provides("libssl.so.3".into());
        let resolved = resolve_capability(&request, &[], Some(&index));

        assert!(resolved.is_resolved());
        assert_eq!(resolved.source, Some(CapabilitySource::CapabilityIndex));
        // Newest first, matching the anchor ranking polarity.
        assert_eq!(resolved.winner().unwrap().version, "3.10");
        assert_eq!(
            resolved.provider_ref_ids(),
            vec!["archlinux/openssl/3.10", "archlinux/openssl/3.9"]
        );
    }

    #[test]
    fn test_plan_candidates_outrank_the_index() {
        let index = index_with(&[("archlinux", "openssl", "3.3.1", "libssl.so.3")]);
        let plan = vec![CapabilityCandidate::from_plan(
            "debian",
            "libssl3",
            "3.0.13",
            Some("BLAKE3-plan".into()),
            Capabilities {
                libraries: vec!["libssl.so.3".into()],
                ..Capabilities::default()
            },
        )];
        let request = CapabilityRequest::Provides("libssl.so.3".into());
        let resolved = resolve_capability(&request, &plan, Some(&index));

        assert_eq!(resolved.source, Some(CapabilitySource::Plan));
        assert_eq!(resolved.providers.len(), 1, "index must not add rows");
        assert_eq!(resolved.winner().unwrap().label(), "debian/libssl3");
    }

    #[test]
    fn test_missing_index_and_miss_are_unresolved() {
        let request = CapabilityRequest::Provides("libssl.so.3".into());
        let resolved = resolve_capability(&request, &[], None);
        assert!(!resolved.is_resolved());
        assert_eq!(resolved.source, None);

        let empty = CapabilityIndex::new();
        let resolved = resolve_capability(&request, &[], Some(&empty));
        assert!(!resolved.is_resolved());
        assert_eq!(resolved.source, None);
        assert!(resolved.winner().is_none());
    }

    #[test]
    fn test_non_soname_requests_do_not_consult_the_index() {
        // The index is sourced from `capabilities.libraries` only, so a virtual
        // or executable request can never be answered by it.
        let index = index_with(&[("archlinux", "openssl", "3.3.1", "libssl.so.3")]);
        let resolved = resolve_capability(
            &CapabilityRequest::Executable {
                name: "openssl".into(),
                version: None,
            },
            &[],
            Some(&index),
        );
        assert!(!resolved.is_resolved());
        assert_eq!(resolved.source, None);
    }

    #[test]
    fn test_in_plan_executable_still_resolves() {
        let plan = vec![CapabilityCandidate::from_plan(
            "archlinux",
            "openssl",
            "3.3.1",
            None,
            Capabilities {
                binaries: vec!["openssl".into()],
                ..Capabilities::default()
            },
        )];
        let resolved = resolve_capability(
            &CapabilityRequest::Executable {
                name: "openssl".into(),
                version: None,
            },
            &plan,
            None,
        );
        assert_eq!(resolved.source, Some(CapabilitySource::Plan));
        assert_eq!(resolved.winner().unwrap().ref_id(), "archlinux/openssl/3.3.1");
    }
}
