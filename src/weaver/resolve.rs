//! Multi-pass dependency resolver (M6.3).
//!
//! Resolves dependencies in three passes:
//! 1. **Strict Pin** (Tier 1): Exact origin + name + version
//! 2. **Loose Ecosystem** (Tier 2): Origin + name, any compatible version
//! 3. **Capability** (Tier 3): SONAME, binary, resource, or virtual duck-typing


use crate::dependency::{CapabilityRequest, DependencySpec};
use crate::error::ExtosError;
use crate::manifest::PackageIdentity;
use crate::weaver::dag::DepGraph;

/// A fully resolved package ready for weaving.
#[derive(Debug, Clone)]
pub struct ResolvedPackage {
    /// Index into DepGraph::nodes
    pub node_idx: usize,
    /// CAS object hash
    pub hash: String,
    /// Identity
    pub identity: PackageIdentity,
    /// Resolved dependency indices (post-resolution)
    pub resolved_deps: Vec<usize>,
    /// Which resolution tier matched each dep
    pub dep_tiers: Vec<ResolutionTier>,
}

/// Which tier resolved a dependency.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolutionTier {
    /// Tier 1: Exact pin matched
    StrictPin,
    /// Tier 2: Loose ecosystem matched
    LooseEcosystem,
    /// Tier 3: Capability duck-typing matched
    Capability,
    /// Unresolved — no provider found
    Unresolved,
}

/// Result of resolving the entire graph.
#[derive(Debug)]
pub struct ResolutionResult {
    /// Resolved packages in topological order (dependencies first)
    pub packages: Vec<ResolvedPackage>,
    /// Warnings for soft failures (unresolved optional deps)
    pub warnings: Vec<String>,
    /// Hard failures (unresolved required deps)
    pub errors: Vec<String>,
}

/// Multi-pass resolver operating on a `DepGraph`.
pub struct MultiPassResolver<'a> {
    graph: &'a DepGraph,
    /// Whether to fail hard on unresolved deps
    strict: bool,
}

impl<'a> MultiPassResolver<'a> {
    pub fn new(graph: &'a DepGraph) -> Self {
        Self { graph, strict: false }
    }

    /// Enable strict mode: unresolved deps are errors, not warnings.
    pub fn strict(mut self) -> Self {
        self.strict = true;
        self
    }

    /// Resolve the entire graph, returning packages in install order.
    pub fn resolve(&self) -> Result<ResolutionResult, ExtosError> {
        let order = self.graph.toposort()?;
        let mut packages = Vec::with_capacity(order.len());
        let mut warnings = Vec::new();
        let mut errors = Vec::new();

        for &idx in &order {
            let node = &self.graph.nodes[idx];
            let mut resolved_deps = Vec::new();
            let mut dep_tiers = Vec::new();

            for dep in &node.requires {
                let (resolved_idx, tier) = self.resolve_single(dep);
                match tier {
                    ResolutionTier::Unresolved => {
                        let msg = format!(
                            "{}/{}: unresolved dependency: {}",
                            node.identity.origin, node.identity.name, dep
                        );
                        if self.strict {
                            errors.push(msg);
                        } else {
                            warnings.push(msg);
                        }
                    }
                    _ => {
                        if let Some(ridx) = resolved_idx {
                            resolved_deps.push(ridx);
                        }
                    }
                }
                dep_tiers.push(tier);
            }

            packages.push(ResolvedPackage {
                node_idx: idx,
                hash: node.hash.clone(),
                identity: node.identity.clone(),
                resolved_deps,
                dep_tiers,
            });
        }

        if self.strict && !errors.is_empty() {
            return Err(ExtosError::DependencyUnresolvable(errors.join("; ")));
        }

        Ok(ResolutionResult { packages, warnings, errors })
    }

    /// Resolve a single dependency through Tier 1 → 2 → 3.
    fn resolve_single(&self, dep: &DependencySpec) -> (Option<usize>, ResolutionTier) {
        match dep {
            // Tier 1: Strict pin
            DependencySpec::StrictPin { origin, name, version } => {
                let key = format!("{origin}/{name}");
                if let Some(idx) = self.graph.find(&key) {
                    let node = &self.graph.nodes[idx];
                    if node.identity.version == *version {
                        return (Some(idx), ResolutionTier::StrictPin);
                    }
                    // Version mismatch — fall through to Tier 2
                    return (Some(idx), ResolutionTier::LooseEcosystem);
                }
                (None, ResolutionTier::Unresolved)
            }

            // Tier 2: Loose ecosystem
            DependencySpec::LooseEcosystem { origin, name, .. } => {
                let key = format!("{origin}/{name}");
                if let Some(idx) = self.graph.find(&key) {
                    return (Some(idx), ResolutionTier::LooseEcosystem);
                }
                (None, ResolutionTier::Unresolved)
            }

            // Tier 3: Capability duck-typing
            DependencySpec::Capability(cap) => {
                match cap {
                    CapabilityRequest::Provides(soname) => {
                        let providers = self.graph.providers_of_library(soname);
                        if let Some(&idx) = providers.first() {
                            return (Some(idx), ResolutionTier::Capability);
                        }
                    }
                    CapabilityRequest::Executable { name, .. } => {
                        let providers = self.graph.providers_of_binary(name);
                        if let Some(&idx) = providers.first() {
                            return (Some(idx), ResolutionTier::Capability);
                        }
                    }
                    CapabilityRequest::Virtual(v) => {
                        let providers = self.graph.providers_of_virtual(v);
                        if let Some(&idx) = providers.first() {
                            return (Some(idx), ResolutionTier::Capability);
                        }
                    }
                    CapabilityRequest::Resource(_) => {
                        // Resource deps are not currently resolved via capability index
                    }
                }
                (None, ResolutionTier::Unresolved)
            }
        }
    }
}

// ─── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{Capabilities, PackageIdentity};
    use crate::weaver::dag::{DagNode, DepGraph};

    fn node(origin: &str, name: &str, ver: &str) -> DagNode {
        DagNode {
            hash: format!("BLAKE3-{name}"),
            identity: PackageIdentity {
                origin: origin.into(), name: name.into(),
                version: ver.into(), aliases: vec![],
            },
            capabilities: Capabilities::default(),
            deps: vec![],
            requires: vec![],
        }
    }

    #[test]
    fn test_strict_pin_resolution() {
        let mut g = DepGraph::new();
        g.insert(node("arch", "glibc", "2.39"));
        let mut htop = node("arch", "htop", "3.3.0");
        htop.requires = vec![DependencySpec::StrictPin {
            origin: "arch".into(), name: "glibc".into(), version: "2.39".into(),
        }];
        g.insert(htop);
        g.nodes[1].deps = vec![0];

        let resolver = MultiPassResolver::new(&g);
        let result = resolver.resolve().unwrap();
        assert_eq!(result.packages.len(), 2);
        assert!(result.warnings.is_empty());
        assert_eq!(result.packages[1].dep_tiers[0], ResolutionTier::StrictPin);
    }

    #[test]
    fn test_capability_resolution() {
        let mut g = DepGraph::new();
        let mut openssl = node("arch", "openssl", "3.2");
        openssl.capabilities.libraries = vec!["libssl.so.3".into()];
        g.insert(openssl);

        let mut curl = node("arch", "curl", "8.5");
        curl.requires = vec![DependencySpec::Capability(
            CapabilityRequest::Provides("libssl.so.3".into()),
        )];
        g.insert(curl);

        let resolver = MultiPassResolver::new(&g);
        let result = resolver.resolve().unwrap();
        assert_eq!(result.packages[1].dep_tiers[0], ResolutionTier::Capability);
        assert_eq!(result.packages[1].resolved_deps, vec![0]);
    }

    #[test]
    fn test_unresolved_warning() {
        let mut g = DepGraph::new();
        let mut app = node("arch", "app", "1.0");
        app.requires = vec![DependencySpec::StrictPin {
            origin: "arch".into(), name: "missing".into(), version: "1.0".into(),
        }];
        g.insert(app);

        let resolver = MultiPassResolver::new(&g);
        let result = resolver.resolve().unwrap();
        assert_eq!(result.warnings.len(), 1);
        assert!(result.warnings[0].contains("missing"));
    }

    #[test]
    fn test_strict_mode_fails() {
        let mut g = DepGraph::new();
        let mut app = node("arch", "app", "1.0");
        app.requires = vec![DependencySpec::StrictPin {
            origin: "arch".into(), name: "missing".into(), version: "1.0".into(),
        }];
        g.insert(app);

        let resolver = MultiPassResolver::new(&g).strict();
        assert!(resolver.resolve().is_err());
    }

    #[test]
    fn test_loose_fallback() {
        let mut g = DepGraph::new();
        g.insert(node("arch", "glibc", "2.39"));
        let mut htop = node("arch", "htop", "3.3.0");
        // StrictPin with wrong version → falls back to LooseEcosystem
        htop.requires = vec![DependencySpec::StrictPin {
            origin: "arch".into(), name: "glibc".into(), version: "2.38".into(),
        }];
        g.insert(htop);

        let resolver = MultiPassResolver::new(&g);
        let result = resolver.resolve().unwrap();
        assert_eq!(result.packages[1].dep_tiers[0], ResolutionTier::LooseEcosystem);
    }
}
