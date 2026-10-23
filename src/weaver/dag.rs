//! DAG builder and topological sorter (M6.1 + M6.2).
//!
//! Builds a directed acyclic graph from CAS manifests, detects cycles,
//! and produces a topologically sorted installation order.

use std::collections::{HashMap, HashSet, VecDeque};

use crate::cas::CasRepository;
use crate::config;
use crate::dependency::{CapabilityRequest, DependencySpec};
use crate::error::ExtosError;
use crate::manifest::{Capabilities, PackageIdentity, PackageManifest};

/// A single node in the dependency graph.
#[derive(Debug, Clone)]
pub struct DagNode {
    /// CAS object hash
    pub hash: String,
    /// Package identity
    pub identity: PackageIdentity,
    /// What this package provides
    pub capabilities: Capabilities,
    /// Direct dependency edges (indices into DepGraph::nodes)
    pub deps: Vec<usize>,
    /// Runtime dependencies (raw specs, before resolution)
    pub requires: Vec<DependencySpec>,
}

/// The full dependency graph.
#[derive(Debug, Clone)]
pub struct DepGraph {
    /// All nodes (packages) in the graph
    pub nodes: Vec<DagNode>,
    /// Index: "origin/name" → node index
    index: HashMap<String, usize>,
    /// Index: capability → node indices that provide it
    cap_index: CapabilityIndex,
}

/// Index mapping capabilities to provider node indices.
#[derive(Debug, Clone, Default)]
struct CapabilityIndex {
    /// SONAME → providers
    libraries: HashMap<String, Vec<usize>>,
    /// Binary name → providers
    binaries: HashMap<String, Vec<usize>>,
    /// Virtual cap → providers
    virtuals: HashMap<String, Vec<usize>>,
    /// Resource path → providers
    resources: HashMap<String, Vec<usize>>,
}

impl DepGraph {
    pub fn new() -> Self {
        Self {
            nodes: Vec::new(),
            index: HashMap::new(),
            cap_index: CapabilityIndex::default(),
        }
    }

    /// Number of packages in the graph.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Look up a node by "origin/name".
    pub fn find(&self, key: &str) -> Option<usize> {
        self.index.get(key).copied()
    }

    /// Look up a node by exact `origin/name/version` (PLAN 5.2.3).
    ///
    /// [`DepGraph::find`] keys on `origin/name` — the graph holds one node per
    /// package, so a lookup cannot distinguish "already planned at exactly this
    /// version" from "planned at another version". Capability promotion needs
    /// that distinction: the first case is a silent dedup hit, the second is a
    /// skip worth warning about. This accessor adds no state and leaves the
    /// private index layout untouched.
    pub fn find_exact(&self, origin: &str, name: &str, version: &str) -> Option<usize> {
        let idx = self.find(&format!("{origin}/{name}"))?;
        (self.nodes.get(idx)?.identity.version == version).then_some(idx)
    }

    /// Look up a node by index.
    pub fn get(&self, idx: usize) -> Option<&DagNode> {
        self.nodes.get(idx)
    }

    /// Find providers of a SONAME.
    pub fn providers_of_library(&self, soname: &str) -> &[usize] {
        self.cap_index.libraries.get(soname).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// Find providers of a binary.
    pub fn providers_of_binary(&self, name: &str) -> &[usize] {
        self.cap_index.binaries.get(name).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// Find providers of a virtual capability.
    pub fn providers_of_virtual(&self, cap: &str) -> &[usize] {
        self.cap_index.virtuals.get(cap).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// Insert a node, updating all indices.
    pub fn insert(&mut self, node: DagNode) -> usize {        let idx = self.nodes.len();
        let key = format!("{}/{}", node.identity.origin, node.identity.name);
        self.index.insert(key, idx);

        // Update capability indices
        for lib in &node.capabilities.libraries {
            self.cap_index.libraries.entry(lib.clone()).or_default().push(idx);
        }
        for bin in &node.capabilities.binaries {
            self.cap_index.binaries.entry(bin.clone()).or_default().push(idx);
        }
        for virt in &node.capabilities.virtual_caps {
            self.cap_index.virtuals.entry(virt.clone()).or_default().push(idx);
        }
        for res in &node.capabilities.resources {
            self.cap_index.resources.entry(res.clone()).or_default().push(idx);
        }

        // Also index aliases
        for alias in &node.identity.aliases {
            self.index.insert(format!("{}/{}", node.identity.origin, alias), idx);
        }

        self.nodes.push(node);
        idx
    }

    /// Resolve a single [`DependencySpec`] to a node index using this graph.
    ///
    /// Tier 1/2 specs match on `origin/name`; Tier 3 specs walk the capability
    /// index. Returns `None` when nothing in the graph satisfies the spec.
    pub fn resolve_spec(&self, dep: &DependencySpec) -> Option<usize> {
        match dep {
            DependencySpec::StrictPin { origin, name, .. }
            | DependencySpec::LooseEcosystem { origin, name, .. } => {
                self.find(&format!("{origin}/{name}"))
            }
            DependencySpec::Capability(cap) => match cap {
                CapabilityRequest::Provides(soname) => {
                    self.providers_of_library(soname).first().copied()
                }
                CapabilityRequest::Executable { name, .. } => {
                    self.providers_of_binary(name).first().copied()
                }
                CapabilityRequest::Virtual(v) => {
                    self.providers_of_virtual(v).first().copied()
                }
                CapabilityRequest::Resource(_) => None,
            },
        }
    }

    /// Rewrite every node's `requires` list into concrete `deps` indices.
    ///
    /// Self-edges and duplicate edges are dropped. Call this after all nodes are
    /// inserted and before [`DepGraph::toposort`] — [`DagBuilder`] does it
    /// internally, but callers that assemble a graph by hand (e.g. the standalone
    /// weaver planner) need it too.
    pub fn link_requires(&mut self) {
        for i in 0..self.nodes.len() {
            let requires = self.nodes[i].requires.clone();
            let mut deps: Vec<usize> = Vec::with_capacity(requires.len());
            for dep in &requires {
                if let Some(idx) = self.resolve_spec(dep) {
                    if idx != i && !deps.contains(&idx) {
                        deps.push(idx);
                    }
                }
            }
            self.nodes[i].deps = deps;
        }
    }

    /// Topological sort using Kahn's algorithm (M6.2).
    ///
    /// Returns nodes in dependency-first order (leaves before roots).
    /// Returns `Err` if a cycle is detected.
    pub fn toposort(&self) -> Result<Vec<usize>, ExtosError> {
        let n = self.nodes.len();
        let mut in_degree = vec![0usize; n];
        for node in &self.nodes {
            for &dep in &node.deps {
                if dep < n {
                    in_degree[dep] += 0; // dep is depended ON
                }
            }
        }
        // Count incoming edges
        let mut in_deg = vec![0usize; n];
        for node in &self.nodes {
            for &dep in &node.deps {
                if dep < n {
                    in_deg[dep] += 1;
                }
            }
        }

        // Wait — standard Kahn's: edge from A→B means "A depends on B".
        // So B must come before A. in-degree counts how many nodes depend on B.
        // Actually let's redefine: deps[i] = "node i depends on deps[i][j]"
        // For toposort, we want dependencies first. So edges go from dependent → dependency.
        // Kahn's: in-degree = number of edges pointing TO a node.
        // Edge: i → deps[i][j] means i depends on deps[i][j].
        // So in_degree[j] = number of nodes that depend on j... that's reverse.
        //
        // Standard approach: if A depends on B, edge is B→A (B must come before A).
        // in_degree[A] = number of dependencies of A.
        let mut in_degree_v = vec![0usize; n];
        for node in &self.nodes {
            in_degree_v[self.nodes.iter().position(|x| std::ptr::eq(x, node)).unwrap_or(0)] = node.deps.len();
        }
        // Fix: just use index
        let mut in_deg_final = Vec::with_capacity(n);
        for (_i, node) in self.nodes.iter().enumerate() {
            in_deg_final.push(node.deps.len());
        }

        // Reverse adjacency: for each dep edge i→j, record j→i
        let mut reverse_adj: Vec<Vec<usize>> = vec![Vec::new(); n];
        for (i, node) in self.nodes.iter().enumerate() {
            for &dep in &node.deps {
                if dep < n {
                    reverse_adj[dep].push(i);
                }
            }
        }

        let mut queue: VecDeque<usize> = VecDeque::new();
        for i in 0..n {
            if in_deg_final[i] == 0 {
                queue.push_back(i);
            }
        }

        let mut order = Vec::with_capacity(n);
        while let Some(node_idx) = queue.pop_front() {
            order.push(node_idx);
            for &dependent in &reverse_adj[node_idx] {
                in_deg_final[dependent] -= 1;
                if in_deg_final[dependent] == 0 {
                    queue.push_back(dependent);
                }
            }
        }

        if order.len() != n {
            let remaining: Vec<String> = (0..n)
                .filter(|i| !order.contains(i))
                .map(|i| format!("{}/{}", self.nodes[i].identity.origin, self.nodes[i].identity.name))
                .collect();
            return Err(ExtosError::Weave(format!(
                "dependency cycle detected among: {}",
                remaining.join(", ")
            )));
        }

        Ok(order)
    }
}

impl Default for DepGraph {
    fn default() -> Self {
        Self::new()
    }
}

/// Builds a `DepGraph` from CAS repository refs.
pub struct DagBuilder<'a> {
    repo: &'a CasRepository,
}

impl<'a> DagBuilder<'a> {
    pub fn new(repo: &'a CasRepository) -> Self {
        Self { repo }
    }

    /// Build a complete dependency graph from all packages in the CAS.
    pub fn build_full(&self) -> Result<DepGraph, ExtosError> {
        let mut graph = DepGraph::new();
        let origins = self.repo.list_origins()?;

        // Phase 1: Load all nodes
        for origin in &origins {
            let pkgs = self.repo.list_packages(origin)?;
            for pkg in &pkgs {
                if let Ok(hash) = self.repo.resolve_ref(origin, pkg, "current") {
                    if let Ok(manifest) = self.load_manifest(&hash) {
                        graph.insert(DagNode {
                            hash: hash.clone(),
                            identity: manifest.identity.clone(),
                            capabilities: manifest.capabilities.clone(),
                            deps: Vec::new(), // filled in Phase 2
                            requires: manifest.requires.clone(),
                        });
                    }
                }
            }
        }

        // Phase 2: Resolve dependency edges
        let node_count = graph.nodes.len();
        for i in 0..node_count {
            let requires = graph.nodes[i].requires.clone();
            let mut resolved_deps = Vec::new();
            for dep in &requires {
                if let Some(idx) = self.resolve_dep_to_index(dep, &graph) {
                    resolved_deps.push(idx);
                }
            }
            graph.nodes[i].deps = resolved_deps;
        }

        Ok(graph)
    }

    /// Build a graph rooted at specific packages (subset).
    pub fn build_for(&self, roots: &[(&str, &str)]) -> Result<DepGraph, ExtosError> {
        let mut graph = DepGraph::new();
        let mut visited = HashSet::new();
        let mut queue: VecDeque<(String, String)> = VecDeque::new();

        for &(origin, name) in roots {
            queue.push_back((origin.to_string(), name.to_string()));
        }

        // BFS: load root and all transitive dependencies
        while let Some((origin, name)) = queue.pop_front() {
            let key = format!("{origin}/{name}");
            if visited.contains(&key) {
                continue;
            }
            visited.insert(key);

            let hash = match self.repo.resolve_ref(&origin, &name, "current") {
                Ok(h) => h,
                Err(_) => continue,
            };
            let manifest = match self.load_manifest(&hash) {
                Ok(m) => m,
                Err(_) => continue,
            };

            graph.insert(DagNode {
                hash: hash.clone(),
                identity: manifest.identity.clone(),
                capabilities: manifest.capabilities.clone(),
                deps: Vec::new(),
                requires: manifest.requires.clone(),
            });

            // Enqueue dependencies
            for dep in &manifest.requires {
                match dep {
                    DependencySpec::StrictPin { origin, name, .. } |
                    DependencySpec::LooseEcosystem { origin, name, .. } => {
                        queue.push_back((origin.clone(), name.clone()));
                    }
                    _ => {} // Capability deps resolved in Phase 2
                }
            }
        }

        // Phase 2: Resolve edges
        let node_count = graph.nodes.len();
        for i in 0..node_count {
            let requires = graph.nodes[i].requires.clone();
            let mut resolved_deps = Vec::new();
            for dep in &requires {
                if let Some(idx) = self.resolve_dep_to_index(dep, &graph) {
                    resolved_deps.push(idx);
                }
            }
            graph.nodes[i].deps = resolved_deps;
        }

        Ok(graph)
    }

    fn load_manifest(&self, hash: &str) -> Result<PackageManifest, ExtosError> {
        let nix_src = self.repo.read_manifest(hash)?;
        let nix_val = config::parse_nix(&nix_src)?;
        PackageManifest::from_nix(&nix_val)
    }

    /// Resolve a DependencySpec to a node index in the graph.
    fn resolve_dep_to_index(&self, dep: &DependencySpec, graph: &DepGraph) -> Option<usize> {
        graph.resolve_spec(dep)
    }
}

// ─── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::Capabilities;

    fn mock_node(origin: &str, name: &str, deps: Vec<usize>) -> DagNode {
        DagNode {
            hash: format!("BLAKE3-{name}hash"),
            identity: PackageIdentity {
                origin: origin.into(),
                name: name.into(),
                version: "1.0".into(),
                aliases: vec![],
            },
            capabilities: Capabilities::default(),
            deps,
            requires: vec![],
        }
    }

    #[test]
    fn test_empty_graph() {
        let g = DepGraph::new();
        assert!(g.is_empty());
        assert_eq!(g.toposort().unwrap(), Vec::<usize>::new());
    }

    #[test]
    fn test_single_node() {
        let mut g = DepGraph::new();
        g.insert(mock_node("arch", "glibc", vec![]));
        assert_eq!(g.len(), 1);
        assert_eq!(g.toposort().unwrap(), vec![0]);
    }

    #[test]
    fn test_linear_chain() {
        let mut g = DepGraph::new();
        g.insert(mock_node("arch", "glibc", vec![]));      // 0
        g.insert(mock_node("arch", "gcc-libs", vec![]));    // 1 (deps set below)
        g.insert(mock_node("arch", "htop", vec![]));        // 2
        // htop → gcc-libs → glibc
        g.nodes[1].deps = vec![0];
        g.nodes[2].deps = vec![1];

        let order = g.toposort().unwrap();
        // glibc must come before gcc-libs, gcc-libs before htop
        let pos_glibc = order.iter().position(|&x| x == 0).unwrap();
        let pos_gcc = order.iter().position(|&x| x == 1).unwrap();
        let pos_htop = order.iter().position(|&x| x == 2).unwrap();
        assert!(pos_glibc < pos_gcc);
        assert!(pos_gcc < pos_htop);
    }

    #[test]
    fn test_diamond_dependency() {
        let mut g = DepGraph::new();
        g.insert(mock_node("arch", "glibc", vec![]));    // 0
        g.insert(mock_node("arch", "libA", vec![]));      // 1
        g.insert(mock_node("arch", "libB", vec![]));      // 2
        g.insert(mock_node("arch", "app", vec![]));       // 3
        // app → {libA, libB}, libA → glibc, libB → glibc
        g.nodes[1].deps = vec![0];
        g.nodes[2].deps = vec![0];
        g.nodes[3].deps = vec![1, 2];

        let order = g.toposort().unwrap();
        let pos = |idx: usize| order.iter().position(|&x| x == idx).unwrap();
        assert!(pos(0) < pos(1));
        assert!(pos(0) < pos(2));
        assert!(pos(1) < pos(3));
        assert!(pos(2) < pos(3));
    }

    #[test]
    fn test_cycle_detection() {
        let mut g = DepGraph::new();
        g.insert(mock_node("arch", "a", vec![]));
        g.insert(mock_node("arch", "b", vec![]));
        g.nodes[0].deps = vec![1];
        g.nodes[1].deps = vec![0];

        let result = g.toposort();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("cycle"));
    }

    #[test]
    fn test_capability_index() {
        let mut g = DepGraph::new();
        let mut node = mock_node("arch", "openssl", vec![]);
        node.capabilities.libraries = vec!["libssl.so.3".into(), "libcrypto.so.3".into()];
        node.capabilities.binaries = vec!["openssl".into()];
        g.insert(node);

        assert_eq!(g.providers_of_library("libssl.so.3"), &[0]);
        assert_eq!(g.providers_of_library("libcrypto.so.3"), &[0]);
        assert_eq!(g.providers_of_binary("openssl"), &[0]);
        assert!(g.providers_of_library("libfoo.so").is_empty());
    }

    #[test]
    fn test_find_by_key() {
        let mut g = DepGraph::new();
        g.insert(mock_node("arch", "htop", vec![]));
        g.insert(mock_node("debian", "vim", vec![]));

        assert_eq!(g.find("arch/htop"), Some(0));
        assert_eq!(g.find("debian/vim"), Some(1));
        assert_eq!(g.find("arch/vim"), None);
    }

    #[test]
    fn test_find_exact_distinguishes_versions() {
        let mut g = DepGraph::new();
        g.insert(mock_node("arch", "htop", vec![]));

        assert_eq!(g.find_exact("arch", "htop", "1.0"), Some(0));
        assert_eq!(g.find_exact("arch", "htop", "2.0"), None);
        assert_eq!(g.find_exact("arch", "missing", "1.0"), None);
    }
}
