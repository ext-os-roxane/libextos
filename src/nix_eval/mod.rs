//! Nix evaluator bridge (PLAN sub-phase 3.1): typed Rust access to the
//! `libexpr-extos` evaluator.
//!
//! # Why a `dlopen` bridge
//!
//! ExtOS does not link against the Nix evaluator at build time. The fork is
//! built separately (`meson setup … && ninja`, see
//! `inherited/libexpr-extos/README.extos.md`), and `libextos` loads it at
//! runtime through [`libloading`]. That keeps `cargo build` working on hosts
//! without Boost/libgc, and lets a distribution choose between the ExtOS fork
//! and no evaluator at all.
//!
//! The library is located exclusively through [`bridge::LIB_ENV`]
//! (`EXTOS_NIX_EVAL_LIB`); there is deliberately no search path, because
//! silently binding a distribution Nix would produce store paths ExtOS cannot
//! weave.
//!
//! # What the bridge returns
//!
//! One JSON document, parsed here into [`EvalDag`]:
//!
//! ```json
//! {
//!   "version": "2.35.0-extos.1",
//!   "config_path": "/config/systems/default.nix",
//!   "store_dir": "/repository/store",
//!   "store_dir_source": "extos_repository",
//!   "store_uri": "auto",
//!   "system": { "name": "workstation", "native_pm": "debian",
//!               "kernel": "6.8.2-extos", "root": null, "linux": null,
//!               "services": ["sshd"] },
//!   "packages": [
//!     { "id": "archlinux/htop/3.3.0-1", "origin": "archlinux",
//!       "name": "htop", "version": "3.3.0-1",
//!       "layout": "/repository/store/archlinux/htop/3.3.0-1" }
//!   ],
//!   "dag": {
//!     "nodes": [ { "id": "system:workstation", "kind": "system", "name": "workstation" },
//!                { "id": "archlinux/htop/3.3.0-1", "kind": "package", "origin": "archlinux",
//!                  "name": "htop", "version": "3.3.0-1" } ],
//!     "edges": [ { "from": "system:workstation", "to": "archlinux/htop/3.3.0-1",
//!                  "kind": "weave" } ]
//!   }
//! }
//! ```
//!
//! `layout` is the ExtOS-visible artifact directory (PLAN 3.1.3):
//! `<EXTOS_REPOSITORY>/store/<origin>/<name>/<version>`. It is `null` when the
//! reference carries a component that cannot be a single path segment, in
//! which case the legacy `<store>/<hash>-<name>` layout applies.
//!
//! # Thread safety
//!
//! [`NixEvaluator`] may be shared across threads: the bridge serializes every
//! evaluation internally behind a process-global mutex, so concurrent calls
//! are safe but run sequentially (Nix's evaluator/GC corrupt the allocator
//! under real concurrency). There is no API change for callers — just do not
//! expect parallelism from this bridge.
//!
//! The `store_uri` and `strict` options are accepted for forward compatibility
//! but are currently inert; `store_dir` + `store_dir_source` in the response
//! describe the resolution that actually happened.
//!
//! The grammar of the evaluated `system.nix` is the one implemented by
//! `instanz::system`: `name`, `native_pm` (aliases `roof`, `roof_native_pm`,
//! `primary_origin`, `roofs`), `kernel`, `root`, `linux`, `services`, and the
//! `packages` list of `"[origin/]name[=version]"` strings or attribute sets.

pub mod bridge;

use std::path::Path;

use serde::{Deserialize, Serialize};

pub use bridge::{LIB_ENV, LIB_FILE_NAME, NixEvalLib, NixEvaluator};

/// Where the evaluator's store directory came from (PLAN 3.1.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StoreDirSource {
    /// `EXTOS_REPOSITORY` was set: `store_dir` is `<repository>/store`.
    ExtosRepository,
    /// No override: the upstream compile-time default (`/nix/store`).
    Upstream,
}

/// The `system` block of the evaluated blueprint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvalSystem {
    /// System name (`name`, else the config file stem).
    pub name: String,
    /// Roof-native package manager, normalised to an origin name
    /// (`archlinux`, `debian`, `alpine`, `void`, `rpm`).
    #[serde(default)]
    pub native_pm: Option<String>,
    /// Kernel version for `depmod`.
    #[serde(default)]
    pub kernel: Option<String>,
    /// Generations root.
    #[serde(default)]
    pub root: Option<String>,
    /// BLS `linux` field.
    #[serde(default)]
    pub linux: Option<String>,
    /// Service names, in declaration order.
    #[serde(default)]
    pub services: Vec<String>,
}

/// One resolved package reference from `packages = [ … ]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvalPackage {
    /// `<origin>/<name>/<version>` — the CAS ref id.
    pub id: String,
    /// Manifest origin (`archlinux`, `debian`, …).
    pub origin: String,
    /// Package name.
    pub name: String,
    /// Package version (`current` when the config omitted one).
    pub version: String,
    /// ExtOS artifact directory, or `None` when the layout is unsafe.
    #[serde(default)]
    pub layout: Option<String>,
}

impl EvalPackage {
    /// `<origin>/<name>/<version>`, recomputed for callers that build a
    /// reference without trusting the bridge's `id` field.
    pub fn ref_id(&self) -> String {
        format!("{}/{}/{}", self.origin, self.name, self.version)
    }
}

/// Kind of node in the evaluation DAG.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DagNodeKind {
    /// The system blueprint itself (root of every `weave` edge).
    System,
    /// A package to weave into the rootfs.
    Package,
}

/// A node of the evaluation DAG.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DagNode {
    /// Stable identifier (`system:<name>` or `<origin>/<name>/<version>`).
    pub id: String,
    /// Node kind; unknown kinds are rejected so ABI skew is loud.
    pub kind: DagNodeKind,
    /// System name, for [`DagNodeKind::System`] nodes.
    #[serde(default)]
    pub name: Option<String>,
    /// Package origin, for [`DagNodeKind::Package`] nodes.
    #[serde(default)]
    pub origin: Option<String>,
    /// Package version, for [`DagNodeKind::Package`] nodes.
    #[serde(default)]
    pub version: Option<String>,
}

/// A directed edge of the evaluation DAG.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DagEdge {
    /// Source node id.
    pub from: String,
    /// Destination node id.
    pub to: String,
    /// Edge kind (`weave` today).
    pub kind: String,
}

/// The DAG emitted by the bridge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DagGraph {
    /// All nodes, root first.
    #[serde(default)]
    pub nodes: Vec<DagNode>,
    /// All edges.
    #[serde(default)]
    pub edges: Vec<DagEdge>,
}

/// A fully evaluated ExtOS system blueprint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvalDag {
    /// Bridge version that produced this document.
    pub version: String,
    /// Path of the evaluated config (echoed by the bridge).
    pub config_path: String,
    /// Effective Nix store directory.
    pub store_dir: String,
    /// Provenance of [`Self::store_dir`].
    pub store_dir_source: StoreDirSource,
    /// Store URI requested by the caller (`auto` by default).
    ///
    /// Echoes the `store_uri` option when one was passed. The option is
    /// **accepted for forward compatibility but currently inert**: the bridge
    /// resolves the store from `EXTOS_REPOSITORY`/the upstream Nix environment
    /// and ignores the override. [`Self::store_dir`] plus
    /// [`Self::store_dir_source`] describe what was actually used.
    #[serde(default)]
    pub store_uri: String,
    /// System metadata.
    pub system: EvalSystem,
    /// Packages in declaration order.
    #[serde(default)]
    pub packages: Vec<EvalPackage>,
    /// Explicit DAG view of the evaluation.
    pub dag: DagGraph,
}

impl EvalDag {
    /// Parse a bridge document.
    ///
    /// # Errors
    ///
    /// [`ExtosError::Serialization`] when the JSON does not match this ABI.
    pub fn from_json(text: &str) -> Result<Self, ExtosError> {
        serde_json::from_str(text)
            .map_err(|e| ExtosError::Serialization(format!("nix_eval: malformed DAG: {e}")))
    }

    /// The `weave` edges as `(system name, package id)` pairs.
    pub fn weave_targets(&self) -> Vec<(&str, &str)> {
        self.dag
            .edges
            .iter()
            .filter(|edge| edge.kind == "weave")
            .map(|edge| (edge.from.as_str(), edge.to.as_str()))
            .collect()
    }

    /// Artifact directories of every package whose layout is well defined.
    pub fn layout_paths(&self) -> Vec<&str> {
        self.packages
            .iter()
            .filter_map(|package| package.layout.as_deref())
            .collect()
    }

    /// Evaluate `config` with the bridge named by `EXTOS_NIX_EVAL_LIB`.
    ///
    /// # Errors
    ///
    /// [`ExtosError::DependencyUnresolvable`] when the bridge is not configured
    /// or not loadable, plus everything [`NixEvaluator::evaluate`] can return.
    pub fn evaluate(config: &Path, opts: &serde_json::Value) -> Result<Self, ExtosError> {
        NixEvalLib::open_from_env()?.evaluate(config, opts)
    }
}

use crate::error::ExtosError;

#[cfg(test)]
mod tests {
    use super::*;

    /// Captured from `extos_nix_eval_config()` against the fork
    /// (v2.35.0-extos.1) with `EXTOS_REPOSITORY=/repo`. Kept inline so the
    /// serde shape is tested unconditionally, without the shared library.
    const FIXTURE: &str = r#"{
      "version": "2.35.0-extos.1",
      "config_path": "/tmp/system.nix",
      "store_dir": "/repo/store",
      "store_dir_source": "extos_repository",
      "store_uri": "auto",
      "system": {
        "name": "workstation",
        "native_pm": "debian",
        "kernel": "6.8.2-extos",
        "root": null,
        "linux": null,
        "services": ["sshd", "chronyd", "networkd"]
      },
      "packages": [
        {"id":"archlinux/htop/3.3.0-1","origin":"archlinux","name":"htop","version":"3.3.0-1",
         "layout":"/repo/store/archlinux/htop/3.3.0-1"},
        {"id":"debian/bash/current","origin":"debian","name":"bash","version":"current",
         "layout":"/repo/store/debian/bash/current"}
      ],
      "dag": {
        "nodes": [
          {"id":"system:workstation","kind":"system","name":"workstation"},
          {"id":"archlinux/htop/3.3.0-1","kind":"package","origin":"archlinux","name":"htop","version":"3.3.0-1"},
          {"id":"debian/bash/current","kind":"package","origin":"debian","name":"bash","version":"current"}
        ],
        "edges": [
          {"from":"system:workstation","to":"archlinux/htop/3.3.0-1","kind":"weave"},
          {"from":"system:workstation","to":"debian/bash/current","kind":"weave"}
        ]
      }
    }"#;

    #[test]
    fn parses_bridge_document() {
        let dag = EvalDag::from_json(FIXTURE).expect("fixture must parse");
        assert_eq!(dag.version, "2.35.0-extos.1");
        assert_eq!(dag.store_dir, "/repo/store");
        assert_eq!(dag.store_dir_source, StoreDirSource::ExtosRepository);
        assert_eq!(dag.system.name, "workstation");
        assert_eq!(dag.system.native_pm.as_deref(), Some("debian"));
        assert_eq!(dag.system.kernel.as_deref(), Some("6.8.2-extos"));
        assert_eq!(dag.system.services, ["sshd", "chronyd", "networkd"]);
    }

    #[test]
    fn exposes_packages_dag_and_layouts() {
        let dag = EvalDag::from_json(FIXTURE).expect("fixture must parse");
        assert_eq!(dag.packages.len(), 2);
        assert_eq!(dag.packages[0].ref_id(), "archlinux/htop/3.3.0-1");
        assert_eq!(
            dag.packages[0].layout.as_deref(),
            Some("/repo/store/archlinux/htop/3.3.0-1")
        );
        assert_eq!(
            dag.layout_paths(),
            ["/repo/store/archlinux/htop/3.3.0-1", "/repo/store/debian/bash/current"]
        );
        assert_eq!(dag.dag.nodes.len(), 3);
        assert_eq!(
            dag.weave_targets(),
            [
                ("system:workstation", "archlinux/htop/3.3.0-1"),
                ("system:workstation", "debian/bash/current"),
            ]
        );
        assert_eq!(dag.dag.nodes[0].kind, DagNodeKind::System);
        assert_eq!(dag.dag.nodes[1].kind, DagNodeKind::Package);
    }

    #[test]
    fn parses_upstream_store_source() {
        let text = FIXTURE
            .replace("\"extos_repository\"", "\"upstream\"")
            .replace("/repo/store", "/nix/store");
        let dag = EvalDag::from_json(&text).expect("fixture must parse");
        assert_eq!(dag.store_dir_source, StoreDirSource::Upstream);
        assert_eq!(dag.store_dir, "/nix/store");
    }

    #[test]
    fn rejects_unknown_store_dir_source() {
        let text = FIXTURE.replace("\"extos_repository\"", "\"somewhere_else\"");
        let err = EvalDag::from_json(&text).expect_err("unknown source must fail");
        assert!(matches!(err, ExtosError::Serialization(_)), "got {err}");
    }

    #[test]
    fn rejects_unknown_node_kind() {
        let text = FIXTURE.replace("\"kind\":\"system\"", "\"kind\":\"planet\"");
        let err = EvalDag::from_json(&text).expect_err("unknown node kind must fail");
        assert!(matches!(err, ExtosError::Serialization(_)), "got {err}");
    }

    #[test]
    fn rejects_malformed_json() {
        let err = EvalDag::from_json("{ not json").expect_err("must fail");
        assert!(matches!(err, ExtosError::Serialization(_)), "got {err}");
    }

    #[test]
    fn missing_bridge_is_a_typed_error() {
        // `EXTOS_NIX_EVAL_LIB` is never set inside the unit-test binary unless
        // the operator did so; either way the call must not panic.
        match NixEvalLib::open_from_env() {
            Ok(lib) => assert!(!lib.version().starts_with('\u{0}')),
            Err(err) => assert!(
                matches!(err, ExtosError::DependencyUnresolvable(_)),
                "unexpected error kind: {err}"
            ),
        }
    }
}
