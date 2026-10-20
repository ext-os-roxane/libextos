//! Symlink/Reflink Weaver engine (M6).
//!
//! Translates a logical dependency DAG into a physical `/usr` tree.
//!
//! Pipeline: system.nix → DAG → toposort → resolve → virtual FHS → collision → weave → hooks
//!
//! Standalone wiring (PLAN 2.4) is exposed by [`plan_from_refs`] /
//! [`execute_plan`], with Tier-3 collision wrappers from [`generate_wrapper`]
//! and strict, chroot-scoped post-weave tools in [`run_ldconfig`] /
//! [`run_depmod`].

pub mod collision;
pub mod dag;
pub mod guard;
pub mod hooks;
pub mod link;
pub mod plan;
pub mod postprocess;
pub mod resolve;
pub mod vfs;
pub mod wrapper;

pub use collision::{CollisionResolver, CollisionResolution, OriginPriority, ResolvedCollision};
pub use dag::{DagBuilder, DagNode, DepGraph};
pub use guard::{GuardStrategy, install_guard, remove_guards};
pub use hooks::{run_post_weave_hooks, HookResult};
pub use link::{weave, unweave, LinkStrategy, WeaveResult};
pub use plan::{
    execute_plan, plan_from_refs, plan_from_refs_with, relative_path, CasRef, JournalAction,
    JournalEntry, PlanEntry, PlanExecution, PlanOp, VfsPlan,
};
pub use postprocess::{run_depmod, run_ldconfig, HookOutcome};
pub use resolve::{MultiPassResolver, ResolvedPackage, ResolutionTier};
pub use vfs::{FhsEntry, FhsEntryKind, VirtualFhs};
pub use wrapper::{
    generate_wrapper, provider_slug, render_wrapper, sanitize_wrapper_name, WrapperAlternative,
    WrapperSpec, ALTERNATIVES_ROOT,
};
