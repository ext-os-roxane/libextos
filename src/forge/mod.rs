//! Runlevel 0 initramfs forge (PLAN sub-phase 4.2).
//!
//! Runlevel 0 is the bootstrap tier: kernels plus a minimal userland that the
//! bootloader hands control to. ExtOS never assembles that image on the host
//! filesystem directly. Instead it declares a **blueprint** (see
//! [`blueprint`]), materialises a **tmpfs forge** whose read-only contents are
//! bind mounts of CAS objects (see [`mount`] / [`forge`]), runs the
//! initramfs generator inside that namespace (see [`mkinitcpio`]), and finally
//! publishes bootloader entries through the Boot Loader Specification (see
//! [`bls`]). No step needs root: an unprivileged user namespace plus a private
//! mount namespace is enough.
//!
//! # Sub-phase map
//!
//! | Task | Module | Contract |
//! |------|--------|----------|
//! | 4.2.1 | [`blueprint`] | `tools` / `hooks` / `output` parser, typed errors |
//! | 4.2.2 | [`mount`], [`forge`] | tmpfs root + CAS bind mounts, two spawn strategies |
//! | 4.2.3 | [`mkinitcpio`] | generator bridge, artifact harvest |
//! | 4.2.4 | [`bls`] | `<boot>/loader/entries/<id>.conf`, `loader.conf` policy |
//! | 4.2.5 | [`bls`] | systems × kernels matrix, stable ids, deterministic order |
//! | 4.2.6 | `tests/forge_int.rs` | full chain, hermetic + env-gated real run |
//!
//! # Design in one paragraph
//!
//! [`mount::MountPlan::build`] turns a validated blueprint plus a CAS repository
//! into an ordered mount program: one tmpfs at `<scratch>/forge`, read-only
//! binds of every tool's `objects/<id>/content` at
//! `<forge>/opt/extos/tools/<name>`, hook scripts under `<forge>/etc/initcpio`,
//! caller-declared host binds, and the output directory mounted read-write at
//! `<forge>/out` so the generated artifact survives the namespace. The forge
//! root is *not* a chroot: the mount namespace alone hides host paths the
//! blueprint did not bind, and every mount dies with the namespace, so there is
//! nothing to unmount or clean up afterwards.
//!
//! # Two execution strategies (PLAN 4.2.2)
//!
//! * [`forge::NamespaceStrategy::SelfExec`] — `std::process::Command` plus a
//!   `pre_exec` child that issues `unshare(2)`, writes the uid/gid maps and
//!   calls `mount(2)`/`mkdir(2)` directly. The closure only performs raw
//!   syscalls on buffers prepared *before* `fork(2)`, which is the
//!   async-signal-safe subset required of a post-fork child.
//! * [`forge::NamespaceStrategy::UnshareCli`] — the util-linux `unshare`
//!   wrapper running a generated `mount` script. Slower, needs `mount` and a
//!   shell in the namespace, but keeps all namespace logic out of the process.
//!
//! Both are selected at runtime through [`forge::ForgeConfig::from_env`]
//! (`EXTOS_FORGE_NS=self|unshare`).

pub mod bls;
pub mod blueprint;
pub mod forge;
pub mod mkinitcpio;
pub mod mount;

use std::io;

use thiserror::Error;

use crate::error::ExtosError;

pub use bls::{
    BlsEntryPlan, BlsPlan, BlsReport, BlsSystem, BlsWriteOptions, BootKernel, LoaderConfAction,
    LoaderDefaultPolicy,
};
pub use blueprint::{ForgeBind, ForgeBlueprint, ForgeHook, ForgeOutput, ForgeTool, HookKind};
pub use forge::{
    Forge, ForgeCommand, ForgeConfig, ForgeOutcome, NamespaceStrategy, probe_unprivileged_userns,
};
pub use mkinitcpio::{MkinitcpioJob, MkinitcpioOutcome};
pub use mount::{ForgeMount, MountPlan, MountPlanOptions};

/// Result alias for the forge stack.
pub type ForgeResult<T> = Result<T, ForgeError>;

/// Errors raised by the Runlevel 0 forge (PLAN 4.2).
///
/// The type is local to this module rather than a variant of
/// [`crate::error::ExtosError`], mirroring `fetcher::alpm::AlpmFetchError`: the
/// forge owns namespace/blueprint/BLS failure modes, and
/// `impl From<ForgeError> for ExtosError` converts at the seam the caller picks
/// (typed errors survive conversion as [`ExtosError::ConfigParse`] for
/// blueprint problems and [`ExtosError::Container`] for runtime problems).
#[derive(Debug, Error)]
pub enum ForgeError {
    /// The blueprint document could not be parsed as `.nix` at all.
    #[error("forge blueprint parse error in {file}: {message}")]
    BlueprintParse {
        /// File name (or `<input>`) used in the message.
        file: String,
        /// Parser detail.
        message: String,
    },

    /// The blueprint parsed, but a required field is missing or has the wrong
    /// kind. `field` uses the blueprint path syntax (`tools[0].object`).
    #[error("forge blueprint error in {file}: {field}: {message}")]
    Blueprint {
        /// File name (or `<input>`) used in the message.
        file: String,
        /// Field-addressed location of the problem.
        field: String,
        /// What is wrong and what was expected.
        message: String,
    },

    /// A CAS object named by the blueprint does not exist in the repository.
    #[error("forge needs CAS object '{object}' but it is not in the repository")]
    ObjectNotFound {
        /// Object id from the blueprint.
        object: String,
    },

    /// The object exists but does not carry the requested tool/hook payload.
    #[error("forge tool '{tool}': '{path}' is missing from CAS object '{object}'")]
    ToolMissing {
        /// Tool or hook name.
        tool: String,
        /// Payload path that could not be found.
        path: String,
        /// Object id that was searched.
        object: String,
    },

    /// A path the forge must mount does not exist on the host.
    #[error("forge mount source '{path}' does not exist")]
    SourceMissing {
        /// Missing host path.
        path: String,
    },

    /// `unshare(2)`/`mount(2)` reported `ENOSYS`/`EINVAL`: user namespaces are
    /// unavailable (kernel option, seccomp policy or container restriction).
    #[error("forge cannot create a mount namespace: {message}")]
    NamespaceUnavailable {
        /// Kernel errno text plus a hint.
        message: String,
    },

    /// The namespace was created but a privileged step was refused (`EPERM` /
    /// `EACCES`), e.g. an unreadable bind source or a non-executable tool.
    #[error("forge permission denied: {message}")]
    PermissionDenied {
        /// Which step failed and why.
        message: String,
    },

    /// A mount operation failed for a reason other than permission/`ENOSYS`.
    #[error("forge mount failed for '{target}': {message}")]
    MountFailed {
        /// Mount target.
        target: String,
        /// `errno` text.
        message: String,
    },

    /// The tool ran but exited non-zero.
    #[error("forge program '{program}' {status}: {stderr}")]
    ToolFailed {
        /// Program that ran.
        program: String,
        /// `ExitStatus` rendering (`exited with 1`, `killed by signal 9`, …).
        status: String,
        /// Captured stderr, trimmed.
        stderr: String,
    },

    /// The generator reported success but produced no artifact.
    #[error("forge artifact '{path}' was not produced by the generator")]
    ArtifactMissing {
        /// Expected artifact path.
        path: String,
    },

    /// Two matrix entries collapse to the same BLS file name.
    #[error("BLS entry id collision: '{id}' produced by '{first}' and '{second}'")]
    BlsIdCollision {
        /// Colliding id (file stem).
        id: String,
        /// First entry that claimed it.
        first: String,
        /// Second entry that claimed it.
        second: String,
    },

    /// Invalid BLS input (empty system, relative kernel path, …).
    #[error("BLS error: {message}")]
    Bls {
        /// What is wrong.
        message: String,
    },

    /// Filesystem failure while staging a forge or writing an entry.
    #[error("forge I/O error: {0}")]
    Io(#[from] io::Error),

    /// A `libextos` call used by the forge failed.
    #[error("libextos error: {0}")]
    Extos(#[from] ExtosError),
}

impl From<ForgeError> for ExtosError {
    fn from(error: ForgeError) -> Self {
        match error {
            ForgeError::BlueprintParse { file, message } => ExtosError::ConfigParse {
                path: file,
                line: 0,
                message,
            },
            ForgeError::Blueprint {
                file,
                field,
                message,
            } => ExtosError::ConfigParse {
                path: file,
                line: 0,
                message: format!("{field}: {message}"),
            },
            ForgeError::Io(error) => ExtosError::Io(error),
            ForgeError::Extos(error) => error,
            other => ExtosError::Container(other.to_string()),
        }
    }
}

impl ForgeError {
    /// Map an `io::Error` from the namespace/mount/exec path onto a typed forge
    /// error (PLAN 4.2.2: "typed failures (EACCES, ENOSYS, missing tool)").
    ///
    /// `step` names the operation for the message. The errno classification is:
    ///
    /// * `ENOSYS` / `EINVAL` / `ENOTSUP` — user namespaces unavailable;
    /// * `EPERM` / `EACCES` — permission denied (tool not executable, bind
    ///   source unreadable, namespace restricted by LSM);
    /// * `ENOENT` — missing program or mount source;
    /// * anything else — generic mount/program failure.
    ///
    /// # Known limitation
    ///
    /// The `pre_exec` child can only hand back an `errno`, not the step that
    /// failed, so the message names the *phase* (`namespace setup`, `program
    /// exec`) rather than the individual syscall.
    pub fn from_io(error: io::Error, step: &str) -> Self {
        let errno = error.raw_os_error().unwrap_or(0);
        let text = format!("{step}: {error}");
        match errno {
            libc::ENOSYS | libc::EINVAL | libc::EOPNOTSUPP => Self::NamespaceUnavailable {
                message: format!(
                    "{text} (unprivileged user namespaces are unavailable on this host)"
                ),
            },
            libc::EPERM | libc::EACCES => Self::PermissionDenied { message: text },
            other => Self::MountFailed {
                target: step.to_string(),
                message: if other == libc::ENOENT {
                    format!("{text} (missing program or mount source)")
                } else {
                    text
                },
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_io_classifies_enosys_as_namespace() {
        let error = io::Error::from_raw_os_error(libc::ENOSYS);
        match ForgeError::from_io(error, "namespace setup") {
            ForgeError::NamespaceUnavailable { message } => {
                assert!(message.contains("namespace setup"), "{message}");
                assert!(message.contains("user namespaces"), "{message}");
            }
            other => panic!("expected NamespaceUnavailable, got {other}"),
        }
    }

    #[test]
    fn test_from_io_classifies_eacces_as_permission() {
        let error = io::Error::from_raw_os_error(libc::EACCES);
        assert!(matches!(
            ForgeError::from_io(error, "program exec"),
            ForgeError::PermissionDenied { .. }
        ));

        let error = io::Error::from_raw_os_error(libc::EPERM);
        assert!(matches!(
            ForgeError::from_io(error, "mount"),
            ForgeError::PermissionDenied { .. }
        ));
    }

    #[test]
    fn test_from_io_missing_program_is_typed() {
        let error = io::Error::from_raw_os_error(libc::ENOENT);
        match ForgeError::from_io(error, "program exec") {
            ForgeError::MountFailed { message, .. } => {
                assert!(message.contains("missing program"), "{message}");
            }
            other => panic!("expected MountFailed, got {other}"),
        }
    }

    #[test]
    fn test_forge_error_converts_to_extos_error() {
        let blueprint = ForgeError::Blueprint {
            file: "s.nix".into(),
            field: "tools".into(),
            message: "missing".into(),
        };
        match ExtosError::from(blueprint) {
            ExtosError::ConfigParse { message, .. } => {
                assert!(message.contains("tools"), "{message}");
            }
            other => panic!("expected ConfigParse, got {other}"),
        }

        let runtime = ForgeError::ArtifactMissing {
            path: "/boot/x".into(),
        };
        assert!(matches!(
            ExtosError::from(runtime),
            ExtosError::Container(_)
        ));
    }
}
