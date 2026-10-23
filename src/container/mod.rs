//! Runlevel 3 — the Tier-4 container runtime (PLAN sub-phase 4.4).
//!
//! # What lives here
//!
//! * [`spec`] — the typed `containerPermissions` profile declared by a manifest
//!   (PLAN 4.4.1). The types themselves live in [`crate::manifest`] so a parsed
//!   profile rides along with [`crate::manifest::PackageManifest`]; this module
//!   re-exports them and adds the runtime policies derived from a level.
//! * [`rootfs`] — per-container rootfs assembly from the shared weaver `VfsPlan`
//!   (PLAN 4.4.7).
//! * [`mounts`] — the mount table for levels 0–4 (`/dev`, `/proc`, `/tmp`,
//!   `/run`, tmpfs root).
//! * [`gui`] — Wayland / PipeWire / PulseAudio / D-Bus / X11 socket
//!   bind-mounts for levels 2–4 (PLAN 4.4.4).
//! * [`namespace`] — the child-side syscall program (unshare → uid/gid maps →
//!   mounts → chroot → fork → exec) plus its async-signal-safety contract
//!   (PLAN 4.4.2/4.4.5/4.4.6).
//! * [`pty`] — parent-side PTY allocation and wiring (PLAN 4.4.3).
//! * [`backend`] — [`Backend`] selection, PATH probing, and per-backend
//!   command-line templates (PLAN 4.4.9).
//! * [`launcher`] — [`launcher::launch`], the one entry point that ties the above
//!   together.
//!
//! `instanz run <profile>` (PLAN 4.4.8) is deliberately **not** implemented
//! here: it belongs to the `instanz` CLI crate.
//!
//! # Isolation levels
//!
//! | Level | Name | Namespaces | Rootfs |
//! |-------|------|------------|--------|
//! | 0 | Isolated | user, mount, pid, ipc, uts, net | tmpfs root + package tree |
//! | 1 | CLI | same as 0 | + controlling PTY |
//! | 2 | GUI | same as 0 | + Wayland/PipeWire/D-Bus sockets |
//! | 3 | Networked | as 2, but **host netns** | as 2 |
//! | 4 | Privileged | none (user ns only as a chroot capability shim) | as 2 |
//!
//! Only level 4 inherits the host network namespace by default, and level 4 is
//! never launched from a manifest unless the caller sets
//! [`launcher::LaunchSpec::allow_privileged`] — the manifest field is a *request*,
//! not an authorisation (a typed [`ContainerError::PrivilegedNotAllowed`] guard
//! enforces this).
//!
//! # Honest limits (see also `PLAN.md` notes and the audit report)
//!
//! * `cgroup` namespaces are never created: unprivileged hosts cannot mount a
//!   delegated cgroup v2 tree, so resource limits are a backend concern.
//! * D-Bus integration is a **socket bind-mount**, not a filtering proxy. The
//!   PLAN's "proxy" wording describes the target architecture; a mediating
//!   `xdg-dbus-proxy` style daemon is out of scope for this sub-phase.
//! * X11 authorisation (`$XAUTHORITY`) is never passed through; X11 is a
//!   fallback for compositors without Wayland and is off unless requested.
//! * The systemd-nspawn template cannot express level 4 (see [`backend`]).
//!
//! ```
//! use libextos::container::{launch, Backend, LaunchSpec, IsolationLevel};
//!
//! // Spec assembly is pure: this never touches the host.
//! let spec = LaunchSpec::new(IsolationLevel::Cli, "/tmp/rootfs", "/bin/sh");
//! assert_eq!(spec.backend, Backend::Native);
//! assert!(spec.level.needs_pty());
//! # let _ = launch; // referenced so the doc link stays live
//! ```

pub mod backend;
pub mod gui;
pub mod launcher;
pub mod mounts;
pub mod namespace;
pub mod pty;
pub mod rootfs;
pub mod spec;

use thiserror::Error;

pub use backend::{Backend, BackendProbe, BackendTemplate, TemplateRequest};
pub use gui::{assemble_gui_spec, GuiEnv, GuiSpec, SocketMount};
pub use launcher::{launch, LaunchOutcome, LaunchSpec};
pub use mounts::{HostPaths, MountPlan, MountSource, MountSpec};
pub use namespace::{NamespacePlan, RootMode};
pub use rootfs::{assemble_rootfs, Rootfs, RootfsRequest};
pub use spec::RuntimePolicy;

pub use crate::manifest::{
    ContainerPermissions, ContainerSocket, IsolationLevel, NamespaceToggles,
};

/// Typed failures of the container runtime.
///
/// Every variant converts into [`crate::error::ExtosError::Container`] so the
/// pipeline can stay on one error type, while tests and callers that care about
/// the *kind* of failure match on this enum directly.
#[derive(Debug, Error)]
pub enum ContainerError {
    /// The manifest/profile/spec combination is structurally invalid.
    #[error("container spec: {0}")]
    Spec(String),

    /// The requested isolation level cannot be honoured by the backend.
    #[error("backend {backend} cannot provide isolation level {level}: {reason}")]
    UnsupportedLevel {
        /// Backend name as reported by [`Backend::as_str`].
        backend: &'static str,
        /// Level name as reported by [`IsolationLevel::as_str`].
        level: &'static str,
        /// Why the combination is refused.
        reason: String,
    },

    /// The backend binary is not installed (or the native path is unusable).
    #[error("container backend unavailable: {0}")]
    BackendUnavailable(String),

    /// A level-4 profile was requested without an explicit opt-in.
    #[error(
        "refusing to launch a privileged (level 4) container: the manifest requested it but the \
         caller did not set LaunchSpec::allow_privileged"
    )]
    PrivilegedNotAllowed,

    /// The requested program does not exist inside the assembled rootfs.
    #[error("container program not found in rootfs: {0}")]
    ProgramNotFound(String),

    /// The rootfs cannot be assembled (empty refs, missing payload, …).
    #[error("container rootfs: {0}")]
    Rootfs(String),

    /// A namespace/mount/chroot syscall failed in the child.
    #[error("container namespace setup failed at {op}: {message}")]
    Namespace {
        /// Name of the syscall or step that failed.
        op: &'static str,
        /// `errno` description.
        message: String,
    },

    /// PTY allocation or wiring failed.
    #[error("container pty: {0}")]
    Pty(String),

    /// A socket source the profile requires does not exist on the host.
    #[error("container socket source missing: {0}")]
    SocketAbsent(String),

    /// A filesystem operation while preparing the launch failed.
    #[error("container io: {0}")]
    Io(#[from] std::io::Error),
}

impl From<ContainerError> for crate::error::ExtosError {
    fn from(err: ContainerError) -> Self {
        crate::error::ExtosError::Container(err.to_string())
    }
}

/// Convenience for mapping a raw `errno` into [`ContainerError::Namespace`].
pub(crate) fn ns_err(op: &'static str, errno: i32) -> ContainerError {
    ContainerError::Namespace {
        op,
        message: std::io::Error::from_raw_os_error(errno).to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn container_error_converts_to_extos_error() {
        let err: crate::error::ExtosError = ContainerError::PrivilegedNotAllowed.into();
        assert!(matches!(err, crate::error::ExtosError::Container(_)));
        assert!(err.to_string().contains("privileged"));
    }

    #[test]
    fn ns_err_keeps_op_and_errno() {
        let err = ns_err("unshare", libc::EPERM);
        match err {
            ContainerError::Namespace { op, message } => {
                assert_eq!(op, "unshare");
                assert!(!message.is_empty());
            }
            other => panic!("unexpected: {other:?}"),
        }
    }
}
