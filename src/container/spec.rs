//! Runtime policy derived from a parsed [`ContainerPermissions`] profile
//! (PLAN 4.4.1).
//!
//! The manifest grammar describes *what a package asks for*; this module turns
//! that into *what the runtime will do*: which namespaces to unshare, whether a
//! PTY is needed, which proxy sockets are in scope, and how the rootfs is
//! mounted. Keeping the two apart means the manifest parser never needs to know
//! about `unshare(2)` and the launcher never re-parses Nix.

use crate::container::{ContainerError, ContainerSocket, IsolationLevel, NamespaceToggles};
use crate::manifest::ContainerPermissions;

/// The resolved, validated plan for one container profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimePolicy {
    /// Declared (and already cross-checked) isolation level.
    pub level: IsolationLevel,
    /// Namespace toggles actually requested.
    pub namespaces: NamespaceToggles,
    /// Whether stdio is wired to a controlling PTY.
    pub pty: bool,
    /// Proxy sockets to bind-mount, in assembly order.
    pub sockets: Vec<ContainerSocket>,
    /// Whether `/` itself is a fresh tmpfs with the package tree bound in.
    pub tmpfs_root: bool,
    /// Whether the bound-in package tree is remounted read-only.
    pub read_only_root: bool,
}

impl RuntimePolicy {
    /// Derive the runtime policy for `profile`.
    ///
    /// Levels ≥ 2 default to a read-only package tree; levels 3/4 keep it
    /// writable because their use cases (browsers, build toolchains) expect a
    /// mutable root.
    pub fn from_permissions(profile: &ContainerPermissions) -> Self {
        let level = profile.level;
        Self {
            level,
            namespaces: profile.namespaces,
            pty: level.needs_pty(),
            sockets: profile.sockets.clone(),
            tmpfs_root: true,
            read_only_root: !matches!(
                level,
                IsolationLevel::Networked | IsolationLevel::Privileged
            ),
        }
    }

    /// Reject profiles that cannot be honoured at all.
    ///
    /// This is deliberately separate from parsing: a struct may be built by
    /// hand (tests, `instanz`, another language binding) and still has to pass
    /// the same gate.
    pub fn validate(&self) -> Result<(), ContainerError> {
        if self.level == IsolationLevel::Privileged && self.namespaces.any() {
            return Err(ContainerError::Spec(
                "privileged profiles must not request namespace isolation".into(),
            ));
        }
        if self.namespaces.cgroup {
            return Err(ContainerError::Spec(
                "cgroup namespaces are not supported by this runtime (unprivileged hosts cannot \
                 mount a delegated cgroup v2 tree); use a backend-level resource limit instead"
                    .into(),
            ));
        }
        if self.level.as_u8() < 2 && !self.sockets.is_empty() {
            return Err(ContainerError::Spec(format!(
                "isolation level {} has no display or IPC sockets, but the profile asks for: {}",
                self.level,
                self.sockets
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )));
        }
        Ok(())
    }

    /// The level's one-line description, for diagnostics and the backend probe
    /// report.
    pub fn describe(&self) -> String {
        let mut parts = Vec::new();
        for (name, on) in [
            ("user", self.namespaces.user),
            ("mount", self.namespaces.mount),
            ("pid", self.namespaces.pid),
            ("ipc", self.namespaces.ipc),
            ("uts", self.namespaces.uts),
            ("net", self.namespaces.net),
        ] {
            if on {
                parts.push(name.to_string());
            }
        }
        format!(
            "level {} ({}): ns=[{}] pty={} sockets=[{}]",
            self.level.as_u8(),
            self.level,
            parts.join(","),
            self.pty,
            self.sockets
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(",")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_follow_the_level_table() {
        let isolated = RuntimePolicy::from_permissions(&ContainerPermissions::new(
            IsolationLevel::Isolated,
        ));
        assert!(!isolated.pty);
        assert!(isolated.namespaces.net);
        assert!(isolated.sockets.is_empty());
        assert!(isolated.read_only_root);
        isolated.validate().unwrap();

        let cli = RuntimePolicy::from_permissions(&ContainerPermissions::new(IsolationLevel::Cli));
        assert!(cli.pty);
        cli.validate().unwrap();

        let gui = RuntimePolicy::from_permissions(&ContainerPermissions::new(IsolationLevel::Gui));
        assert!(gui.pty);
        assert!(gui.sockets.contains(&ContainerSocket::Wayland));
        assert!(gui.sockets.contains(&ContainerSocket::Pipewire));
        assert!(gui.sockets.contains(&ContainerSocket::DbusSession));

        let net = RuntimePolicy::from_permissions(&ContainerPermissions::new(
            IsolationLevel::Networked,
        ));
        assert!(!net.namespaces.net);
        assert!(!net.read_only_root);

        let priv_ = RuntimePolicy::from_permissions(&ContainerPermissions::new(
            IsolationLevel::Privileged,
        ));
        assert!(!priv_.namespaces.any());
        priv_.validate().unwrap();
    }

    #[test]
    fn sockets_at_level_one_are_rejected() {
        let profile = ContainerPermissions::new(IsolationLevel::Cli)
            .with_sockets([ContainerSocket::Wayland]);
        let policy = RuntimePolicy::from_permissions(&profile);
        assert!(matches!(policy.validate(), Err(ContainerError::Spec(_))));
    }

    #[test]
    fn privileged_with_namespaces_is_rejected() {
        let mut profile = ContainerPermissions::new(IsolationLevel::Privileged);
        profile.namespaces.user = true;
        let policy = RuntimePolicy::from_permissions(&profile);
        assert!(policy.validate().is_err());
    }

    #[test]
    fn cgroup_namespace_is_explicitly_unsupported() {
        let mut profile = ContainerPermissions::new(IsolationLevel::Isolated);
        profile.namespaces.cgroup = true;
        let policy = RuntimePolicy::from_permissions(&profile);
        let err = policy.validate().unwrap_err();
        assert!(err.to_string().contains("cgroup"));
    }

    #[test]
    fn describe_mentions_level_and_namespaces() {
        let policy =
            RuntimePolicy::from_permissions(&ContainerPermissions::new(IsolationLevel::Isolated));
        let text = policy.describe();
        assert!(text.contains("level 0"));
        assert!(text.contains("net"));
    }
}
