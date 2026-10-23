//! The mount table handed to the child-side namespace program (PLAN 4.4.2,
//! 4.4.5, 4.4.6).
//!
//! Building a mount table is pure: it inspects the host only to *probe* optional
//! sources (`/dev/null` and friends) and never mounts anything itself. The
//! table is then materialised by [`crate::container::namespace`] inside the
//! child, after `unshare(CLONE_NEWNS)`.
//!
//! # Layout
//!
//! * `/` — fresh tmpfs (the "tmpfs root"), with the assembled package tree
//!   bind-mounted in at its top level (see [`crate::container::launcher`]).
//! * `/dev` — fresh tmpfs plus bind-mounts of the six kernel device nodes a
//!   userspace program realistically needs. `mknod(2)` for real device numbers
//!   is refused inside unprivileged user namespaces, so bind-mounting the host
//!   nodes is the only portable unprivileged option.
//! * `/proc` — mounted by the container's PID 1 only, and only when a fresh PID
//!   namespace was created; otherwise the directory stays **empty** on purpose
//!   (a host `/proc` inside a container leaks every host process).
//! * `/sys` — never mounted: sysfs is not reachable from an unprivileged user
//!   namespace and the PLAN asks for empty mounts at levels 0–3.
//! * `/tmp`, `/run` — fresh tmpfs, so container writes never reach the host.
//!
//! Paths under `/dev`, `/proc`, `/sys` are Linux ABI locations, not ExtOS
//! configuration; the *host* device directory is still injectable through
//! [`HostPaths`] (and the `EXTOS_CONTAINER_HOST_DEV` environment variable) so
//! nothing is hard-coded behind the caller's back.

use std::path::{Path, PathBuf};

use crate::container::IsolationLevel;

/// Where a mount entry gets its content from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MountSource {
    /// A fresh anonymous tmpfs.
    Tmpfs {
        /// Size limit in KiB.
        size_kib: u64,
    },
    /// A bind-mount of an existing host path.
    Bind {
        /// Path on the host.
        source: PathBuf,
        /// Remount read-only after the bind.
        read_only: bool,
    },
    /// `mount -t proc`, performed by the container's PID 1.
    Proc,
}

/// One entry of the container mount table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountSpec {
    /// Absolute path *inside* the container rootfs.
    pub target: PathBuf,
    /// Where the content comes from.
    pub source: MountSource,
    /// When `false`, a missing host source drops the entry with a warning
    /// instead of failing the launch.
    pub required: bool,
    /// Why this entry exists (surfaced in diagnostics).
    pub rationale: &'static str,
}

impl MountSpec {
    fn tmpfs(target: &str, size_kib: u64, rationale: &'static str) -> Self {
        Self {
            target: PathBuf::from(target),
            source: MountSource::Tmpfs { size_kib },
            required: true,
            rationale,
        }
    }

    fn bind(target: &str, source: impl Into<PathBuf>, required: bool, rationale: &'static str) -> Self {
        Self {
            target: PathBuf::from(target),
            source: MountSource::Bind {
                source: source.into(),
                read_only: true,
            },
            required,
            rationale,
        }
    }

    /// Whether the host side of this entry is present.
    pub fn source_present(&self) -> bool {
        match &self.source {
            MountSource::Tmpfs { .. } | MountSource::Proc => true,
            MountSource::Bind { source, .. } => source.exists(),
        }
    }
}

/// Host paths the mount table borrows from.
///
/// Defaults are Linux ABI locations and can be overridden so tests (and exotic
/// hosts) never depend on the real `/dev`:
/// * `EXTOS_CONTAINER_HOST_DEV` — replaces `/dev`.
/// * `EXTOS_CONTAINER_HOST_RESOLV_CONF` — replaces `/etc/resolv.conf`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostPaths {
    /// Directory holding `null`, `zero`, `full`, `random`, `urandom`, `tty`.
    pub dev: PathBuf,
    /// Host resolver configuration, bound into networked containers.
    pub resolv_conf: PathBuf,
}

impl Default for HostPaths {
    fn default() -> Self {
        Self {
            dev: PathBuf::from("/dev"),
            resolv_conf: PathBuf::from("/etc/resolv.conf"),
        }
    }
}

impl HostPaths {
    /// Resolve the host paths from the environment, falling back to the Linux
    /// ABI defaults.
    pub fn from_env() -> Self {
        let mut paths = Self::default();
        if let Some(dev) = std::env::var_os("EXTOS_CONTAINER_HOST_DEV") {
            if !dev.is_empty() {
                paths.dev = PathBuf::from(dev);
            }
        }
        if let Some(resolv) = std::env::var_os("EXTOS_CONTAINER_HOST_RESOLV_CONF") {
            if !resolv.is_empty() {
                paths.resolv_conf = PathBuf::from(resolv);
            }
        }
        paths
    }

    /// The six device nodes every userspace program may reasonably need.
    pub fn device_nodes(&self) -> [&'static str; 6] {
        ["null", "zero", "full", "random", "urandom", "tty"]
    }
}

/// A complete mount plan plus the non-fatal notes gathered while building it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MountPlan {
    /// Entries in application order (the child applies them verbatim).
    pub mounts: Vec<MountSpec>,
    /// Optional sources that were absent and therefore dropped.
    pub warnings: Vec<String>,
}

impl MountPlan {
    /// Build the mount table for `level`.
    ///
    /// `tmpfs_size_kib` bounds every anonymous tmpfs (`/`, `/tmp`, `/run`).
    pub fn for_level(level: IsolationLevel, host: &HostPaths, tmpfs_size_kib: u64) -> Self {
        let mut plan = MountPlan::default();
        let tmpfs_size_kib = tmpfs_size_kib.max(1024);

        plan.mounts.push(MountSpec::tmpfs(
            "/dev",
            tmpfs_size_kib,
            "device tmpfs; mknod is refused in unprivileged user namespaces",
        ));
        for node in host.device_nodes() {
            let source = host.dev.join(node);
            if !source.exists() {
                plan.warnings.push(format!(
                    "optional device node {} is absent; container /dev/{node} will be missing",
                    source.display()
                ));
                continue;
            }
            plan.mounts.push(MountSpec::bind(
                &format!("/dev/{node}"),
                source,
                false,
                "kernel device node",
            ));
        }
        plan.mounts.push(MountSpec::tmpfs(
            "/tmp",
            tmpfs_size_kib,
            "private scratch space; never the host /tmp",
        ));
        plan.mounts.push(MountSpec::tmpfs(
            "/run",
            tmpfs_size_kib,
            "runtime state; also hosts GUI proxy sockets",
        ));

        // `/proc` is mounted by the container's PID 1 (see the namespace
        // program); only schedule it when a fresh PID namespace exists.
        if level != IsolationLevel::Privileged {
            plan.mounts.push(MountSpec {
                target: PathBuf::from("/proc"),
                source: MountSource::Proc,
                required: true,
                rationale: "pid-namespace procfs, mounted by the container's PID 1",
            });
        } else {
            plan.warnings.push(
                "privileged profile: no PID namespace, so /proc stays an empty directory"
                    .to_string(),
            );
        }

        if level.shares_host_network() {
            let resolv = &host.resolv_conf;
            if resolv.exists() {
                plan.mounts.push(MountSpec::bind(
                    "/etc/resolv.conf",
                    resolv.clone(),
                    false,
                    "host resolver configuration for an inherited network namespace",
                ));
            } else {
                plan.warnings.push(format!(
                    "networked container without DNS: {} is absent",
                    resolv.display()
                ));
            }
        }

        plan
    }

    /// Entries whose host source is a bind-mount, in plan order.
    pub fn binds(&self) -> impl Iterator<Item = &MountSpec> {
        self.mounts
            .iter()
            .filter(|m| matches!(m.source, MountSource::Bind { .. }))
    }

    /// Whether the plan schedules a procfs mount.
    pub fn mounts_proc(&self) -> bool {
        self.mounts
            .iter()
            .any(|m| matches!(m.source, MountSource::Proc))
    }

    /// Absent *required* sources, as typed errors.
    pub fn missing_required(&self) -> Vec<String> {
        self.mounts
            .iter()
            .filter(|m| m.required && !m.source_present())
            .map(|m| m.target.display().to_string())
            .collect()
    }
}

/// Whether `path` is a socket (`S_IFSOCK`) — used by the GUI assembler.
pub(crate) fn is_socket(path: &Path) -> bool {
    use std::os::unix::fs::FileTypeExt;
    path.symlink_metadata()
        .map(|meta| meta.file_type().is_socket())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn level_zero_has_dev_tmp_run_and_proc() {
        let host = HostPaths {
            dev: PathBuf::from("/dev"),
            resolv_conf: PathBuf::from("/etc/resolv.conf"),
        };
        let plan = MountPlan::for_level(IsolationLevel::Isolated, &host, 16 * 1024);
        let targets: Vec<String> = plan
            .mounts
            .iter()
            .map(|m| m.target.display().to_string())
            .collect();
        assert!(targets.contains(&"/dev".to_string()));
        assert!(targets.contains(&"/tmp".to_string()));
        assert!(targets.contains(&"/run".to_string()));
        assert!(targets.contains(&"/proc".to_string()));
        assert!(!targets.iter().any(|t| t == "/sys"));
        assert!(plan.mounts_proc());
        // Every device bind is optional, so an absent /dev/xyz cannot fail us.
        let required: Vec<&MountSpec> = plan.mounts.iter().filter(|m| m.required).collect();
        assert!(required.iter().all(|m| m.source_present()));
        assert!(plan.missing_required().is_empty());
    }

    #[test]
    fn isolated_profile_never_binds_resolv_conf() {
        let host = HostPaths {
            dev: PathBuf::from("/dev"),
            resolv_conf: PathBuf::from("/etc/resolv.conf"),
        };
        let isolated = MountPlan::for_level(IsolationLevel::Cli, &host, 4096);
        assert!(!isolated
            .mounts
            .iter()
            .any(|m| m.target == Path::new("/etc/resolv.conf")));

        let networked = MountPlan::for_level(IsolationLevel::Networked, &host, 4096);
        if host.resolv_conf.exists() {
            assert!(networked
                .mounts
                .iter()
                .any(|m| m.target == Path::new("/etc/resolv.conf")));
        } else {
            assert!(
                networked
                    .warnings
                    .iter()
                    .any(|w| w.contains("without DNS"))
            );
        }
    }

    #[test]
    fn privileged_level_skips_procfs() {
        let host = HostPaths::default();
        let plan = MountPlan::for_level(IsolationLevel::Privileged, &host, 4096);
        assert!(!plan.mounts_proc());
        assert!(plan.warnings.iter().any(|w| w.contains("/proc")));
    }

    #[test]
    fn missing_device_is_a_warning_not_an_error() {
        let host = HostPaths {
            dev: PathBuf::from("/definitely/not/a/dev"),
            resolv_conf: PathBuf::from("/definitely/not/resolv.conf"),
        };
        let plan = MountPlan::for_level(IsolationLevel::Isolated, &host, 4096);
        assert!(plan.warnings.iter().any(|w| w.contains("device node")));
        assert!(plan.missing_required().is_empty());
        // The tmpfs entries still exist for /dev even with no device binds.
        assert!(plan
            .mounts
            .iter()
            .any(|m| m.target == Path::new("/dev")));
    }

    #[test]
    fn host_paths_honours_env_override() {
        // `from_env` only reads; assert the default shape without mutating the
        // process environment (tests run in parallel).
        let paths = HostPaths::default();
        assert_eq!(paths.dev, PathBuf::from("/dev"));
        assert_eq!(paths.device_nodes().len(), 6);
    }

    #[test]
    fn socket_probe_distinguishes_sockets_from_files() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("plain");
        std::fs::write(&file, b"x").unwrap();
        assert!(!is_socket(&file));
        assert!(!is_socket(&tmp.path().join("missing")));

        let sock = tmp.path().join("sock");
        let _listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        assert!(is_socket(&sock));
    }
}
