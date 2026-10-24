//! ID-mapped mounts for cross-system UID translation (PLAN 7.1.4).
//!
//! An ExtOS user has one identity per system (a snapshot root under
//! `/runlevel/1/<system>`), while the universal pool under `/user/<name>/` is
//! shared. ID-mapped mounts (kernel 5.12+, `Documentation/filesystems/idmappings.rst`)
//! let a pool subtree owned by one system's UID view appear under another
//! system's UID mapping without chown-ing any bytes: the mapping is recorded
//! *on the mount*, not on the inodes.
//!
//! # The kernel sequence ([`mount_setattr_idmap`])
//!
//! 1. `open_tree(AT_FDCWD, source, OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC)` —
//!    clone the source subtree as a detached `O_PATH` mount.
//! 2. `mount_setattr(fd, "", AT_EMPTY_PATH | AT_RECURSIVE,
//!    { attr_set = MOUNT_ATTR_IDMAP, userns_fd }, sizeof(mount_attr))` — mark
//!    the clone (recursively) as ID-mapped with the mapping taken from the
//!    user namespace referenced by `userns_fd`.
//! 3. `move_mount(fd, "", AT_FDCWD, target, MOVE_MOUNT_F_EMPTY_PATH)` —
//!    attach the idmapped clone at `target`; the source is untouched.
//!
//! # Semantics and preconditions
//!
//! * `MOUNT_ATTR_IDMAP` derives the ID conversion from the *owning* user
//!   namespace of the source mount into the namespace referenced by
//!   `userns_fd`, and pins it at mount time — later map changes in either
//!   namespace do not propagate to an existing idmapped mount.
//! * The kernel requires the caller to hold `CAP_SYS_ADMIN` over the user
//!   namespace that owns the source mount *and* over the namespace referenced
//!   by `userns_fd`. The mapping target must be a *different* namespace:
//!   mapping a mount into its own owning namespace is refused (`EINVAL`,
//!   verified empirically on 6.18), so `userns_fd` typically references a
//!   nested descendant of the mount's owning namespace — the probe in
//!   `tests/users_int.rs` proves the full sequence with an outer
//!   `unshare --user --map-root-user --mount` (tmpfs owner) and a nested
//!   `unshare --user --map-root-user` as the mapping target. Otherwise the
//!   syscall fails with `EPERM`/`EINVAL`, surfaced as a typed
//!   [`IdmapError::MountSetattr`] — never a silent fallback.
//! * An idmapped clone is created detached; [`mount_setattr_idmap`] closes
//!   the clone fd on every path, success or failure.
//!
//! libc 0.2 ships the constants (`OPEN_TREE_*`, `MOUNT_ATTR_IDMAP`,
//! `mount_attr`, `AT_EMPTY_PATH`, `AT_RECURSIVE`, `MOVE_MOUNT_F_EMPTY_PATH`)
//! and the arch-specific `SYS_*` numbers, but no wrapper functions, so the
//! syscalls go through `libc::syscall`.

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::RawFd;
use std::path::Path;

/// Errors raised while creating an ID-mapped mount; each variant names the
/// kernel operation that refused.
#[derive(Debug, thiserror::Error)]
pub enum IdmapError {
    /// A path contains an interior NUL and cannot address a file.
    #[error("path contains an interior NUL and cannot address a file")]
    InvalidPath,
    /// `open_tree` refused to clone the source subtree.
    #[error("open_tree failed to clone {path}: {source}")]
    OpenTree {
        /// The source path, displayed.
        path: String,
        /// The kernel error (`EPERM` without `CAP_SYS_ADMIN`, …).
        #[source]
        source: std::io::Error,
    },
    /// `mount_setattr` refused to mark the clone `MOUNT_ATTR_IDMAP`.
    #[error("mount_setattr failed to idmap {path}: {source}")]
    MountSetattr {
        /// The source path, displayed.
        path: String,
        /// The kernel error (`EINVAL` for a non-owning namespace, `EPERM`
        /// for missing capability, `EBUSY` for an already-idmapped mount).
        #[source]
        source: std::io::Error,
    },
    /// `move_mount` refused to attach the idmapped clone at the target.
    #[error("move_mount failed to attach the idmapped clone at {path}: {source}")]
    MoveMount {
        /// The target path, displayed.
        path: String,
        /// The kernel error.
        #[source]
        source: std::io::Error,
    },
}

/// Create an ID-mapped clone of `source` and attach it at `target`
/// (PLAN 7.1.4).
///
/// `userns_fd` must reference a user namespace (typically
/// `/proc/<pid>/ns/user` of a nested child namespace or a namespace fd
/// captured via `open_tree`/`NS_GET_*`) that is *distinct from* the
/// namespace owning the source mount — mapping into the owning namespace
/// itself is refused by the kernel — and the caller must hold `CAP_SYS_ADMIN`
/// over both the mount's owning namespace and the mapping target. On success
/// the idmapped subtree is attached at `target` — the mapping is fixed on
/// that mount and `source` itself is unchanged. The clone fd is always closed
/// before returning.
///
/// Kernel 5.12+ required; the sequence is `open_tree(OPEN_TREE_CLONE)` →
/// `mount_setattr(MOUNT_ATTR_IDMAP, AT_RECURSIVE)` → `move_mount`, exactly as
/// documented in `mount_setattr(2)`.
pub fn mount_setattr_idmap(
    source: &Path,
    target: &Path,
    userns_fd: RawFd,
) -> Result<(), IdmapError> {
    let c_source = path_to_cstring(source)?;
    let c_target = path_to_cstring(target)?;
    let c_empty = CString::new("").expect("an empty string contains no NUL");

    // 1. Clone the source subtree as a detached O_PATH mount.
    // SAFETY: the C strings outlive the call and the remaining arguments are
    // plain data; a negative return is the errno convention of raw syscalls.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_open_tree,
            libc::AT_FDCWD,
            c_source.as_ptr(),
            libc::OPEN_TREE_CLONE | libc::OPEN_TREE_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(IdmapError::OpenTree {
            path: source.display().to_string(),
            source: std::io::Error::last_os_error(),
        });
    }
    let fd = fd as RawFd;

    // 2. Mark the clone ID-mapped, recursively, with the given namespace.
    let attr = libc::mount_attr {
        attr_set: libc::MOUNT_ATTR_IDMAP,
        attr_clr: 0,
        propagation: 0,
        userns_fd: userns_fd as u64,
    };
    // SAFETY: `attr` is a valid `mount_attr` of the declared size and the fd
    // is the open clone; "" with AT_EMPTY_PATH addresses the mount itself.
    let setattr_rc = unsafe {
        libc::syscall(
            libc::SYS_mount_setattr,
            fd,
            c_empty.as_ptr(),
            libc::AT_EMPTY_PATH | libc::AT_RECURSIVE,
            &attr as *const libc::mount_attr,
            std::mem::size_of::<libc::mount_attr>(),
        )
    };
    if setattr_rc != 0 {
        let err = IdmapError::MountSetattr {
            path: source.display().to_string(),
            source: std::io::Error::last_os_error(),
        };
        // SAFETY: fd is the open clone from open_tree above.
        unsafe { libc::close(fd) };
        return Err(err);
    }

    // 3. Attach the detached idmapped clone at the target path. The kernel
    // flag for addressing the clone by fd with an empty from-path is
    // MOVE_MOUNT_F_EMPTY_PATH (there is no MOVE_MOUNT_F_MOVE in the UAPI).
    // SAFETY: both C strings outlive the call; the remaining arguments are
    // plain data.
    let move_rc = unsafe {
        libc::syscall(
            libc::SYS_move_mount,
            fd,
            c_empty.as_ptr(),
            libc::AT_FDCWD,
            c_target.as_ptr(),
            libc::MOVE_MOUNT_F_EMPTY_PATH,
        )
    };
    // SAFETY: fd is the open clone; it is closed on every remaining path.
    unsafe { libc::close(fd) };
    if move_rc != 0 {
        return Err(IdmapError::MoveMount {
            path: target.display().to_string(),
            source: std::io::Error::last_os_error(),
        });
    }
    Ok(())
}

/// Address a path as a C string; interior NULs cannot name a file.
fn path_to_cstring(path: &Path) -> Result<CString, IdmapError> {
    CString::new(path.as_os_str().as_bytes()).map_err(|_| IdmapError::InvalidPath)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;
    use std::path::PathBuf;

    #[test]
    fn interior_nul_is_a_typed_rejection() {
        let hostile = PathBuf::from(OsString::from_vec(b"bad\0path".to_vec()));
        let err = mount_setattr_idmap(&hostile, Path::new("/tmp"), 0)
            .expect_err("interior NUL must be rejected before any syscall");
        assert!(matches!(err, IdmapError::InvalidPath), "{err:?}");
    }

    #[test]
    fn kernel_refusal_surfaces_as_a_typed_operation_named_error() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        let dst = dir.path().join("dst");
        std::fs::create_dir(&src).unwrap();
        std::fs::create_dir(&dst).unwrap();

        let nsfd = unsafe {
            libc::open(c"/proc/self/ns/user".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC)
        };
        assert!(nsfd >= 0, "open /proc/self/ns/user");

        let result = mount_setattr_idmap(&src, &dst, nsfd);
        // SAFETY: nsfd is the open namespace fd above.
        unsafe { libc::close(nsfd) };

        let err = result.expect_err(
            "outside a namespace that owns the source mount the kernel must refuse",
        );
        match &err {
            // Unprivileged: open_tree(OPEN_TREE_CLONE) needs CAP_SYS_ADMIN.
            IdmapError::OpenTree { path, .. } => {
                assert_eq!(path, &src.display().to_string());
                assert!(err.to_string().contains("open_tree"), "{err}");
            }
            // Privileged caller, but the initial user namespace may not be
            // used as an ID mapping target — mount_setattr refuses.
            IdmapError::MountSetattr { path, .. } => {
                assert_eq!(path, &src.display().to_string());
                assert!(err.to_string().contains("mount_setattr"), "{err}");
            }
            other => panic!("expected OpenTree or MountSetattr, got: {other:?}"),
        }
        // The refused sequence leaves no mount attached at the target.
        assert!(std::fs::read_dir(&dst).unwrap().count() == 0, "{err}");
    }
}
