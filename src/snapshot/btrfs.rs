//! Raw Btrfs ioctl layer, hand-rolled on top of `libc`.
//!
//! Only the handful of ioctls the snapshot engine needs are implemented:
//!
//! | ioctl | number | purpose |
//! |-------|--------|---------|
//! | `BTRFS_IOC_SNAP_CREATE` | `0x5000_9401` | snapshot a subvolume (v1 args) |
//! | `BTRFS_IOC_SNAP_CREATE_V2` | `0x5000_9417` | same, with flags (read-only snapshots) |
//! | `BTRFS_IOC_SUBVOL_CREATE` | `0x5000_940e` | create an empty subvolume |
//! | `BTRFS_IOC_SNAP_DESTROY` | `0x5000_940f` | delete a subvolume / snapshot |
//!
//! The request numbers are *computed* at compile time with the same
//! `_IOC(dir, type, nr, size)` formula the kernel headers use, and the tests
//! below pin them to the literal values from `linux/btrfs.h`, so a layout
//! mistake is caught at test time instead of at runtime.
//!
//! Everything here is path-parameterised: no path is assumed to exist, no
//! rootfs layout is baked in. Callers pass the source subvolume and the
//! *parent directory* of the snapshot.

use std::ffi::CString;
use std::fs::File;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

use crate::error::ExtosError;

/// `BTRFS_SUPER_MAGIC` from `linux/magic.h`.
pub const BTRFS_SUPER_MAGIC: u32 = 0x9123_683e;

/// Inode number of the root directory of every Btrfs subvolume
/// (`BTRFS_FIRST_FREE_OBJECTID`).
pub const BTRFS_FIRST_FREE_OBJECTID: u64 = 256;

/// `BTRFS_SUBVOL_RDONLY` — create the snapshot read-only.
pub const BTRFS_SUBVOL_RDONLY: u64 = 1 << 1;

const BTRFS_IOCTL_MAGIC: u32 = 0x94;

const IOC_WRITE: u32 = 1;

/// `sizeof(struct btrfs_ioctl_vol_args)` — both arg structs are exactly one
/// page, which is why the encoded size is 4096.
const VOL_ARGS_SIZE: usize = 4096;

const fn ioc(dir: u32, ty: u32, nr: u32, size: usize) -> libc::c_ulong {
    // Same definition as the kernel's <asm-generic/ioctl.h>:
    // _IOC(dir,type,nr,size) == (dir << 30) | (type << 8) | nr | (size << 16)
    ((dir << 30) | (ty << 8) | (nr & 0xff) | ((size as u32) << 16)) as libc::c_ulong
}

const fn iow(ty: u32, nr: u32, size: usize) -> libc::c_ulong {
    ioc(IOC_WRITE, ty, nr, size)
}

/// Snapshot a subvolume (v1 args).
pub const BTRFS_IOC_SNAP_CREATE: libc::c_ulong = iow(BTRFS_IOCTL_MAGIC, 1, VOL_ARGS_SIZE);
/// Snapshot a subvolume with flags (v2 args).
pub const BTRFS_IOC_SNAP_CREATE_V2: libc::c_ulong = iow(BTRFS_IOCTL_MAGIC, 23, VOL_ARGS_SIZE);
/// Create an empty subvolume.
pub const BTRFS_IOC_SUBVOL_CREATE: libc::c_ulong = iow(BTRFS_IOCTL_MAGIC, 14, VOL_ARGS_SIZE);
/// Destroy a subvolume / snapshot.
pub const BTRFS_IOC_SNAP_DESTROY: libc::c_ulong = iow(BTRFS_IOCTL_MAGIC, 15, VOL_ARGS_SIZE);

/// `struct btrfs_ioctl_vol_args` — `{ __s64 fd; char name[4088]; }`.
#[repr(C)]
struct VolArgs {
    fd: i64,
    name: [u8; VOL_ARGS_SIZE - 8],
}

/// `struct btrfs_ioctl_vol_args_v2` — `{ __s64 fd; __u64 transid; __u64 flags;
/// union {...} ; union { char name[4040]; ... }; }`.
#[repr(C)]
struct VolArgsV2 {
    fd: i64,
    transid: u64,
    flags: u64,
    unused: [u64; 4],
    name: [u8; VOL_ARGS_SIZE - 56],
}

impl VolArgs {
    fn new(fd: i64, name: &str) -> Result<Self, ExtosError> {
        let mut args = Self {
            fd,
            name: [0u8; VOL_ARGS_SIZE - 8],
        };
        args.set_name(name)?;
        Ok(args)
    }

    fn set_name(&mut self, name: &str) -> Result<(), ExtosError> {
        write_name(&mut self.name, name)
    }
}

impl VolArgsV2 {
    fn new(fd: i64, name: &str, flags: u64) -> Result<Self, ExtosError> {
        let mut args = Self {
            fd,
            transid: 0,
            flags,
            unused: [0u64; 4],
            name: [0u8; VOL_ARGS_SIZE - 56],
        };
        write_name(&mut args.name, name)?;
        Ok(args)
    }
}

fn write_name(buf: &mut [u8], name: &str) -> Result<(), ExtosError> {
    super::validate_snapshot_name(name)?;
    let bytes = name.as_bytes();
    if bytes.len() >= buf.len() {
        return Err(ExtosError::Snapshot(format!(
            "snapshot name too long for btrfs ioctl ({} >= {} bytes)",
            bytes.len(),
            buf.len()
        )));
    }
    buf[..bytes.len()].copy_from_slice(bytes);
    Ok(())
}

/// Whether `path` (which must exist) lives on a Btrfs filesystem.
///
/// Uses `statfs(2)` — no shelling out to `btrfs-progs`, so this works in a
/// minimal rescue environment.
pub fn is_btrfs(path: &Path) -> bool {
    let Ok(c_path) = CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };
    // SAFETY: `statfs` only writes into the out-parameter we own.
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::statfs(c_path.as_ptr(), &mut st) };
    rc == 0 && (st.f_type as u64 & 0xffff_ffff) == BTRFS_SUPER_MAGIC as u64
}

/// Whether `path` is the root directory of a Btrfs subvolume.
///
/// Btrfs always numbers the root inode of a subvolume `256`
/// (`BTRFS_FIRST_FREE_OBJECTID`), so an existing directory on a Btrfs
/// filesystem with inode 256 *is* a subvolume root. Plain directories and
/// directories inherited from a parent subvolume get ordinary inode numbers.
///
/// Returns `false` for anything that is not an existing directory.
pub fn is_subvolume(path: &Path) -> bool {
    if !is_btrfs(path) {
        return false;
    }
    let Ok(md) = std::fs::symlink_metadata(path) else {
        return false;
    };
    if !md.is_dir() {
        return false;
    }
    use std::os::unix::fs::MetadataExt;
    md.ino() == BTRFS_FIRST_FREE_OBJECTID
}

/// Create a snapshot of the subvolume `source` named `name` inside `dest_dir`.
///
/// Uses `BTRFS_IOC_SNAP_CREATE` (v1) for writable snapshots and
/// `BTRFS_IOC_SNAP_CREATE_V2` with `BTRFS_SUBVOL_RDONLY` for read-only ones.
/// `source` must be a subvolume root and `dest_dir` must already exist.
pub fn snap_create(
    source: &Path,
    dest_dir: &Path,
    name: &str,
    readonly: bool,
) -> Result<PathBuf, ExtosError> {
    let src_file = open_dir(source)?;
    let dst_file = open_dir(dest_dir)?;
    let src_fd = src_file.as_raw_fd();
    let dst_fd = dst_file.as_raw_fd();

    if readonly {
        let mut args = VolArgsV2::new(src_fd as i64, name, BTRFS_SUBVOL_RDONLY)?;
        let rc = unsafe { libc::ioctl(dst_fd, BTRFS_IOC_SNAP_CREATE_V2, &mut args as *mut VolArgsV2) };
        if rc < 0 {
            return Err(ioctl_error("BTRFS_IOC_SNAP_CREATE_V2", std::io::Error::last_os_error()));
        }
    } else {
        let mut args = VolArgs::new(src_fd as i64, name)?;
        let rc = unsafe { libc::ioctl(dst_fd, BTRFS_IOC_SNAP_CREATE, &mut args as *mut VolArgs) };
        if rc < 0 {
            return Err(ioctl_error("BTRFS_IOC_SNAP_CREATE", std::io::Error::last_os_error()));
        }
    }

    Ok(dest_dir.join(name))
}

/// Create an empty subvolume named `name` inside `parent`.
pub fn subvol_create(parent: &Path, name: &str) -> Result<PathBuf, ExtosError> {
    let dir = open_dir(parent)?;
    let mut args = VolArgs::new(0, name)?;
    let rc = unsafe { libc::ioctl(dir.as_raw_fd(), BTRFS_IOC_SUBVOL_CREATE, &mut args as *mut VolArgs) };
    if rc < 0 {
        return Err(ioctl_error("BTRFS_IOC_SUBVOL_CREATE", std::io::Error::last_os_error()));
    }
    Ok(parent.join(name))
}

/// Destroy the subvolume at `target` (`BTRFS_IOC_SNAP_DESTROY`).
///
/// The ioctl is issued on the *parent* directory with `target`'s file name;
/// `target` itself must be a subvolume root (see [`is_subvolume`]).
pub fn snap_destroy(target: &Path) -> Result<(), ExtosError> {
    let name = target
        .file_name()
        .ok_or_else(|| ExtosError::Snapshot(format!("cannot delete filesystem root {}", target.display())))?
        .to_string_lossy()
        .into_owned();
    let parent = target.parent().unwrap_or_else(|| Path::new("."));
    let dir = open_dir(parent)?;
    let mut args = VolArgs::new(0, &name)?;
    let rc = unsafe { libc::ioctl(dir.as_raw_fd(), BTRFS_IOC_SNAP_DESTROY, &mut args as *mut VolArgs) };
    if rc < 0 {
        return Err(ioctl_error("BTRFS_IOC_SNAP_DESTROY", std::io::Error::last_os_error()));
    }
    Ok(())
}

fn open_dir(path: &Path) -> Result<File, ExtosError> {
    File::open(path).map_err(|e| {
        ExtosError::Snapshot(format!("cannot open directory {}: {e}", path.display()))
    })
}

/// Map an `ioctl(2)` failure onto a human-actionable [`ExtosError::Snapshot`].
///
/// Kept separate from the ioctl call sites so the mapping is unit-testable
/// without a Btrfs filesystem.
fn ioctl_error(op: &str, err: std::io::Error) -> ExtosError {
    let code = err.raw_os_error().unwrap_or(0);
    let detail = match code {
        libc::ENOTTY => "not a btrfs filesystem, or the kernel lacks btrfs ioctl support (ENOTTY)".to_string(),
        libc::ENOSYS => "btrfs ioctls unavailable in this kernel (ENOSYS)".to_string(),
        libc::EOPNOTSUPP => "operation not supported by this filesystem (EOPNOTSUPP)".to_string(),
        libc::EPERM | libc::EACCES => format!("permission denied (errno {code}); btrfs subvolume operations need CAP_SYS_ADMIN"),
        libc::EINVAL => "invalid argument (EINVAL): source is not a btrfs subvolume, or the destination name is invalid".to_string(),
        libc::ENOTEMPTY => "subvolume is not empty (ENOTEMPTY)".to_string(),
        libc::ENOENT => "path component vanished (ENOENT)".to_string(),
        libc::ENOSPC => "no space left on device (ENOSPC)".to_string(),
        other => format!("errno {other}: {err}"),
    };
    ExtosError::Snapshot(format!("{op}: {detail}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pin the computed request numbers to `linux/btrfs.h`.
    #[test]
    fn test_ioctl_numbers_match_kernel_header() {
        assert_eq!(BTRFS_IOC_SNAP_CREATE, 0x5000_9401);
        assert_eq!(BTRFS_IOC_SNAP_CREATE_V2, 0x5000_9417);
        assert_eq!(BTRFS_IOC_SUBVOL_CREATE, 0x5000_940e);
        assert_eq!(BTRFS_IOC_SNAP_DESTROY, 0x5000_940f);
        // Sanity: the encoding is _IOW('B', nr, 4096).
        assert_eq!(BTRFS_IOC_SNAP_CREATE >> 30, IOC_WRITE as libc::c_ulong);
        assert_eq!((BTRFS_IOC_SNAP_CREATE >> 8) & 0xff, BTRFS_IOCTL_MAGIC as libc::c_ulong);
        assert_eq!((BTRFS_IOC_SNAP_CREATE >> 16) & 0x3fff, VOL_ARGS_SIZE as libc::c_ulong);
    }

    #[test]
    fn test_vol_args_layout() {
        assert_eq!(std::mem::size_of::<VolArgs>(), VOL_ARGS_SIZE);
        assert_eq!(std::mem::size_of::<VolArgsV2>(), VOL_ARGS_SIZE);

        let args = VolArgs::new(42, "gen-7").unwrap();
        assert_eq!(args.fd, 42);
        assert_eq!(&args.name[..5], b"gen-7");
        assert_eq!(args.name[5], 0, "name must be NUL terminated");

        let args = VolArgsV2::new(7, "gen-8", BTRFS_SUBVOL_RDONLY).unwrap();
        assert_eq!(args.fd, 7);
        assert_eq!(args.flags, BTRFS_SUBVOL_RDONLY);
        assert_eq!(args.transid, 0);
        assert_eq!(&args.name[..5], b"gen-8");
        assert_eq!(args.name[5], 0);
    }

    #[test]
    fn test_name_validation() {
        assert!(write_name(&mut [0u8; 16], "").is_err());
        assert!(write_name(&mut [0u8; 16], "a/b").is_err());
        assert!(write_name(&mut [0u8; 16], "..").is_err());
        assert!(write_name(&mut [0u8; 16], "ok").is_ok());
        assert!(write_name(&mut [0u8; 4], "toolong").is_err());
    }

    /// Error mapping is pure logic and must work without any Btrfs around.
    #[test]
    fn test_ioctl_error_mapping() {
        let e = ioctl_error("X", std::io::Error::from_raw_os_error(libc::ENOTTY));
        let msg = e.to_string();
        assert!(msg.contains("ENOTTY"), "{msg}");
        assert!(msg.contains("not a btrfs"), "{msg}");

        let e = ioctl_error("X", std::io::Error::from_raw_os_error(libc::EPERM));
        assert!(e.to_string().contains("CAP_SYS_ADMIN"), "{e}");
    }

    /// A non-Btrfs directory must never be mistaken for a subvolume, and the
    /// ioctl must fail with a mapped (not panicking) error when attempted.
    #[test]
    fn test_non_btrfs_detection_and_ioctl_failure() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let plain = dir.join("plain");
        std::fs::create_dir(&plain).unwrap();
        assert!(!is_subvolume(&plain), "a plain directory is not a subvolume");

        if is_btrfs(dir) {
            // On btrfs an unprivileged process may be allowed to *create* a
            // subvolume while being unable to destroy it, so probing the ioctl
            // here would leave undeletable garbage behind. The failure mapping
            // is covered by `test_ioctl_error_mapping` and by the non-btrfs
            // branch below.
            eprintln!(
                "note: tempdir is on btrfs at {} — skipping the ioctl-failure probe",
                dir.display()
            );
        } else {
            let err = subvol_create(dir, "subvol").expect_err("ioctl must fail on non-btrfs");
            let msg = err.to_string();
            assert!(
                msg.contains("ENOTTY") || msg.contains("EOPNOTSUPP") || msg.contains("ENOSYS") || msg.contains("EINVAL"),
                "unexpected error: {msg}"
            );
        }
        // Whatever the filesystem, a missing path is not a subvolume.
        assert!(!is_subvolume(&dir.join("does-not-exist")));
    }

    #[test]
    fn test_statfs_btrfs_probe() {
        let tmp = tempfile::tempdir().unwrap();
        // Both answers are acceptable — this only asserts the probe does not
        // panic and is consistent with the compiled-in magic.
        let _ = is_btrfs(tmp.path());
        assert_eq!(BTRFS_SUPER_MAGIC, 0x9123683e);
        assert!(!is_btrfs(Path::new("/nonexistent/extos/definitely-missing")));
    }
}
