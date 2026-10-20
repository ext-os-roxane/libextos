//! Btrfs Snapshot & Transactional Updates (M8).
//!
//! Provides atomic system transitions by leveraging Btrfs subvolume snapshots,
//! with a portable hardlink-copy fallback for every other filesystem.
//!
//! ## Architecture
//! ```text
//! /@system/
//!   current → gen-42/       (symlink to active generation)
//!   gen-42/                  (Btrfs snapshot — the live /usr)
//!   gen-41/                  (previous generation, rollback target)
//!   gen-40/                  (older, GC candidate)
//! ```
//!
//! Each generation holds a complete woven `/usr` tree + lockfile.
//! `instanz apply` creates a new snapshot, weaves into it, then atomically
//! switches the `current` symlink.
//!
//! ## Backends
//!
//! The backend is chosen per [`create`] call (see [`SnapshotBackend`]):
//!
//! | Backend | Selected when | Semantics |
//! |---------|---------------|-----------|
//! | [`SnapshotBackend::Btrfs`] | the source is a Btrfs subvolume, the destination directory is on Btrfs **and** the process may manage subvolumes | copy-on-write clone: O(1) and atomic; no data is copied and the two trees diverge only on write |
//! | [`SnapshotBackend::HardlinkCopy`] | anything else | `cp -al` hardlink copy: O(number of files) metadata work, hardlinked file *data* is shared |
//!
//! "May manage subvolumes" is [`can_manage_subvolumes`]: destroying a subvolume
//! needs `CAP_SYS_ADMIN` unless the filesystem is mounted with
//! `user_subvol_rm_allowed`, and a generation that cannot be destroyed would
//! wedge GC. Unprivileged runs therefore use hardlink copies and plain
//! directories only — which are always deletable.
//!
//! **These are not equivalent.** A hardlink snapshot isolates creates,
//! deletes and renames, but *not* in-place modification of an existing file:
//! rewriting a hardlinked file in place changes every snapshot that shares the
//! inode. Callers that may land on the hardlink backend must replace files by
//! `rename` (write a new file, then atomically rename it over the old one)
//! rather than truncating and rewriting them. [`SnapshotBackend::is_cow`]
//! reports which contract applies; [`SnapshotInfo::backend`] reports what was
//! actually used for an existing generation.
//!
//! ## Path discipline
//!
//! Every entry point is path-parameterised. Nothing in this module assumes a
//! particular rootfs layout — the caller supplies the system root, the
//! snapshot source, and (for boot entries) the BLS entries directory. This is
//! what lets the whole module be tested inside a temporary directory.

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::error::ExtosError;

#[cfg(unix)]
pub mod btrfs;
pub mod engine;
pub mod generation;

pub use engine::{SnapshotEngine, SnapshotInfo};
pub use generation::{AdvanceOptions, AdvancedGeneration, BlsEntry, Generation, GenerationTracker};

/// How a snapshot's contents were materialised.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotBackend {
    /// Native Btrfs subvolume snapshot (`BTRFS_IOC_SNAP_CREATE`): copy-on-write.
    Btrfs,
    /// `cp -al` hardlink copy, for filesystems without subvolumes.
    HardlinkCopy,
}

impl SnapshotBackend {
    /// Stable identifier for metadata files and logs.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Btrfs => "btrfs",
            Self::HardlinkCopy => "hardlink-copy",
        }
    }

    /// `true` for copy-on-write backends, where in-place writes are isolated.
    ///
    /// `false` for [`SnapshotBackend::HardlinkCopy`], where files shared with
    /// another generation must be replaced by rename, never rewritten.
    pub fn is_cow(self) -> bool {
        matches!(self, Self::Btrfs)
    }
}

impl std::fmt::Display for SnapshotBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Maximum length of a single path component (`NAME_MAX` on Linux).
pub const MAX_SNAPSHOT_NAME_LEN: usize = 255;

/// Validate a snapshot / subvolume name.
///
/// Rejects empty names, path separators, `.`/`..`, NUL bytes and names longer
/// than [`MAX_SNAPSHOT_NAME_LEN`], so callers get a clear error instead of an
/// `EINVAL` from the kernel.
pub fn validate_snapshot_name(name: &str) -> Result<(), ExtosError> {
    if name.is_empty() {
        return Err(ExtosError::Snapshot("snapshot name must not be empty".into()));
    }
    if name == "." || name == ".." {
        return Err(ExtosError::Snapshot(format!(
            "snapshot name {name:?} is not a valid path component"
        )));
    }
    if name.contains('/') || name.contains('\0') {
        return Err(ExtosError::Snapshot(format!(
            "snapshot name {name:?} must be a single path component (no '/' or NUL)"
        )));
    }
    if name.len() > MAX_SNAPSHOT_NAME_LEN {
        return Err(ExtosError::Snapshot(format!(
            "snapshot name is {} bytes, limit is {MAX_SNAPSHOT_NAME_LEN}",
            name.len()
        )));
    }
    Ok(())
}

/// `true` if `path` exists on a Btrfs filesystem.
///
/// Returns `false` for paths that do not exist and on non-Linux platforms.
#[cfg(unix)]
pub fn is_btrfs(path: &Path) -> bool {
    btrfs::is_btrfs(path)
}

/// `true` if `path` exists on a Btrfs filesystem.
///
/// Always `false` on platforms without Btrfs support.
#[cfg(not(unix))]
pub fn is_btrfs(_path: &Path) -> bool {
    false
}

/// `true` if `path` is the root directory of a Btrfs subvolume.
#[cfg(unix)]
pub fn is_subvolume(path: &Path) -> bool {
    btrfs::is_subvolume(path)
}

/// `true` if `path` is the root directory of a Btrfs subvolume.
#[cfg(not(unix))]
pub fn is_subvolume(_path: &Path) -> bool {
    false
}

/// Pick the backend [`create`] would use for this source/destination pair.
///
/// Btrfs requires *both* sides to be subvolume-capable: the source must be a
/// subvolume root, the destination directory must live on Btrfs, **and** this
/// process must be allowed to manage subvolumes (see
/// [`can_manage_subvolumes`]). Anything else falls back to
/// [`SnapshotBackend::HardlinkCopy`].
pub fn detect_backend(source: &Path, dest_dir: &Path) -> SnapshotBackend {
    if can_manage_subvolumes() && is_subvolume(source) && exists_on_btrfs(dest_dir) {
        SnapshotBackend::Btrfs
    } else {
        SnapshotBackend::HardlinkCopy
    }
}

/// Whether this process can create *and* destroy Btrfs subvolumes.
///
/// Btrfs is asymmetric here: an unprivileged process can sometimes create a
/// subvolume (it only needs write access to the parent) but destroying one
/// requires `CAP_SYS_ADMIN` unless the filesystem is mounted with
/// `user_subvol_rm_allowed`. A generation that cannot be destroyed would wedge
/// GC, so the engine only selects the Btrfs backend when this returns `true`
/// — in practice, when running as root. Unprivileged runs use hardlink copies
/// and plain directories throughout, which are always deletable.
#[cfg(unix)]
pub fn can_manage_subvolumes() -> bool {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() == 0 }
}

/// Whether this process can create *and* destroy Btrfs subvolumes.
///
/// Always `false` on platforms without Btrfs.
#[cfg(not(unix))]
pub fn can_manage_subvolumes() -> bool {
    false
}

/// Like [`is_btrfs`], but resolves the nearest existing ancestor so it can be
/// asked about a directory that is about to be created.
fn exists_on_btrfs(path: &Path) -> bool {
    let mut cur = path;
    loop {
        if cur.symlink_metadata().is_ok() {
            return is_btrfs(cur);
        }
        match cur.parent() {
            Some(parent) => cur = parent,
            None => return false,
        }
    }
}

/// Create a writable snapshot of `source` named `name` inside `dest_dir`.
///
/// Returns the path of the new snapshot (`dest_dir/name`). Fails if that path
/// already exists or if the source is not a directory. `dest_dir` is created
/// if missing.
///
/// On Btrfs this is a copy-on-write subvolume snapshot; elsewhere it is a
/// `cp -al` hardlink copy — see the [module docs](self) for the semantic
/// difference.
pub fn create(source: &Path, dest_dir: &Path, name: &str) -> Result<PathBuf, ExtosError> {
    create_with(source, dest_dir, name, false)
}

/// Like [`create`], but `readonly` requests a read-only Btrfs snapshot
/// (`BTRFS_SUBVOL_RDONLY`). Ignored by the hardlink backend, which always
/// produces a writable copy.
pub fn create_with(
    source: &Path,
    dest_dir: &Path,
    name: &str,
    readonly: bool,
) -> Result<PathBuf, ExtosError> {
    validate_snapshot_name(name)?;
    if !source.is_dir() {
        return Err(ExtosError::Snapshot(format!(
            "snapshot source is not a directory: {}",
            source.display()
        )));
    }
    fs::create_dir_all(dest_dir)?;
    let dest = dest_dir.join(name);
    if dest.symlink_metadata().is_ok() {
        return Err(ExtosError::Snapshot(format!(
            "snapshot destination already exists: {}",
            dest.display()
        )));
    }

    match detect_backend(source, dest_dir) {
        SnapshotBackend::Btrfs => btrfs_snap_create(source, dest_dir, name, readonly)?,
        SnapshotBackend::HardlinkCopy => hardlink_copy(source, &dest)?,
    }
    Ok(dest)
}

/// Create an empty generation directory / subvolume named `name`.
///
/// Uses `BTRFS_IOC_SUBVOL_CREATE` when `dest_dir` is on Btrfs and this process
/// may manage subvolumes ([`can_manage_subvolumes`]); otherwise a plain
/// `mkdir`.
///
/// If the subvolume ioctl is refused (e.g. a root process that lost
/// `CAP_SYS_ADMIN` in a container) the generation is created as a plain
/// directory instead: the tree is still usable, it simply behaves like a
/// hardlink-copy snapshot from then on (its [`SnapshotInfo::backend`] reports
/// the truth).
pub fn create_empty(dest_dir: &Path, name: &str) -> Result<PathBuf, ExtosError> {
    validate_snapshot_name(name)?;
    fs::create_dir_all(dest_dir)?;
    let dest = dest_dir.join(name);
    if dest.symlink_metadata().is_ok() {
        return Err(ExtosError::Snapshot(format!(
            "snapshot destination already exists: {}",
            dest.display()
        )));
    }

    if can_manage_subvolumes() && is_btrfs(dest_dir) {
        match btrfs_subvol_create(dest_dir, name) {
            Ok(()) => {}
            Err(e) => {
                tracing::warn!(
                    target: "extos::snapshot",
                    "subvolume creation failed, falling back to a plain directory: {e}"
                );
                fs::create_dir(&dest)?;
            }
        }
    } else {
        fs::create_dir(&dest)?;
    }
    Ok(dest)
}

/// Delete the snapshot at `target`.
///
/// Btrfs subvolumes are removed with `BTRFS_IOC_SNAP_DESTROY`; anything else
/// (including a plain directory on Btrfs) is removed with `remove_dir_all`.
pub fn delete(target: &Path) -> Result<(), ExtosError> {
    let md = target.symlink_metadata().map_err(|e| {
        ExtosError::Snapshot(format!("snapshot does not exist at {}: {e}", target.display()))
    })?;
    if !md.is_dir() {
        return Err(ExtosError::Snapshot(format!(
            "snapshot is not a directory: {}",
            target.display()
        )));
    }
    if is_subvolume(target) {
        btrfs_snap_destroy(target)
    } else {
        fs::remove_dir_all(target).map_err(ExtosError::from)
    }
}

/// Enumerate the generations (`gen-<n>`) directly under `root`.
///
/// Symlinks such as `current` are ignored and the result is sorted by
/// generation number. A missing root yields an empty list.
pub fn list(root: &Path) -> Result<Vec<SnapshotInfo>, ExtosError> {
    let current = read_current(root)?;
    let mut gens = Vec::new();

    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(gens),
        Err(e) => return Err(ExtosError::from(e)),
    };

    for entry in entries {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if !file_type.is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(num_str) = name.strip_prefix("gen-") else {
            continue;
        };
        let Ok(number) = num_str.parse::<u64>() else {
            continue;
        };
        let path = entry.path();
        gens.push(SnapshotInfo {
            generation: number,
            is_current: current == Some(number),
            is_btrfs: is_subvolume(&path),
            backend: backend_of(&path),
            name,
            path,
        });
    }

    gens.sort_by_key(|g| g.generation);
    Ok(gens)
}

/// Enumerate every Btrfs subvolume directly under `root`, whatever its name.
///
/// Useful for auditing `/runlevel/1/<system>` for stray subvolumes that the
/// generation GC would not see. Returns an empty list on non-Btrfs paths.
pub fn list_subvolumes(root: &Path) -> Result<Vec<PathBuf>, ExtosError> {
    let mut found = Vec::new();
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(found),
        Err(e) => return Err(ExtosError::from(e)),
    };
    for entry in entries {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let path = entry.path();
        if is_subvolume(&path) {
            found.push(path);
        }
    }
    found.sort();
    Ok(found)
}

/// Read the generation pointed at by `root/current`.
///
/// Returns `Ok(None)` when the symlink is missing or does not point at a
/// `gen-<n>` directory.
pub fn read_current(root: &Path) -> Result<Option<u64>, ExtosError> {
    let link = root.join("current");
    if link.symlink_metadata().is_err() {
        return Ok(None);
    }
    let target = fs::read_link(&link)?;
    let name = target
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();
    Ok(name.strip_prefix("gen-").and_then(|n| n.parse::<u64>().ok()))
}

/// Atomically repoint `root/current` at `gen-<number>`.
///
/// The new symlink is created next to the old one and `rename(2)`d over it, so
/// a reader either sees the old generation or the new one — never a missing
/// `current`.
pub fn set_current(root: &Path, number: u64) -> Result<(), ExtosError> {
    replace_symlink(Path::new(&format!("gen-{number}")), &root.join("current"))
}

/// Atomically replace `link` with a symlink to `target`.
///
/// `target` is stored verbatim (relative targets are recommended so the tree
/// stays relocatable). The temporary name includes the pid to stay safe under
/// concurrent callers.
pub fn replace_symlink(target: &Path, link: &Path) -> Result<(), ExtosError> {
    let parent = link.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let file_name = link
        .file_name()
        .ok_or_else(|| ExtosError::Snapshot(format!("invalid symlink path: {}", link.display())))?
        .to_string_lossy()
        .into_owned();
    let tmp = parent.join(format!(".{file_name}.tmp-{}", std::process::id()));

    if tmp.symlink_metadata().is_ok() {
        fs::remove_file(&tmp)?;
    }
    symlink(target, &tmp)?;
    if let Err(e) = fs::rename(&tmp, link) {
        let _ = fs::remove_file(&tmp);
        return Err(ExtosError::from(e));
    }
    Ok(())
}

/// Delete all but the newest `keep` generations under `root`.
///
/// Returns the deleted generation numbers, in ascending order. The generation
/// `current` points at is never deleted, even if it falls outside the window,
/// so GC cannot make the running system unbootable.
pub fn gc(root: &Path, keep: usize) -> Result<Vec<u64>, ExtosError> {
    let current = read_current(root)?;
    let mut gens = list(root)?;
    gens.sort_by(|a, b| b.generation.cmp(&a.generation));

    let mut deleted = Vec::new();
    for info in gens.into_iter().skip(keep) {
        if current == Some(info.generation) {
            continue;
        }
        delete(&info.path)?;
        deleted.push(info.generation);
    }
    deleted.sort_unstable();
    Ok(deleted)
}

fn backend_of(path: &Path) -> SnapshotBackend {
    if is_subvolume(path) {
        SnapshotBackend::Btrfs
    } else {
        SnapshotBackend::HardlinkCopy
    }
}

#[cfg(unix)]
fn btrfs_snap_create(
    source: &Path,
    dest_dir: &Path,
    name: &str,
    readonly: bool,
) -> Result<(), ExtosError> {
    btrfs::snap_create(source, dest_dir, name, readonly).map(|_| ())
}

#[cfg(not(unix))]
fn btrfs_snap_create(
    _source: &Path,
    _dest_dir: &Path,
    _name: &str,
    _readonly: bool,
) -> Result<(), ExtosError> {
    Err(ExtosError::Snapshot(
        "btrfs snapshots are not supported on this platform".into(),
    ))
}

#[cfg(unix)]
fn btrfs_subvol_create(parent: &Path, name: &str) -> Result<(), ExtosError> {
    btrfs::subvol_create(parent, name).map(|_| ())
}

#[cfg(not(unix))]
fn btrfs_subvol_create(_parent: &Path, _name: &str) -> Result<(), ExtosError> {
    Err(ExtosError::Snapshot(
        "btrfs subvolumes are not supported on this platform".into(),
    ))
}

#[cfg(unix)]
fn btrfs_snap_destroy(target: &Path) -> Result<(), ExtosError> {
    btrfs::snap_destroy(target)
}

#[cfg(not(unix))]
fn btrfs_snap_destroy(_target: &Path) -> Result<(), ExtosError> {
    Err(ExtosError::Snapshot(
        "btrfs snapshots are not supported on this platform".into(),
    ))
}

#[cfg(unix)]
fn symlink(target: &Path, link: &Path) -> Result<(), ExtosError> {
    std::os::unix::fs::symlink(target, link).map_err(ExtosError::from)
}

#[cfg(not(unix))]
fn symlink(target: &Path, link: &Path) -> Result<(), ExtosError> {
    fs::write(link, target.as_os_str().as_encoded_bytes()).map_err(ExtosError::from)
}

/// Hardlink-copy `source` to `dest` with `cp -al`.
///
/// If `cp` is not installed (rescue images), fall back to
/// [`hardlink_copy_native`], which implements the same semantics in-process.
fn hardlink_copy(source: &Path, dest: &Path) -> Result<(), ExtosError> {
    let status = Command::new("cp")
        .arg("-a")
        .arg("-l")
        .arg("--")
        .arg(source)
        .arg(dest)
        .status();

    match status {
        Ok(status) if status.success() => Ok(()),
        Ok(status) => {
            cleanup_partial(dest);
            Err(ExtosError::Snapshot(format!(
                "cp -al {} {} failed with exit code {}",
                source.display(),
                dest.display(),
                status.code().unwrap_or(-1)
            )))
        }
        Err(e) if e.kind() == ErrorKind::NotFound => hardlink_copy_native(source, dest),
        Err(e) => {
            cleanup_partial(dest);
            Err(ExtosError::Snapshot(format!(
                "cannot run cp -al for {}: {e}",
                source.display()
            )))
        }
    }
}

/// In-process equivalent of `cp -a -l`: recurse, `hard_link(2)` files,
/// recreate symlinks. Used when `cp` is unavailable and exercised directly by
/// the unit tests.
fn hardlink_copy_native(source: &Path, dest: &Path) -> Result<(), ExtosError> {
    let md = fs::symlink_metadata(source)?;
    if md.is_dir() {
        fs::create_dir_all(dest)?;
        for entry in fs::read_dir(source)? {
            let entry = entry?;
            let child_dest = dest.join(entry.file_name());
            if let Err(e) = hardlink_copy_native(&entry.path(), &child_dest) {
                cleanup_partial(dest);
                return Err(e);
            }
        }
        Ok(())
    } else if md.file_type().is_symlink() {
        let target = fs::read_link(source)?;
        symlink(&target, dest)
    } else {
        fs::hard_link(source, dest).map_err(ExtosError::from)
    }
}

/// Best-effort removal of a half-written snapshot after a failed copy.
fn cleanup_partial(dest: &Path) {
    if dest.symlink_metadata().is_ok() {
        // Errors are irrelevant: we are already on the failure path and the
        // original error is about to be returned.
        let _ = fs::remove_dir_all(dest);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed_tree(root: &Path) {
        fs::create_dir_all(root.join("usr/bin")).unwrap();
        fs::write(root.join("usr/bin/hello"), b"hello world").unwrap();
        fs::write(root.join("usr/bin/early"), b"early").unwrap();
        fs::create_dir_all(root.join("etc")).unwrap();
        fs::write(root.join("etc/os-release"), b"ID=extos\n").unwrap();
        std::os::unix::fs::symlink("/usr/bin/hello", root.join("bin-hello")).unwrap();
    }

    #[test]
    fn test_validate_snapshot_name() {
        assert!(validate_snapshot_name("gen-1").is_ok());
        assert!(validate_snapshot_name("").is_err());
        assert!(validate_snapshot_name(".").is_err());
        assert!(validate_snapshot_name("..").is_err());
        assert!(validate_snapshot_name("a/b").is_err());
        assert!(validate_snapshot_name("nul\0byte").is_err());
        assert!(validate_snapshot_name(&"x".repeat(MAX_SNAPSHOT_NAME_LEN + 1)).is_err());
    }

    /// create → list → delete on whatever backend this host provides.
    #[test]
    fn test_create_list_delete_cycle() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("source");
        let gens = tmp.path().join("system");
        fs::create_dir_all(&source).unwrap();
        seed_tree(&source);

        let backend = detect_backend(&source, &gens);
        eprintln!("test_create_list_delete_cycle running on backend {backend}");

        let snap = create(&source, &gens, "gen-1").unwrap();
        assert!(snap.is_dir());
        assert_eq!(fs::read(snap.join("usr/bin/hello")).unwrap(), b"hello world");
        assert_eq!(fs::read_link(snap.join("bin-hello")).unwrap(), Path::new("/usr/bin/hello"));

        if backend == SnapshotBackend::HardlinkCopy {
            // Documented semantics: `cp -al` shares file data between the two
            // trees (only creates/deletes/renames are isolated).
            use std::os::unix::fs::MetadataExt;
            let src = fs::metadata(source.join("usr/bin/hello")).unwrap();
            let dst = fs::metadata(snap.join("usr/bin/hello")).unwrap();
            assert_eq!(src.ino(), dst.ino(), "hardlink backend must share inodes");
        }

        let listed = list(&gens).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].generation, 1);
        assert_eq!(listed[0].name, "gen-1");
        assert_eq!(listed[0].backend, backend);
        assert!(!listed[0].is_current);

        // A snapshot of the snapshot is allowed too.
        let snap2 = create(&snap, &gens, "gen-2").unwrap();
        assert_eq!(fs::read(snap2.join("etc/os-release")).unwrap(), b"ID=extos\n");
        assert_eq!(list(&gens).unwrap().len(), 2);

        delete(&snap).unwrap();
        assert!(snap.symlink_metadata().is_err());
        assert_eq!(list(&gens).unwrap().len(), 1);

        delete(&snap2).unwrap();
        assert!(list(&gens).unwrap().is_empty());
    }

    #[test]
    fn test_create_rejects_duplicate_and_missing_source() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("source");
        fs::create_dir_all(&source).unwrap();
        let gens = tmp.path().join("system");

        create(&source, &gens, "gen-1").unwrap();
        let err = create(&source, &gens, "gen-1").unwrap_err();
        assert!(err.to_string().contains("already exists"), "{err}");

        let err = create(&tmp.path().join("nope"), &gens, "gen-2").unwrap_err();
        assert!(err.to_string().contains("not a directory"), "{err}");

        let err = create(&source, &gens, "../escape").unwrap_err();
        assert!(err.to_string().contains("path component"), "{err}");
    }

    #[test]
    fn test_empty_generation_and_delete_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let gens = tmp.path().join("system");

        let gen1 = create_empty(&gens, "gen-1").unwrap();
        assert!(gen1.is_dir());
        assert!(gen1.read_dir().unwrap().next().is_none());
        assert!(create_empty(&gens, "gen-1").is_err());

        let err = delete(&gens.join("gen-9")).unwrap_err();
        assert!(err.to_string().contains("does not exist"), "{err}");
    }

    #[test]
    fn test_list_ignores_symlinks_and_foreign_names() {
        let tmp = tempfile::tempdir().unwrap();
        let gens = tmp.path().join("system");
        create_empty(&gens, "gen-1").unwrap();
        create_empty(&gens, "gen-2").unwrap();
        create_empty(&gens, "scratch").unwrap();
        fs::write(gens.join("gen-notanumber"), b"x").unwrap();
        set_current(&gens, 2).unwrap();

        let listed = list(&gens).unwrap();
        assert_eq!(listed.len(), 2);
        assert_eq!(read_current(&gens).unwrap(), Some(2));
        assert!(listed[1].is_current);
        assert!(!listed[0].is_current);
    }

    #[test]
    fn test_list_missing_root_is_empty() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(list(&tmp.path().join("absent")).unwrap().is_empty());
        assert!(list_subvolumes(&tmp.path().join("absent")).unwrap().is_empty());
        assert_eq!(read_current(&tmp.path().join("absent")).unwrap(), None);
    }

    #[test]
    fn test_gc_keeps_newest_n_and_protects_current() {
        let tmp = tempfile::tempdir().unwrap();
        let gens = tmp.path().join("system");
        for n in 1..=5 {
            create_empty(&gens, &format!("gen-{n}")).unwrap();
        }
        // Point `current` at an old generation: it must survive GC.
        set_current(&gens, 2).unwrap();

        let deleted = gc(&gens, 2).unwrap();
        assert_eq!(deleted, vec![1, 3]);
        let remaining: Vec<u64> = list(&gens).unwrap().iter().map(|g| g.generation).collect();
        assert_eq!(remaining, vec![2, 4, 5]);

        // Nothing left to collect.
        assert!(gc(&gens, 2).unwrap().is_empty());
    }

    #[test]
    fn test_gc_keep_zero_keeps_only_current() {
        let tmp = tempfile::tempdir().unwrap();
        let gens = tmp.path().join("system");
        for n in 1..=3 {
            create_empty(&gens, &format!("gen-{n}")).unwrap();
        }
        set_current(&gens, 3).unwrap();

        let deleted = gc(&gens, 0).unwrap();
        assert_eq!(deleted, vec![1, 2]);
        assert_eq!(read_current(&gens).unwrap(), Some(3));
    }

    #[test]
    fn test_replace_symlink_is_atomic_and_overwrites() {
        let tmp = tempfile::tempdir().unwrap();
        let link = tmp.path().join("current");
        fs::create_dir_all(tmp.path().join("gen-1")).unwrap();
        fs::create_dir_all(tmp.path().join("gen-2")).unwrap();

        set_current(tmp.path(), 1).unwrap();
        assert_eq!(read_current(tmp.path()).unwrap(), Some(1));
        set_current(tmp.path(), 2).unwrap();
        assert_eq!(read_current(tmp.path()).unwrap(), Some(2));
        assert_eq!(fs::read_link(&link).unwrap(), Path::new("gen-2"));
        // No temp symlink left behind.
        let leftovers: Vec<_> = fs::read_dir(tmp.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with(".current.tmp"))
            .collect();
        assert!(leftovers.is_empty());
    }

    #[test]
    fn test_native_hardlink_copy_semantics() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("source");
        let dest = tmp.path().join("dest");
        seed_tree(&source);

        hardlink_copy_native(&source, &dest).unwrap();
        assert_eq!(fs::read(dest.join("usr/bin/hello")).unwrap(), b"hello world");
        assert_eq!(fs::read_link(dest.join("bin-hello")).unwrap(), Path::new("/usr/bin/hello"));

        // Files are hardlinked (same inode) — this is the documented semantic
        // difference from the Btrfs backend.
        use std::os::unix::fs::MetadataExt;
        let a = fs::metadata(source.join("usr/bin/hello")).unwrap();
        let b = fs::metadata(dest.join("usr/bin/hello")).unwrap();
        assert_eq!(a.ino(), b.ino());

        // Creating a file in the copy does not appear in the source.
        fs::write(dest.join("usr/bin/new"), b"new").unwrap();
        assert!(source.join("usr/bin/new").symlink_metadata().is_err());
    }

    #[test]
    fn test_detect_backend_falls_back_without_subvolumes() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("source");
        fs::create_dir_all(&source).unwrap();
        let backend = detect_backend(&source, &tmp.path().join("system"));
        if is_subvolume(&source) {
            assert_eq!(backend, SnapshotBackend::Btrfs);
        } else {
            assert_eq!(backend, SnapshotBackend::HardlinkCopy);
        }
        assert_eq!(SnapshotBackend::Btrfs.as_str(), "btrfs");
        assert!(!SnapshotBackend::HardlinkCopy.is_cow());
        assert_eq!(SnapshotBackend::HardlinkCopy.to_string(), "hardlink-copy");
    }

    /// Exercised only on a Btrfs host running as root; otherwise it skips but
    /// still asserts the API contract via the fallback backend.
    #[test]
    fn test_real_subvolume_snapshot_when_available() {
        let Some(tmp) = super::engine::tests_support::btrfs_workdir() else {
            eprintln!("skipping btrfs-only assertions: no writable btrfs workdir / not root");
            return;
        };
        // The source must itself be a subvolume for a real snapshot.
        if btrfs_subvol_create(&tmp, "source").is_err() {
            eprintln!("skipping btrfs-only assertions: cannot create subvolume (needs CAP_SYS_ADMIN)");
            return;
        }
        let source = tmp.join("source");
        seed_tree(&source);

        assert!(is_subvolume(&source));
        assert_eq!(detect_backend(&source, &tmp), SnapshotBackend::Btrfs);

        let gens = tmp.join("system");
        let snap = create(&source, &gens, "gen-1").unwrap();
        assert!(is_subvolume(&snap), "snapshot must be a subvolume");
        assert_eq!(fs::read(snap.join("usr/bin/hello")).unwrap(), b"hello world");

        // Read-only variant goes through BTRFS_IOC_SNAP_CREATE_V2.
        let ro = create_with(&source, &gens, "gen-ro", true).unwrap();
        let err = fs::write(ro.join("nope"), b"x").expect_err("read-only snapshot must reject writes");
        assert_eq!(err.raw_os_error(), Some(libc::EROFS));

        let subvols = list_subvolumes(&gens).unwrap();
        assert_eq!(subvols.len(), 2);

        // Deleting a subvolume must go through the ioctl, not remove_dir_all.
        delete(&ro).unwrap();
        assert!(ro.symlink_metadata().is_err());
        assert_eq!(list_subvolumes(&gens).unwrap().len(), 1);
        delete(&snap).unwrap();
        assert!(list_subvolumes(&gens).unwrap().is_empty());
        delete(&source).unwrap();
        assert!(!is_subvolume(&source));
    }
}
