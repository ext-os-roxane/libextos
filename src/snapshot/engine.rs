//! Generation-oriented facade over the snapshot primitives (M8.1).
//!
//! [`SnapshotEngine`] owns a *system root* (the directory holding `gen-<n>/`
//! subvolumes plus the `current` symlink) and turns the path-based primitives
//! in [`super`] into generation-numbered operations.
//!
//! The engine picks the storage backend per snapshot ([`SnapshotBackend`]):
//! a Btrfs subvolume snapshot when both sides of the operation live on Btrfs
//! and the source is itself a subvolume, otherwise a `cp -al` hardlink copy.
//! See the [module documentation](super) for the semantic difference between
//! the two.

use std::fs;
use std::path::{Path, PathBuf};

use super::{SnapshotBackend, detect_backend, is_subvolume};
use crate::error::ExtosError;

/// Information about a snapshot.
#[derive(Debug, Clone)]
pub struct SnapshotInfo {
    /// Snapshot directory path
    pub path: PathBuf,
    /// Directory / subvolume name (e.g. `gen-42`)
    pub name: String,
    /// Generation number
    pub generation: u64,
    /// Whether this is the active generation
    pub is_current: bool,
    /// Whether this snapshot is a real Btrfs subvolume (vs. a plain directory)
    pub is_btrfs: bool,
    /// Backend that produced this snapshot
    pub backend: SnapshotBackend,
}

/// The snapshot engine — manages system generation snapshots.
///
/// Works with both Btrfs (native snapshots) and non-Btrfs (hardlink copies of
/// the tree).
pub struct SnapshotEngine {
    /// Root of the system generations (e.g., `/@system/`)
    root: PathBuf,
    /// Whether the root lives on a Btrfs filesystem
    btrfs_available: bool,
}

impl SnapshotEngine {
    /// Open the snapshot engine at the given system root.
    ///
    /// The root directory is created if it does not exist. No path is assumed:
    /// the caller decides where generations live.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, ExtosError> {
        let root = root.into();
        fs::create_dir_all(&root)?;
        let btrfs_available = super::is_btrfs(&root);
        Ok(Self {
            root,
            btrfs_available,
        })
    }

    /// The generations root this engine operates on.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Whether the generations root is on Btrfs.
    ///
    /// This is a filesystem property, not a promise that snapshots will use
    /// the Btrfs backend — see [`SnapshotInfo::backend`] for what a specific
    /// generation actually used.
    pub fn is_btrfs(&self) -> bool {
        self.btrfs_available
    }

    /// Create a new snapshot of `source` as generation `gen_number`.
    ///
    /// On Btrfs (source is a subvolume on a Btrfs destination) this is a
    /// copy-on-write subvolume snapshot; otherwise the tree is hardlink-copied.
    pub fn create_snapshot(
        &self,
        source: &Path,
        gen_number: u64,
    ) -> Result<SnapshotInfo, ExtosError> {
        self.create_snapshot_with(source, gen_number, false)
    }

    /// Create a new generation snapshot, optionally read-only.
    ///
    /// A read-only snapshot uses `BTRFS_IOC_SNAP_CREATE_V2` with
    /// `BTRFS_SUBVOL_RDONLY`, which is how a freshly woven system is frozen
    /// before the `current` switch. The hardlink backend always produces a
    /// writable copy, so the flag is advisory there.
    pub fn create_snapshot_with(
        &self,
        source: &Path,
        gen_number: u64,
        readonly: bool,
    ) -> Result<SnapshotInfo, ExtosError> {
        let name = format!("gen-{gen_number}");
        if self.gen_path(gen_number).symlink_metadata().is_ok() {
            return Err(ExtosError::Snapshot(format!(
                "generation {gen_number} already exists at {}",
                self.gen_path(gen_number).display()
            )));
        }
        let path = super::create_with(source, &self.root, &name, readonly)?;
        Ok(self.info(path, gen_number))
    }

    /// Create an empty generation (for initial weaving).
    ///
    /// Falls back to a plain directory when the subvolume ioctl is refused.
    pub fn create_empty(&self, gen_number: u64) -> Result<SnapshotInfo, ExtosError> {
        let name = format!("gen-{gen_number}");
        if self.gen_path(gen_number).symlink_metadata().is_ok() {
            return Err(ExtosError::Snapshot(format!(
                "generation {gen_number} already exists"
            )));
        }
        let path = super::create_empty(&self.root, &name)?;
        Ok(self.info(path, gen_number))
    }

    /// Delete generation `gen_number`.
    ///
    /// Btrfs subvolumes are destroyed with `BTRFS_IOC_SNAP_DESTROY`; plain
    /// directories are removed recursively.
    pub fn delete(&self, gen_number: u64) -> Result<(), ExtosError> {
        let target = self.gen_path(gen_number);
        if target.symlink_metadata().is_err() {
            return Err(ExtosError::Snapshot(format!(
                "generation {gen_number} does not exist"
            )));
        }
        super::delete(&target)
    }

    /// List all generations, ascending.
    pub fn list(&self) -> Result<Vec<SnapshotInfo>, ExtosError> {
        super::list(&self.root)
    }

    /// Get the current (active) generation number.
    pub fn current_generation(&self) -> Result<Option<u64>, ExtosError> {
        super::read_current(&self.root)
    }

    /// Switch the active generation by atomically replacing the `current`
    /// symlink.
    pub fn switch_to(&self, gen_number: u64) -> Result<(), ExtosError> {
        if self.gen_path(gen_number).symlink_metadata().is_err() {
            return Err(ExtosError::Snapshot(format!(
                "generation {gen_number} does not exist"
            )));
        }
        super::set_current(&self.root, gen_number)
    }

    /// Delete all but the newest `keep` generations, never touching `current`.
    ///
    /// Returns the deleted generation numbers in ascending order.
    pub fn gc(&self, keep: usize) -> Result<Vec<u64>, ExtosError> {
        super::gc(&self.root, keep)
    }

    /// Path to a generation directory.
    pub fn gen_path(&self, gen_number: u64) -> PathBuf {
        self.root.join(format!("gen-{gen_number}"))
    }

    /// Which backend [`Self::create_snapshot`] would use to snapshot `source`.
    pub fn backend_for(&self, source: &Path) -> SnapshotBackend {
        detect_backend(source, &self.root)
    }

    fn info(&self, path: PathBuf, gen_number: u64) -> SnapshotInfo {
        let is_btrfs = is_subvolume(&path);
        SnapshotInfo {
            name: path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
            is_current: self.current_generation().ok().flatten() == Some(gen_number),
            is_btrfs,
            backend: if is_btrfs {
                SnapshotBackend::Btrfs
            } else {
                SnapshotBackend::HardlinkCopy
            },
            path,
            generation: gen_number,
        }
    }
}

/// Helpers shared by the snapshot tests that need a real Btrfs filesystem.
#[cfg(test)]
pub(crate) mod tests_support {
    use std::fs;
    use std::ops::Deref;
    use std::path::{Path, PathBuf};

    /// A scratch directory that cleans up Btrfs subvolumes on drop
    /// (`remove_dir_all` cannot delete a subvolume).
    pub struct WorkDir {
        path: PathBuf,
    }

    impl Deref for WorkDir {
        type Target = Path;
        fn deref(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for WorkDir {
        fn drop(&mut self) {
            cleanup(&self.path);
        }
    }

    /// A writable scratch directory on a Btrfs filesystem, or `None`.
    ///
    /// Subvolume creation needs `CAP_SYS_ADMIN`, so this returns `None` for
    /// unprivileged test runs; the Btrfs-only tests then skip instead of
    /// failing. Candidate parents are `$EXTOS_TEST_BTRFS_DIR`, the crate's
    /// `target/` directory (a dev checkout often lives on Btrfs) and the
    /// platform temp dir — nothing is hardcoded.
    pub fn btrfs_workdir() -> Option<WorkDir> {
        // SAFETY: geteuid is always safe to call.
        if unsafe { libc::geteuid() } != 0 {
            return None;
        }
        for base in candidate_bases() {
            if !crate::snapshot::is_btrfs(&base) {
                continue;
            }
            let dir = base.join(format!("extos-snapshot-test-{}", std::process::id()));
            if fs::create_dir_all(&dir).is_err() {
                continue;
            }
            return Some(WorkDir { path: dir });
        }
        None
    }

    fn candidate_bases() -> Vec<PathBuf> {
        let mut bases = Vec::new();
        if let Ok(dir) = std::env::var("EXTOS_TEST_BTRFS_DIR") {
            bases.push(PathBuf::from(dir));
        }
        bases.push(Path::new(env!("CARGO_MANIFEST_DIR")).join("target"));
        bases.push(std::env::temp_dir());
        bases
    }

    fn cleanup(path: &Path) {
        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten() {
                let child = entry.path();
                if crate::snapshot::is_subvolume(&child) {
                    let _ = crate::snapshot::delete(&child);
                }
            }
        }
        let _ = fs::remove_dir_all(path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed(path: &Path) {
        fs::create_dir_all(path.join("usr/bin")).unwrap();
        fs::write(path.join("usr/bin/sh"), b"#!/bin/sh\n").unwrap();
    }

    #[test]
    fn test_create_empty_and_list() {
        let tmp = tempfile::tempdir().unwrap();
        let engine = SnapshotEngine::open(tmp.path().join("system")).unwrap();

        engine.create_empty(1).unwrap();
        engine.create_empty(2).unwrap();

        let gens = engine.list().unwrap();
        assert_eq!(gens.len(), 2);
        assert_eq!(gens[0].generation, 1);
        assert_eq!(gens[1].generation, 2);
        assert_eq!(gens[0].name, "gen-1");
        assert_eq!(engine.root(), tmp.path().join("system"));
    }

    #[test]
    fn test_switch_and_current() {
        let tmp = tempfile::tempdir().unwrap();
        let engine = SnapshotEngine::open(tmp.path().join("system")).unwrap();

        engine.create_empty(1).unwrap();
        assert_eq!(engine.current_generation().unwrap(), None);

        engine.switch_to(1).unwrap();
        assert_eq!(engine.current_generation().unwrap(), Some(1));

        engine.create_empty(2).unwrap();
        engine.switch_to(2).unwrap();
        assert_eq!(engine.current_generation().unwrap(), Some(2));

        // Switching to a generation that does not exist is an error, and the
        // active generation is left untouched.
        assert!(engine.switch_to(9).is_err());
        assert_eq!(engine.current_generation().unwrap(), Some(2));

        // `list` reflects the active generation.
        let gens = engine.list().unwrap();
        assert!(gens[1].is_current);
        assert!(!gens[0].is_current);
    }

    #[test]
    fn test_delete() {
        let tmp = tempfile::tempdir().unwrap();
        let engine = SnapshotEngine::open(tmp.path().join("system")).unwrap();

        engine.create_empty(1).unwrap();
        assert!(engine.gen_path(1).exists());

        engine.delete(1).unwrap();
        assert!(!engine.gen_path(1).exists());
        assert!(engine.delete(1).is_err());
    }

    #[test]
    fn test_duplicate_generation_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let engine = SnapshotEngine::open(tmp.path().join("system")).unwrap();

        engine.create_empty(1).unwrap();
        assert!(engine.create_empty(1).is_err());

        seed(&tmp.path().join("src"));
        assert!(engine.create_snapshot(&tmp.path().join("src"), 1).is_err());
    }

    #[test]
    fn test_snapshot_from_existing() {
        let tmp = tempfile::tempdir().unwrap();
        let engine = SnapshotEngine::open(tmp.path().join("system")).unwrap();

        // Create gen-1 with some content
        engine.create_empty(1).unwrap();
        let gen1 = engine.gen_path(1);
        fs::create_dir_all(gen1.join("usr/bin")).unwrap();
        fs::write(gen1.join("usr/bin/hello"), b"hello").unwrap();

        // Snapshot gen-1 → gen-2
        let info = engine.create_snapshot(&gen1, 2).unwrap();
        assert!(info.path.join("usr/bin/hello").exists());
        assert_eq!(info.generation, 2);
        assert_eq!(info.backend, engine.backend_for(&gen1));
        assert_eq!(info.is_btrfs, info.backend == SnapshotBackend::Btrfs);
        // The copy is independent: removing a file from gen-2 leaves gen-1.
        fs::remove_file(info.path.join("usr/bin/hello")).unwrap();
        assert!(engine.gen_path(1).join("usr/bin/hello").exists());
    }

    #[test]
    fn test_engine_gc_keeps_newest() {
        let tmp = tempfile::tempdir().unwrap();
        let engine = SnapshotEngine::open(tmp.path().join("system")).unwrap();

        for n in 1..=4 {
            engine.create_empty(n).unwrap();
            engine.switch_to(n).unwrap();
        }
        assert_eq!(engine.gc(2).unwrap(), vec![1, 2]);
        let remaining: Vec<u64> = engine.list().unwrap().iter().map(|g| g.generation).collect();
        assert_eq!(remaining, vec![3, 4]);
        assert_eq!(engine.current_generation().unwrap(), Some(4));

        // `current` survives even when it is the oldest generation.
        engine.switch_to(3).unwrap();
        assert!(engine.gc(1).unwrap().is_empty());
        assert_eq!(engine.current_generation().unwrap(), Some(3));
    }

    #[test]
    fn test_open_creates_root() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("a/b/c");
        let engine = SnapshotEngine::open(&root).unwrap();
        assert!(root.is_dir());
        assert!(engine.list().unwrap().is_empty());
        assert_eq!(engine.current_generation().unwrap(), None);
    }

    /// Whatever the host filesystem, the reported backend must match reality
    /// and create/delete must round-trip.
    #[test]
    fn test_backend_matches_filesystem() {
        let tmp = tempfile::tempdir().unwrap();
        let engine = SnapshotEngine::open(tmp.path().join("system")).unwrap();
        eprintln!(
            "engine root on btrfs: {} (running as uid {})",
            engine.is_btrfs(),
            unsafe { libc::geteuid() }
        );

        let info = engine.create_empty(1).unwrap();
        assert_eq!(info.is_btrfs, is_subvolume(&info.path));
        if engine.is_btrfs() {
            // Either a real subvolume, or a plain-dir fallback when the ioctl
            // was refused; both must be self-consistent.
            assert_eq!(info.backend, if info.is_btrfs {
                SnapshotBackend::Btrfs
            } else {
                SnapshotBackend::HardlinkCopy
            });
        } else {
            assert_eq!(info.backend, SnapshotBackend::HardlinkCopy);
        }
        engine.delete(1).unwrap();
    }

    /// Real Btrfs subvolume round-trip: only runs as root on a Btrfs host.
    #[test]
    fn test_btrfs_engine_roundtrip_when_available() {
        let Some(dir) = tests_support::btrfs_workdir() else {
            eprintln!("skipping engine btrfs round-trip: needs root + a btrfs workdir");
            return;
        };
        let engine = SnapshotEngine::open(dir.join("system")).unwrap();
        assert!(engine.is_btrfs());

        let gen1 = engine.create_empty(1).unwrap();
        if !gen1.is_btrfs {
            eprintln!("skipping engine btrfs round-trip: subvolume create refused");
            return;
        }
        seed(&gen1.path);

        let gen2 = engine.create_snapshot(&gen1.path, 2).unwrap();
        assert_eq!(gen2.backend, SnapshotBackend::Btrfs);
        assert!(is_subvolume(&gen2.path));
        assert_eq!(fs::read(gen2.path.join("usr/bin/sh")).unwrap(), b"#!/bin/sh\n");

        engine.switch_to(2).unwrap();
        assert_eq!(engine.current_generation().unwrap(), Some(2));
        assert_eq!(engine.gc(1).unwrap(), vec![1]);
        assert_eq!(engine.list().unwrap().len(), 1);
        engine.delete(2).unwrap();
        assert!(engine.list().unwrap().is_empty());
    }
}
