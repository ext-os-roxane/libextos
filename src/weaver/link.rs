//! Filesystem link weavers (M6.6–6.8).
//!
//! Materializes the virtual FHS tree into the physical filesystem using:
//! - **Symlinks** (M6.6): Default, cross-device compatible
//! - **Reflinks** (M6.7): Copy-on-write, same-filesystem only (Btrfs/XFS)
//! - **Hardlinks** (M6.8): Same-inode, same-filesystem only
//!
//! The weaver iterates the `VirtualFhs` entries and creates the
//! appropriate link type from `CAS objects/content/` → target `/usr/`.

use std::fs;
use std::os::unix;
use std::path::Path;

use crate::error::ExtosError;
use crate::weaver::vfs::{FhsEntryKind, VirtualFhs};

/// Which link strategy to use for weaving.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkStrategy {
    /// Symlinks (always works, default)
    Symlink,
    /// Reflinks (Btrfs/XFS CoW, falls back to symlink on EXDEV)
    Reflink,
    /// Hardlinks (same-filesystem, falls back to symlink on EXDEV)
    Hardlink,
}

impl Default for LinkStrategy {
    fn default() -> Self {
        Self::Symlink
    }
}

/// Result of a weave operation.
#[derive(Debug, Default)]
pub struct WeaveResult {
    /// Successfully linked entries
    pub linked: usize,
    /// Directories created
    pub dirs_created: usize,
    /// Symlinks created (original symlinks from packages)
    pub symlinks_created: usize,
    /// Entries that fell back to a different strategy
    pub fallbacks: usize,
    /// Entries that failed
    pub errors: Vec<String>,
}

/// Weave a virtual FHS tree into a target directory.
///
/// Creates all directories, then links/copies all files from their
/// CAS source paths into the target tree.
pub fn weave(
    vfs: &VirtualFhs,
    target_root: &Path,
    strategy: LinkStrategy,
) -> Result<WeaveResult, ExtosError> {
    let mut result = WeaveResult::default();

    // Pass 1: Create all directories first (sorted order ensures parents before children)
    for (_key, entry) in vfs.iter() {
        if entry.kind == FhsEntryKind::Directory {
            let target = target_root.join(&entry.rel_path);
            if !target.exists() {
                fs::create_dir_all(&target)?;
                result.dirs_created += 1;
            }
        }
    }

    // Pass 2: Link/copy all files and symlinks
    for (_key, entry) in vfs.iter() {
        let target = target_root.join(&entry.rel_path);

        // Ensure parent directory exists
        if let Some(parent) = target.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent)?;
            }
        }

        match &entry.kind {
            FhsEntryKind::Directory => {
                // Already handled in pass 1
            }
            FhsEntryKind::Symlink(link_target) => {
                // Recreate the original symlink as-is
                if target.symlink_metadata().is_ok() {
                    fs::remove_file(&target)?;
                }
                unix::fs::symlink(link_target, &target)?;
                result.symlinks_created += 1;
            }
            FhsEntryKind::File => {
                if target.exists() {
                    fs::remove_file(&target)?;
                }

                match strategy {
                    LinkStrategy::Symlink => {
                        link_symlink(&entry.source_path, &target)?;
                        result.linked += 1;
                    }
                    LinkStrategy::Reflink => {
                        match link_reflink(&entry.source_path, &target) {
                            Ok(()) => result.linked += 1,
                            Err(_) => {
                                // EXDEV fallback to symlink
                                link_symlink(&entry.source_path, &target)?;
                                result.linked += 1;
                                result.fallbacks += 1;
                            }
                        }
                    }
                    LinkStrategy::Hardlink => {
                        match link_hardlink(&entry.source_path, &target) {
                            Ok(()) => result.linked += 1,
                            Err(_) => {
                                // EXDEV fallback to symlink
                                link_symlink(&entry.source_path, &target)?;
                                result.linked += 1;
                                result.fallbacks += 1;
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(result)
}

/// Unweave: remove all entries that were woven into the target.
pub fn unweave(
    vfs: &VirtualFhs,
    target_root: &Path,
) -> Result<usize, ExtosError> {
    let mut removed = 0;

    // Remove files first (reverse order: children before parents)
    let entries: Vec<_> = vfs.iter().collect();
    for (_key, entry) in entries.iter().rev() {
        let target = target_root.join(&entry.rel_path);
        match entry.kind {
            FhsEntryKind::File | FhsEntryKind::Symlink(_) => {
                if target.symlink_metadata().is_ok() {
                    fs::remove_file(&target)?;
                    removed += 1;
                }
            }
            FhsEntryKind::Directory => {
                // Only remove empty directories
                if target.is_dir() {
                    if fs::read_dir(&target)?.next().is_none() {
                        fs::remove_dir(&target)?;
                        removed += 1;
                    }
                }
            }
        }
    }

    Ok(removed)
}

// ─── Link Implementations ───────────────────────────────────────

/// M6.6: Create a symlink from source → target.
pub(crate) fn link_symlink(source: &Path, target: &Path) -> Result<(), ExtosError> {
    // Use absolute path for the symlink target
    let abs_source = fs::canonicalize(source).unwrap_or_else(|_| source.to_path_buf());
    unix::fs::symlink(&abs_source, target)?;
    Ok(())
}

/// M6.7: Create a reflink (CoW copy) from source → target.
///
/// Uses `ioctl(FICLONE)` on Linux for Btrfs/XFS.
/// Falls back to regular copy if FICLONE is unavailable.
pub(crate) fn link_reflink(source: &Path, target: &Path) -> Result<(), ExtosError> {
    // Try FICLONE ioctl first
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        let src_file = fs::File::open(source)?;
        let dst_file = fs::File::create(target)?;

        // FICLONE = _IOW(0x94, 9, int) = 0x40049409
        const FICLONE: libc::c_ulong = 0x40049409;
        let ret = unsafe {
            libc::ioctl(dst_file.as_raw_fd(), FICLONE, src_file.as_raw_fd())
        };

        if ret == 0 {
            return Ok(());
        }
        // FICLONE failed (wrong FS, etc.) — fall through to error
        fs::remove_file(target).ok(); // clean up partial file
        return Err(ExtosError::Weave(format!(
            "FICLONE failed for {}: {}",
            source.display(),
            std::io::Error::last_os_error()
        )));
    }

    #[cfg(not(target_os = "linux"))]
    {
        Err(ExtosError::Weave("reflink not supported on this platform".into()))
    }
}

/// M6.8: Create a hardlink from source → target.
pub(crate) fn link_hardlink(source: &Path, target: &Path) -> Result<(), ExtosError> {
    fs::hard_link(source, target).map_err(|e| {
        ExtosError::Weave(format!(
            "hardlink {} → {}: {}",
            source.display(),
            target.display(),
            e
        ))
    })
}

/// Probe whether reflinks are supported between two paths.
///
/// Creates a temporary file on the target filesystem and attempts FICLONE
/// from a temporary file on the source filesystem.
pub fn probe_reflink_support(source_dir: &Path, target_dir: &Path) -> bool {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        let src_path = source_dir.join(".extos-reflink-probe-src");
        let dst_path = target_dir.join(".extos-reflink-probe-dst");

        // Create probe files
        if fs::write(&src_path, b"probe").is_err() {
            return false;
        }

        let result = (|| -> bool {
            let src = match fs::File::open(&src_path) {
                Ok(f) => f,
                Err(_) => return false,
            };
            let dst = match fs::File::create(&dst_path) {
                Ok(f) => f,
                Err(_) => return false,
            };

            const FICLONE: libc::c_ulong = 0x40049409;
            let ret = unsafe {
                libc::ioctl(dst.as_raw_fd(), FICLONE, src.as_raw_fd())
            };
            ret == 0
        })();

        // Cleanup probes
        fs::remove_file(&src_path).ok();
        fs::remove_file(&dst_path).ok();
        result
    }

    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

// ─── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use crate::weaver::vfs::{FhsEntry, VirtualFhs};

    #[test]
    fn test_symlink_weave() {
        let tmp = tempfile::tempdir().unwrap();
        let cas_content = tmp.path().join("cas/content");
        let target = tmp.path().join("usr");
        fs::create_dir_all(cas_content.join("bin")).unwrap();
        fs::write(cas_content.join("bin/hello"), b"#!/bin/sh\necho hi").unwrap();
        fs::create_dir_all(&target).unwrap();

        let vfs = VirtualFhs::from_entries(vec![
            FhsEntry {
                rel_path: PathBuf::from("bin"),
                kind: FhsEntryKind::Directory,
                provider: "test/hello".into(),
                provider_hash: "BLAKE3-test".into(),
                source_path: cas_content.join("bin"),
                size: 0,
            },
            FhsEntry {
                rel_path: PathBuf::from("bin/hello"),
                kind: FhsEntryKind::File,
                provider: "test/hello".into(),
                provider_hash: "BLAKE3-test".into(),
                source_path: cas_content.join("bin/hello"),
                size: 17,
            },
        ]);

        let result = weave(&vfs, &target, LinkStrategy::Symlink).unwrap();
        assert_eq!(result.linked, 1);
        assert_eq!(result.dirs_created, 1);
        assert!(target.join("bin/hello").exists());
        // Verify it's a symlink
        assert!(target.join("bin/hello").symlink_metadata().unwrap().file_type().is_symlink());
    }

    #[test]
    fn test_hardlink_weave() {
        let tmp = tempfile::tempdir().unwrap();
        let cas_content = tmp.path().join("cas/content");
        let target = tmp.path().join("usr");
        fs::create_dir_all(cas_content.join("lib")).unwrap();
        fs::write(cas_content.join("lib/libfoo.so"), b"ELF...").unwrap();
        fs::create_dir_all(&target).unwrap();

        let vfs = VirtualFhs::from_entries(vec![
            FhsEntry {
                rel_path: PathBuf::from("lib"),
                kind: FhsEntryKind::Directory,
                provider: "test/foo".into(),
                provider_hash: "BLAKE3-test".into(),
                source_path: cas_content.join("lib"),
                size: 0,
            },
            FhsEntry {
                rel_path: PathBuf::from("lib/libfoo.so"),
                kind: FhsEntryKind::File,
                provider: "test/foo".into(),
                provider_hash: "BLAKE3-test".into(),
                source_path: cas_content.join("lib/libfoo.so"),
                size: 6,
            },
        ]);

        let result = weave(&vfs, &target, LinkStrategy::Hardlink).unwrap();
        assert_eq!(result.linked, 1);
        assert!(target.join("lib/libfoo.so").exists());
        // Verify content
        assert_eq!(fs::read(target.join("lib/libfoo.so")).unwrap(), b"ELF...");
    }

    #[test]
    fn test_unweave() {
        let tmp = tempfile::tempdir().unwrap();
        let cas_content = tmp.path().join("cas/content");
        let target = tmp.path().join("usr");
        fs::create_dir_all(cas_content.join("bin")).unwrap();
        fs::write(cas_content.join("bin/tool"), b"binary").unwrap();

        let vfs = VirtualFhs::from_entries(vec![
            FhsEntry {
                rel_path: PathBuf::from("bin"),
                kind: FhsEntryKind::Directory,
                provider: "test/tool".into(),
                provider_hash: "BLAKE3-test".into(),
                source_path: cas_content.join("bin"),
                size: 0,
            },
            FhsEntry {
                rel_path: PathBuf::from("bin/tool"),
                kind: FhsEntryKind::File,
                provider: "test/tool".into(),
                provider_hash: "BLAKE3-test".into(),
                source_path: cas_content.join("bin/tool"),
                size: 6,
            },
        ]);

        weave(&vfs, &target, LinkStrategy::Symlink).unwrap();
        assert!(target.join("bin/tool").exists());

        let removed = unweave(&vfs, &target).unwrap();
        assert!(removed >= 1);
        assert!(!target.join("bin/tool").exists());
    }

    #[test]
    fn test_symlink_preservation() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("usr");
        fs::create_dir_all(&target).unwrap();

        let vfs = VirtualFhs::from_entries(vec![
            FhsEntry {
                rel_path: PathBuf::from("lib"),
                kind: FhsEntryKind::Directory,
                provider: "test/lib".into(),
                provider_hash: "BLAKE3-test".into(),
                source_path: PathBuf::from("/tmp"),
                size: 0,
            },
            FhsEntry {
                rel_path: PathBuf::from("lib/libfoo.so"),
                kind: FhsEntryKind::Symlink(PathBuf::from("libfoo.so.1")),
                provider: "test/lib".into(),
                provider_hash: "BLAKE3-test".into(),
                source_path: PathBuf::from("/tmp/libfoo.so"),
                size: 0,
            },
        ]);

        let result = weave(&vfs, &target, LinkStrategy::Symlink).unwrap();
        assert_eq!(result.symlinks_created, 1);
        let link = target.join("lib/libfoo.so");
        assert!(link.symlink_metadata().unwrap().file_type().is_symlink());
        assert_eq!(fs::read_link(&link).unwrap(), PathBuf::from("libfoo.so.1"));
    }

    #[test]
    fn test_link_strategy_default() {
        assert_eq!(LinkStrategy::default(), LinkStrategy::Symlink);
    }
}
