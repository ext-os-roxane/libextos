//! Virtual FHS matrix (M6.4).
//!
//! Builds an in-memory representation of the target `/usr` filesystem tree
//! by overlaying content from all resolved packages. Detects collisions
//! (multiple packages providing the same path) before any disk I/O.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::cas::CasRepository;
use crate::error::ExtosError;
use crate::weaver::resolve::ResolvedPackage;

/// What kind of entry this is in the virtual tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FhsEntryKind {
    /// Regular file
    File,
    /// Directory
    Directory,
    /// Symlink with a target path
    Symlink(PathBuf),
}

/// A single entry in the virtual FHS tree.
#[derive(Debug, Clone)]
pub struct FhsEntry {
    /// Relative path from the FHS root (e.g., `usr/bin/htop`)
    pub rel_path: PathBuf,
    /// Entry kind
    pub kind: FhsEntryKind,
    /// Which package provides this entry (origin/name)
    pub provider: String,
    /// CAS object hash of the provider
    pub provider_hash: String,
    /// Absolute source path in CAS (for weaving)
    pub source_path: PathBuf,
    /// File size in bytes (0 for dirs/symlinks)
    pub size: u64,
}

/// A collision: two packages claim the same path.
#[derive(Debug, Clone)]
pub struct Collision {
    pub path: PathBuf,
    pub claimant_a: String,
    pub claimant_b: String,
}

/// The complete virtual FHS tree.
///
/// Maps every relative path to its entry, tracking which package provides it.
/// Built by scanning CAS content directories for all resolved packages.
#[derive(Debug)]
pub struct VirtualFhs {
    /// All entries, keyed by relative path string
    entries: BTreeMap<String, FhsEntry>,
    /// Detected collisions
    collisions: Vec<Collision>,
    /// Total file count
    file_count: usize,
    /// Total directory count
    dir_count: usize,
}

impl VirtualFhs {
    /// Build a virtual FHS tree from resolved packages.
    ///
    /// Scans each package's CAS `content/` directory and registers
    /// every file/dir/symlink in the virtual tree. If two non-directory
    /// entries claim the same path, a collision is recorded.
    pub fn build(
        repo: &CasRepository,
        packages: &[ResolvedPackage],
    ) -> Result<Self, ExtosError> {
        let mut vfs = Self {
            entries: BTreeMap::new(),
            collisions: Vec::new(),
            file_count: 0,
            dir_count: 0,
        };

        for pkg in packages {
            let provider = format!("{}/{}", pkg.identity.origin, pkg.identity.name);
            let content_dir = repo.object_path(&pkg.hash).join("content");

            if !content_dir.exists() {
                continue;
            }

            vfs.scan_directory(&content_dir, &content_dir, &provider, &pkg.hash)?;
        }

        Ok(vfs)
    }

    /// Build from explicit entries (for testing without a CAS).
    pub fn from_entries(entries: Vec<FhsEntry>) -> Self {
        let mut vfs = Self {
            entries: BTreeMap::new(),
            collisions: Vec::new(),
            file_count: 0,
            dir_count: 0,
        };
        for entry in entries {
            vfs.insert_entry(entry);
        }
        vfs
    }

    /// Get all collisions detected during the build.
    pub fn collisions(&self) -> &[Collision] {
        &self.collisions
    }

    /// Whether any collisions were detected.
    pub fn has_collisions(&self) -> bool {
        !self.collisions.is_empty()
    }

    /// Get an entry by relative path.
    pub fn get(&self, rel_path: &str) -> Option<&FhsEntry> {
        self.entries.get(rel_path)
    }

    /// Iterate all entries in sorted path order.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &FhsEntry)> {
        self.entries.iter()
    }

    /// Total number of entries.
    pub fn total_entries(&self) -> usize {
        self.entries.len()
    }

    /// Number of files.
    pub fn file_count(&self) -> usize {
        self.file_count
    }

    /// Number of directories.
    pub fn dir_count(&self) -> usize {
        self.dir_count
    }

    /// List all entries provided by a specific package.
    pub fn entries_by_provider(&self, provider: &str) -> Vec<&FhsEntry> {
        self.entries
            .values()
            .filter(|e| e.provider == provider)
            .collect()
    }

    /// List all entries under a given directory prefix.
    pub fn entries_under(&self, prefix: &str) -> Vec<&FhsEntry> {
        let prefix_slash = if prefix.ends_with('/') {
            prefix.to_string()
        } else {
            format!("{prefix}/")
        };
        self.entries
            .range(prefix_slash.clone()..)
            .take_while(|(k, _)| k.starts_with(&prefix_slash))
            .map(|(_, v)| v)
            .collect()
    }

    // ── Internal ────────────────────────────────────────────────

    fn scan_directory(
        &mut self,
        base: &Path,
        dir: &Path,
        provider: &str,
        hash: &str,
    ) -> Result<(), ExtosError> {
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => return Ok(()),
        };

        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            let rel = path.strip_prefix(base).unwrap_or(&path);
            // `DirEntry::file_type` never follows symlinks, so in-tree links are
            // reported as links instead of as their (possibly missing) target.
            let file_type = entry.file_type()?;

            if file_type.is_symlink() {
                let target = std::fs::read_link(&path).unwrap_or_default();
                self.insert_entry(FhsEntry {
                    rel_path: rel.to_path_buf(),
                    kind: FhsEntryKind::Symlink(target),
                    provider: provider.to_string(),
                    provider_hash: hash.to_string(),
                    source_path: path,
                    size: 0,
                });
            } else if file_type.is_dir() {
                self.insert_entry(FhsEntry {
                    rel_path: rel.to_path_buf(),
                    kind: FhsEntryKind::Directory,
                    provider: provider.to_string(),
                    provider_hash: hash.to_string(),
                    source_path: path.clone(),
                    size: 0,
                });
                self.scan_directory(base, &path, provider, hash)?;
            } else {
                let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
                self.insert_entry(FhsEntry {
                    rel_path: rel.to_path_buf(),
                    kind: FhsEntryKind::File,
                    provider: provider.to_string(),
                    provider_hash: hash.to_string(),
                    source_path: path,
                    size,
                });
            }
        }
        Ok(())
    }

    fn insert_entry(&mut self, entry: FhsEntry) {
        let key = entry.rel_path.to_string_lossy().to_string();

        if let Some(existing) = self.entries.get(&key) {
            // Directories can be shared by multiple packages (merged)
            if existing.kind == FhsEntryKind::Directory
                && entry.kind == FhsEntryKind::Directory
            {
                return; // OK — directories merge
            }
            // Non-directory collision
            self.collisions.push(Collision {
                path: entry.rel_path.clone(),
                claimant_a: existing.provider.clone(),
                claimant_b: entry.provider.clone(),
            });
            return;
        }

        match entry.kind {
            FhsEntryKind::File => self.file_count += 1,
            FhsEntryKind::Directory => self.dir_count += 1,
            FhsEntryKind::Symlink(_) => self.file_count += 1,
        }

        self.entries.insert(key, entry);
    }
}

// ─── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn file_entry(path: &str, provider: &str) -> FhsEntry {
        FhsEntry {
            rel_path: PathBuf::from(path),
            kind: FhsEntryKind::File,
            provider: provider.into(),
            provider_hash: "BLAKE3-test".into(),
            source_path: PathBuf::from("/tmp/test"),
            size: 100,
        }
    }

    fn dir_entry(path: &str, provider: &str) -> FhsEntry {
        FhsEntry {
            rel_path: PathBuf::from(path),
            kind: FhsEntryKind::Directory,
            provider: provider.into(),
            provider_hash: "BLAKE3-test".into(),
            source_path: PathBuf::from("/tmp/test"),
            size: 0,
        }
    }

    #[test]
    fn test_no_collision() {
        let vfs = VirtualFhs::from_entries(vec![
            file_entry("usr/bin/htop", "arch/htop"),
            file_entry("usr/bin/vim", "arch/vim"),
        ]);
        assert!(!vfs.has_collisions());
        assert_eq!(vfs.file_count(), 2);
    }

    #[test]
    fn test_file_collision() {
        let vfs = VirtualFhs::from_entries(vec![
            file_entry("usr/lib/libssl.so.3", "arch/openssl"),
            file_entry("usr/lib/libssl.so.3", "debian/openssl"),
        ]);
        assert!(vfs.has_collisions());
        assert_eq!(vfs.collisions().len(), 1);
        assert_eq!(
            vfs.collisions()[0].path,
            PathBuf::from("usr/lib/libssl.so.3")
        );
    }

    #[test]
    fn test_directory_merges() {
        let vfs = VirtualFhs::from_entries(vec![
            dir_entry("usr/bin", "arch/htop"),
            dir_entry("usr/bin", "arch/vim"),
        ]);
        assert!(!vfs.has_collisions());
        assert_eq!(vfs.dir_count(), 1); // merged
    }

    #[test]
    fn test_entries_by_provider() {
        let vfs = VirtualFhs::from_entries(vec![
            file_entry("usr/bin/htop", "arch/htop"),
            file_entry("usr/share/htop/htoprc", "arch/htop"),
            file_entry("usr/bin/vim", "arch/vim"),
        ]);
        let htop_entries = vfs.entries_by_provider("arch/htop");
        assert_eq!(htop_entries.len(), 2);
    }

    #[test]
    fn test_entries_under_prefix() {
        let vfs = VirtualFhs::from_entries(vec![
            file_entry("usr/bin/htop", "arch/htop"),
            file_entry("usr/bin/vim", "arch/vim"),
            file_entry("usr/lib/libssl.so", "arch/openssl"),
            file_entry("usr/share/doc/readme", "arch/htop"),
        ]);
        let bin_entries = vfs.entries_under("usr/bin");
        assert_eq!(bin_entries.len(), 2);
    }

    #[test]
    fn test_get_entry() {
        let vfs = VirtualFhs::from_entries(vec![
            file_entry("usr/bin/htop", "arch/htop"),
        ]);
        let entry = vfs.get("usr/bin/htop").unwrap();
        assert_eq!(entry.provider, "arch/htop");
        assert!(vfs.get("usr/bin/missing").is_none());
    }

    #[test]
    fn test_symlink_entry() {
        let vfs = VirtualFhs::from_entries(vec![FhsEntry {
            rel_path: PathBuf::from("usr/lib/libssl.so"),
            kind: FhsEntryKind::Symlink(PathBuf::from("libssl.so.3")),
            provider: "arch/openssl".into(),
            provider_hash: "BLAKE3-test".into(),
            source_path: PathBuf::from("/tmp/test"),
            size: 0,
        }]);
        let entry = vfs.get("usr/lib/libssl.so").unwrap();
        assert!(matches!(entry.kind, FhsEntryKind::Symlink(_)));
    }
}
