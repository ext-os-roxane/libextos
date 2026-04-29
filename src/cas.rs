//! Content-Addressable Storage engine.
//!
//! Handles hash computation (BLAKE3/SHA-256), object storage in
//! `/repository/objects/<algo>-<hash>/`, and semantic ref symlink management
//! in `/repository/refs/<origin>/<pkg>/<ver>/`.
//!
//! ## Object Layout (per ARCHITECTURE.md §3.1)
//! ```text
//! /repository/objects/<algo>-<hash>/
//!   metadata/
//!     manifest.nix        ← ExtOS-translated manifest
//!     cache.bin           ← (optional) cached raw bytes for non-tree objects
//!   content/              ← Extracted FHS tree (usr/, lib/, etc.)
//!   payload.img           ← (optional) Loop-mountable image (Android, AppImage)
//! ```

use std::collections::HashSet;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use crate::error::ExtosError;
use crate::types::HashAlgorithm;

/// Maximum symlink chain depth before reporting ELOOP.
const MAX_SYMLINK_DEPTH: usize = 40;

// ─── Hash Computation ───────────────────────────────────────────

/// Compute a content hash over raw bytes, prefixed with algorithm tag.
pub fn hash_bytes(data: &[u8], algo: HashAlgorithm) -> String {
    match algo {
        HashAlgorithm::Blake3 => {
            let h = blake3::hash(data);
            format!("BLAKE3-{}", h.to_hex())
        }
        HashAlgorithm::Sha256 => {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(data);
            format!("SHA256-{}", hex::encode(hasher.finalize()))
        }
    }
}

/// Compute a content hash by streaming from a reader, prefixed with algorithm tag.
pub fn hash_reader<R: Read>(reader: &mut R, algo: HashAlgorithm) -> io::Result<String> {
    match algo {
        HashAlgorithm::Blake3 => {
            let mut hasher = blake3::Hasher::new();
            let mut buf = [0u8; 8192];
            loop {
                let n = reader.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
            }
            Ok(format!("BLAKE3-{}", hasher.finalize().to_hex()))
        }
        HashAlgorithm::Sha256 => {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            let mut buf = [0u8; 8192];
            loop {
                let n = reader.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
            }
            Ok(format!("SHA256-{}", hex::encode(hasher.finalize())))
        }
    }
}

/// Hash the entire contents of a directory tree (sorted file names + contents).
pub fn hash_directory(dir: &Path, algo: HashAlgorithm) -> Result<String, ExtosError> {
    let mut entries = Vec::new();
    collect_files(dir, dir, &mut entries)?;
    entries.sort();

    match algo {
        HashAlgorithm::Blake3 => {
            let mut hasher = blake3::Hasher::new();
            for (rel, data) in &entries {
                hasher.update(rel.as_bytes());
                hasher.update(data);
            }
            Ok(format!("BLAKE3-{}", hasher.finalize().to_hex()))
        }
        HashAlgorithm::Sha256 => {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            for (rel, data) in &entries {
                hasher.update(rel.as_bytes());
                hasher.update(data);
            }
            Ok(format!("SHA256-{}", hex::encode(hasher.finalize())))
        }
    }
}

fn collect_files(
    base: &Path,
    dir: &Path,
    out: &mut Vec<(String, Vec<u8>)>,
) -> Result<(), ExtosError> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_files(base, &path, out)?;
        } else if path.is_file() {
            let rel = path
                .strip_prefix(base)
                .unwrap()
                .to_string_lossy()
                .to_string();
            let data = fs::read(&path)?;
            out.push((rel, data));
        }
    }
    Ok(())
}

// ─── CAS Repository ────────────────────────────────────────────

/// The CAS repository rooted at a filesystem path.
///
/// Layout:
/// ```text
/// <root>/
///   objects/<algo>-<hash>/
///     metadata/manifest.nix
///     metadata/cache.bin           ← raw bytes cache
///     content/usr/...              ← extracted FHS tree
///     payload.img                  ← loop-mountable image
///   refs/<origin>/<pkg>/<ver> -> ../../../objects/<algo>-<hash>
/// ```
#[derive(Debug, Clone)]
pub struct CasRepository {
    /// Root path (configurable, e.g. `/repository`)
    pub root: PathBuf,
    /// Default hash algorithm
    pub algo: HashAlgorithm,
}

impl CasRepository {
    /// Open or create a CAS repository at the given root.
    pub fn open(root: impl Into<PathBuf>, algo: HashAlgorithm) -> Result<Self, ExtosError> {
        let root = root.into();
        fs::create_dir_all(root.join("objects"))?;
        fs::create_dir_all(root.join("refs"))?;
        Ok(Self { root, algo })
    }

    // ── Object operations ──

    /// Path to an object directory by hash (including algo prefix).
    pub fn object_path(&self, hash: &str) -> PathBuf {
        self.root.join("objects").join(hash)
    }

    /// Store raw bytes as a cached CAS object in `metadata/cache.bin`.
    /// The `content/` directory is created but left empty (to be populated
    /// by the ingestion pipeline after extraction). Returns the computed hash.
    pub fn store_bytes(&self, data: &[u8]) -> Result<String, ExtosError> {
        let hash = hash_bytes(data, self.algo);
        let obj_dir = self.object_path(&hash);
        if obj_dir.exists() {
            return Ok(hash); // dedup: already stored
        }
        fs::create_dir_all(obj_dir.join("content"))?;
        fs::create_dir_all(obj_dir.join("metadata"))?;
        // Store raw bytes as a metadata cache, NOT in content/
        fs::write(obj_dir.join("metadata").join("cache.bin"), data)?;
        Ok(hash)
    }

    /// Store a loop-mountable image (e.g., EROFS/ext4 payload) as `payload.img`
    /// at the object root. The `content/` directory exists but is intended to be
    /// populated via `losetup` + mount at boot (initrd stage).
    pub fn store_image(&self, image_data: &[u8]) -> Result<String, ExtosError> {
        let hash = hash_bytes(image_data, self.algo);
        let obj_dir = self.object_path(&hash);
        if obj_dir.exists() {
            return Ok(hash);
        }
        fs::create_dir_all(obj_dir.join("content"))?;
        fs::create_dir_all(obj_dir.join("metadata"))?;
        fs::write(obj_dir.join("payload.img"), image_data)?;
        Ok(hash)
    }

    /// Store an extracted directory tree. The content of `source_dir` is copied
    /// into `objects/<hash>/content/`. Returns the computed hash.
    pub fn store_directory(&self, source_dir: &Path) -> Result<String, ExtosError> {
        let hash = hash_directory(source_dir, self.algo)?;
        let obj_dir = self.object_path(&hash);
        if obj_dir.exists() {
            return Ok(hash);
        }
        let content_dir = obj_dir.join("content");
        fs::create_dir_all(&content_dir)?;
        fs::create_dir_all(obj_dir.join("metadata"))?;
        copy_dir_recursive(source_dir, &content_dir)?;
        Ok(hash)
    }

    /// Retrieve the content path for a stored object.
    pub fn retrieve(&self, hash: &str) -> Result<PathBuf, ExtosError> {
        let obj_dir = self.object_path(hash);
        if !obj_dir.exists() {
            return Err(ExtosError::PackageNotFound {
                origin: String::new(),
                name: hash.to_string(),
                version: String::new(),
            });
        }
        Ok(obj_dir.join("content"))
    }

    /// Check whether an object has a loop-mountable `payload.img`.
    pub fn has_payload_image(&self, hash: &str) -> bool {
        self.object_path(hash).join("payload.img").exists()
    }

    /// Get the path to the loop-mountable `payload.img` for an object.
    pub fn payload_image_path(&self, hash: &str) -> PathBuf {
        self.object_path(hash).join("payload.img")
    }

    /// Verify the integrity of a stored object against its expected hash.
    pub fn verify(&self, hash: &str) -> Result<bool, ExtosError> {
        let obj_dir = self.object_path(hash);
        if !obj_dir.exists() {
            return Ok(false);
        }
        // Check metadata cache (byte-stored objects)
        let cache = obj_dir.join("metadata").join("cache.bin");
        if cache.is_file() {
            let data = fs::read(&cache)?;
            let actual = hash_bytes(&data, self.algo);
            return Ok(actual == hash);
        }
        // Check payload.img (image-stored objects)
        let payload = obj_dir.join("payload.img");
        if payload.is_file() {
            let data = fs::read(&payload)?;
            let actual = hash_bytes(&data, self.algo);
            return Ok(actual == hash);
        }
        // Directory tree check (extracted FHS content)
        let content_dir = obj_dir.join("content");
        if content_dir.exists() {
            let actual = hash_directory(&content_dir, self.algo)?;
            return Ok(actual == hash);
        }
        Ok(false)
    }

    /// Write a manifest file into an object's metadata directory.
    pub fn write_manifest(&self, hash: &str, manifest_nix: &str) -> Result<(), ExtosError> {
        let meta_dir = self.object_path(hash).join("metadata");
        fs::create_dir_all(&meta_dir)?;
        fs::write(meta_dir.join("manifest.nix"), manifest_nix)?;
        Ok(())
    }

    /// Read the manifest file from an object's metadata directory.
    pub fn read_manifest(&self, hash: &str) -> Result<String, ExtosError> {
        let path = self.object_path(hash).join("metadata").join("manifest.nix");
        Ok(fs::read_to_string(path)?)
    }

    // ── Ref operations ──

    /// Path to a ref symlink: `refs/<origin>/<pkg>/<ver>`
    pub fn ref_path(&self, origin: &str, pkg: &str, ver: &str) -> PathBuf {
        self.root.join("refs").join(origin).join(pkg).join(ver)
    }

    /// Create or update a ref symlink pointing to an object.
    ///
    /// `refs/<origin>/<pkg>/<ver>` -> `../../../objects/<hash>`
    pub fn create_ref(
        &self,
        origin: &str,
        pkg: &str,
        ver: &str,
        hash: &str,
    ) -> Result<(), ExtosError> {
        let ref_dir = self.root.join("refs").join(origin).join(pkg);
        fs::create_dir_all(&ref_dir)?;
        let ref_link = ref_dir.join(ver);
        let target = PathBuf::from("../../../objects").join(hash);

        // Atomically replace: remove old, create new
        if ref_link.exists() || ref_link.symlink_metadata().is_ok() {
            fs::remove_file(&ref_link)?;
        }

        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, &ref_link)?;
        #[cfg(not(unix))]
        fs::write(&ref_link, target.to_string_lossy().as_bytes())?;

        Ok(())
    }

    /// Create or update a `current` ref that points to another version ref.
    ///
    /// `refs/<origin>/<pkg>/current` -> `./<ver>`
    pub fn update_current(&self, origin: &str, pkg: &str, ver: &str) -> Result<(), ExtosError> {
        let ref_dir = self.root.join("refs").join(origin).join(pkg);
        fs::create_dir_all(&ref_dir)?;
        let current_link = ref_dir.join("current");

        if current_link.exists() || current_link.symlink_metadata().is_ok() {
            fs::remove_file(&current_link)?;
        }

        #[cfg(unix)]
        std::os::unix::fs::symlink(PathBuf::from("./").join(ver), &current_link)?;
        #[cfg(not(unix))]
        fs::write(&current_link, ver)?;

        Ok(())
    }

    /// Resolve a ref to its target object hash.
    ///
    /// Uses bounded symlink resolution with a stack limit of [`MAX_SYMLINK_DEPTH`]
    /// to detect cycles (ELOOP).
    pub fn resolve_ref(&self, origin: &str, pkg: &str, ver: &str) -> Result<String, ExtosError> {
        let ref_link = self.ref_path(origin, pkg, ver);
        if !ref_link.exists() && ref_link.symlink_metadata().is_err() {
            return Err(ExtosError::PackageNotFound {
                origin: origin.to_string(),
                name: pkg.to_string(),
                version: ver.to_string(),
            });
        }

        // Bounded symlink resolution (ELOOP guard)
        let canonical = resolve_symlink_bounded(&ref_link, MAX_SYMLINK_DEPTH)?;
        let hash = canonical
            .file_name()
            .ok_or_else(|| ExtosError::CasIntegrity {
                expected: "object hash directory".into(),
                actual: canonical.to_string_lossy().into(),
            })?
            .to_string_lossy()
            .to_string();
        Ok(hash)
    }

    /// List all versions available for origin/pkg.
    pub fn list_versions(&self, origin: &str, pkg: &str) -> Result<Vec<String>, ExtosError> {
        let pkg_dir = self.root.join("refs").join(origin).join(pkg);
        if !pkg_dir.exists() {
            return Ok(vec![]);
        }
        let mut versions = Vec::new();
        for entry in fs::read_dir(&pkg_dir)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().to_string();
            if name != "current" {
                versions.push(name);
            }
        }
        versions.sort();
        Ok(versions)
    }

    // ── Virtual origin ──

    /// Create a virtual ref: `refs/virtual/<alias>/<ver>` -> `../../<real_origin>/<real_pkg>/<ver>`
    pub fn create_virtual_ref(
        &self,
        virtual_name: &str,
        ver: &str,
        real_origin: &str,
        real_pkg: &str,
    ) -> Result<(), ExtosError> {
        let ref_dir = self.root.join("refs").join("virtual").join(virtual_name);
        fs::create_dir_all(&ref_dir)?;
        let ref_link = ref_dir.join(ver);

        let target = PathBuf::from("../../")
            .join(real_origin)
            .join(real_pkg)
            .join(ver);

        if ref_link.exists() || ref_link.symlink_metadata().is_ok() {
            fs::remove_file(&ref_link)?;
        }

        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, &ref_link)?;
        #[cfg(not(unix))]
        fs::write(&ref_link, target.to_string_lossy().as_bytes())?;

        Ok(())
    }

    // ── Lockfile ──

    /// Generate a lockfile entry: resolve `version = "current"` to a concrete hash.
    pub fn resolve_lock(
        &self,
        origin: &str,
        pkg: &str,
        ver: &str,
    ) -> Result<LockEntry, ExtosError> {
        let resolved_ver = if ver == "current" {
            // Follow the `current` symlink to get the real version
            let current = self.ref_path(origin, pkg, "current");
            if current.symlink_metadata().is_ok() {
                let target = fs::read_link(&current)?;
                target
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .trim_start_matches("./")
                    .to_string()
            } else {
                return Err(ExtosError::PackageNotFound {
                    origin: origin.into(),
                    name: pkg.into(),
                    version: "current".into(),
                });
            }
        } else {
            ver.to_string()
        };

        let hash = self.resolve_ref(origin, pkg, &resolved_ver)?;
        Ok(LockEntry {
            origin: origin.to_string(),
            name: pkg.to_string(),
            version: resolved_ver,
            hash,
        })
    }

    /// Write a full lockfile to disk (Nix format).
    pub fn write_lockfile(&self, entries: &[LockEntry], output: &Path) -> Result<(), ExtosError> {
        let mut content = String::from("# ExtOS Lockfile — auto-generated, do not edit\n{\n");
        for e in entries {
            content.push_str(&format!(
                "  \"{}/{}\" = {{ version = \"{}\"; hash = \"{}\"; }};\n",
                e.origin, e.name, e.version, e.hash
            ));
        }
        content.push_str("}\n");
        fs::write(output, content)?;
        Ok(())
    }

    // ── Garbage collection ──

    /// Collect all object hashes that are reachable from ref symlinks.
    pub fn collect_live_objects(&self) -> Result<HashSet<String>, ExtosError> {
        let mut live = HashSet::new();
        let refs_dir = self.root.join("refs");
        if !refs_dir.exists() {
            return Ok(live);
        }
        self.walk_refs_for_hashes(&refs_dir, &mut live)?;
        Ok(live)
    }

    fn walk_refs_for_hashes(
        &self,
        dir: &Path,
        live: &mut HashSet<String>,
    ) -> Result<(), ExtosError> {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() && !path.is_symlink() {
                self.walk_refs_for_hashes(&path, live)?;
            } else if path.is_symlink() {
                // Resolve the symlink chain to the final canonical path
                if let Ok(canonical) = fs::canonicalize(&path) {
                    // The canonical path should be .../objects/<hash>/...
                    // Walk up from the canonical path to find the hash under objects/
                    let objects_dir = self.root.join("objects");
                    if let Ok(objects_canon) = fs::canonicalize(&objects_dir) {
                        if let Ok(rel) = canonical.strip_prefix(&objects_canon) {
                            if let Some(first) = rel.components().next() {
                                live.insert(first.as_os_str().to_string_lossy().to_string());
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Garbage collect: remove all objects not reachable from any ref.
    /// Returns the list of purged hashes.
    pub fn gc(&self) -> Result<Vec<String>, ExtosError> {
        let live = self.collect_live_objects()?;
        let objects_dir = self.root.join("objects");
        let mut purged = Vec::new();

        if !objects_dir.exists() {
            return Ok(purged);
        }

        for entry in fs::read_dir(&objects_dir)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().to_string();
            if !live.contains(&name) {
                fs::remove_dir_all(entry.path())?;
                purged.push(name);
            }
        }

        purged.sort();
        Ok(purged)
    }

    // ── Dynamic scratch namespaces ──

    /// Create a scratch namespace origin.
    pub fn create_namespace(&self, namespace: &str) -> Result<(), ExtosError> {
        let ns_dir = self.root.join("refs").join(namespace);
        fs::create_dir_all(&ns_dir)?;
        Ok(())
    }

    /// List all known origins (top-level directories under `refs/`).
    pub fn list_origins(&self) -> Result<Vec<String>, ExtosError> {
        let refs_dir = self.root.join("refs");
        if !refs_dir.exists() {
            return Ok(vec![]);
        }
        let mut origins = Vec::new();
        for entry in fs::read_dir(&refs_dir)? {
            let entry = entry?;
            if entry.path().is_dir() {
                origins.push(entry.file_name().to_string_lossy().to_string());
            }
        }
        origins.sort();
        Ok(origins)
    }

    /// List all packages under an origin.
    pub fn list_packages(&self, origin: &str) -> Result<Vec<String>, ExtosError> {
        let origin_dir = self.root.join("refs").join(origin);
        if !origin_dir.exists() {
            return Ok(vec![]);
        }
        let mut pkgs = Vec::new();
        for entry in fs::read_dir(&origin_dir)? {
            let entry = entry?;
            if entry.path().is_dir() {
                pkgs.push(entry.file_name().to_string_lossy().to_string());
            }
        }
        pkgs.sort();
        Ok(pkgs)
    }
}

/// A resolved lockfile entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockEntry {
    pub origin: String,
    pub name: String,
    pub version: String,
    pub hash: String,
}

// ─── Bounded Symlink Resolution ─────────────────────────────────

/// Resolve a symlink chain with a bounded depth to prevent ELOOP.
fn resolve_symlink_bounded(path: &Path, max_depth: usize) -> Result<PathBuf, ExtosError> {
    let mut current = path.to_path_buf();
    for _ in 0..max_depth {
        match fs::symlink_metadata(&current) {
            Ok(meta) if meta.file_type().is_symlink() => {
                let target = fs::read_link(&current)?;
                // Resolve relative symlinks against parent directory
                if target.is_relative() {
                    if let Some(parent) = current.parent() {
                        current = parent.join(&target);
                    } else {
                        current = target;
                    }
                } else {
                    current = target;
                }
            }
            Ok(_) => {
                // Not a symlink; canonicalize the final path
                return fs::canonicalize(&current).map_err(ExtosError::from);
            }
            Err(e) => return Err(ExtosError::Io(e)),
        }
    }
    Err(ExtosError::CasIntegrity {
        expected: format!("symlink resolved within {max_depth} hops"),
        actual: format!("ELOOP: symlink cycle detected at {}", path.display()),
    })
}

// ─── Helpers ────────────────────────────────────────────────────

fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<(), ExtosError> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        if src_path.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else {
            fs::copy(&src_path, &dst_path)?;
        }
    }
    Ok(())
}

// ─── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tmp_repo() -> (tempfile::TempDir, CasRepository) {
        let dir = tempfile::tempdir().unwrap();
        let repo = CasRepository::open(dir.path(), HashAlgorithm::Blake3).unwrap();
        (dir, repo)
    }

    #[test]
    fn test_hash_prefix_blake3() {
        let h = hash_bytes(b"hello world", HashAlgorithm::Blake3);
        assert!(h.starts_with("BLAKE3-"));
        assert_eq!(h.len(), 7 + 64); // "BLAKE3-" + 64 hex chars
        // Deterministic
        assert_eq!(h, hash_bytes(b"hello world", HashAlgorithm::Blake3));
    }

    #[test]
    fn test_hash_prefix_sha256() {
        let h = hash_bytes(b"hello world", HashAlgorithm::Sha256);
        assert!(h.starts_with("SHA256-"));
        assert_eq!(h.len(), 7 + 64);
        // Known SHA-256 of "hello world"
        assert_eq!(
            h,
            "SHA256-b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_store_bytes_in_metadata_cache() {
        let (_dir, repo) = tmp_repo();
        let hash = repo.store_bytes(b"package payload").unwrap();
        let obj_dir = repo.object_path(&hash);
        // Raw bytes stored in metadata/cache.bin, NOT in content/
        assert!(obj_dir.join("metadata").join("cache.bin").exists());
        assert!(!obj_dir.join("content").join("payload").exists());
        let data = fs::read(obj_dir.join("metadata").join("cache.bin")).unwrap();
        assert_eq!(data, b"package payload");
    }

    #[test]
    fn test_store_image() {
        let (_dir, repo) = tmp_repo();
        let hash = repo.store_image(b"EROFS_IMAGE_DATA").unwrap();
        let obj_dir = repo.object_path(&hash);
        assert!(obj_dir.join("payload.img").exists());
        assert!(!obj_dir.join("content").join("payload").exists());
        assert!(repo.has_payload_image(&hash));
        let data = fs::read(repo.payload_image_path(&hash)).unwrap();
        assert_eq!(data, b"EROFS_IMAGE_DATA");
    }

    #[test]
    fn test_store_dedup() {
        let (_dir, repo) = tmp_repo();
        let h1 = repo.store_bytes(b"same data").unwrap();
        let h2 = repo.store_bytes(b"same data").unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_verify_integrity_bytes() {
        let (_dir, repo) = tmp_repo();
        let hash = repo.store_bytes(b"verify me").unwrap();
        assert!(repo.verify(&hash).unwrap());
    }

    #[test]
    fn test_verify_integrity_image() {
        let (_dir, repo) = tmp_repo();
        let hash = repo.store_image(b"verify image").unwrap();
        assert!(repo.verify(&hash).unwrap());
    }

    #[test]
    fn test_verify_nonexistent() {
        let (_dir, repo) = tmp_repo();
        assert!(!repo.verify("nonexistent_hash").unwrap());
    }

    #[test]
    fn test_manifest_roundtrip() {
        let (_dir, repo) = tmp_repo();
        let hash = repo.store_bytes(b"data").unwrap();
        repo.write_manifest(&hash, "{ name = \"test\"; }").unwrap();
        let content = repo.read_manifest(&hash).unwrap();
        assert_eq!(content, "{ name = \"test\"; }");
    }

    #[test]
    fn test_refs_create_and_resolve() {
        let (_dir, repo) = tmp_repo();
        let hash = repo.store_bytes(b"htop binary").unwrap();
        repo.create_ref("archlinux", "htop", "3.3.0", &hash)
            .unwrap();
        let resolved = repo.resolve_ref("archlinux", "htop", "3.3.0").unwrap();
        assert_eq!(resolved, hash);
    }

    #[test]
    fn test_refs_current() {
        let (_dir, repo) = tmp_repo();
        let hash = repo.store_bytes(b"htop v3.3.0").unwrap();
        repo.create_ref("archlinux", "htop", "3.3.0", &hash)
            .unwrap();
        repo.update_current("archlinux", "htop", "3.3.0").unwrap();
        let resolved = repo.resolve_ref("archlinux", "htop", "current").unwrap();
        assert_eq!(resolved, hash);
    }

    #[test]
    fn test_list_versions() {
        let (_dir, repo) = tmp_repo();
        let h1 = repo.store_bytes(b"v1").unwrap();
        let h2 = repo.store_bytes(b"v2").unwrap();
        repo.create_ref("arch", "mesa", "24.0", &h1).unwrap();
        repo.create_ref("arch", "mesa", "24.1", &h2).unwrap();
        repo.update_current("arch", "mesa", "24.1").unwrap();
        let versions = repo.list_versions("arch", "mesa").unwrap();
        assert_eq!(versions, vec!["24.0", "24.1"]);
    }

    #[test]
    fn test_virtual_ref() {
        let (_dir, repo) = tmp_repo();
        let hash = repo.store_bytes(b"glibc").unwrap();
        repo.create_ref("archlinux", "glibc", "2.39", &hash)
            .unwrap();
        repo.create_virtual_ref("glibc", "2.39", "archlinux", "glibc")
            .unwrap();
        let resolved = repo.resolve_ref("virtual", "glibc", "2.39").unwrap();
        assert_eq!(resolved, hash);
    }

    #[test]
    fn test_lockfile() {
        let (_dir, repo) = tmp_repo();
        let hash = repo.store_bytes(b"locked pkg").unwrap();
        repo.create_ref("arch", "htop", "3.3.0", &hash).unwrap();
        repo.update_current("arch", "htop", "3.3.0").unwrap();
        let entry = repo.resolve_lock("arch", "htop", "current").unwrap();
        assert_eq!(entry.version, "3.3.0");
        assert_eq!(entry.hash, hash);

        let lock_path = repo.root.join("test.lock");
        repo.write_lockfile(&[entry], &lock_path).unwrap();
        let content = fs::read_to_string(&lock_path).unwrap();
        assert!(content.contains("arch/htop"));
        assert!(content.contains(&hash));
    }

    #[test]
    fn test_gc() {
        let (_dir, repo) = tmp_repo();
        let live_hash = repo.store_bytes(b"keep me").unwrap();
        let dead_hash = repo.store_bytes(b"delete me").unwrap();
        repo.create_ref("arch", "live", "1.0", &live_hash).unwrap();
        // dead_hash has no ref pointing to it
        let purged = repo.gc().unwrap();
        assert!(purged.contains(&dead_hash));
        assert!(!purged.contains(&live_hash));
        assert!(!repo.object_path(&dead_hash).exists());
        assert!(repo.object_path(&live_hash).exists());
    }

    #[test]
    fn test_namespaces() {
        let (_dir, repo) = tmp_repo();
        repo.create_namespace("shadichy-labs").unwrap();
        let origins = repo.list_origins().unwrap();
        assert!(origins.contains(&"shadichy-labs".to_string()));
    }

    #[test]
    fn test_list_packages() {
        let (_dir, repo) = tmp_repo();
        let hash = repo.store_bytes(b"pkg").unwrap();
        repo.create_ref("archlinux", "htop", "3.3.0", &hash)
            .unwrap();
        repo.create_ref("archlinux", "mesa", "24.0", &hash).unwrap();
        let pkgs = repo.list_packages("archlinux").unwrap();
        assert_eq!(pkgs, vec!["htop", "mesa"]);
    }

    #[test]
    fn test_store_directory() {
        let tmpdir = tempfile::tempdir().unwrap();
        let src = tmpdir.path().join("source");
        fs::create_dir_all(src.join("usr/bin")).unwrap();
        fs::write(src.join("usr/bin/hello"), b"#!/bin/sh\necho hello").unwrap();

        let (_dir, repo) = tmp_repo();
        let hash = repo.store_directory(&src).unwrap();
        assert!(!hash.is_empty());
        assert!(hash.starts_with("BLAKE3-"));

        let content = repo.retrieve(&hash).unwrap();
        assert!(content.join("usr/bin/hello").exists());
    }
}
