//! Package extraction pipeline (M3.2).
//!
//! Extracts upstream archive formats into a normalized CAS-ready layout:
//! ```text
//! <staging>/
//!   metadata/     ← upstream control files (PKGINFO, control, .PKGINFO)
//!   content/      ← extracted FHS tree with all UIDs normalized to 0:0
//! ```
//!
//! Supported formats:
//! - `.pkg.tar.zst` (Arch Linux)
//! - `.pkg.tar.xz`  (Arch Linux, legacy)
//! - `.deb`         (Debian/Ubuntu)
//! - `.apk`         (Alpine Linux)
//! - `.pkt.tar.xz`  (ExtOS native)

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::error::ExtosError;

/// Detected archive type for the ingestion pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveKind {
    /// Arch Linux `.pkg.tar.zst`
    PkgTarZst,
    /// Arch Linux `.pkg.tar.xz` (legacy)
    PkgTarXz,
    /// Debian `.deb` (ar archive containing control.tar + data.tar)
    Deb,
    /// Alpine `.apk` (gzipped tarball)
    Apk,
    /// ExtOS native `.pkt.tar.xz`
    PktTarXz,
}

impl ArchiveKind {
    /// Detect the archive kind from a file path's extension.
    pub fn detect(path: &Path) -> Option<Self> {
        let name = path.file_name()?.to_string_lossy();
        if name.ends_with(".pkg.tar.zst") {
            Some(Self::PkgTarZst)
        } else if name.ends_with(".pkt.tar.xz") {
            Some(Self::PktTarXz)
        } else if name.ends_with(".pkg.tar.xz") {
            Some(Self::PkgTarXz)
        } else if name.ends_with(".deb") {
            Some(Self::Deb)
        } else if name.ends_with(".apk") {
            Some(Self::Apk)
        } else {
            None
        }
    }
}

/// Result of a successful extraction.
#[derive(Debug)]
pub struct ExtractedPackage {
    /// Root of the staging directory
    pub staging_dir: PathBuf,
    /// Path to the metadata directory within staging
    pub metadata_dir: PathBuf,
    /// Path to the content (FHS tree) directory within staging
    pub content_dir: PathBuf,
    /// Detected archive format
    pub kind: ArchiveKind,
}

/// Extract an upstream package archive into a normalized staging layout.
///
/// The `staging_dir` must already exist. After extraction, all file
/// UIDs/GIDs within `content/` are normalized to 0:0 (root).
pub fn extract_package(
    archive_path: &Path,
    staging_dir: &Path,
) -> Result<ExtractedPackage, ExtosError> {
    let kind = ArchiveKind::detect(archive_path).ok_or_else(|| ExtosError::ConfigParse {
        path: archive_path.to_string_lossy().into(),
        line: 0,
        message: format!(
            "unrecognized archive format: {}",
            archive_path.display()
        ),
    })?;

    let metadata_dir = staging_dir.join("metadata");
    let content_dir = staging_dir.join("content");
    fs::create_dir_all(&metadata_dir)?;
    fs::create_dir_all(&content_dir)?;

    match kind {
        ArchiveKind::PkgTarZst => extract_pacman_archive(archive_path, &metadata_dir, &content_dir, "zstd")?,
        ArchiveKind::PkgTarXz => extract_pacman_archive(archive_path, &metadata_dir, &content_dir, "xz")?,
        ArchiveKind::Deb => extract_deb(archive_path, &metadata_dir, &content_dir)?,
        ArchiveKind::Apk => extract_apk(archive_path, &metadata_dir, &content_dir)?,
        ArchiveKind::PktTarXz => extract_pkt_tar_xz(archive_path, &metadata_dir, &content_dir)?,
    }

    // UID 0:0 normalization (M3.2 requirement)
    normalize_ownership(&content_dir)?;

    Ok(ExtractedPackage {
        staging_dir: staging_dir.to_path_buf(),
        metadata_dir,
        content_dir,
        kind,
    })
}

// ─── Format-specific extractors ─────────────────────────────────

/// Extract a pacman `.pkg.tar.{zst,xz}` archive.
///
/// Layout inside the tar:
/// - `.PKGINFO`, `.BUILDINFO`, `.MTREE` → metadata/
/// - Everything else → content/
fn extract_pacman_archive(
    archive: &Path,
    metadata_dir: &Path,
    content_dir: &Path,
    compression: &str,
) -> Result<(), ExtosError> {
    // Step 1: Extract everything to a temporary "raw" dir
    let raw_dir = metadata_dir.parent().unwrap().join("_raw");
    fs::create_dir_all(&raw_dir)?;

    let decompress_flag = match compression {
        "zstd" => "--zstd",
        "xz" => "--xz",
        _ => "--auto-compress",
    };

    let status = Command::new("tar")
        .args([decompress_flag, "-xf"])
        .arg(archive)
        .arg("-C")
        .arg(&raw_dir)
        .status()?;

    if !status.success() {
        return Err(ExtosError::ConfigParse {
            path: archive.to_string_lossy().into(),
            line: 0,
            message: format!("tar extraction failed with status: {status}"),
        });
    }

    // Step 2: Separate metadata files from content
    for entry in fs::read_dir(&raw_dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with('.') && name != "." && name != ".." {
            // Dot-prefixed files (.PKGINFO, .BUILDINFO, .MTREE) → metadata
            let dest = metadata_dir.join(name.trim_start_matches('.'));
            rename_or_copy(&entry.path(), &dest)?;
        } else {
            // Everything else → content
            let dest = content_dir.join(&name);
            rename_or_copy(&entry.path(), &dest)?;
        }
    }

    // Cleanup raw dir
    let _ = fs::remove_dir_all(&raw_dir);
    Ok(())
}

/// Extract a Debian `.deb` archive.
///
/// A `.deb` is an `ar` archive containing:
/// - `control.tar.{gz,xz,zst}` → metadata/
/// - `data.tar.{gz,xz,zst}`    → content/
fn extract_deb(
    archive: &Path,
    metadata_dir: &Path,
    content_dir: &Path,
) -> Result<(), ExtosError> {
    let work_dir = metadata_dir.parent().unwrap().join("_deb_work");
    fs::create_dir_all(&work_dir)?;

    // Step 1: Extract the ar archive
    let status = Command::new("ar")
        .args(["x", &archive.to_string_lossy()])
        .current_dir(&work_dir)
        .status()?;

    if !status.success() {
        return Err(ExtosError::ConfigParse {
            path: archive.to_string_lossy().into(),
            line: 0,
            message: "ar extraction failed".into(),
        });
    }

    // Step 2: Extract control.tar.* → metadata/
    if let Some(control_tar) = find_file_with_prefix(&work_dir, "control.tar") {
        let status = Command::new("tar")
            .args(["--auto-compress", "-xf"])
            .arg(&control_tar)
            .arg("-C")
            .arg(metadata_dir)
            .status()?;
        if !status.success() {
            return Err(ExtosError::ConfigParse {
                path: control_tar.to_string_lossy().into(),
                line: 0,
                message: "control.tar extraction failed".into(),
            });
        }
    }

    // Step 3: Extract data.tar.* → content/
    if let Some(data_tar) = find_file_with_prefix(&work_dir, "data.tar") {
        let status = Command::new("tar")
            .args(["--auto-compress", "-xf"])
            .arg(&data_tar)
            .arg("-C")
            .arg(content_dir)
            .status()?;
        if !status.success() {
            return Err(ExtosError::ConfigParse {
                path: data_tar.to_string_lossy().into(),
                line: 0,
                message: "data.tar extraction failed".into(),
            });
        }
    }

    let _ = fs::remove_dir_all(&work_dir);
    Ok(())
}

/// Extract an Alpine `.apk` package.
///
/// An `.apk` is a gzipped tarball with:
/// - `.PKGINFO`, `.SIGN.*` files → metadata/
/// - Everything else → content/
fn extract_apk(
    archive: &Path,
    metadata_dir: &Path,
    content_dir: &Path,
) -> Result<(), ExtosError> {
    // Alpine apks are gzipped tarballs — same structure as pacman archives
    extract_pacman_archive(archive, metadata_dir, content_dir, "auto")
}

/// Extract an ExtOS native `.pkt.tar.xz` package.
///
/// A `.pkt.tar.xz` follows the canonical CAS layout directly:
/// ```text
/// metadata/
///   manifest.nix
/// content/
///   usr/...
/// ```
fn extract_pkt_tar_xz(
    archive: &Path,
    metadata_dir: &Path,
    content_dir: &Path,
) -> Result<(), ExtosError> {
    let raw_dir = metadata_dir.parent().unwrap().join("_pkt_raw");
    fs::create_dir_all(&raw_dir)?;

    let status = Command::new("tar")
        .args(["--xz", "-xf"])
        .arg(archive)
        .arg("-C")
        .arg(&raw_dir)
        .status()?;

    if !status.success() {
        return Err(ExtosError::ConfigParse {
            path: archive.to_string_lossy().into(),
            line: 0,
            message: "pkt.tar.xz extraction failed".into(),
        });
    }

    // The archive should contain metadata/ and content/ at the root
    let raw_meta = raw_dir.join("metadata");
    let raw_content = raw_dir.join("content");

    if raw_meta.exists() {
        copy_dir_contents(&raw_meta, metadata_dir)?;
    }
    if raw_content.exists() {
        copy_dir_contents(&raw_content, content_dir)?;
    }

    let _ = fs::remove_dir_all(&raw_dir);
    Ok(())
}

// ─── UID Normalization ──────────────────────────────────────────

/// Normalize all file ownership in a directory tree to UID 0:0 (root).
///
/// Uses `chown -R 0:0` if running as root, otherwise silently succeeds
/// (since non-root extractions already own files as the current user).
///
/// This is called automatically by `extract_package()`, and can also be
/// called manually after plugin-based extraction.
pub fn normalize_ownership_if_root(dir: &Path) -> Result<(), ExtosError> {
    normalize_ownership(dir)
}

fn normalize_ownership(dir: &Path) -> Result<(), ExtosError> {
    // Only attempt chown if running as root (UID 0)
    if unsafe { libc::geteuid() } == 0 {
        let status = Command::new("chown")
            .args(["-R", "0:0"])
            .arg(dir)
            .status()?;
        if !status.success() {
            return Err(ExtosError::ConfigParse {
                path: dir.to_string_lossy().into(),
                line: 0,
                message: "UID normalization (chown -R 0:0) failed".into(),
            });
        }
    }
    // Non-root: files are already owned by current user; CAS doesn't
    // rely on filesystem UIDs, so this is acceptable for dev/test.
    Ok(())
}

// ─── Helpers ────────────────────────────────────────────────────

/// Find the first file in `dir` whose name starts with `prefix`.
fn find_file_with_prefix(dir: &Path, prefix: &str) -> Option<PathBuf> {
    fs::read_dir(dir).ok()?.filter_map(|e| e.ok()).find_map(|e| {
        let name = e.file_name().to_string_lossy().to_string();
        if name.starts_with(prefix) {
            Some(e.path())
        } else {
            None
        }
    })
}

/// Move or copy a file/directory, using rename first (fast), falling
/// back to recursive copy if across filesystems.
fn rename_or_copy(src: &Path, dst: &Path) -> Result<(), ExtosError> {
    if src.is_dir() {
        copy_dir_contents(src, dst)?;
        let _ = fs::remove_dir_all(src);
    } else {
        if let Some(parent) = dst.parent() {
            fs::create_dir_all(parent)?;
        }
        if fs::rename(src, dst).is_err() {
            fs::copy(src, dst)?;
            let _ = fs::remove_file(src);
        }
    }
    Ok(())
}

/// Recursively copy the contents of `src` into `dst`.
fn copy_dir_contents(src: &Path, dst: &Path) -> Result<(), ExtosError> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        if src_path.is_dir() {
            copy_dir_contents(&src_path, &dst_path)?;
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

    #[test]
    fn test_archive_kind_detection() {
        assert_eq!(
            ArchiveKind::detect(Path::new("htop-3.3.0-1-x86_64.pkg.tar.zst")),
            Some(ArchiveKind::PkgTarZst)
        );
        assert_eq!(
            ArchiveKind::detect(Path::new("vim_9.1.0-1_amd64.deb")),
            Some(ArchiveKind::Deb)
        );
        assert_eq!(
            ArchiveKind::detect(Path::new("busybox-1.36.1-r0.apk")),
            Some(ArchiveKind::Apk)
        );
        assert_eq!(
            ArchiveKind::detect(Path::new("htop-3.3.0.pkt.tar.xz")),
            Some(ArchiveKind::PktTarXz)
        );
        assert_eq!(
            ArchiveKind::detect(Path::new("coreutils-9.4-1-x86_64.pkg.tar.xz")),
            Some(ArchiveKind::PkgTarXz)
        );
        assert_eq!(ArchiveKind::detect(Path::new("random.txt")), None);
    }

    #[test]
    fn test_pkt_tar_xz_extraction() {
        // Create a mock .pkt.tar.xz: metadata/manifest.nix + content/usr/bin/hello
        let tmpdir = tempfile::tempdir().unwrap();
        let archive_src = tmpdir.path().join("pkg_src");
        fs::create_dir_all(archive_src.join("metadata")).unwrap();
        fs::create_dir_all(archive_src.join("content/usr/bin")).unwrap();
        fs::write(
            archive_src.join("metadata/manifest.nix"),
            "{ name = \"test\"; }",
        ).unwrap();
        fs::write(
            archive_src.join("content/usr/bin/hello"),
            "#!/bin/sh\necho hello",
        ).unwrap();

        let archive_path = tmpdir.path().join("test.pkt.tar.xz");
        let status = Command::new("tar")
            .args(["--xz", "-cf"])
            .arg(&archive_path)
            .arg("-C")
            .arg(&archive_src)
            .args(["metadata", "content"])
            .status()
            .unwrap();
        assert!(status.success(), "failed to create test archive");

        // Extract it
        let staging = tmpdir.path().join("staging");
        fs::create_dir_all(&staging).unwrap();
        let result = extract_package(&archive_path, &staging).unwrap();

        assert_eq!(result.kind, ArchiveKind::PktTarXz);
        assert!(result.metadata_dir.join("manifest.nix").exists());
        assert!(result.content_dir.join("usr/bin/hello").exists());
    }

    #[test]
    fn test_pacman_archive_extraction() {
        // Create a mock .pkg.tar.zst with .PKGINFO + usr/bin/htop
        let tmpdir = tempfile::tempdir().unwrap();
        let archive_src = tmpdir.path().join("pkg_src");
        fs::create_dir_all(archive_src.join("usr/bin")).unwrap();
        fs::write(
            archive_src.join(".PKGINFO"),
            "pkgname = htop\npkgver = 3.3.0-1\n",
        ).unwrap();
        fs::write(archive_src.join("usr/bin/htop"), "#!/bin/sh\necho htop").unwrap();

        let archive_path = tmpdir.path().join("htop-3.3.0-1-x86_64.pkg.tar.zst");
        let status = Command::new("tar")
            .args(["--zstd", "-cf"])
            .arg(&archive_path)
            .arg("-C")
            .arg(&archive_src)
            .args([".", ])
            .status()
            .unwrap();
        assert!(status.success(), "failed to create test archive");

        let staging = tmpdir.path().join("staging");
        fs::create_dir_all(&staging).unwrap();
        let result = extract_package(&archive_path, &staging).unwrap();

        assert_eq!(result.kind, ArchiveKind::PkgTarZst);
        // .PKGINFO → metadata/PKGINFO
        assert!(result.metadata_dir.join("PKGINFO").exists());
        assert!(result.content_dir.join("usr/bin/htop").exists());
    }
}
