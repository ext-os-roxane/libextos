//! Debian/Ubuntu phantom database (M7.2).
//!
//! Appends entries to `/var/lib/dpkg/status` in RFC-822 control format.
//! Each phantom entry contains an `X-ExtOS-Phantom: true` field for cleanup.
//!
//! Spoof mode (PLAN 2.7.8) writes a block with the spoofed `Package:`/`Version:`
//! fields and an `info/<spoof>.list`, which is how Debian splits packages such
//! as `libc6` / `libc6-dev` out of one upstream `glibc`.

use std::fs;
use std::path::Path;

use crate::error::ExtosError;
use crate::manifest::{PackageManifest, SpoofEntry};
use crate::phantom::{PHANTOM_TAG, PhantomWriter, ResolvedEntry};

/// Debian dpkg phantom writer.
pub struct DebianPhantom;

impl DebianPhantom {
    fn write_resolved(
        &self,
        manifest: &PackageManifest,
        db_root: &Path,
        files: &[String],
        resolved: ResolvedEntry<'_>,
    ) -> Result<(), ExtosError> {
        fs::create_dir_all(db_root)?;
        let status_file = db_root.join("status");

        let entry = generate_status_entry(manifest, &resolved);

        // Append to status file
        let mut content = if status_file.exists() {
            fs::read_to_string(&status_file)?
        } else {
            String::new()
        };

        // Check if entry already exists
        let marker = format!("Package: {}\n", resolved.name);
        if content.contains(&marker) {
            // Remove old entry first
            content = remove_entry_from_status(&content, resolved.name);
        }

        if !content.is_empty() && !content.ends_with("\n\n") {
            content.push('\n');
        }
        content.push_str(&entry);
        fs::write(&status_file, content)?;

        // Write file list in info/<pkg>.list
        let info_dir = db_root.join("info");
        fs::create_dir_all(&info_dir)?;
        let list_content = files.join("\n");
        fs::write(info_dir.join(format!("{}.list", resolved.name)), list_content)?;

        Ok(())
    }
}

impl PhantomWriter for DebianPhantom {
    fn origin(&self) -> &str {
        "debian"
    }

    fn default_db_path(&self) -> &Path {
        Path::new("var/lib/dpkg")
    }

    fn write_entry(
        &self,
        manifest: &PackageManifest,
        db_root: &Path,
        files: &[String],
    ) -> Result<(), ExtosError> {
        self.write_resolved(manifest, db_root, files, ResolvedEntry::new(manifest, None))
    }

    fn write_spoof(
        &self,
        manifest: &PackageManifest,
        db_root: &Path,
        files: &[String],
        entry: &SpoofEntry,
    ) -> Result<(), ExtosError> {
        self.write_resolved(manifest, db_root, files, ResolvedEntry::new(manifest, Some(entry)))
    }

    fn cleanup(&self, db_root: &Path) -> Result<usize, ExtosError> {
        let status_file = db_root.join("status");
        if !status_file.exists() {
            return Ok(0);
        }

        let content = fs::read_to_string(&status_file)?;
        let mut cleaned = String::new();
        let mut removed = 0;

        // Parse entries separated by blank lines
        for block in content.split("\n\n") {
            if block.trim().is_empty() {
                continue;
            }
            if block.contains(&format!("X-ExtOS-Phantom: {PHANTOM_TAG}")) {
                // Remove corresponding .list file
                if let Some(name) = extract_field(block, "Package") {
                    let list_file = db_root.join("info").join(format!("{name}.list"));
                    if list_file.exists() {
                        fs::remove_file(&list_file)?;
                    }
                }
                removed += 1;
            } else {
                if !cleaned.is_empty() {
                    cleaned.push_str("\n\n");
                }
                cleaned.push_str(block.trim());
                cleaned.push('\n');
            }
        }

        fs::write(&status_file, cleaned)?;
        Ok(removed)
    }
}

/// Generate a dpkg status entry.
fn generate_status_entry(manifest: &PackageManifest, resolved: &ResolvedEntry<'_>) -> String {
    let id = &manifest.identity;
    let name = resolved.name;
    let version = resolved.version;
    let mut entry = String::new();

    entry.push_str(&format!("Package: {name}\n"));
    entry.push_str("Status: install ok installed\n");
    entry.push_str("Priority: optional\n");
    entry.push_str("Section: misc\n");
    entry.push_str("Installed-Size: 0\n");
    entry.push_str("Maintainer: ExtOS PhantomDB\n");
    entry.push_str("Architecture: amd64\n");
    entry.push_str(&format!("Version: {version}\n"));

    // Provides
    let mut provides: Vec<String> = id.aliases.clone();
    for lib in &manifest.capabilities.libraries {
        // Debian provides format: libname (= version)
        provides.push(lib.clone());
    }
    for extra in resolved.extra_provides {
        if !provides.contains(extra) {
            provides.push(extra.clone());
        }
    }
    if !provides.is_empty() {
        entry.push_str(&format!("Provides: {}\n", provides.join(", ")));
    }

    // Dependencies
    let deps: Vec<String> = manifest.requires.iter().map(|d| d.to_string()).collect();
    if !deps.is_empty() {
        entry.push_str(&format!("Depends: {}\n", deps.join(", ")));
    }

    entry.push_str(&format!("Description: {name} (managed by ExtOS)\n"));
    entry.push_str(&format!("X-ExtOS-Phantom: {PHANTOM_TAG}\n"));
    entry.push('\n');
    entry
}

fn remove_entry_from_status(content: &str, package_name: &str) -> String {
    let mut cleaned = String::new();
    for block in content.split("\n\n") {
        if block.trim().is_empty() {
            continue;
        }
        if let Some(name) = extract_field(block, "Package") {
            if name == package_name {
                continue; // skip this entry
            }
        }
        if !cleaned.is_empty() {
            cleaned.push_str("\n\n");
        }
        cleaned.push_str(block.trim());
        cleaned.push('\n');
    }
    cleaned
}

fn extract_field<'a>(block: &'a str, field: &str) -> Option<&'a str> {
    for line in block.lines() {
        if let Some(rest) = line.strip_prefix(&format!("{field}: ")) {
            return Some(rest.trim());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::*;
    use crate::types::PackageFormat;

    fn test_manifest() -> PackageManifest {
        PackageManifest {
            identity: PackageIdentity {
                origin: "debian".into(),
                name: "libssl3".into(),
                version: "3.0.13-1".into(),
                aliases: vec!["libssl".into()],
            },
            archive: None,
            format: PackageFormat::ExtractedTree,
            requires: vec![],
            suggests: vec![],
            build_requires: vec![],
            capabilities: Capabilities {
                binaries: vec![],
                libraries: vec!["libssl.so.3".into(), "libcrypto.so.3".into()],
                virtual_caps: vec![],
                resources: vec![],
            },
            security: None,
            container: None,
            phantom_spoofs: Default::default(),
        }
    }

    fn resolved<'a>(manifest: &'a PackageManifest) -> ResolvedEntry<'a> {
        ResolvedEntry::new(manifest, None)
    }

    #[test]
    fn test_status_entry() {
        let m = test_manifest();
        let entry = generate_status_entry(&m, &resolved(&m));
        assert!(entry.contains("Package: libssl3\n"));
        assert!(entry.contains("Version: 3.0.13-1\n"));
        assert!(entry.contains("Status: install ok installed\n"));
        assert!(entry.contains(PHANTOM_TAG));
        assert!(entry.contains("Provides:"));
    }

    #[test]
    fn test_status_entry_spoofed() {
        let m = test_manifest();
        let spoof = SpoofEntry::new("libc6", "2.39-0extos1")
            .with_extra_provides(vec!["libc.so.6".into()]);
        let entry = generate_status_entry(&m, &ResolvedEntry::new(&m, Some(&spoof)));
        assert!(entry.contains("Package: libc6\n"));
        assert!(entry.contains("Version: 2.39-0extos1\n"));
        assert!(entry.contains("libc.so.6"));
        assert!(entry.contains(PHANTOM_TAG));
    }

    #[test]
    fn test_write_and_cleanup() {
        let tmp = tempfile::tempdir().unwrap();
        let db = tmp.path().join("var/lib/dpkg");
        let writer = DebianPhantom;

        writer
            .write_entry(&test_manifest(), &db, &["/usr/lib/libssl.so.3".into()])
            .unwrap();
        let status = fs::read_to_string(db.join("status")).unwrap();
        assert!(status.contains("Package: libssl3"));

        let removed = writer.cleanup(&db).unwrap();
        assert_eq!(removed, 1);
        let status = fs::read_to_string(db.join("status")).unwrap();
        assert!(!status.contains("Package: libssl3"));
    }

    #[test]
    fn test_write_spoof_and_cleanup() {
        let tmp = tempfile::tempdir().unwrap();
        let db = tmp.path().join("var/lib/dpkg");
        let writer = DebianPhantom;
        let spoof = SpoofEntry::new("libc6", "2.39-0extos1");

        writer
            .write_spoof(&test_manifest(), &db, &["/usr/lib/libc.so.6".into()], &spoof)
            .unwrap();

        let status = fs::read_to_string(db.join("status")).unwrap();
        assert!(status.contains("Package: libc6\n"));
        assert!(db.join("info/libc6.list").exists());

        assert_eq!(writer.cleanup(&db).unwrap(), 1);
        assert!(!db.join("info/libc6.list").exists());
    }
}
