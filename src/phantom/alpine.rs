//! Alpine APK phantom database (M7.3).
//!
//! Appends entries to `/lib/apk/db/installed` in APK's KEY:VALUE format.
//! Each entry is a block separated by blank lines.
//!
//! Key format: single letter codes (P=name, V=version, T=description, etc.)
//!
//! Spoof mode (PLAN 2.7.9) overrides `P:`/`V:` and injects extra provides as
//! `so:` entries, so a glibc-origin package can satisfy `apk`'s `musl` checks.

use std::fs;
use std::path::Path;

use crate::error::ExtosError;
use crate::manifest::{PackageManifest, SpoofEntry};
use crate::phantom::{PHANTOM_TAG, PhantomWriter, ResolvedEntry};

/// Alpine APK phantom writer.
pub struct AlpinePhantom;

impl AlpinePhantom {
    fn write_resolved(
        &self,
        manifest: &PackageManifest,
        db_root: &Path,
        files: &[String],
        resolved: &ResolvedEntry<'_>,
    ) -> Result<(), ExtosError> {
        fs::create_dir_all(db_root)?;
        let installed = db_root.join("installed");

        let entry = generate_apk_entry(manifest, files, resolved);

        let mut content = if installed.exists() {
            fs::read_to_string(&installed)?
        } else {
            String::new()
        };

        // Remove existing entry for this package
        content = remove_apk_entry(&content, resolved.name);

        if !content.is_empty() && !content.ends_with("\n\n") {
            content.push('\n');
        }
        content.push_str(&entry);
        fs::write(&installed, content)?;

        Ok(())
    }
}

impl PhantomWriter for AlpinePhantom {
    fn origin(&self) -> &str {
        "alpine"
    }

    fn default_db_path(&self) -> &Path {
        Path::new("lib/apk/db")
    }

    fn write_entry(
        &self,
        manifest: &PackageManifest,
        db_root: &Path,
        files: &[String],
    ) -> Result<(), ExtosError> {
        self.write_resolved(manifest, db_root, files, &ResolvedEntry::new(manifest, None))
    }

    fn write_spoof(
        &self,
        manifest: &PackageManifest,
        db_root: &Path,
        files: &[String],
        entry: &SpoofEntry,
    ) -> Result<(), ExtosError> {
        self.write_resolved(
            manifest,
            db_root,
            files,
            &ResolvedEntry::new(manifest, Some(entry)),
        )
    }

    fn cleanup(&self, db_root: &Path) -> Result<usize, ExtosError> {
        let installed = db_root.join("installed");
        if !installed.exists() {
            return Ok(0);
        }

        let content = fs::read_to_string(&installed)?;
        let mut cleaned = String::new();
        let mut removed = 0;

        for block in content.split("\n\n") {
            if block.trim().is_empty() {
                continue;
            }
            if block.contains(&format!("o:{PHANTOM_TAG}")) {
                removed += 1;
            } else {
                if !cleaned.is_empty() {
                    cleaned.push_str("\n\n");
                }
                cleaned.push_str(block.trim());
                cleaned.push('\n');
            }
        }

        fs::write(&installed, cleaned)?;
        Ok(removed)
    }
}

/// Generate an APK installed entry.
///
/// APK format uses single-letter keys:
/// - C: checksum, P: name, V: version, A: arch
/// - S: size, I: installed-size, T: description
/// - U: url, L: license, o: origin, m: maintainer
/// - p: provides, D: depends, F: directory, R: file
fn generate_apk_entry(
    manifest: &PackageManifest,
    files: &[String],
    resolved: &ResolvedEntry<'_>,
) -> String {
    let id = &manifest.identity;
    let name = resolved.name;
    let version = resolved.version;
    let mut entry = String::new();

    entry.push_str("C:Q1phantom==\n"); // fake checksum
    entry.push_str(&format!("P:{name}\n"));
    entry.push_str(&format!("V:{version}\n"));
    entry.push_str("A:x86_64\n");
    entry.push_str("S:0\n");
    entry.push_str("I:0\n");
    entry.push_str(&format!("T:{name} (managed by ExtOS)\n"));
    entry.push_str("U:https://extos.dev\n");
    entry.push_str("L:unknown\n");
    entry.push_str(&format!("o:{PHANTOM_TAG}\n"));
    entry.push_str("m:ExtOS PhantomDB\n");
    // Timestamp
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    entry.push_str(&format!("t:{ts}\n"));

    // Provides
    let mut provides = Vec::new();
    for lib in &manifest.capabilities.libraries {
        provides.push(format!("so:{lib}"));
    }
    for extra in resolved.extra_provides {
        let provided = if extra.starts_with("so:") {
            extra.clone()
        } else {
            format!("so:{extra}")
        };
        if !provides.contains(&provided) {
            provides.push(provided);
        }
    }
    for alias in &id.aliases {
        provides.push(alias.clone());
    }
    if !provides.is_empty() {
        entry.push_str(&format!("p:{}\n", provides.join(" ")));
    }

    // Dependencies
    let deps: Vec<String> = manifest.requires.iter().map(|d| d.to_string()).collect();
    if !deps.is_empty() {
        entry.push_str(&format!("D:{}\n", deps.join(" ")));
    }

    // File listing (F=directory, R=filename)
    let mut dirs_seen = std::collections::HashSet::new();
    for f in files {
        let clean = f.strip_prefix('/').unwrap_or(f);
        if let Some(parent) = std::path::Path::new(clean).parent() {
            let dir = parent.to_string_lossy().to_string();
            if !dir.is_empty() && dirs_seen.insert(dir.clone()) {
                entry.push_str(&format!("F:{dir}\n"));
            }
        }
        if let Some(fname) = std::path::Path::new(clean).file_name() {
            entry.push_str(&format!("R:{}\n", fname.to_string_lossy()));
        }
    }

    entry.push('\n');
    entry
}

fn remove_apk_entry(content: &str, package_name: &str) -> String {
    let mut cleaned = String::new();
    for block in content.split("\n\n") {
        if block.trim().is_empty() {
            continue;
        }
        if block.lines().any(|l| l == format!("P:{package_name}")) {
            continue;
        }
        if !cleaned.is_empty() {
            cleaned.push_str("\n\n");
        }
        cleaned.push_str(block.trim());
        cleaned.push('\n');
    }
    cleaned
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::*;
    use crate::types::PackageFormat;

    fn test_manifest() -> PackageManifest {
        PackageManifest {
            identity: PackageIdentity {
                origin: "alpine".into(),
                name: "musl".into(),
                version: "1.2.5-r0".into(),
                aliases: vec![],
            },
            archive: None,
            format: PackageFormat::ExtractedTree,
            requires: vec![],
            suggests: vec![],
            build_requires: vec![],
            capabilities: Capabilities {
                binaries: vec![],
                libraries: vec!["libc.musl-x86_64.so.1".into()],
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
    fn test_apk_entry() {
        let m = test_manifest();
        let entry = generate_apk_entry(&m, &["/lib/ld-musl-x86_64.so.1".into()], &resolved(&m));
        assert!(entry.contains("P:musl\n"));
        assert!(entry.contains("V:1.2.5-r0\n"));
        assert!(entry.contains(&format!("o:{PHANTOM_TAG}\n")));
        assert!(entry.contains("p:so:libc.musl-x86_64.so.1"));
    }

    #[test]
    fn test_apk_entry_spoofed() {
        let m = test_manifest();
        let spoof = SpoofEntry::new("glibc", "2.39")
            .with_extra_provides(vec!["libc.so.6".into()]);
        let entry = generate_apk_entry(&m, &[], &ResolvedEntry::new(&m, Some(&spoof)));
        assert!(entry.contains("P:glibc\n"));
        assert!(entry.contains("V:2.39\n"));
        assert!(entry.contains("so:libc.so.6"));
        assert!(entry.contains(&format!("o:{PHANTOM_TAG}\n")));
    }

    #[test]
    fn test_write_and_cleanup() {
        let tmp = tempfile::tempdir().unwrap();
        let db = tmp.path().join("lib/apk/db");
        let writer = AlpinePhantom;

        writer
            .write_entry(&test_manifest(), &db, &["/lib/ld-musl.so.1".into()])
            .unwrap();
        let content = fs::read_to_string(db.join("installed")).unwrap();
        assert!(content.contains("P:musl"));

        let removed = writer.cleanup(&db).unwrap();
        assert_eq!(removed, 1);
    }

    #[test]
    fn test_write_spoof_and_cleanup() {
        let tmp = tempfile::tempdir().unwrap();
        let db = tmp.path().join("lib/apk/db");
        let writer = AlpinePhantom;

        writer
            .write_entry(&test_manifest(), &db, &["/lib/ld-musl.so.1".into()])
            .unwrap();
        writer
            .write_spoof(&test_manifest(), &db, &[], &SpoofEntry::new("glibc", "2.39"))
            .unwrap();

        let content = fs::read_to_string(db.join("installed")).unwrap();
        assert!(content.contains("P:glibc\n"));
        assert!(content.contains("P:musl\n"));

        assert_eq!(writer.cleanup(&db).unwrap(), 2);
        let content = fs::read_to_string(db.join("installed")).unwrap();
        assert!(!content.contains("P:glibc"));
        assert!(!content.contains("P:musl"));
    }
}
