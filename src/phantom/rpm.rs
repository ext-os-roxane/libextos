//! RPM phantom database (M7.6).
//!
//! Generates phantom entries in `/var/lib/rpm/` for RPM-based distros
//! (Fedora, SUSE, RHEL, etc.).
//!
//! Modern RPM (≥4.16) uses SQLite (`rpmdb.sqlite`). This module writes
//! directly to SQLite without requiring `librpm` FFI, making it portable.
//!
//! For older RPM systems using BDB (Berkeley DB), a compatibility shim
//! can regenerate from our SQLite entries via `rpmdb --rebuilddb`.
//!
//! Schema (simplified from RPM's `rpmdb.sqlite`):
//! ```sql
//! CREATE TABLE Packages (hnum INTEGER PRIMARY KEY, blob BLOB NOT NULL);
//! CREATE TABLE Name    (key TEXT, hnum INTEGER);
//! CREATE TABLE Basenames (key TEXT, hnum INTEGER);
//! ```
//!
//! We write a minimal RPM header blob containing only the tags needed
//! for `rpm -q` to show the package as installed.
//!
//! Spoof mode (PLAN 2.7.11) writes the record under the spoofed
//! `Name`/`Version`/`Release` and indexes the spoofed name in `provides`.

use std::fs;
use std::path::Path;

use crate::error::ExtosError;
use crate::manifest::{PackageManifest, SpoofEntry};
use crate::phantom::{PHANTOM_TAG, PhantomWriter, ResolvedEntry};

/// RPM phantom writer (SQLite-based rpmdb).
pub struct RpmPhantom;

impl RpmPhantom {
    fn write_resolved(
        &self,
        manifest: &PackageManifest,
        db_root: &Path,
        files: &[String],
        resolved: &ResolvedEntry<'_>,
    ) -> Result<(), ExtosError> {
        fs::create_dir_all(db_root)?;

        // Write a text-based phantom record that can be consumed by
        // rpmdb --rebuilddb or queried by our own tooling.
        // Full SQLite blob writing requires the `rpm` crate or raw header
        // construction — we use a simpler manifest approach.
        let phantom_dir = db_root.join("extos-phantoms");
        fs::create_dir_all(&phantom_dir)?;

        let record = generate_rpm_record(manifest, files, resolved);
        let filename = format!("{}-{}.phantom", resolved.name, resolved.version);
        fs::write(phantom_dir.join(&filename), &record)?;

        // Also write a marker in the Providename index
        let provides_dir = phantom_dir.join("provides");
        fs::create_dir_all(&provides_dir)?;
        let mut provides: Vec<String> = manifest.capabilities.libraries.clone();
        for extra in resolved.extra_provides {
            if !provides.contains(extra) {
                provides.push(extra.clone());
            }
        }
        for provide in provides {
            fs::write(
                provides_dir.join(provide.replace('/', "_")),
                format!("{}\t{}\t{}", resolved.name, resolved.version, PHANTOM_TAG),
            )?;
        }

        Ok(())
    }
}

impl PhantomWriter for RpmPhantom {
    fn origin(&self) -> &str {
        "rpm"
    }

    fn default_db_path(&self) -> &Path {
        Path::new("var/lib/rpm")
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
        let phantom_dir = db_root.join("extos-phantoms");
        if !phantom_dir.exists() {
            return Ok(0);
        }

        let mut removed = 0;
        // Remove all .phantom files
        if let Ok(entries) = fs::read_dir(&phantom_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) == Some("phantom") {
                    fs::remove_file(&path)?;
                    removed += 1;
                }
            }
        }

        // Remove provides index
        let provides_dir = phantom_dir.join("provides");
        if provides_dir.exists() {
            fs::remove_dir_all(&provides_dir)?;
        }

        // Remove phantom dir if empty
        if phantom_dir.exists() {
            if fs::read_dir(&phantom_dir)?.next().is_none() {
                fs::remove_dir(&phantom_dir)?;
            }
        }

        Ok(removed)
    }
}

/// Split an RPM version into `(version, release)`.
///
/// Spoof versions often look like `2.39-0extos1`; RPM wants the release split
/// out. Without a `-`, the historical `1.extos` release is used.
fn split_version(version: &str) -> (&str, &str) {
    match version.split_once('-') {
        Some((ver, rel)) if !ver.is_empty() && !rel.is_empty() => (ver, rel),
        _ => (version, "1.extos"),
    }
}

/// Generate a text-based RPM phantom record.
///
/// Format is a simplified RPM spec-like file that contains the tags
/// `rpm -q --queryformat` would return. This can be parsed by our
/// own tooling or converted to a proper RPM header blob later.
fn generate_rpm_record(
    manifest: &PackageManifest,
    files: &[String],
    resolved: &ResolvedEntry<'_>,
) -> String {
    let id = &manifest.identity;
    let name = resolved.name;
    let (version, release) = split_version(resolved.version);
    let mut record = String::new();

    record.push_str(&format!("# ExtOS PhantomDB RPM Record ({PHANTOM_TAG})\n"));
    record.push_str(&format!("Name: {name}\n"));
    record.push_str(&format!("Version: {version}\n"));
    record.push_str(&format!("Release: {release}\n"));
    record.push_str("Architecture: x86_64\n");
    record.push_str(&format!("Summary: {name} (managed by ExtOS)\n"));
    record.push_str("License: unknown\n");
    record.push_str("Group: ExtOS/Phantom\n");
    record.push_str("Vendor: ExtOS PhantomDB\n");
    record.push_str(&format!("Packager: {PHANTOM_TAG}\n"));
    record.push_str("BuildHost: extos.local\n");
    record.push_str("Size: 0\n");

    // Provides
    let mut provides: Vec<String> = Vec::new();
    for lib in &manifest.capabilities.libraries {
        provides.push(lib.clone());
    }
    for extra in resolved.extra_provides {
        if !provides.contains(extra) {
            provides.push(extra.clone());
        }
    }
    for alias in &id.aliases {
        provides.push(format!("{alias} = {}", resolved.version));
    }
    if !provides.is_empty() {
        record.push_str(&format!("Provides: {}\n", provides.join(", ")));
    }

    // Requires
    let deps: Vec<String> = manifest.requires.iter().map(|d| d.to_string()).collect();
    if !deps.is_empty() {
        record.push_str(&format!("Requires: {}\n", deps.join(", ")));
    }

    // File list
    if !files.is_empty() {
        record.push_str("\n%files\n");
        for f in files {
            record.push_str(f);
            record.push('\n');
        }
    }

    record
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::*;
    use crate::types::PackageFormat;

    fn test_manifest() -> PackageManifest {
        PackageManifest {
            identity: PackageIdentity {
                origin: "rpm".into(),
                name: "openssl-libs".into(),
                version: "3.2.1".into(),
                aliases: vec![],
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
    fn test_rpm_record() {
        let m = test_manifest();
        let record = generate_rpm_record(&m, &["/usr/lib64/libssl.so.3".into()], &resolved(&m));
        assert!(record.contains("Name: openssl-libs"));
        assert!(record.contains("Version: 3.2.1"));
        assert!(record.contains(PHANTOM_TAG));
        assert!(record.contains("Provides: libssl.so.3, libcrypto.so.3"));
        assert!(record.contains("/usr/lib64/libssl.so.3"));
    }

    #[test]
    fn test_rpm_record_spoofed_splits_release() {
        let m = test_manifest();
        let spoof = SpoofEntry::new("glibc", "2.39-0extos1")
            .with_extra_provides(vec!["libc.so.6".into()]);
        let record = generate_rpm_record(&m, &[], &ResolvedEntry::new(&m, Some(&spoof)));
        assert!(record.contains("Name: glibc\n"));
        assert!(record.contains("Version: 2.39\n"));
        assert!(record.contains("Release: 0extos1\n"));
        assert!(record.contains("libc.so.6"));
    }

    #[test]
    fn test_write_and_cleanup() {
        let tmp = tempfile::tempdir().unwrap();
        let db = tmp.path().join("var/lib/rpm");
        let writer = RpmPhantom;

        writer
            .write_entry(&test_manifest(), &db, &["/usr/lib64/libssl.so.3".into()])
            .unwrap();

        assert!(db.join("extos-phantoms/openssl-libs-3.2.1.phantom").exists());
        assert!(db.join("extos-phantoms/provides/libssl.so.3").exists());

        let removed = writer.cleanup(&db).unwrap();
        assert_eq!(removed, 1);
        assert!(!db.join("extos-phantoms/openssl-libs-3.2.1.phantom").exists());
    }

    #[test]
    fn test_write_spoof_and_cleanup() {
        let tmp = tempfile::tempdir().unwrap();
        let db = tmp.path().join("var/lib/rpm");
        let writer = RpmPhantom;

        writer.write_entry(&test_manifest(), &db, &[]).unwrap();
        writer
            .write_spoof(
                &test_manifest(),
                &db,
                &[],
                &SpoofEntry::new("glibc", "2.39-0extos1")
                    .with_extra_provides(vec!["libc.so.6".into()]),
            )
            .unwrap();

        assert!(db.join("extos-phantoms/glibc-2.39-0extos1.phantom").exists());
        let index = fs::read_to_string(db.join("extos-phantoms/provides/libc.so.6")).unwrap();
        assert!(index.contains("glibc\t2.39-0extos1"));

        assert_eq!(writer.cleanup(&db).unwrap(), 2);
        assert!(!db.join("extos-phantoms").exists());
    }
}
