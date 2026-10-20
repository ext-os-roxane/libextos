//! Arch Linux phantom database (M7.1).
//!
//! Writes entries to `/var/lib/pacman/local/<name>-<ver>/`:
//! - `desc`: Package metadata (NAME, VERSION, DESC, etc.)
//! - `files`: Installed file list (%FILES%)
//!
//! Format: pacman's `desc` uses `%FIELD%\n<value>\n\n` blocks.
//!
//! Spoof mode (PLAN 2.7.7) writes the same layout under the spoofed
//! `<name>-<version>` directory, with `NAME`/`VERSION`/`BASE` overridden and the
//! spoof's extra provides appended.

use std::fs;
use std::path::Path;

use crate::error::ExtosError;
use crate::manifest::{PackageManifest, SpoofEntry};
use crate::phantom::{PHANTOM_TAG, PhantomWriter, ResolvedEntry};

/// Arch Linux pacman phantom writer.
pub struct ArchPhantom;

impl ArchPhantom {
    /// Write one row using an already-resolved name/version view.
    fn write_resolved(
        &self,
        manifest: &PackageManifest,
        db_root: &Path,
        files: &[String],
        resolved: ResolvedEntry<'_>,
    ) -> Result<(), ExtosError> {
        let pkg_dir = db_root.join(format!("{}-{}", resolved.name, resolved.version));
        fs::create_dir_all(&pkg_dir)?;

        // Write desc
        let desc = generate_desc(manifest, &resolved);
        fs::write(pkg_dir.join("desc"), desc)?;

        // Write files
        let files_content = generate_files(files);
        fs::write(pkg_dir.join("files"), files_content)?;

        Ok(())
    }
}

impl PhantomWriter for ArchPhantom {
    fn origin(&self) -> &str {
        "archlinux"
    }

    fn default_db_path(&self) -> &Path {
        Path::new("var/lib/pacman/local")
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
        let mut removed = 0;
        if !db_root.exists() {
            return Ok(0);
        }

        for entry in fs::read_dir(db_root)? {
            let entry = entry?;
            let desc_path = entry.path().join("desc");
            if desc_path.exists() {
                if let Ok(content) = fs::read_to_string(&desc_path) {
                    if content.contains(PHANTOM_TAG) {
                        fs::remove_dir_all(entry.path())?;
                        removed += 1;
                    }
                }
            }
        }

        Ok(removed)
    }
}

/// Generate pacman `desc` file content.
fn generate_desc(manifest: &PackageManifest, resolved: &ResolvedEntry<'_>) -> String {
    let id = &manifest.identity;
    let name = resolved.name;
    let version = resolved.version;
    let mut desc = String::new();

    field(&mut desc, "NAME", name);
    field(&mut desc, "VERSION", version);
    field(&mut desc, "BASE", name);
    field(
        &mut desc,
        "DESC",
        &format!("{name} (managed by ExtOS, {PHANTOM_TAG})"),
    );
    field(&mut desc, "URL", "https://extos.dev");
    field(&mut desc, "ARCH", "x86_64");
    field(&mut desc, "BUILDDATE", &chrono_timestamp());
    field(&mut desc, "INSTALLDATE", &chrono_timestamp());
    field(
        &mut desc,
        "PACKAGER",
        &format!("ExtOS PhantomDB <{PHANTOM_TAG}>"),
    );
    field(&mut desc, "SIZE", "0");
    field(&mut desc, "VALIDATION", "none");

    // Provides
    let mut provides = Vec::new();
    for lib in &manifest.capabilities.libraries {
        provides.push(lib.clone());
    }
    for extra in resolved.extra_provides {
        if !provides.contains(extra) {
            provides.push(extra.clone());
        }
    }
    for alias in &id.aliases {
        provides.push(format!("{alias}={version}"));
    }
    if !provides.is_empty() {
        field_list(&mut desc, "PROVIDES", &provides);
    }

    // Dependencies
    let dep_names: Vec<String> = manifest.requires.iter().map(|d| d.to_string()).collect();
    if !dep_names.is_empty() {
        field_list(&mut desc, "DEPENDS", &dep_names);
    }

    desc
}

/// Generate pacman `files` file content.
fn generate_files(files: &[String]) -> String {
    let mut content = String::from("%FILES%\n");
    for f in files {
        // pacman stores paths without leading /
        let clean = f.strip_prefix('/').unwrap_or(f);
        content.push_str(clean);
        content.push('\n');
    }
    content.push('\n');
    content
}

fn field(out: &mut String, name: &str, value: &str) {
    out.push_str(&format!("%{name}%\n{value}\n\n"));
}

fn field_list(out: &mut String, name: &str, values: &[String]) {
    out.push_str(&format!("%{name}%\n"));
    for v in values {
        out.push_str(v);
        out.push('\n');
    }
    out.push('\n');
}

fn chrono_timestamp() -> String {
    // Use seconds since epoch
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    duration.as_secs().to_string()
}

// ─── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::*;
    use crate::types::PackageFormat;

    fn test_manifest() -> PackageManifest {
        PackageManifest {
            identity: PackageIdentity {
                origin: "archlinux".into(),
                name: "htop".into(),
                version: "3.3.0".into(),
                aliases: vec!["htop-vim".into()],
            },
            archive: None,
            format: PackageFormat::ExtractedTree,
            requires: vec![],
            suggests: vec![],
            build_requires: vec![],
            capabilities: Capabilities {
                binaries: vec!["htop".into()],
                libraries: vec![],
                virtual_caps: vec![],
                resources: vec![],
            },
            security: None,
            phantom_spoofs: Default::default(),
        }
    }

    fn resolved<'a>(manifest: &'a PackageManifest) -> ResolvedEntry<'a> {
        ResolvedEntry::new(manifest, None)
    }

    #[test]
    fn test_desc_generation() {
        let m = test_manifest();
        let desc = generate_desc(&m, &resolved(&m));
        assert!(desc.contains("%NAME%\nhtop\n"));
        assert!(desc.contains("%VERSION%\n3.3.0\n"));
        assert!(desc.contains(PHANTOM_TAG));
        assert!(desc.contains("%PROVIDES%\nhtop-vim=3.3.0\n"));
    }

    #[test]
    fn test_desc_generation_spoofed() {
        let m = test_manifest();
        let spoof = SpoofEntry::new("glibc", "2.39")
            .with_extra_provides(vec!["libc.so.6".to_string()]);
        let desc = generate_desc(&m, &ResolvedEntry::new(&m, Some(&spoof)));
        assert!(desc.contains("%NAME%\nglibc\n"));
        assert!(desc.contains("%BASE%\nglibc\n"));
        assert!(desc.contains("%VERSION%\n2.39\n"));
        assert!(desc.contains("libc.so.6"));
        assert!(desc.contains(PHANTOM_TAG));
    }

    #[test]
    fn test_files_generation() {
        let files = generate_files(&[
            "/usr/bin/htop".into(),
            "/usr/share/man/man1/htop.1.gz".into(),
        ]);
        assert!(files.contains("%FILES%\n"));
        assert!(files.contains("usr/bin/htop\n"));
        assert!(!files.contains("/usr/bin/htop")); // no leading /
    }

    #[test]
    fn test_write_and_cleanup() {
        let tmp = tempfile::tempdir().unwrap();
        let db = tmp.path().join("var/lib/pacman/local");
        let writer = ArchPhantom;

        writer
            .write_entry(&test_manifest(), &db, &["/usr/bin/htop".into()])
            .unwrap();

        assert!(db.join("htop-3.3.0/desc").exists());
        assert!(db.join("htop-3.3.0/files").exists());

        let removed = writer.cleanup(&db).unwrap();
        assert_eq!(removed, 1);
        assert!(!db.join("htop-3.3.0").exists());
    }

    #[test]
    fn test_write_spoof_and_cleanup() {
        let tmp = tempfile::tempdir().unwrap();
        let db = tmp.path().join("var/lib/pacman/local");
        let writer = ArchPhantom;
        let spoof = SpoofEntry::new("glibc", "2.39");

        writer
            .write_entry(&test_manifest(), &db, &["/usr/bin/htop".into()])
            .unwrap();
        writer
            .write_spoof(&test_manifest(), &db, &["/usr/bin/htop".into()], &spoof)
            .unwrap();

        assert!(db.join("glibc-2.39/desc").exists());
        let desc = fs::read_to_string(db.join("glibc-2.39/desc")).unwrap();
        assert!(desc.contains("%NAME%\nglibc\n"));
        assert_eq!(writer.cleanup(&db).unwrap(), 2); // canonical + spoof
    }
}
