//! Void Linux XBPS phantom database (M7.5).
//!
//! Writes entries to `/var/db/xbps/pkgdb-0.38.plist` in XML plist format.
//! Each package is a `<dict>` inside the root `<dict>` keyed by
//! `<pkgname>-<version>`.
//!
//! Spoof mode (PLAN 2.7.10) writes the row under the spoofed key with
//! `pkgname`/`pkgver`/`version` overridden and the spoof's extra provides
//! appended to the `provides` array.

use std::fs;
use std::path::Path;

use crate::error::ExtosError;
use crate::manifest::{PackageManifest, SpoofEntry};
use crate::phantom::{PHANTOM_TAG, PhantomWriter, ResolvedEntry};

/// Void Linux XBPS phantom writer.
pub struct VoidPhantom;

impl VoidPhantom {
    fn write_resolved(
        &self,
        manifest: &PackageManifest,
        db_root: &Path,
        files: &[String],
        resolved: &ResolvedEntry<'_>,
    ) -> Result<(), ExtosError> {
        fs::create_dir_all(db_root)?;
        let plist_path = db_root.join("pkgdb-0.38.plist");

        let pkg_key = format!("{}-{}", resolved.name, resolved.version);
        let dict_entry = generate_plist_dict(manifest, files, resolved);

        if plist_path.exists() {
            let mut content = fs::read_to_string(&plist_path)?;
            // Remove existing entry
            content = remove_plist_entry(&content, &pkg_key);
            // Insert before closing </dict></plist>
            if let Some(pos) = content.rfind("</dict>") {
                content.insert_str(pos, &format!("\t<key>{pkg_key}</key>\n{dict_entry}\n"));
            }
            fs::write(&plist_path, content)?;
        } else {
            let content = format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>{pkg_key}</key>
{dict_entry}
</dict>
</plist>
"#
            );
            fs::write(&plist_path, content)?;
        }

        Ok(())
    }
}

impl PhantomWriter for VoidPhantom {
    fn origin(&self) -> &str {
        "void"
    }

    fn default_db_path(&self) -> &Path {
        Path::new("var/db/xbps")
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
        let plist_path = db_root.join("pkgdb-0.38.plist");
        if !plist_path.exists() {
            return Ok(0);
        }

        let content = fs::read_to_string(&plist_path)?;
        let phantom_marker = format!("<string>{PHANTOM_TAG}</string>");
        let lines: Vec<&str> = content.lines().collect();

        let mut cleaned = String::new();
        let mut removed = 0;
        let mut i = 0;

        // Walk top-level `<key>` + `<dict> ... </dict>` pairs. Inner keys are
        // indented one level deeper, so a key directly followed by `<dict>` is
        // always a package entry.
        while i < lines.len() {
            let is_entry_key = lines[i].trim_start().starts_with("<key>")
                && lines[i].trim_end().ends_with("</key>")
                && lines
                    .get(i + 1)
                    .is_some_and(|next| next.trim() == "<dict>");

            if !is_entry_key {
                cleaned.push_str(lines[i]);
                cleaned.push('\n');
                i += 1;
                continue;
            }

            // Find the matching `</dict>` for this entry (no nested dicts are
            // emitted by this writer).
            let close = lines[i..]
                .iter()
                .position(|line| line.trim() == "</dict>")
                .map(|offset| i + offset);

            let Some(end) = close else {
                // Malformed tail — keep it rather than silently dropping data.
                cleaned.push_str(lines[i]);
                cleaned.push('\n');
                i += 1;
                continue;
            };

            let block = &lines[i..=end];
            if block.iter().any(|line| line.contains(&phantom_marker)) {
                removed += 1;
            } else {
                for line in block {
                    cleaned.push_str(line);
                    cleaned.push('\n');
                }
            }
            i = end + 1;
        }

        fs::write(&plist_path, cleaned)?;
        Ok(removed)
    }
}

/// Generate an XBPS plist dict entry for a package.
fn generate_plist_dict(
    manifest: &PackageManifest,
    _files: &[String],
    resolved: &ResolvedEntry<'_>,
) -> String {
    let id = &manifest.identity;
    let name = resolved.name;
    let version = resolved.version;
    let mut dict = String::from("\t<dict>\n");

    plist_kv(&mut dict, "pkgname", name);
    plist_kv(&mut dict, "pkgver", &format!("{name}-{version}"));
    plist_kv(&mut dict, "version", version);
    plist_kv(&mut dict, "architecture", "x86_64");
    plist_kv(
        &mut dict,
        "short_desc",
        &format!("{name} (managed by ExtOS)"),
    );
    plist_kv(&mut dict, "state", "installed");
    plist_kv(&mut dict, "extos-phantom", PHANTOM_TAG);

    // Provides
    let mut provides: Vec<String> = manifest.capabilities.libraries.clone();
    for extra in resolved.extra_provides {
        if !provides.contains(extra) {
            provides.push(extra.clone());
        }
    }
    if !provides.is_empty() || !id.aliases.is_empty() {
        dict.push_str("\t\t<key>provides</key>\n\t\t<array>\n");
        for lib in &provides {
            dict.push_str(&format!("\t\t\t<string>{lib}</string>\n"));
        }
        for alias in &id.aliases {
            dict.push_str(&format!("\t\t\t<string>{alias}-{version}</string>\n"));
        }
        dict.push_str("\t\t</array>\n");
    }

    dict.push_str("\t</dict>\n");
    dict
}

fn plist_kv(out: &mut String, key: &str, value: &str) {
    out.push_str(&format!("\t\t<key>{key}</key>\n\t\t<string>{value}</string>\n"));
}

/// Remove an existing plist entry by its key.
fn remove_plist_entry(content: &str, pkg_key: &str) -> String {
    let key_tag = format!("\t<key>{pkg_key}</key>");
    let mut cleaned = String::new();
    let mut skip_dict = false;
    let mut found_key = false;

    for line in content.lines() {
        if line.trim() == key_tag.trim() {
            found_key = true;
            continue; // skip the key line
        }
        if found_key {
            found_key = false;
            if line.trim() == "<dict>" {
                skip_dict = true;
                continue;
            }
        }
        if skip_dict {
            if line.trim() == "</dict>" {
                skip_dict = false;
            }
            continue;
        }
        cleaned.push_str(line);
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
                origin: "void".into(),
                name: "curl".into(),
                version: "8.5.0_1".into(),
                aliases: vec![],
            },
            archive: None,
            format: PackageFormat::ExtractedTree,
            requires: vec![],
            suggests: vec![],
            build_requires: vec![],
            capabilities: Capabilities {
                binaries: vec!["curl".into()],
                libraries: vec!["libcurl.so.4".into()],
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
    fn test_plist_dict() {
        let m = test_manifest();
        let dict = generate_plist_dict(&m, &[], &resolved(&m));
        assert!(dict.contains("<key>pkgname</key>"));
        assert!(dict.contains("<string>curl</string>"));
        assert!(dict.contains(PHANTOM_TAG));
    }

    #[test]
    fn test_plist_dict_spoofed() {
        let m = test_manifest();
        let spoof = SpoofEntry::new("glibc", "2.39")
            .with_extra_provides(vec!["libc.so.6".into()]);
        let dict = generate_plist_dict(&m, &[], &ResolvedEntry::new(&m, Some(&spoof)));
        assert!(dict.contains("<string>glibc</string>"));
        assert!(dict.contains("<string>glibc-2.39</string>"));
        assert!(dict.contains("<string>libc.so.6</string>"));
    }

    #[test]
    fn test_write_and_cleanup() {
        let tmp = tempfile::tempdir().unwrap();
        let db = tmp.path().join("var/db/xbps");
        let writer = VoidPhantom;

        writer.write_entry(&test_manifest(), &db, &[]).unwrap();
        let plist = fs::read_to_string(db.join("pkgdb-0.38.plist")).unwrap();
        assert!(plist.contains("curl-8.5.0_1"));
        assert!(plist.contains(PHANTOM_TAG));

        let removed = writer.cleanup(&db).unwrap();
        assert_eq!(removed, 1);
    }

    #[test]
    fn test_write_spoof_and_cleanup_multiple() {
        let tmp = tempfile::tempdir().unwrap();
        let db = tmp.path().join("var/db/xbps");
        let writer = VoidPhantom;

        writer.write_entry(&test_manifest(), &db, &[]).unwrap();
        writer
            .write_spoof(&test_manifest(), &db, &[], &SpoofEntry::new("glibc", "2.39"))
            .unwrap();
        writer
            .write_spoof(&test_manifest(), &db, &[], &SpoofEntry::new("glibc-dev", "2.39"))
            .unwrap();

        let plist = fs::read_to_string(db.join("pkgdb-0.38.plist")).unwrap();
        assert!(plist.contains("glibc-2.39"));
        assert!(plist.contains("glibc-dev-2.39"));
        // Header must be intact before cleanup.
        assert!(plist.starts_with("<?xml"));

        assert_eq!(writer.cleanup(&db).unwrap(), 3);
        let plist = fs::read_to_string(db.join("pkgdb-0.38.plist")).unwrap();
        assert!(!plist.contains(PHANTOM_TAG));
        assert!(plist.contains("</plist>"));
        // Re-cleaning is a no-op and never corrupts the file.
        assert_eq!(writer.cleanup(&db).unwrap(), 0);
    }
}
