//! PhantomDB Generator (M7).
//!
//! Generates fake native package manager database entries so that
//! guest-origin tools (`pacman -Q`, `dpkg -l`, `apk info`, etc.)
//! can see ExtOS-managed packages as "installed".
//!
//! Each generator reads an ExtOS `PackageManifest` and writes the
//! appropriate database format:
//!
//! | Origin    | DB Path                          | Format                |
//! |-----------|----------------------------------|-----------------------|
//! | Arch      | `/var/lib/pacman/local/`         | desc + files          |
//! | Debian    | `/var/lib/dpkg/status`           | RFC-822 control       |
//! | Alpine    | `/lib/apk/db/installed`          | KEY:VALUE blocks      |
//! | Void      | `/var/db/xbps/pkgdb-0.38.plist`  | XML plist             |
//! | RPM       | `/var/lib/rpm/extos-phantoms/`    | Text record + provides index |
//!
//! All entries include an `extos-phantom` tag so cleanup can strip them.
//!
//! Since PLAN 2.7 a single package can additionally emit **spoofed** rows into
//! foreign package-manager databases (see
//! [`PackageManifest::phantom_spoofs`](crate::manifest::PackageManifest::phantom_spoofs)),
//! which share the canonical entry's file list because the files are identical.

pub mod alpine;
pub mod arch;
pub mod debian;
pub mod rpm;
pub mod void_xbps;

use std::path::Path;

use crate::error::ExtosError;
use crate::manifest::{PackageManifest, SpoofEntry, SpoofTarget};

/// The tag embedded in all phantom entries for identification.
pub const PHANTOM_TAG: &str = "extos-phantom";

/// The name/version/provides a writer should use for one row.
///
/// For the canonical row these come straight from the manifest identity; for a
/// spoofed row they are overridden by the [`SpoofEntry`], while dependencies and
/// the file list still come from the manifest.
pub(crate) struct ResolvedEntry<'a> {
    /// Package name to write.
    pub name: &'a str,
    /// Package version to write (spoofs inherit the manifest version when empty).
    pub version: &'a str,
    /// Extra provides injected into the row.
    pub extra_provides: &'a [String],
}

impl<'a> ResolvedEntry<'a> {
    pub(crate) fn new(manifest: &'a PackageManifest, spoof: Option<&'a SpoofEntry>) -> Self {
        match spoof {
            Some(entry) => Self {
                name: &entry.name,
                version: if entry.version.is_empty() {
                    &manifest.identity.version
                } else {
                    &entry.version
                },
                extra_provides: &entry.extra_provides,
            },
            None => Self {
                name: &manifest.identity.name,
                version: &manifest.identity.version,
                extra_provides: &[],
            },
        }
    }
}

/// Trait for phantom database generators.
pub trait PhantomWriter {
    /// The origin this writer handles (e.g., "archlinux").
    fn origin(&self) -> &str;

    /// Default database path for this PM.
    fn default_db_path(&self) -> &Path;

    /// Write a phantom entry for a single package.
    fn write_entry(
        &self,
        manifest: &PackageManifest,
        db_root: &Path,
        files: &[String],
    ) -> Result<(), ExtosError>;

    /// Write a spoofed phantom row for a foreign package manager.
    ///
    /// The row uses this writer's native format and the `extos-phantom` tag, but
    /// reports `entry.name`/`entry.version` and injects `entry.extra_provides`
    /// into the provides list. The installed file list is identical to the
    /// canonical entry.
    fn write_spoof(
        &self,
        manifest: &PackageManifest,
        db_root: &Path,
        files: &[String],
        entry: &SpoofEntry,
    ) -> Result<(), ExtosError>;

    /// Remove all phantom entries (identified by `extos-phantom` tag).
    fn cleanup(&self, db_root: &Path) -> Result<usize, ExtosError>;
}

/// The writer responsible for a spoof target.
pub fn writer_for_target(target: SpoofTarget) -> Box<dyn PhantomWriter> {
    match target {
        SpoofTarget::Arch => Box::new(arch::ArchPhantom),
        SpoofTarget::Debian => Box::new(debian::DebianPhantom),
        SpoofTarget::Alpine => Box::new(alpine::AlpinePhantom),
        SpoofTarget::Void => Box::new(void_xbps::VoidPhantom),
        SpoofTarget::Rpm => Box::new(rpm::RpmPhantom),
    }
}

/// Write phantom entries for the manifest's own origin, plus spoofed rows for
/// the roof's native package manager.
///
/// The canonical entry (matching `manifest.identity.origin`) is always written.
/// When `roof_native_pm` is `Some(pm)` and `pm` names a *different* package
/// manager, every entry in `manifest.phantom_spoofs[pm]` is also written in that
/// PM's native format. If the manifest declares no explicit spoofs at all, the
/// well-known mapping table is used as a fallback (see
/// [`resolve_auto_spoofs`](crate::manifest::resolve_auto_spoofs)).
///
/// Pass `None` for `roof_native_pm` to keep the pre-2.7 behavior (canonical row
/// only).
///
/// The returned labels list what was written: the canonical origin label (e.g.
/// `"archlinux"`) and one `"<target>:<name>"` label per spoofed row.
pub fn write_all_phantoms(
    manifest: &PackageManifest,
    target_root: &Path,
    files: &[String],
    roof_native_pm: Option<&str>,
) -> Result<Vec<String>, ExtosError> {
    let mut written = Vec::new();
    let origin = &manifest.identity.origin;

    let canonical_target = SpoofTarget::from_origin(origin);
    if let Some(target) = canonical_target {
        let writer = writer_for_target(target);
        let db = target_root.join(writer.default_db_path());
        writer.write_entry(manifest, &db, files)?;
        written.push(target.canonical_origin().to_string());
    }

    if let Some(native) = roof_native_pm {
        if let Some(target) = SpoofTarget::from_origin(native) {
            // Only spoof when the roof's PM is not the package's own PM.
            if canonical_target != Some(target) {
                let entries = manifest.effective_spoofs_for(target);
                if !entries.is_empty() {
                    let writer = writer_for_target(target);
                    let db = target_root.join(writer.default_db_path());
                    for entry in &entries {
                        writer.write_spoof(manifest, &db, files, entry)?;
                        written.push(format!("{}:{}", target.as_str(), entry.name));
                    }
                }
            }
        } else {
            tracing::debug!(
                pm = native,
                "roof native package manager has no phantom database; skipping spoofs"
            );
        }
    }

    Ok(written)
}

/// Cleanup all phantom entries across all supported origins.
///
/// Removes every `extos-phantom`-tagged row — canonical and spoofed alike —
/// from every database that exists under `target_root` (PLAN 2.7.12).
pub fn cleanup_all_phantoms(target_root: &Path) -> Result<usize, ExtosError> {
    let mut total = 0;

    for target in SpoofTarget::ALL {
        let writer = writer_for_target(target);
        let db = target_root.join(writer.default_db_path());
        if db.exists() {
            total += writer.cleanup(&db)?;
        }
    }

    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{Capabilities, PackageIdentity, SpoofEntry, resolve_auto_spoofs};
    use crate::types::PackageFormat;
    use std::fs;

    fn manifest(
        origin: &str,
        name: &str,
        version: &str,
        spoofs: &[(SpoofTarget, &str, &str)],
    ) -> PackageManifest {
        let mut phantom_spoofs = std::collections::BTreeMap::new();
        for (target, spoof_name, spoof_version) in spoofs {
            phantom_spoofs
                .entry(*target)
                .or_insert_with(Vec::new)
                .push(SpoofEntry::new(*spoof_name, *spoof_version));
        }
        PackageManifest {
            identity: PackageIdentity {
                origin: origin.into(),
                name: name.into(),
                version: version.into(),
                aliases: vec![],
            },
            archive: None,
            format: PackageFormat::ExtractedTree,
            requires: vec![],
            suggests: vec![],
            build_requires: vec![],
            capabilities: Capabilities {
                binaries: vec![],
                libraries: vec!["libc.so.6".into()],
                virtual_caps: vec![],
                resources: vec![],
            },
            security: None,
            phantom_spoofs,
        }
    }

    #[test]
    fn legacy_mode_writes_canonical_only() {
        let tmp = tempfile::tempdir().unwrap();
        let m = manifest(
            "archlinux",
            "glibc",
            "2.39",
            &[(SpoofTarget::Debian, "libc6", "2.39-0extos1")],
        );
        let files = vec!["/usr/lib/libc.so.6".to_string()];

        let written = write_all_phantoms(&m, tmp.path(), &files, None).unwrap();
        assert_eq!(written, vec!["archlinux"]);
        assert!(tmp.path().join("var/lib/pacman/local/glibc-2.39/desc").exists());
        assert!(!tmp.path().join("var/lib/dpkg/status").exists());
    }

    #[test]
    fn no_spoof_when_roof_matches_origin() {
        let tmp = tempfile::tempdir().unwrap();
        let m = manifest(
            "archlinux",
            "glibc",
            "2.39",
            &[(SpoofTarget::Arch, "glibc", "2.39")],
        );
        let written = write_all_phantoms(&m, tmp.path(), &[], Some("archlinux")).unwrap();
        assert_eq!(written, vec!["archlinux"]);
    }

    /// PLAN 2.7.13: Arch glibc with Debian spoofs → dpkg status gains libc6 rows.
    #[test]
    fn arch_glibc_spoofs_debian_rows() {
        let tmp = tempfile::tempdir().unwrap();
        let m = manifest(
            "archlinux",
            "glibc",
            "2.39",
            &[
                (SpoofTarget::Debian, "libc6", "2.39-0extos1"),
                (SpoofTarget::Debian, "libc6-dev", "2.39-0extos1"),
            ],
        );
        let files = vec!["/usr/lib/libc.so.6".to_string()];
        let written = write_all_phantoms(&m, tmp.path(), &files, Some("debian")).unwrap();
        assert!(written.contains(&"debian:libc6".to_string()));
        assert!(written.contains(&"debian:libc6-dev".to_string()));

        let status = fs::read_to_string(tmp.path().join("var/lib/dpkg/status")).unwrap();
        assert!(status.contains("Package: libc6\n"), "status: {status}");
        assert!(status.contains("Package: libc6-dev\n"), "status: {status}");
        assert!(status.contains("Version: 2.39-0extos1\n"));
        assert!(status.contains(PHANTOM_TAG));

        let list = fs::read_to_string(tmp.path().join("var/lib/dpkg/info/libc6-dev.list")).unwrap();
        assert_eq!(list, "/usr/lib/libc.so.6");
    }

    /// PLAN 2.7.14: Debian libc6 with Arch spoofs → pacman local db has glibc.
    #[test]
    fn debian_libc6_spoofs_arch_rows() {
        let tmp = tempfile::tempdir().unwrap();
        let m = manifest(
            "debian",
            "libc6",
            "2.36-9",
            &[(SpoofTarget::Arch, "glibc", "2.39")],
        );
        let files = vec!["/usr/lib/x86_64-linux-gnu/libc.so.6".to_string()];
        write_all_phantoms(&m, tmp.path(), &files, Some("archlinux")).unwrap();

        let pkg_dir = tmp.path().join("var/lib/pacman/local/glibc-2.39");
        assert!(pkg_dir.join("desc").exists());
        assert!(pkg_dir.join("files").exists());

        let desc = fs::read_to_string(pkg_dir.join("desc")).unwrap();
        assert!(desc.contains("%NAME%\nglibc\n"), "desc: {desc}");
        assert!(desc.contains("%VERSION%\n2.39\n"));
        assert!(desc.contains(PHANTOM_TAG));

        let files = fs::read_to_string(pkg_dir.join("files")).unwrap();
        assert!(files.contains("usr/lib/x86_64-linux-gnu/libc.so.6\n"));
    }

    /// PLAN 2.7.15: one manifest emits both Arch and Debian spoof rows.
    #[test]
    fn bidirectional_spoofs_from_one_manifest() {
        let tmp = tempfile::tempdir().unwrap();
        let m = manifest(
            "alpine",
            "musl",
            "1.2.5-r0",
            &[
                (SpoofTarget::Arch, "glibc", "2.39"),
                (SpoofTarget::Debian, "libc6", "2.39-0extos1"),
            ],
        );
        let files = vec!["/lib/ld-musl-x86_64.so.1".to_string()];

        write_all_phantoms(&m, tmp.path(), &files, Some("archlinux")).unwrap();
        write_all_phantoms(&m, tmp.path(), &files, Some("debian")).unwrap();

        assert!(tmp.path().join("var/lib/pacman/local/glibc-2.39/desc").exists());
        let status = fs::read_to_string(tmp.path().join("var/lib/dpkg/status")).unwrap();
        assert!(status.contains("Package: libc6\n"));
        // Canonical alpine db written too.
        let apk = fs::read_to_string(tmp.path().join("lib/apk/db/installed")).unwrap();
        assert!(apk.contains("P:musl\n"));
    }

    /// PLAN 2.7.12: cleanup removes canonical *and* spoofed rows everywhere.
    #[test]
    fn cleanup_removes_canonical_and_spoofed_rows() {
        let tmp = tempfile::tempdir().unwrap();
        let m = manifest(
            "alpine",
            "musl",
            "1.2.5-r0",
            &[
                (SpoofTarget::Arch, "glibc", "2.39"),
                (SpoofTarget::Debian, "libc6", "2.39-0extos1"),
                (SpoofTarget::Rpm, "glibc", "2.39"),
                (SpoofTarget::Void, "musl", "1.2.5_1"),
            ],
        );
        let files = vec!["/lib/ld-musl-x86_64.so.1".to_string()];
        for pm in ["archlinux", "debian", "rpm", "void"] {
            write_all_phantoms(&m, tmp.path(), &files, Some(pm)).unwrap();
        }

        let removed = cleanup_all_phantoms(tmp.path()).unwrap();
        assert!(removed >= 5, "removed: {removed}");

        for pm in ["archlinux", "debian", "rpm", "void", "alpine"] {
            let writer = writer_for_target(SpoofTarget::from_origin(pm).unwrap());
            let db = tmp.path().join(writer.default_db_path());
            if !db.exists() {
                continue;
            }
            let leftovers = writer.cleanup(&db).unwrap();
            assert_eq!(leftovers, 0, "phantom rows left in {pm}");
        }
    }

    /// PLAN 2.7.17: auto-spoof fallback is used when no explicit spoofs exist.
    #[test]
    fn auto_spoof_fallback_when_manifest_has_none() {
        let tmp = tempfile::tempdir().unwrap();
        let m = manifest("archlinux", "glibc", "2.39", &[]);
        let written = write_all_phantoms(&m, tmp.path(), &[], Some("debian")).unwrap();

        assert!(written.contains(&"debian:libc6".to_string()), "written: {written:?}");
        let status = fs::read_to_string(tmp.path().join("var/lib/dpkg/status")).unwrap();
        assert!(status.contains("Package: libc6\n"));
        // Explicit spoon versions from the mapping table are used verbatim.
        assert!(status.contains("Version: 2.39-0extos1\n"));

        // Empty mapping versions inherit the manifest version.
        let musl = manifest("alpine", "musl", "1.2.5-r0", &[]);
        write_all_phantoms(&musl, tmp.path(), &[], Some("archlinux")).unwrap();
        let desc = fs::read_to_string(tmp.path().join("var/lib/pacman/local/glibc-1.2.5-r0/desc"))
            .unwrap();
        assert!(desc.contains("%VERSION%\n1.2.5-r0\n"), "desc: {desc}");
    }

    #[test]
    fn auto_spoof_ignores_unknown_package() {
        let m = manifest("archlinux", "totally-unknown-pkg", "1.0", &[]);
        assert!(m.effective_spoofs_for(SpoofTarget::Debian).is_empty());
        assert!(resolve_auto_spoofs("archlinux", "totally-unknown-pkg").is_empty());
    }

    #[test]
    fn explicit_spoofs_beat_auto_table() {
        let m = manifest(
            "archlinux",
            "glibc",
            "2.39",
            &[(SpoofTarget::Debian, "libc6-custom", "1.0-extos")],
        );
        let entries = m.effective_spoofs_for(SpoofTarget::Debian);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "libc6-custom");
    }
}
