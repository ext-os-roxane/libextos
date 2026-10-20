//! Built-in Rosetta translator for Arch Linux packages (`.PKGINFO`).
//!
//! Arch packages embed a `.PKGINFO` file at the archive root made of
//! `key = value` lines. Repeatable keys (`depend`, `provides`, `replaces`, ...)
//! appear once per value.
//!
//! ## Translation rules
//!
//! | `.PKGINFO`    | ExtOS manifest                                |
//! |---------------|-----------------------------------------------|
//! | `pkgname`     | `identity.name`                               |
//! | `pkgver`      | `identity.version`                            |
//! | `depend`      | `requires[]` (Tier-2, relational constraint)  |
//! | `provides`    | `identity.aliases` + `capabilities.virtual`   |
//! | `provides` with `.so` in the name | additionally `capabilities.libraries` |
//! | `replaces`    | `identity.aliases`                            |
//!
//! `optdepend`, `makedepend`, `checkdepend` and `conflict` are intentionally
//! not translated: optional deps become `suggests{}` groups in ExtOS, which is
//! a Phase 3 concern once the suggest schema is wired to ingestion.

use std::path::Path;

use crate::error::ExtosError;
use crate::rosetta::common::{self, NativeDep, NativeManifest};
use crate::rosetta::{PluginCapability, RosettaPlugin};

/// Canonical origin name handled by this plugin.
pub const ORIGIN: &str = "archlinux";

/// Metadata file names probed inside a staging `metadata/` directory.
const METADATA_CANDIDATES: &[&str] = &[".PKGINFO", "PKGINFO", "pkginfo"];

/// Built-in Rosetta plugin for Arch Linux.
///
/// Implements the PARSE and TRANSLATE capabilities; fetching, extraction,
/// database sync and PhantomDB writing remain the responsibility of the
/// `pacman-extos` fork (Phase 3).
pub struct ArchPlugin;

impl ArchPlugin {
    /// Parse `.PKGINFO` metadata into an origin-agnostic [`NativeManifest`].
    ///
    /// `metadata_path` may point at the `.PKGINFO` file itself or at a staging
    /// `metadata/` directory containing it.
    pub fn translate(&self, metadata_path: &Path) -> Result<NativeManifest, ExtosError> {
        let text = common::read_metadata_text(metadata_path, METADATA_CANDIDATES, ORIGIN)?;
        parse_pkginfo(&text)
    }
}

impl RosettaPlugin for ArchPlugin {
    fn origin_name(&self) -> &str {
        ORIGIN
    }

    fn api_version(&self) -> u32 {
        crate::rosetta::ROSETTA_API_VERSION
    }

    fn capabilities(&self) -> PluginCapability {
        PluginCapability::PARSE | PluginCapability::TRANSLATE
    }

    fn parse_metadata(&self, metadata_path: &Path) -> Result<String, ExtosError> {
        Ok(self.translate(metadata_path)?.to_manifest_nix(ORIGIN))
    }

    fn translate_deps(&self, metadata_path: &Path) -> Result<String, ExtosError> {
        self.translate(metadata_path)?.to_deps_json(ORIGIN)
    }

    fn fetch_package(
        &self,
        _pkg_name: &str,
        _version: Option<&str>,
        _mirror_url: &str,
        _dest_path: &Path,
    ) -> Result<(), ExtosError> {
        Err(ExtosError::RosettaPlugin {
            plugin: ORIGIN.to_string(),
            message: "FETCH is handled by pacman-extos, not the builtin translator".into(),
        })
    }

    fn extract(&self, _archive_path: &Path, _staging_dir: &Path) -> Result<(), ExtosError> {
        Err(ExtosError::RosettaPlugin {
            plugin: ORIGIN.to_string(),
            message: "EXTRACT is handled by the generic extractor, not the builtin translator".into(),
        })
    }

    fn sync_db(&self, _mirror_url: &str, _cache_dir: &Path) -> Result<(), ExtosError> {
        Err(ExtosError::RosettaPlugin {
            plugin: ORIGIN.to_string(),
            message: "SYNC is handled by pacman-extos, not the builtin translator".into(),
        })
    }

    fn phantom_write(
        &self,
        _manifest_nix_path: &Path,
        _phantom_db_dir: &Path,
    ) -> Result<(), ExtosError> {
        Err(ExtosError::RosettaPlugin {
            plugin: ORIGIN.to_string(),
            message: "PHANTOM is handled by crate::phantom, not the builtin translator".into(),
        })
    }

    fn cleanup(&self) {}
}

/// Parse the body of an Arch `.PKGINFO` document.
///
/// Returns [`ExtosError::RosettaPlugin`] when `pkgname` is absent, since a
/// manifest without a package name cannot be ingested.
pub fn parse_pkginfo(text: &str) -> Result<NativeManifest, ExtosError> {
    let mut name = String::new();
    let mut version = String::new();
    let mut native = NativeManifest::default();

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();
        if value.is_empty() {
            continue;
        }

        match key {
            "pkgname" => name = value.to_string(),
            "pkgver" => version = value.to_string(),
            "depend" => {
                let (dep_name, constraint) = common::split_constraint(value);
                if dep_name.is_empty() {
                    continue;
                }
                if dep_name.contains(".so") {
                    native.requires.push(NativeDep::Capability(dep_name));
                } else {
                    native.requires.push(NativeDep::Package {
                        name: dep_name,
                        constraint,
                    });
                }
            }
            "provides" => {
                let (provided, _) = common::split_constraint(value);
                native.add_provide(&provided);
            }
            "replaces" => {
                let (replaced, _) = common::split_constraint(value);
                if !replaced.is_empty() {
                    native.aliases.push(replaced);
                }
            }
            _ => {}
        }
    }

    if name.is_empty() {
        return Err(ExtosError::RosettaPlugin {
            plugin: ORIGIN.to_string(),
            message: "missing required 'pkgname' key in .PKGINFO".into(),
        });
    }

    native.name = name;
    native.version = version;
    Ok(native)
}

// ─── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_pkginfo_minimal() {
        let native = parse_pkginfo("pkgname = htop\npkgver = 3.3.0-1\n").unwrap();
        assert_eq!(native.name, "htop");
        assert_eq!(native.version, "3.3.0-1");
        assert!(native.requires.is_empty());
    }

    #[test]
    fn test_parse_pkginfo_deps_and_provides() {
        let text = "\
# generated by makepkg
pkgname = htop
pkgver = 3.3.0-1
depend = glibc
depend = ncurses>=6.4
provides = libhtop.so=1-64
provides = system-monitor=3.3
replaces = htop-legacy
";
        let native = parse_pkginfo(text).unwrap();
        assert_eq!(native.requires.len(), 2);
        assert_eq!(
            native.requires[0],
            NativeDep::Package {
                name: "glibc".into(),
                constraint: None
            }
        );
        assert_eq!(
            native.requires[1],
            NativeDep::Package {
                name: "ncurses".into(),
                constraint: Some(">=6.4".into())
            }
        );
        assert!(native.aliases.contains(&"libhtop.so".to_string()));
        assert!(native.aliases.contains(&"system-monitor".to_string()));
        assert!(native.aliases.contains(&"htop-legacy".to_string()));
        assert_eq!(native.libraries, vec!["libhtop.so"]);
        assert_eq!(native.virtual_caps, vec!["system-monitor"]);
    }

    #[test]
    fn test_parse_pkginfo_missing_name() {
        assert!(parse_pkginfo("pkgver = 1.0\n").is_err());
    }
}
