//! Built-in Rosetta translator for Debian packages (`control` files).
//!
//! Debian (and Ubuntu, and every `deb822`-style index) describes a package with
//! an RFC-822-ish stanza: `Field: value` lines, where a line starting with a
//! space or tab continues the previous value.
//!
//! ## Translation rules
//!
//! | `control` field | ExtOS manifest                               |
//! |-----------------|----------------------------------------------|
//! | `Package`       | `identity.name`                              |
//! | `Version`       | `identity.version` (epoch kept verbatim)     |
//! | `Depends`, `Pre-Depends` | `requires[]` (Tier-2)               |
//! | `Provides`      | `identity.aliases` + `capabilities.virtual`  |
//! | `Replaces`      | `identity.aliases`                           |
//!
//! ### Dependency syntax handled
//!
//! * alternatives (`a | b`) — the first alternative is kept and the rest are
//!   dropped, because [`crate::dependency::DependencySpec`] has no union node;
//! * version relations `(>= 2.34)`, `(<< 1.0)`, `(= 1.0)` — exact pins are
//!   demoted to unconstrained edges (see [`crate::rosetta::common`] docs);
//! * architecture qualifiers (`[amd64 i386]`) — stripped;
//! * multiarch qualifiers (`libc6:any`) — stripped.
//!
//! `Recommends`/`Suggests` are not translated yet (they map onto
//! `suggests{}` groups, a Phase 3 concern).

use std::path::Path;

use crate::error::ExtosError;
use crate::rosetta::common::{self, NativeDep, NativeManifest};
use crate::rosetta::{PluginCapability, RosettaPlugin};

/// Canonical origin name handled by this plugin.
pub const ORIGIN: &str = "debian";

/// Metadata file names probed inside a staging `metadata/` directory.
const METADATA_CANDIDATES: &[&str] = &["control", "CONTROL", "control.txt"];

/// Built-in Rosetta plugin for Debian/Ubuntu packages.
///
/// Implements PARSE and TRANSLATE; fetch/extract/sync/phantom remain with
/// `dpkg`/`apt` and the PhantomDB writers.
pub struct DebianPlugin;

impl DebianPlugin {
    /// Parse a `control` document into an origin-agnostic [`NativeManifest`].
    pub fn translate(&self, metadata_path: &Path) -> Result<NativeManifest, ExtosError> {
        let text = common::read_metadata_text(metadata_path, METADATA_CANDIDATES, ORIGIN)?;
        parse_control(&text)
    }
}

impl RosettaPlugin for DebianPlugin {
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
            message: "FETCH is handled by apt, not the builtin translator".into(),
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
            message: "SYNC is handled by apt, not the builtin translator".into(),
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

/// Parse the first stanza of a Debian `control` / `Packages` document.
///
/// Later stanzas (a `Packages` index holds many) are ignored; extraction always
/// yields exactly one package's control file.
pub fn parse_control(text: &str) -> Result<NativeManifest, ExtosError> {
    let fields = first_paragraph_fields(text);

    let name = fields
        .iter()
        .find(|(key, _)| key == "package")
        .map(|(_, value)| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| ExtosError::RosettaPlugin {
            plugin: ORIGIN.to_string(),
            message: "missing required 'Package:' field in control file".into(),
        })?;

    let version = fields
        .iter()
        .find(|(key, _)| key == "version")
        .map(|(_, value)| value.trim().to_string())
        .unwrap_or_default();

    let mut native = NativeManifest::new(name, version);

    for (key, value) in &fields {
        match key.as_str() {
            "depends" | "pre-depends" => {
                native.requires.extend(parse_relations(value));
            }
            "provides" => {
                for relation in split_relations(value) {
                    let provided = relation_name(&relation);
                    native.add_provide(&provided);
                }
            }
            "replaces" => {
                for relation in split_relations(value) {
                    let replaced = relation_name(&relation);
                    if !replaced.is_empty() {
                        native.aliases.push(replaced);
                    }
                }
            }
            _ => {}
        }
    }

    Ok(native)
}

/// Collect `(lowercase-field, unfolded-value)` pairs of the first paragraph.
fn first_paragraph_fields(text: &str) -> Vec<(String, String)> {
    let mut fields: Vec<(String, String)> = Vec::new();

    for line in text.lines() {
        if line.trim().is_empty() {
            if !fields.is_empty() {
                break; // end of the first stanza
            }
            continue;
        }

        if line.starts_with(' ') || line.starts_with('\t') {
            // Continuation of the previous field value.
            if let Some((_, value)) = fields.last_mut() {
                let continuation = line.trim();
                if !continuation.is_empty() {
                    if !value.is_empty() {
                        value.push(' ');
                    }
                    value.push_str(continuation);
                }
            }
            continue;
        }

        if let Some((key, value)) = line.split_once(':') {
            fields.push((key.trim().to_ascii_lowercase(), value.trim().to_string()));
        }
    }

    fields
}

/// Split a relation field into individual relation strings.
///
/// Commas separate relations; `|` alternatives are resolved to the first
/// alternative; `[...]` architecture qualifiers are removed.
fn split_relations(field: &str) -> Vec<String> {
    field
        .split(',')
        .filter_map(|relation| {
            let first = relation.split('|').next()?.trim();
            let without_arch = match first.find('[') {
                Some(idx) => first[..idx].trim(),
                None => first,
            };
            if without_arch.is_empty() {
                None
            } else {
                Some(without_arch.to_string())
            }
        })
        .collect()
}

/// Parse a relation field into [`NativeDep`] values.
fn parse_relations(field: &str) -> Vec<NativeDep> {
    split_relations(field)
        .into_iter()
        .filter_map(|relation| {
            // `name (>= 1.2)` — the constraint lives inside parentheses.
            if let Some(open) = relation.find('(') {
                let name = strip_multiarch(relation[..open].trim());
                let inside = relation[open + 1..]
                    .split(')')
                    .next()
                    .unwrap_or_default()
                    .trim();
                if name.is_empty() {
                    return None;
                }
                return Some(NativeDep::Package {
                    name,
                    constraint: common::parse_op_version(inside),
                });
            }

            let name = strip_multiarch(&relation);
            if name.is_empty() {
                None
            } else {
                Some(NativeDep::Package {
                    name,
                    constraint: None,
                })
            }
        })
        .collect()
}

/// Reduce a relation to its bare package name.
///
/// Drops a parenthesised version constraint, an inline `>=1.2` style constraint
/// and a multiarch qualifier: `libfoo (= 1:2.39)` → `libfoo`.
fn relation_name(relation: &str) -> String {
    let without_version = match relation.find('(') {
        Some(idx) => &relation[..idx],
        None => relation,
    };
    let (name, _) = common::split_constraint(without_version);
    strip_multiarch(&name)
}

/// Remove a `:any` / `:amd64` multiarch qualifier from a package name.
fn strip_multiarch(name: &str) -> String {
    match name.split_once(':') {
        Some((base, qualifier)) if !qualifier.contains('.') => base.trim().to_string(),
        _ => name.trim().to_string(),
    }
}

// ─── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_control_full() {
        let text = "\
Package: libfoo
Version: 1:2.39-0ubuntu1
Architecture: amd64
Pre-Depends: dpkg (>= 1.19)
Depends: libc6 (>= 2.34), zlib1g, libssl3t64 | libssl3,
 libgcc-s1
Provides: libfoo-alternative (= 1:2.39)
Replaces: libfoo-old
Description: Foo library
 Long description that continues on a second line.
";
        let native = parse_control(text).unwrap();
        assert_eq!(native.name, "libfoo");
        assert_eq!(native.version, "1:2.39-0ubuntu1");
        assert_eq!(
            native.requires[0],
            NativeDep::Package {
                name: "dpkg".into(),
                constraint: Some(">=1.19".into())
            }
        );
        assert!(native.requires.iter().any(|dep| dep
            == &NativeDep::Package {
                name: "libc6".into(),
                constraint: Some(">=2.34".into())
            }));
        // Alternatives collapse to the first branch.
        assert!(native.requires.iter().any(|dep| dep
            == &NativeDep::Package {
                name: "libssl3t64".into(),
                constraint: None
            }));
        // Folded continuation lines are joined.
        assert!(native.requires.iter().any(|dep| dep
            == &NativeDep::Package {
                name: "libgcc-s1".into(),
                constraint: None
            }));
        assert!(native.aliases.contains(&"libfoo-alternative".to_string()));
        assert!(native.aliases.contains(&"libfoo-old".to_string()));
    }

    #[test]
    fn test_parse_control_strips_multiarch() {
        let native = parse_control("Package: foo\nDepends: libc6:any\n").unwrap();
        assert_eq!(
            native.requires[0],
            NativeDep::Package {
                name: "libc6".into(),
                constraint: None
            }
        );
    }

    #[test]
    fn test_parse_control_missing_package() {
        assert!(parse_control("Version: 1.0\n").is_err());
    }
}
