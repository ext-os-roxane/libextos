//! Built-in Rosetta translator for Alpine Linux packages (`APKINDEX` entries).
//!
//! Alpine package databases (`APKINDEX`) are blank-line-separated stanzas of
//! single-letter, colon-delimited fields:
//!
//! ```text
//! C:Q1abc...=
//! P:htop
//! V:3.3.0-r0
//! D:musl so:libc.musl-x86_64.so.1 cmd:sh
//! p:cmd:htop
//! ```
//!
//! ## Translation rules
//!
//! | `APKINDEX` | ExtOS manifest                              |
//! |------------|---------------------------------------------|
//! | `P:`       | `identity.name`                             |
//! | `V:`       | `identity.version`                          |
//! | `D:`       | `requires[]`                                |
//! | `p:`       | `identity.aliases` + capabilities           |
//!
//! ### Dependency tokens
//!
//! * `so:libc.musl-x86_64.so.1` → `{ provides = "libc.musl-x86_64.so.1"; }`
//! * `cmd:sh` → `{ executable = "sh"; }`
//! * `!foo` (conflict marker) → skipped; conflicts are not dependency edges
//! * `foo>=1.2` → Tier-2 edge with a `>=1.2` constraint
//! * bare `libssl.so.3` (shared-library dependency without a `so:` prefix) →
//!   `{ provides = "libssl.so.3"; }`
//!
//! ### Provides tokens
//!
//! `p:` accepts the same `so:`/`cmd:`/`name=version` shapes. `so:` entries also
//! populate `capabilities.libraries`, `cmd:` entries populate
//! `capabilities.binaries`, and plain names populate `capabilities.virtual`.

use std::path::Path;

use crate::error::ExtosError;
use crate::rosetta::common::{self, NativeDep, NativeManifest};
use crate::rosetta::{PluginCapability, RosettaPlugin};

/// Canonical origin name handled by this plugin.
pub const ORIGIN: &str = "alpine";

/// Metadata file names probed inside a staging `metadata/` directory.
///
/// The generic extractor stores an `.apk`'s control file as
/// `metadata/PKGINFO`, while database indexes arrive as `APKINDEX`.
const METADATA_CANDIDATES: &[&str] = &["APKINDEX", "apkindex", "PKGINFO"];

/// Built-in Rosetta plugin for Alpine Linux packages.
///
/// Implements PARSE and TRANSLATE; fetch/extract/sync/phantom stay with `apk`
/// and the PhantomDB writers.
pub struct AlpinePlugin;

impl AlpinePlugin {
    /// Parse an `APKINDEX` document into an origin-agnostic [`NativeManifest`].
    ///
    /// Only the first stanza is used — extraction always yields a single
    /// package's metadata. Use [`parse_apkindex_entries`] to read a whole index.
    pub fn translate(&self, metadata_path: &Path) -> Result<NativeManifest, ExtosError> {
        let text = common::read_metadata_text(metadata_path, METADATA_CANDIDATES, ORIGIN)?;
        parse_apk_metadata(&text)
    }
}

impl RosettaPlugin for AlpinePlugin {
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
            message: "FETCH is handled by apk, not the builtin translator".into(),
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
            message: "SYNC is handled by apk, not the builtin translator".into(),
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

/// Parse every stanza of an `APKINDEX` document.
///
/// Stanzas without a `P:` field are skipped.
pub fn parse_apkindex_entries(text: &str) -> Vec<NativeManifest> {
    split_stanzas(text)
        .into_iter()
        .filter_map(|stanza| parse_stanza(&stanza).ok())
        .collect()
}

/// Parse the first package stanza of an `APKINDEX` document.
pub fn parse_apkindex(text: &str) -> Result<NativeManifest, ExtosError> {
    let stanza = split_stanzas(text)
        .into_iter()
        .next()
        .ok_or_else(|| ExtosError::RosettaPlugin {
            plugin: ORIGIN.to_string(),
            message: "empty APKINDEX document".into(),
        })?;
    parse_stanza(&stanza)
}

/// Translate either an `APKINDEX` entry or an `.apk`'s `key = value` `.PKGINFO`.
///
/// Both dialects describe Alpine packages and both reach this plugin through
/// [`crate::extract`]: index files keep single-letter fields (`P:`, `V:`, `D:`,
/// `p:`), whereas the control file stored in `metadata/PKGINFO` uses
/// `pkgname = ...` lines (the same shape Arch uses, plus `so:`/`cmd:` tokens).
pub fn parse_apk_metadata(text: &str) -> Result<NativeManifest, ExtosError> {
    if looks_like_apkindex(text) {
        parse_apkindex(text)
    } else {
        parse_apk_pkginfo(text)
    }
}

/// Heuristic: `APKINDEX` stanzas use single-letter colon-prefixed fields.
fn looks_like_apkindex(text: &str) -> bool {
    text.lines().any(|line| {
        let line = line.trim_start();
        line.starts_with("P:") || line.starts_with("V:") || line.starts_with("C:")
    })
}

/// Parse an `.apk` `key = value` control file into a [`NativeManifest`].
fn parse_apk_pkginfo(text: &str) -> Result<NativeManifest, ExtosError> {
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
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        match key.trim() {
            "pkgname" => name = value.to_string(),
            "pkgver" => version = value.to_string(),
            "depend" => add_dependency_token(&mut native, value),
            "provides" => add_provide_token(&mut native, value),
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
            message: "missing required 'pkgname' key in APK .PKGINFO".into(),
        });
    }

    native.name = name;
    native.version = version;
    Ok(native)
}

/// Record one Alpine dependency token (`so:`, `cmd:`, `!conflict`, or a name).
fn add_dependency_token(native: &mut NativeManifest, token: &str) {
    let token = token.trim();
    if token.is_empty() || token.starts_with('!') {
        return; // conflict marker, not a dependency edge
    }
    if let Some(soname) = token.strip_prefix("so:") {
        let (soname, _) = common::split_constraint(soname);
        native.requires.push(NativeDep::Capability(soname));
        return;
    }
    if let Some(cmd) = token.strip_prefix("cmd:") {
        let (binary, _) = common::split_constraint(cmd);
        native.requires.push(NativeDep::Executable(binary));
        return;
    }
    let (dep_name, constraint) = common::split_constraint(token);
    if dep_name.is_empty() {
        return;
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

/// Record one Alpine provides token (`so:`, `cmd:` or a virtual name).
fn add_provide_token(native: &mut NativeManifest, token: &str) {
    let token = token.trim();
    if token.is_empty() {
        return;
    }
    if let Some(soname) = token.strip_prefix("so:") {
        let (soname, _) = common::split_constraint(soname);
        native.add_provide(&soname);
        return;
    }
    if let Some(cmd) = token.strip_prefix("cmd:") {
        let (binary, _) = common::split_constraint(cmd);
        native.add_binary(&binary);
        return;
    }
    let (provided, _) = common::split_constraint(token);
    native.add_provide(&provided);
}

/// Split an `APKINDEX` document into stanzas of non-empty lines.
fn split_stanzas(text: &str) -> Vec<Vec<&str>> {
    let mut stanzas = Vec::new();
    let mut current: Vec<&str> = Vec::new();

    for line in text.lines() {
        let line = line.trim_end();
        if line.trim().is_empty() {
            if !current.is_empty() {
                stanzas.push(std::mem::take(&mut current));
            }
            continue;
        }
        current.push(line);
    }
    if !current.is_empty() {
        stanzas.push(current);
    }
    stanzas
}

/// Parse one stanza (a list of `K:value` lines) into a [`NativeManifest`].
fn parse_stanza(lines: &[&str]) -> Result<NativeManifest, ExtosError> {
    let mut name = String::new();
    let mut version = String::new();
    let mut depends = String::new();
    let mut provides = String::new();

    for line in lines {
        let Some((field, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        match field {
            "P" => name = value.to_string(),
            "V" => version = value.to_string(),
            "D" => depends = value.to_string(),
            "p" => provides = value.to_string(),
            _ => {}
        }
    }

    if name.is_empty() {
        return Err(ExtosError::RosettaPlugin {
            plugin: ORIGIN.to_string(),
            message: "APKINDEX stanza missing required 'P:' field".into(),
        });
    }

    let mut native = NativeManifest::new(name, version);

    for token in depends.split_whitespace() {
        add_dependency_token(&mut native, token);
    }

    for token in provides.split_whitespace() {
        add_provide_token(&mut native, token);
    }

    Ok(native)
}

// ─── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
C:Q1abc=
P:htop
V:3.3.0-r0
A:x86_64
D:musl so:libc.musl-x86_64.so.1 cmd:sh !bash
p:cmd:htop so:libhtop.so.1 htop-virtual

C:Q1def=
P:musl
V:1.2.5-r0
D:
";

    #[test]
    fn test_parse_apkindex_first_entry() {
        let native = parse_apkindex(SAMPLE).unwrap();
        assert_eq!(native.name, "htop");
        assert_eq!(native.version, "3.3.0-r0");
        assert!(native.requires.contains(&NativeDep::Package {
            name: "musl".into(),
            constraint: None
        }));
        assert!(native
            .requires
            .contains(&NativeDep::Capability("libc.musl-x86_64.so.1".into())));
        assert!(native.requires.contains(&NativeDep::Executable("sh".into())));
        // Conflicts are skipped entirely.
        assert!(!native
            .requires
            .iter()
            .any(|dep| matches!(dep, NativeDep::Package { name, .. } if name == "bash")));
        assert_eq!(native.binaries, vec!["htop"]);
        assert_eq!(native.libraries, vec!["libhtop.so.1"]);
        assert!(native.virtual_caps.contains(&"htop-virtual".to_string()));
    }

    #[test]
    fn test_parse_apkindex_all_entries() {
        let entries = parse_apkindex_entries(SAMPLE);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1].name, "musl");
        assert!(entries[1].requires.is_empty());
    }

    #[test]
    fn test_parse_apkindex_constraints() {
        let native = parse_apkindex("P:foo\nV:1\nD:musl>=1.2.5-r0\n").unwrap();
        assert_eq!(
            native.requires[0],
            NativeDep::Package {
                name: "musl".into(),
                constraint: Some(">=1.2.5-r0".into())
            }
        );
    }

    #[test]
    fn test_parse_apk_pkginfo_dialect() {
        let text = "\
pkgname = htop
pkgver = 3.3.0-r0
depend = musl
depend = so:libc.musl-x86_64.so.1
provides = cmd:htop=3.3.0-r0
provides = so:libhtop.so.1
replaces = htop-legacy
";
        let native = parse_apk_metadata(text).unwrap();
        assert_eq!(native.name, "htop");
        assert_eq!(native.version, "3.3.0-r0");
        assert!(native.requires.contains(&NativeDep::Package {
            name: "musl".into(),
            constraint: None
        }));
        assert!(native
            .requires
            .contains(&NativeDep::Capability("libc.musl-x86_64.so.1".into())));
        assert_eq!(native.binaries, vec!["htop"]);
        assert_eq!(native.libraries, vec!["libhtop.so.1"]);
        assert!(native.aliases.contains(&"htop-legacy".to_string()));
    }

    #[test]
    fn test_parse_apkindex_missing_name() {
        assert!(parse_apkindex("V:1.0\n").is_err());
        assert!(parse_apkindex("").is_err());
    }
}
