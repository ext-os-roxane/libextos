//! Built-in Rosetta translator for Void Linux packages (XBPS metadata).
//!
//! XBPS stores package metadata as an Apple-style property list
//! (`props.plist`), optionally alongside plain-text XBPS metadata
//! (`<key>: <value>` lines). Both dialects are accepted.
//!
//! ```xml
//! <dict>
//!   <key>pkgname</key><string>htop</string>
//!   <key>pkgver</key><string>3.3.0_1</string>
//!   <key>run_depends</key><array><string>glibc&gt;=2.32_1</string></array>
//! </dict>
//! ```
//!
//! ## Translation rules
//!
//! | plist key        | ExtOS manifest                                  |
//! |------------------|-------------------------------------------------|
//! | `pkgname`        | `identity.name`                                 |
//! | `pkgver`         | `identity.version` (revision `_N` kept)         |
//! | `run_depends`    | `requires[]`                                    |
//! | `shlib-requires` | `requires[]` as `{ provides = "<soname>"; }`    |
//! | `provides`       | `identity.aliases` + `capabilities.virtual`     |
//! | `shlib-provides` | additionally `capabilities.libraries`           |
//! | `replaces`       | `identity.aliases`                              |
//!
//! XBPS spells versions with an underscore revision (`3.3.0_1`) and embeds the
//! revision in `provides` entries (`htop-3.3.0_1`); the revision suffix is
//! stripped from provided names but kept in `identity.version`.

use std::collections::BTreeMap;
use std::path::Path;

use crate::error::ExtosError;
use crate::rosetta::common::{self, NativeDep, NativeManifest, XmlToken};
use crate::rosetta::{PluginCapability, RosettaPlugin};

/// Canonical origin name handled by this plugin.
pub const ORIGIN: &str = "void";

/// Metadata file names probed inside a staging `metadata/` directory.
const METADATA_CANDIDATES: &[&str] = &[
    "props.plist",
    "PROPS",
    "props",
    "xbps.plist",
    "metadata",
];

/// A single property-list value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlistValue {
    /// `<string>...</string>` (or a scalar from the plain-text dialect).
    Scalar(String),
    /// `<array><string>...</string>...</array>`.
    Array(Vec<String>),
}

impl PlistValue {
    /// Borrow the value as a single string (arrays are joined with spaces).
    fn as_scalar(&self) -> String {
        match self {
            PlistValue::Scalar(value) => value.clone(),
            PlistValue::Array(values) => values.join(" "),
        }
    }

    /// Borrow the value as a list of strings.
    fn as_list(&self) -> Vec<String> {
        match self {
            PlistValue::Scalar(value) => value
                .split_whitespace()
                .map(std::string::ToString::to_string)
                .collect(),
            PlistValue::Array(values) => values.clone(),
        }
    }
}

/// Built-in Rosetta plugin for Void Linux packages.
///
/// Implements PARSE and TRANSLATE; fetch/extract/sync/phantom stay with `xbps`
/// and the PhantomDB writers.
pub struct VoidPlugin;

impl VoidPlugin {
    /// Parse XBPS metadata into an origin-agnostic [`NativeManifest`].
    pub fn translate(&self, metadata_path: &Path) -> Result<NativeManifest, ExtosError> {
        let text = common::read_metadata_text(metadata_path, METADATA_CANDIDATES, ORIGIN)?;
        parse_xbps_metadata(&text)
    }
}

impl RosettaPlugin for VoidPlugin {
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
            message: "FETCH is handled by xbps, not the builtin translator".into(),
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
            message: "SYNC is handled by xbps, not the builtin translator".into(),
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

/// Parse either an XBPS property list or plain-text XBPS metadata.
pub fn parse_xbps_metadata(text: &str) -> Result<NativeManifest, ExtosError> {
    let fields = if text.contains("<key>") {
        parse_plist(text)
    } else {
        parse_plain(text)
    };

    let name = fields
        .get("pkgname")
        .map(PlistValue::as_scalar)
        .unwrap_or_default();
    if name.is_empty() {
        return Err(ExtosError::RosettaPlugin {
            plugin: ORIGIN.to_string(),
            message: "missing required 'pkgname' key in XBPS metadata".into(),
        });
    }

    let version = fields
        .get("pkgver")
        .map(PlistValue::as_scalar)
        .unwrap_or_default();

    let mut native = NativeManifest::new(name, version);

    for key in ["run_depends", "shlib_requires"] {
        if let Some(value) = fields.get(key) {
            for token in value.as_list() {
                let token = token.trim();
                if token.is_empty() {
                    continue;
                }
                if token.contains(".so") {
                    native.requires.push(NativeDep::Capability(token.to_string()));
                    continue;
                }
                let (dep_name, constraint) = common::split_constraint(token);
                if !dep_name.is_empty() {
                    native.requires.push(NativeDep::Package {
                        name: dep_name,
                        constraint,
                    });
                }
            }
        }
    }

    if let Some(value) = fields.get("provides") {
        for token in value.as_list() {
            let provided = strip_revision(token.trim());
            native.add_provide(&provided);
        }
    }
    if let Some(value) = fields.get("shlib_provides") {
        for token in value.as_list() {
            let provided = strip_revision(token.trim());
            native.add_provide(&provided);
        }
    }
    if let Some(value) = fields.get("replaces") {
        for token in value.as_list() {
            let replaced = strip_revision(token.trim());
            if !replaced.is_empty() {
                native.aliases.push(replaced);
            }
        }
    }

    Ok(native)
}

/// Strip an XBPS version revision from a provided name (`foo-1.2_1` → `foo`).
fn strip_revision(token: &str) -> String {
    let Some((base, suffix)) = token.rsplit_once('-') else {
        return token.to_string();
    };
    if suffix.starts_with(|c: char| c.is_ascii_digit()) && !base.is_empty() {
        base.to_string()
    } else {
        token.to_string()
    }
}

/// Parse an Apple-style property list into a flat key → value map.
///
/// Nested `<dict>` elements are flattened; only `<key>`/`<string>`/`<array>`
/// are interpreted, which covers every XBPS metadata document in practice.
fn parse_plist(text: &str) -> BTreeMap<String, PlistValue> {
    let tokens = common::xml_tokens(text);
    let mut map = BTreeMap::new();
    let mut index = 0;

    while index < tokens.len() {
        let XmlToken::Open { name, .. } = &tokens[index] else {
            index += 1;
            continue;
        };
        if name != "key" {
            index += 1;
            continue;
        }

        let key = match tokens.get(index + 1) {
            Some(XmlToken::Text(text)) => normalize_key(text),
            _ => {
                index += 1;
                continue;
            }
        };
        index += 2;

        // Skip the `</key>` tag when present.
        if matches!(tokens.get(index), Some(XmlToken::Close(name)) if name == "key") {
            index += 1;
        }

        match tokens.get(index) {
            Some(XmlToken::Open { name, .. }) if name == "string" => {
                index += 1;
                let value = match tokens.get(index) {
                    Some(XmlToken::Text(text)) => common::xml_unescape(text),
                    _ => String::new(),
                };
                map.insert(key, PlistValue::Scalar(value));
                index += 1;
                if matches!(tokens.get(index), Some(XmlToken::Close(name)) if name == "string") {
                    index += 1;
                }
            }
            Some(XmlToken::Open { name, .. }) if name == "array" => {
                index += 1;
                let mut items = Vec::new();
                while let Some(token) = tokens.get(index) {
                    match token {
                        XmlToken::Close(name) if name == "array" => {
                            index += 1;
                            break;
                        }
                        XmlToken::Text(text) => {
                            items.push(common::xml_unescape(text));
                            index += 1;
                        }
                        _ => index += 1,
                    }
                }
                map.insert(key, PlistValue::Array(items));
            }
            _ => {}
        }
    }

    map
}

/// Parse the plain-text XBPS dialect (`key: value` or `key=value` lines).
fn parse_plain(text: &str) -> BTreeMap<String, PlistValue> {
    let mut map = BTreeMap::new();

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let split = line.split_once(':').or_else(|| line.split_once('='));
        let Some((key, value)) = split else { continue };
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        map.insert(normalize_key(key), PlistValue::Scalar(value.to_string()));
    }

    map
}

/// Normalize a metadata key: lowercase, `-` folded to `_`.
fn normalize_key(raw: &str) -> String {
    raw.trim().to_ascii_lowercase().replace('-', "_")
}

// ─── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const PLIST: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
	<key>pkgname</key>
	<string>htop</string>
	<key>pkgver</key>
	<string>3.3.0_1</string>
	<key>run_depends</key>
	<array>
		<string>glibc&gt;=2.32_1</string>
		<string>ncurses</string>
	</array>
	<key>shlib-requires</key>
	<array>
		<string>libc.so.6</string>
	</array>
	<key>provides</key>
	<array>
		<string>htop-3.3.0_1</string>
		<string>system-monitor</string>
	</array>
	<key>shlib-provides</key>
	<array>
		<string>libhtop.so.1</string>
	</array>
	<key>replaces</key>
	<array>
		<string>htop-legacy-2.0_1</string>
	</array>
</dict>
</plist>
"#;

    #[test]
    fn test_parse_plist() {
        let native = parse_xbps_metadata(PLIST).unwrap();
        assert_eq!(native.name, "htop");
        assert_eq!(native.version, "3.3.0_1");
        assert!(native.requires.contains(&NativeDep::Package {
            name: "glibc".into(),
            constraint: Some(">=2.32_1".into())
        }));
        assert!(native.requires.contains(&NativeDep::Package {
            name: "ncurses".into(),
            constraint: None
        }));
        assert!(native
            .requires
            .contains(&NativeDep::Capability("libc.so.6".into())));
        assert!(native.aliases.contains(&"htop".to_string()));
        assert!(native.aliases.contains(&"system-monitor".to_string()));
        assert!(native.aliases.contains(&"htop-legacy".to_string()));
        assert_eq!(native.libraries, vec!["libhtop.so.1"]);
    }

    #[test]
    fn test_parse_plain_dialect() {
        let text = "pkgname=foo\npkgver=1.0_1\nrun_depends=musl libfoo.so.1\n";
        let native = parse_xbps_metadata(text).unwrap();
        assert_eq!(native.name, "foo");
        assert!(native.requires.contains(&NativeDep::Package {
            name: "musl".into(),
            constraint: None
        }));
        assert!(native
            .requires
            .contains(&NativeDep::Capability("libfoo.so.1".into())));
    }

    #[test]
    fn test_parse_missing_pkgname() {
        assert!(parse_xbps_metadata("<dict><key>pkgver</key><string>1</string></dict>").is_err());
    }

    #[test]
    fn test_strip_revision() {
        assert_eq!(strip_revision("htop-3.3.0_1"), "htop");
        assert_eq!(strip_revision("system-monitor"), "system-monitor");
    }
}
