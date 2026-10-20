//! Shared plumbing for the built-in (Tier-0) Rosetta translators.
//!
//! Every built-in translator follows the same two-step shape:
//!
//! 1. **Parse** an upstream metadata document into a [`NativeManifest`] —
//!    an origin-agnostic, structurally comparable description of the package.
//! 2. **Render** that description either as `manifest.nix` text
//!    ([`NativeManifest::to_manifest_nix`]) or as a JSON array of
//!    [`DependencySpec`] values ([`NativeManifest::to_deps_json`]).
//!
//! Keeping the intermediate representation shared means the five per-origin
//! plugins only own their dialect parsers, while manifest emission (quoting,
//! deduplication, dependency rendering) lives in exactly one place.
//!
//! ## Version-constraint demotion
//!
//! [`NativeManifest`] only distinguishes "unconstrained" from a relational
//! constraint (`>=`, `<=`, `>`, `<`). Upstream *exact* pins (`foo=1.2`,
//! `foo (= 1.2)`) carry no representation in the manifest schema
//! ([`crate::manifest::PackageManifest`] has no exact-match constraint form),
//! so they are demoted to unconstrained Tier-2 edges by [`split_constraint`].
//! This is deliberate: an unconstrained edge is always resolvable, whereas a
//! mis-rendered `=1.2` string would be read back as an exact pin to the literal
//! version `"=1.2"`.

use std::fmt::Write as _;
use std::fs;
use std::path::Path;

use crate::dependency::{CapabilityRequest, DependencySpec};
use crate::error::ExtosError;

/// A dependency expressed in the upstream package manager's own vocabulary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativeDep {
    /// A dependency on another package of the same origin.
    ///
    /// `constraint` is a relational constraint such as `">=2.38"`, or `None`
    /// for an unconstrained Tier-2 edge.
    Package {
        /// Upstream package name.
        name: String,
        /// Optional relational version constraint (`>=`, `<=`, `>`, `<`).
        constraint: Option<String>,
    },

    /// A capability dependency (shared-library SONAME, `so:` in Alpine, ...).
    ///
    /// Rendered as `{ provides = "..."; }`, i.e. Tier-3 duck typing.
    Capability(String),

    /// A dependency on an executable being present in `$PATH`.
    ///
    /// Rendered as `{ executable = "..."; }`.
    Executable(String),

    /// A dependency on an absolute filesystem resource.
    ///
    /// Rendered as `{ resource = "..."; }`.
    Resource(String),
}

/// Origin-agnostic translation of one upstream metadata document.
///
/// This is the pivot type between the per-origin parsers
/// ([`crate::rosetta::arch`], [`crate::rosetta::debian`],
/// [`crate::rosetta::alpine`], [`crate::rosetta::void_xbps`],
/// [`crate::rosetta::rpm`]) and the manifest/JSON emitters below.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NativeManifest {
    /// Package name (`pkgname`, `Package:`, `P:`, ...).
    pub name: String,
    /// Package version, kept verbatim as the upstream manager spells it.
    pub version: String,
    /// Names this package replaces or advertises (`identity.aliases`).
    pub aliases: Vec<String>,
    /// Virtual capabilities contributed to `capabilities.virtual`.
    pub virtual_caps: Vec<String>,
    /// Executable names contributed to `capabilities.binaries`.
    pub binaries: Vec<String>,
    /// Shared-library SONAMEs contributed to `capabilities.libraries`.
    pub libraries: Vec<String>,
    /// Runtime requirements, in upstream order.
    pub requires: Vec<NativeDep>,
}

impl NativeManifest {
    /// Create a manifest skeleton for a named version.
    pub fn new(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
            ..Self::default()
        }
    }

    /// Record a provided name, classifying it as a library, an executable or a
    /// virtual capability.
    ///
    /// The name is always added to [`Self::aliases`]; SONAME-looking names
    /// (containing `.so`) additionally become `capabilities.libraries`, while
    /// everything else becomes `capabilities.virtual`.
    pub fn add_provide(&mut self, name: &str) {
        let name = name.trim();
        if name.is_empty() {
            return;
        }
        push_unique(&mut self.aliases, name);
        if name.contains(".so") {
            push_unique(&mut self.libraries, name);
        } else {
            push_unique(&mut self.virtual_caps, name);
        }
    }

    /// Record a provided executable (`cmd:` in Alpine, `binaries` elsewhere).
    pub fn add_binary(&mut self, name: &str) {
        let name = name.trim();
        if !name.is_empty() {
            push_unique(&mut self.binaries, name);
        }
    }

    /// Render the translation as an ExtOS `manifest.nix` document.
    ///
    /// The produced text is accepted by [`crate::config::parse_nix`] followed
    /// by [`crate::manifest::PackageManifest::from_nix`].
    pub fn to_manifest_nix(&self, origin: &str) -> String {
        let mut out = String::with_capacity(512);

        out.push_str("{\n  identity = {\n");
        let _ = writeln!(out, "    origin = {};", nix_quote(origin));
        let _ = writeln!(out, "    name = {};", nix_quote(&self.name));
        let _ = writeln!(out, "    version = {};", nix_quote(&self.version));
        let _ = writeln!(
            out,
            "    aliases = {};",
            nix_list(&dedup_preserving_order(&self.aliases))
        );
        out.push_str("  };\n");

        out.push_str("  format = \"extracted-tree\";\n");

        out.push_str("  requires = [\n");
        for dep in &self.requires {
            // Nix list elements are whitespace separated — no trailing `;`.
            let _ = writeln!(out, "    {}", render_dep(dep, origin));
        }
        out.push_str("  ];\n");

        out.push_str("  capabilities = {\n");
        let _ = writeln!(
            out,
            "    binaries = {};",
            nix_list(&dedup_preserving_order(&self.binaries))
        );
        let _ = writeln!(
            out,
            "    libraries = {};",
            nix_list(&dedup_preserving_order(&self.libraries))
        );
        let _ = writeln!(
            out,
            "    virtual = {};",
            nix_list(&dedup_preserving_order(&self.virtual_caps))
        );
        out.push_str("  };\n");

        out.push_str("}\n");
        out
    }

    /// Convert the translated requirements into `DependencySpec` values.
    ///
    /// `origin` is the origin the package's own dependencies belong to (the
    /// plugin's canonical origin name).
    pub fn to_dependency_specs(&self, origin: &str) -> Vec<DependencySpec> {
        self.requires
            .iter()
            .map(|dep| match dep {
                NativeDep::Package { name, constraint } => {
                    DependencySpec::LooseEcosystem {
                        origin: origin.to_string(),
                        name: name.clone(),
                        version_constraint: constraint.clone(),
                    }
                }
                NativeDep::Capability(cap) => {
                    DependencySpec::Capability(CapabilityRequest::Provides(cap.clone()))
                }
                NativeDep::Executable(name) => {
                    DependencySpec::Capability(CapabilityRequest::Executable {
                        name: name.clone(),
                        version: None,
                    })
                }
                NativeDep::Resource(path) => {
                    DependencySpec::Capability(CapabilityRequest::Resource(path.clone()))
                }
            })
            .collect()
    }

    /// Translate requirements to a JSON array of `DependencySpec` values.
    ///
    /// This is the payload returned by
    /// [`crate::rosetta::RosettaPlugin::translate_deps`].
    pub fn to_deps_json(&self, origin: &str) -> Result<String, ExtosError> {
        serde_json::to_string(&self.to_dependency_specs(origin))
            .map_err(|e| ExtosError::Serialization(e.to_string()))
    }
}

/// Render a single [`NativeDep`] as a `manifest.nix` attribute set (no `;`).
fn render_dep(dep: &NativeDep, origin: &str) -> String {
    match dep {
        NativeDep::Package {
            name,
            constraint: Some(constraint),
        } => format!(
            "{{ name = {}; origin = {}; version = {}; }}",
            nix_quote(name),
            nix_quote(origin),
            nix_quote(constraint)
        ),
        NativeDep::Package {
            name,
            constraint: None,
        } => format!(
            "{{ name = {}; origin = {}; }}",
            nix_quote(name),
            nix_quote(origin)
        ),
        NativeDep::Capability(cap) => format!("{{ provides = {}; }}", nix_quote(cap)),
        NativeDep::Executable(name) => format!("{{ executable = {}; }}", nix_quote(name)),
        NativeDep::Resource(path) => format!("{{ resource = {}; }}", nix_quote(path)),
    }
}

/// Quote a string as a Nix double-quoted literal.
///
/// Escapes backslashes, double quotes, newlines, tabs and `${` (so generated
/// manifests never accidentally interpolate).
fn nix_quote(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    let mut chars = value.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            '$' if chars.peek() == Some(&'{') => out.push_str("\\$"),
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

/// Render a string list as a Nix list literal (`[ "a" "b" ]`).
fn nix_list(items: &[String]) -> String {
    if items.is_empty() {
        return "[]".to_string();
    }
    let mut out = String::from("[ ");
    for item in items {
        out.push_str(&nix_quote(item));
        out.push(' ');
    }
    out.push(']');
    out
}

/// Append `value` unless it is already present (order preserving).
fn push_unique(target: &mut Vec<String>, value: &str) {
    if !target.iter().any(|existing| existing == value) {
        target.push(value.to_string());
    }
}

/// Clone a list with duplicates removed, preserving first-seen order.
///
/// Deduplication mostly happens in [`NativeManifest::add_provide`] and
/// [`push_unique`], but callers may also push into the public fields directly.
fn dedup_preserving_order(items: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(items.len());
    for item in items {
        push_unique(&mut out, item);
    }
    out
}

/// Split an upstream `name<op>version` token into its parts.
///
/// Handles `foo`, `foo>=1.2`, `foo > 1.2`, `foo<=3`, `foo=1` and
/// `libssl.so.3=3.0`. Exact pins (`=`) are demoted to `None` — see the module
/// docs for why.
pub fn split_constraint(raw: &str) -> (String, Option<String>) {
    let raw = raw.trim();
    let op_pos = raw.char_indices().find(|(_, c)| matches!(c, '<' | '>' | '='));

    let Some((idx, _)) = op_pos else {
        return (raw.to_string(), None);
    };

    let name = raw[..idx].trim();
    let rest = &raw[idx..];
    let (op, version) = if let Some(r) = rest.strip_prefix("<=") {
        ("<=", r)
    } else if let Some(r) = rest.strip_prefix(">=") {
        (">=", r)
    } else if let Some(r) = rest.strip_prefix("<<") {
        ("<", r)
    } else if let Some(r) = rest.strip_prefix(">>") {
        (">", r)
    } else if let Some(r) = rest.strip_prefix('<') {
        ("<", r)
    } else if let Some(r) = rest.strip_prefix('>') {
        (">", r)
    } else if let Some(r) = rest.strip_prefix('=') {
        ("=", r)
    } else {
        ("", rest)
    };

    let version = version.trim();
    if version.is_empty() || op == "=" || op.is_empty() {
        return (name.to_string(), None);
    }
    (name.to_string(), Some(format!("{op}{version}")))
}

/// Parse a bare relational constraint such as `>= 2.34` or `<< 1.0`.
///
/// Returns `None` for exact pins (`=`) for the same reason [`split_constraint`]
/// demotes them.
pub fn parse_op_version(raw: &str) -> Option<String> {
    let raw = raw.trim();
    let (op, version) = if let Some(r) = raw.strip_prefix("<=") {
        ("<=", r)
    } else if let Some(r) = raw.strip_prefix(">=") {
        (">=", r)
    } else if let Some(r) = raw.strip_prefix("<<") {
        ("<", r)
    } else if let Some(r) = raw.strip_prefix(">>") {
        (">", r)
    } else if let Some(r) = raw.strip_prefix('<') {
        ("<", r)
    } else if let Some(r) = raw.strip_prefix('>') {
        (">", r)
    } else if raw.starts_with('=') {
        return None;
    } else {
        return None;
    };

    let version = version.trim();
    if version.is_empty() {
        return None;
    }
    Some(format!("{op}{version}"))
}

/// Read an upstream metadata document as UTF-8 text.
///
/// `metadata_path` may either be the control file itself or a staging
/// `metadata/` directory, in which case `candidates` are probed in order. This
/// matters because [`crate::ingest::ingest_package_with_rosetta`] passes the
/// staging metadata *directory* to [`crate::rosetta::RosettaPlugin::parse_metadata`],
/// while tests and callers with an extracted control file pass the file path.
pub fn read_metadata_text(
    metadata_path: &Path,
    candidates: &[&str],
    plugin: &str,
) -> Result<String, ExtosError> {
    let bytes = read_metadata_bytes(metadata_path, candidates, plugin)?;
    String::from_utf8(bytes).map_err(|e| ExtosError::RosettaPlugin {
        plugin: plugin.to_string(),
        message: format!("metadata is not valid UTF-8: {e}"),
    })
}

/// Read an upstream metadata document as raw bytes.
///
/// Same file-or-directory resolution as [`read_metadata_text`], but keeps the
/// bytes intact so binary formats (RPM headers) survive.
pub fn read_metadata_bytes(
    metadata_path: &Path,
    candidates: &[&str],
    plugin: &str,
) -> Result<Vec<u8>, ExtosError> {
    if !metadata_path.is_dir() {
        return Ok(fs::read(metadata_path)?);
    }

    for candidate in candidates {
        let candidate_path = metadata_path.join(candidate);
        if candidate_path.is_file() {
            return Ok(fs::read(candidate_path)?);
        }
    }

    Err(ExtosError::RosettaPlugin {
        plugin: plugin.to_string(),
        message: format!(
            "no metadata file (tried {}) in directory {}",
            candidates.join(", "),
            metadata_path.display()
        ),
    })
}

// ─── Minimal XML tokeniser ──────────────────────────────────────
//
// Both the XBPS props.plist (`<key>`/`<string>`/`<array>`) and the RPM
// `primary.xml` (repomd) dialects are XML-shaped. A full XML parser is out of
// scope — we only need element names, attributes and text nodes, and this
// scanner never fails (malformed input simply yields fewer tokens).

/// One token produced by [`xml_tokens`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum XmlToken {
    /// An opening (or self-closing) element with its attributes.
    Open {
        /// Element name, including any namespace prefix (`rpm:entry`).
        name: String,
        /// Attribute key/value pairs in document order.
        attrs: Vec<(String, String)>,
    },
    /// A closing element name.
    Close(String),
    /// A text node with surrounding whitespace trimmed (never empty).
    Text(String),
}

/// Tokenise a fragment of XML into [`XmlToken`]s.
pub(crate) fn xml_tokens(input: &str) -> Vec<XmlToken> {
    let mut tokens = Vec::new();
    let mut rest = input;

    while let Some(lt) = rest.find('<') {
        push_text(&mut tokens, &rest[..lt]);

        let Some(gt_rel) = rest[lt..].find('>') else {
            // Unterminated tag: treat the remainder as text.
            push_text(&mut tokens, &rest[lt..]);
            rest = "";
            break;
        };

        let end = lt + gt_rel;
        let inner = rest[lt + 1..end].trim();
        rest = &rest[end + 1..];

        if inner.starts_with('?') || inner.starts_with('!') || inner.is_empty() {
            continue; // declaration, comment, doctype, or `<>`
        }

        if let Some(name) = inner.strip_prefix('/') {
            tokens.push(XmlToken::Close(name.trim().to_string()));
            continue;
        }

        let self_closing = inner.ends_with('/');
        let body = if self_closing {
            inner[..inner.len() - 1].trim_end()
        } else {
            inner
        };
        let (name, attrs) = split_tag(body);
        tokens.push(XmlToken::Open {
            name: name.clone(),
            attrs,
        });
        if self_closing {
            tokens.push(XmlToken::Close(name));
        }
    }

    push_text(&mut tokens, rest);
    tokens
}

fn push_text(tokens: &mut Vec<XmlToken>, raw: &str) {
    let text = raw.trim();
    if !text.is_empty() {
        tokens.push(XmlToken::Text(text.to_string()));
    }
}

/// Split a tag body into its name and attribute list.
fn split_tag(body: &str) -> (String, Vec<(String, String)>) {
    let mut parts = body.splitn(2, char::is_whitespace);
    let name = parts.next().unwrap_or("").to_string();
    let attrs = split_attrs(parts.next().unwrap_or(""));
    (name, attrs)
}

/// Parse `key="value"` attribute pairs.
fn split_attrs(mut rest: &str) -> Vec<(String, String)> {
    let mut attrs = Vec::new();
    loop {
        rest = rest.trim_start();
        if rest.is_empty() {
            break;
        }
        let Some(eq) = rest.find('=') else { break };
        let key = rest[..eq].trim().to_string();
        let after = rest[eq + 1..].trim_start();
        match after.chars().next() {
            Some(quote @ ('"' | '\'')) => {
                let Some(close) = after[1..].find(quote) else {
                    break;
                };
                attrs.push((key, after[1..1 + close].to_string()));
                rest = &after[1 + close + 1..];
            }
            _ => {
                let end = after.find(char::is_whitespace).unwrap_or(after.len());
                attrs.push((key, after[..end].to_string()));
                rest = &after[end..];
            }
        }
    }
    attrs
}

/// Look up an attribute by key in an [`XmlToken::Open`] attribute list.
pub(crate) fn attr<'a>(attrs: &'a [(String, String)], key: &str) -> Option<&'a str> {
    attrs
        .iter()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value.as_str())
}

/// Decode the five predefined XML entities plus numeric character references.
///
/// Property lists and repomd metadata both escape relation operators
/// (`glibc&gt;=2.32`), so text nodes must be decoded before parsing.
pub(crate) fn xml_unescape(input: &str) -> String {
    if !input.contains('&') {
        return input.to_string();
    }

    let mut out = String::with_capacity(input.len());
    let mut rest = input;

    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        let after = &rest[amp..];
        let Some(semi) = after.find(';') else {
            out.push_str(after);
            return out;
        };
        let entity = &after[1..semi];
        let decoded = match entity {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            _ => entity
                .strip_prefix("#x")
                .or_else(|| entity.strip_prefix("#X"))
                .and_then(|hex| u32::from_str_radix(hex, 16).ok())
                .or_else(|| {
                    entity
                        .strip_prefix('#')
                        .and_then(|dec| dec.parse::<u32>().ok())
                })
                .and_then(char::from_u32),
        };
        match decoded {
            Some(c) => out.push(c),
            None => out.push_str(&after[..=semi]),
        }
        rest = &after[semi + 1..];
    }

    out.push_str(rest);
    out
}

// ─── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_constraint_forms() {
        assert_eq!(split_constraint("glibc"), ("glibc".to_string(), None));
        assert_eq!(
            split_constraint("glibc>=2.38"),
            ("glibc".to_string(), Some(">=2.38".to_string()))
        );
        assert_eq!(
            split_constraint("glibc >= 2.38"),
            ("glibc".to_string(), Some(">=2.38".to_string()))
        );
        assert_eq!(
            split_constraint("foo<1.2"),
            ("foo".to_string(), Some("<1.2".to_string()))
        );
        // Exact pins are demoted to unconstrained edges.
        assert_eq!(split_constraint("foo=1.2"), ("foo".to_string(), None));
        assert_eq!(
            split_constraint("libfoo.so=1-64"),
            ("libfoo.so".to_string(), None)
        );
    }

    #[test]
    fn test_parse_op_version() {
        assert_eq!(parse_op_version(">= 2.34"), Some(">=2.34".to_string()));
        assert_eq!(parse_op_version("<< 1.0"), Some("<1.0".to_string()));
        assert_eq!(parse_op_version("= 1.0"), None);
    }

    #[test]
    fn test_to_manifest_nix_roundtrips() {
        let mut native = NativeManifest::new("htop", "3.3.0-1");
        native.add_provide("libhtop.so");
        native.add_provide("system-monitor");
        native.add_binary("htop");
        native.requires.push(NativeDep::Package {
            name: "glibc".into(),
            constraint: Some(">=2.38".into()),
        });
        native.requires.push(NativeDep::Capability("libc.so.6".into()));
        native.requires.push(NativeDep::Executable("sh".into()));

        let nix = native.to_manifest_nix("archlinux");
        let value = crate::config::parse_nix(&nix).unwrap();
        let manifest = crate::manifest::PackageManifest::from_nix(&value).unwrap();

        assert_eq!(manifest.identity.name, "htop");
        assert_eq!(manifest.identity.version, "3.3.0-1");
        assert_eq!(manifest.identity.origin, "archlinux");
        assert_eq!(manifest.identity.aliases, vec!["libhtop.so", "system-monitor"]);
        assert_eq!(manifest.capabilities.libraries, vec!["libhtop.so"]);
        assert_eq!(manifest.capabilities.binaries, vec!["htop"]);
        assert_eq!(manifest.requires.len(), 3);
    }

    #[test]
    fn test_deps_json() {
        let mut native = NativeManifest::new("x", "1");
        native.requires.push(NativeDep::Package {
            name: "glibc".into(),
            constraint: Some(">=2.38".into()),
        });
        let json = native.to_deps_json("debian").unwrap();
        assert!(json.contains("\"LooseEcosystem\""));
        assert!(json.contains("glibc"));
    }

    #[test]
    fn test_xml_tokens_self_closing_and_attrs() {
        let tokens = xml_tokens(r#"<a x="1"><b/><c y='2'>t</c></a>"#);
        assert_eq!(
            tokens,
            vec![
                XmlToken::Open {
                    name: "a".into(),
                    attrs: vec![("x".into(), "1".into())]
                },
                XmlToken::Open {
                    name: "b".into(),
                    attrs: vec![]
                },
                XmlToken::Close("b".into()),
                XmlToken::Open {
                    name: "c".into(),
                    attrs: vec![("y".into(), "2".into())]
                },
                XmlToken::Text("t".into()),
                XmlToken::Close("c".into()),
                XmlToken::Close("a".into()),
            ]
        );
    }

    #[test]
    fn test_read_metadata_directory_candidates() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("PKGINFO"), "pkgname = x\n").unwrap();
        let text = read_metadata_text(dir.path(), &[".PKGINFO", "PKGINFO"], "archlinux").unwrap();
        assert!(text.contains("pkgname"));

        let missing = read_metadata_text(dir.path(), &["nope"], "archlinux");
        assert!(missing.is_err());
    }
}
