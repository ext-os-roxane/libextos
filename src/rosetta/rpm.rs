//! Built-in Rosetta translator for RPM packages.
//!
//! # Two input dialects
//!
//! RPM metadata reaches ExtOS in one of two shapes, and both are accepted:
//!
//! 1. **Binary RPM header** — a `.rpm` file, or a header blob extracted from one.
//!    This module hand-rolls the on-disk format (lead + signature header + main
//!    header) instead of linking `librpm`, so no new native dependency is
//!    introduced. Only the tags needed for translation are decoded:
//!    `NAME`, `VERSION`, `RELEASE`, `EPOCH`, `PROVIDENAME`, `REQUIRENAME`,
//!    `REQUIREFLAGS`, `REQUIREVERSION`.
//! 2. **`primary.xml` (repomd)** — the text index shipped inside
//!    `repodata/`. Used as the graceful fallback whenever the input does not
//!    start with an RPM lead, and it is the recommended input for testing
//!    because it is plain text.
//!
//! ## Constraint: no full `librpm` semantics
//!
//! This translator is *metadata-level* by design:
//!
//! * rich/boolean dependencies (`(foo if bar)`) and `rpmlib(...)` requirements
//!   are skipped — [`crate::dependency::DependencySpec`] cannot express them;
//! * scriptlets, triggers, file lists and signature verification are not read;
//! * exact pins (`RPMSENSE_EQUAL`) are demoted to unconstrained edges, matching
//!   the rest of the translator family (see [`crate::rosetta::common`]);
//! * the header is parsed big-endian, unaligned, and assembled in memory: a
//!   malformed or truncated header yields [`ExtosError::RosettaPlugin`] rather
//!   than a panic.
//!
//! The `librpm-extos` fork (Phase 3) is expected to take over signature
//! verification and full header semantics; this module stays as the
//! dependency-free fallback for index-driven ingestion.

use std::path::Path;

use crate::error::ExtosError;
use crate::rosetta::common::{self, NativeDep, NativeManifest, XmlToken};
use crate::rosetta::{PluginCapability, RosettaPlugin};

/// Canonical origin name handled by this plugin.
///
/// RPM-based distributions are modelled as one ExtOS origin (`rpm`); the
/// registry also answers to `suse`, `fedora`, `centos` and `rhel`.
pub const ORIGIN: &str = "rpm";

/// Metadata file names probed inside a staging `metadata/` directory.
const METADATA_CANDIDATES: &[&str] = &["primary.xml", "primary", "metadata.xml", "header"];

/// RPM lead magic (`ED AB EE DB`).
const LEAD_MAGIC: [u8; 4] = [0xED, 0xAB, 0xEE, 0xDB];
/// RPM header magic (`8E AD E8 01`) used by both signature and main headers.
const HEADER_MAGIC: [u8; 4] = [0x8E, 0xAD, 0xE8, 0x01];
/// Size of the legacy RPM lead (always 96 bytes).
const LEAD_SIZE: usize = 96;

const RPMTAG_NAME: u32 = 1000;
const RPMTAG_VERSION: u32 = 1001;
const RPMTAG_RELEASE: u32 = 1002;
const RPMTAG_EPOCH: u32 = 1003;
const RPMTAG_PROVIDENAME: u32 = 1047;
const RPMTAG_REQUIREFLAGS: u32 = 1048;
const RPMTAG_REQUIRENAME: u32 = 1049;
const RPMTAG_REQUIREVERSION: u32 = 1050;

const RPMSENSE_LESS: u32 = 0x02;
const RPMSENSE_GREATER: u32 = 0x04;
const RPMSENSE_EQUAL: u32 = 0x08;

/// Header data types we understand.
const TYPE_INT32: u32 = 4;
const TYPE_STRING: u32 = 6;
const TYPE_STRING_ARRAY: u32 = 8;
const TYPE_I18NSTRING: u32 = 9;

/// Upper bound on header index entries, to reject corrupt counts.
const MAX_ENTRIES: u32 = 1_000_000;

/// Built-in Rosetta plugin for RPM-based origins.
///
/// Implements PARSE and TRANSLATE; fetch/extract/sync/phantom stay with `dnf`,
/// `zypper` and the PhantomDB writers.
pub struct RpmPlugin;

impl RpmPlugin {
    /// Translate an RPM header or `primary.xml` document.
    pub fn translate(&self, metadata_path: &Path) -> Result<NativeManifest, ExtosError> {
        let bytes = common::read_metadata_bytes(metadata_path, METADATA_CANDIDATES, ORIGIN)?;
        Self::translate_bytes(&bytes)
    }

    /// Translate an in-memory RPM payload.
    ///
    /// Dispatches on the lead magic: binary headers go to
    /// [`parse_binary_rpm`], everything else is decoded as UTF-8 text and
    /// handed to [`parse_primary_xml`].
    pub fn translate_bytes(bytes: &[u8]) -> Result<NativeManifest, ExtosError> {
        if bytes.starts_with(&LEAD_MAGIC) {
            parse_binary_rpm(bytes)
        } else {
            let text = std::str::from_utf8(bytes).map_err(|e| ExtosError::RosettaPlugin {
                plugin: ORIGIN.to_string(),
                message: format!(
                    "metadata is neither an RPM header nor UTF-8 primary.xml: {e}"
                ),
            })?;
            parse_primary_xml(text)
        }
    }
}

impl RosettaPlugin for RpmPlugin {
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
            message: "FETCH is handled by dnf/zypper, not the builtin translator".into(),
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
            message: "SYNC is handled by dnf/zypper, not the builtin translator".into(),
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

// ─── Binary header parsing ──────────────────────────────────────

/// One `(tag, type, offset, count)` entry of an RPM header index.
#[derive(Debug, Clone, Copy)]
struct HeaderEntry {
    tag: u32,
    data_type: u32,
    offset: u32,
    count: u32,
}

/// A parsed RPM header: its index plus the raw data store.
struct Header<'a> {
    entries: Vec<HeaderEntry>,
    data: &'a [u8],
    data_size: u32,
}

impl<'a> Header<'a> {
    /// Parse a header (magic, index count, data size, index, data) at the start
    /// of `slice`. Trailing bytes are ignored, so this works both for the
    /// signature header and for the main header.
    fn parse(slice: &'a [u8]) -> Result<Self, ExtosError> {
        if slice.len() < 16 {
            return Err(rpm_error("truncated RPM header (need at least 16 bytes)"));
        }
        if slice[0..4] != HEADER_MAGIC {
            return Err(rpm_error("missing RPM header magic 8E AD E8 01"));
        }

        let index_count = u32_at(slice, 8).ok_or_else(|| rpm_error("truncated header index count"))?;
        let data_size = u32_at(slice, 12).ok_or_else(|| rpm_error("truncated header data size"))?;

        if index_count > MAX_ENTRIES {
            return Err(rpm_error("RPM header index count is implausibly large"));
        }

        let index_count_usize = index_count as usize;
        let data_size_usize = data_size as usize;
        let data_start = 16usize
            .checked_add(index_count_usize * 16)
            .ok_or_else(|| rpm_error("RPM header index size overflow"))?;
        let data_end = data_start
            .checked_add(data_size_usize)
            .ok_or_else(|| rpm_error("RPM header data size overflow"))?;

        if slice.len() < data_end {
            return Err(rpm_error("truncated RPM header: declared data exceeds input"));
        }

        let mut entries = Vec::with_capacity(index_count_usize);
        for i in 0..index_count_usize {
            let base = 16 + i * 16;
            let tag = u32_at(slice, base).ok_or_else(|| rpm_error("truncated header entry"))?;
            let data_type =
                u32_at(slice, base + 4).ok_or_else(|| rpm_error("truncated header entry"))?;
            let offset =
                u32_at(slice, base + 8).ok_or_else(|| rpm_error("truncated header entry"))?;
            let count =
                u32_at(slice, base + 12).ok_or_else(|| rpm_error("truncated header entry"))?;
            entries.push(HeaderEntry {
                tag,
                data_type,
                offset,
                count,
            });
        }

        Ok(Self {
            entries,
            data: &slice[data_start..data_end],
            data_size,
        })
    }

    fn entry(&self, tag: u32) -> Option<&HeaderEntry> {
        self.entries.iter().find(|entry| entry.tag == tag)
    }

    /// Read a single string tag (STRING or I18NSTRING).
    fn string(&self, tag: u32) -> Option<String> {
        let entry = self.entry(tag)?;
        if entry.data_type != TYPE_STRING && entry.data_type != TYPE_I18NSTRING {
            return None;
        }
        cstr_at(self.data, entry.offset as usize)
    }

    /// Read a string-array tag, or a single string as a one-element array.
    fn string_array(&self, tag: u32) -> Vec<String> {
        let Some(entry) = self.entry(tag) else {
            return Vec::new();
        };
        match entry.data_type {
            TYPE_STRING_ARRAY | TYPE_I18NSTRING => {
                let mut values = Vec::new();
                let mut offset = entry.offset as usize;
                for _ in 0..entry.count {
                    let Some((value, next)) = cstr_at_with_next(self.data, offset) else {
                        break;
                    };
                    values.push(value);
                    offset = next;
                }
                values
            }
            TYPE_STRING => self.string(tag).into_iter().collect(),
            _ => Vec::new(),
        }
    }

    /// Read an INT32 array tag.
    fn int32_array(&self, tag: u32) -> Vec<u32> {
        let Some(entry) = self.entry(tag) else {
            return Vec::new();
        };
        if entry.data_type != TYPE_INT32 || entry.count > MAX_ENTRIES {
            return Vec::new();
        }
        (0..entry.count as usize)
            .filter_map(|i| {
                let base = entry.offset as usize + i * 4;
                u32_at(self.data, base)
            })
            .collect()
    }

    /// Byte length of the data store (used for diagnostics only).
    #[allow(dead_code)]
    fn data_size(&self) -> u32 {
        self.data_size
    }
}

/// Read a big-endian `u32` at `offset`.
fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    let slice = bytes.get(offset..offset + 4)?;
    Some(u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

/// Read a NUL-terminated UTF-8 string at `offset`.
fn cstr_at(data: &[u8], offset: usize) -> Option<String> {
    cstr_at_with_next(data, offset).map(|(value, _)| value)
}

/// Read a NUL-terminated UTF-8 string and report the offset just past it.
fn cstr_at_with_next(data: &[u8], offset: usize) -> Option<(String, usize)> {
    let rest = data.get(offset..)?;
    let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
    let value = std::str::from_utf8(&rest[..end]).ok()?.to_string();
    Some((value, offset + end + 1))
}

/// Parse a binary RPM and translate its main header.
pub fn parse_binary_rpm(bytes: &[u8]) -> Result<NativeManifest, ExtosError> {
    if bytes.len() < LEAD_SIZE + 16 {
        return Err(rpm_error("truncated RPM: lead or signature header missing"));
    }

    // The signature header is skipped: we do not verify digests here.
    let signature = Header::parse(&bytes[LEAD_SIZE..])?;
    let signature_size = 16usize
        .checked_add(signature.entries.len() * 16)
        .and_then(|n| n.checked_add(signature.data_size as usize))
        .ok_or_else(|| rpm_error("signature header size overflow"))?;
    let padding = (8 - (signature_size % 8)) % 8;
    let main_offset = LEAD_SIZE + signature_size + padding;

    if bytes.len() <= main_offset {
        return Err(rpm_error("truncated RPM: main header missing"));
    }

    let header = Header::parse(&bytes[main_offset..])?;

    let name = header
        .string(RPMTAG_NAME)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| rpm_error("RPM header missing NAME tag"))?;
    let version = header.string(RPMTAG_VERSION).unwrap_or_default();
    let release = header.string(RPMTAG_RELEASE).unwrap_or_default();
    let epoch = header
        .int32_array(RPMTAG_EPOCH)
        .first()
        .copied()
        .unwrap_or(0);

    let mut native = NativeManifest::new(name, compose_version(epoch, &version, &release));

    // Provides.
    for provided in header.string_array(RPMTAG_PROVIDENAME) {
        let provided = provided.trim();
        if provided.is_empty()
            || provided.starts_with('/')
            || provided.starts_with("rpmlib(")
            || provided.starts_with("config(")
        {
            continue;
        }
        native.add_provide(strip_capability(provided));
    }

    // Requires, aligned index-by-index with their flags and versions.
    let require_names = header.string_array(RPMTAG_REQUIRENAME);
    let require_flags = header.int32_array(RPMTAG_REQUIREFLAGS);
    let require_versions = header.string_array(RPMTAG_REQUIREVERSION);

    for (index, name) in require_names.iter().enumerate() {
        let flags = require_flags.get(index).copied().unwrap_or(0);
        let constraint = rpm_flags_constraint(flags, require_versions.get(index));
        push_require(&mut native, name, constraint);
    }

    Ok(native)
}

/// Classify and record one RPM requirement.
fn push_require(native: &mut NativeManifest, raw_name: &str, constraint: Option<String>) {
    let name = raw_name.trim();
    if name.is_empty()
        || name.starts_with("rpmlib(")
        || name.starts_with('(')
        || name.starts_with("config(")
    {
        return;
    }

    // RPM encodes capability suffixes inline: `libc.so.6(GLIBC_2.38)(64bit)`.
    let base = strip_capability(name);

    if base.starts_with('/') {
        native.requires.push(NativeDep::Resource(base.to_string()));
        return;
    }

    if base.contains(".so") {
        native.requires.push(NativeDep::Capability(base.to_string()));
        return;
    }

    native.requires.push(NativeDep::Package {
        name: base.to_string(),
        constraint,
    });
}

/// Strip an inline RPM capability suffix: `libc.so.6(GLIBC_2.38)` → `libc.so.6`.
fn strip_capability(name: &str) -> &str {
    name.split('(').next().unwrap_or(name).trim()
}

/// Translate RPM sense flags + version into an ExtOS relational constraint.
fn rpm_flags_constraint(flags: u32, version: Option<&String>) -> Option<String> {
    let version = version.map(|value| value.trim()).unwrap_or_default();
    if version.is_empty() {
        return None;
    }
    let less = flags & RPMSENSE_LESS != 0;
    let greater = flags & RPMSENSE_GREATER != 0;
    let equal = flags & RPMSENSE_EQUAL != 0;

    match (less, greater, equal) {
        (true, false, true) => Some(format!("<={version}")),
        (false, true, true) => Some(format!(">={version}")),
        (true, false, false) => Some(format!("<{version}")),
        (false, true, false) => Some(format!(">{version}")),
        // Exact pins and contradictory flag sets are demoted (see module docs).
        _ => None,
    }
}

/// Compose `epoch:version-release` the way RPM displays it.
fn compose_version(epoch: u32, version: &str, release: &str) -> String {
    let mut out = String::new();
    if epoch != 0 {
        out.push_str(&epoch.to_string());
        out.push(':');
    }
    out.push_str(version);
    if !release.is_empty() {
        out.push('-');
        out.push_str(release);
    }
    out
}

// ─── primary.xml parsing ───────────────────────────────────────

/// Parse a `primary.xml` (repomd) document and translate its first package.
///
/// Only well-known elements are read: `<name>`, `<version epoch= ver= rel=>`,
/// `<rpm:provides>` and `<rpm:requires>` entries (`<rpm:entry name= ver= flags=>`).
/// Anything else — file lists, changelogs, checksums — is ignored.
pub fn parse_primary_xml(text: &str) -> Result<NativeManifest, ExtosError> {
    let tokens = common::xml_tokens(text);
    let mut name = String::new();
    let mut version = String::new();
    let mut section = String::new();
    let mut native = NativeManifest::default();
    let mut seen_package = false;
    let mut index = 0;

    while index < tokens.len() {
        match &tokens[index] {
            XmlToken::Open { name: tag, attrs } => match tag.as_str() {
                "package" => {
                    if seen_package {
                        break; // only the first package is translated
                    }
                    seen_package = true;
                }
                "name" => {
                    if name.is_empty() {
                        if let Some(XmlToken::Text(text)) = tokens.get(index + 1) {
                            name = common::xml_unescape(text);
                        }
                    }
                }
                "version" => {
                    if version.is_empty() && common::attr(attrs, "ver").is_some() {
                        version = primary_version(attrs);
                    }
                }
                "rpm:provides" | "provides" => section = "provides".to_string(),
                "rpm:requires" | "requires" => section = "requires".to_string(),
                "rpm:entry" | "entry" => {
                    let entry_name = common::attr(attrs, "name").unwrap_or_default();
                    match section.as_str() {
                        "provides" => {
                            if !entry_name.is_empty()
                                && !entry_name.starts_with('/')
                                && !entry_name.starts_with("rpmlib(")
                                && !entry_name.starts_with("config(")
                            {
                                native.add_provide(strip_capability(entry_name));
                            }
                        }
                        "requires" => {
                            let constraint = primary_constraint(
                                common::attr(attrs, "flags").unwrap_or_default(),
                                common::attr(attrs, "ver"),
                            );
                            push_require(&mut native, entry_name, constraint);
                        }
                        _ => {}
                    }
                }
                _ => {}
            },
            XmlToken::Close(tag)
                if matches!(
                    tag.as_str(),
                    "rpm:provides" | "rpm:requires" | "provides" | "requires"
                ) =>
            {
                section.clear();
            }
            _ => {}
        }
        index += 1;
    }

    if name.is_empty() {
        return Err(ExtosError::RosettaPlugin {
            plugin: ORIGIN.to_string(),
            message: "primary.xml contains no <package><name> element".into(),
        });
    }

    native.name = name;
    native.version = version;
    Ok(native)
}

/// Compose the version of a `primary.xml` `<version>` element.
fn primary_version(attrs: &[(String, String)]) -> String {
    let epoch = common::attr(attrs, "epoch").unwrap_or("0");
    let epoch = epoch.parse::<u32>().unwrap_or(0);
    let ver = common::attr(attrs, "ver").unwrap_or_default();
    let rel = common::attr(attrs, "rel").unwrap_or_default();
    compose_version(epoch, ver, rel)
}

/// Map a `primary.xml` `flags` attribute to an ExtOS relational constraint.
fn primary_constraint(flags: &str, version: Option<&str>) -> Option<String> {
    let version = version.unwrap_or_default().trim();
    if version.is_empty() {
        return None;
    }
    match flags {
        "GE" => Some(format!(">={version}")),
        "LE" => Some(format!("<={version}")),
        "GT" => Some(format!(">{version}")),
        "LT" => Some(format!("<{version}")),
        // EQ and anything else: demoted to an unconstrained edge.
        _ => None,
    }
}

/// Build a Rosetta plugin error for the RPM origin.
fn rpm_error(message: &str) -> ExtosError {
    ExtosError::RosettaPlugin {
        plugin: ORIGIN.to_string(),
        message: message.to_string(),
    }
}

// ─── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const PRIMARY: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<metadata xmlns="http://linux.duke.edu/metadata/common"
          xmlns:rpm="http://linux.duke.edu/metadata/rpm" packages="1">
  <package type="rpm">
    <name>htop</name>
    <arch>x86_64</arch>
    <version epoch="0" ver="3.3.0" rel="1.fc40"/>
    <format>
      <rpm:provides>
        <rpm:entry name="htop" flags="EQ" epoch="0" ver="3.3.0" rel="1.fc40"/>
        <rpm:entry name="libhtop.so.1()(64bit)"/>
        <rpm:entry name="system-monitor"/>
      </rpm:provides>
      <rpm:requires>
        <rpm:entry name="glibc" flags="GE" epoch="0" ver="2.38"/>
        <rpm:entry name="libc.so.6(GLIBC_2.38)(64bit)"/>
        <rpm:entry name="rpmlib(CompressedFileNames)" flags="LE" epoch="0" ver="3.0.4-1"/>
        <rpm:entry name="/bin/sh"/>
      </rpm:requires>
    </format>
  </package>
</metadata>
"#;

    /// Build one RPM header (index + data store) from `(tag, type, count, payload)`.
    fn build_header(entries: &[(u32, u32, u32, Vec<u8>)]) -> Vec<u8> {
        let mut index = Vec::new();
        let mut data = Vec::new();
        for (tag, data_type, count, payload) in entries {
            index.extend_from_slice(&tag.to_be_bytes());
            index.extend_from_slice(&data_type.to_be_bytes());
            index.extend_from_slice(&(data.len() as u32).to_be_bytes());
            index.extend_from_slice(&count.to_be_bytes());
            data.extend_from_slice(payload);
        }
        let mut out = Vec::new();
        out.extend_from_slice(&HEADER_MAGIC);
        out.extend_from_slice(&0u32.to_be_bytes()); // reserved
        out.extend_from_slice(&(entries.len() as u32).to_be_bytes());
        out.extend_from_slice(&(data.len() as u32).to_be_bytes());
        out.extend_from_slice(&index);
        out.extend_from_slice(&data);
        out
    }

    /// Encode a string tag payload.
    fn str_payload(value: &str) -> Vec<u8> {
        let mut out = value.as_bytes().to_vec();
        out.push(0);
        out
    }

    /// Encode a string-array tag payload.
    fn arr_payload(values: &[&str]) -> Vec<u8> {
        let mut out = Vec::new();
        for value in values {
            out.extend_from_slice(&str_payload(value));
        }
        out
    }

    /// Synthesize a minimal `.rpm` byte image.
    fn build_test_rpm() -> Vec<u8> {
        let mut rpm = Vec::new();
        // Lead: magic + 92 zero bytes.
        rpm.extend_from_slice(&LEAD_MAGIC);
        rpm.extend_from_slice(&[0u8; LEAD_SIZE - 4]);
        // Signature header: empty index, empty data store.
        rpm.extend_from_slice(&build_header(&[]));
        // Main header.
        let requires = arr_payload(&["glibc", "libc.so.6(GLIBC_2.38)(64bit)", "rpmlib(X)", "/bin/sh"]);
        let require_flags: Vec<u8> = [0x0Cu32, 0, 0, 0]
            .iter()
            .flat_map(|flag| flag.to_be_bytes())
            .collect();
        let require_versions = arr_payload(&["2.38", "", "", ""]);
        rpm.extend_from_slice(&build_header(&[
            (RPMTAG_NAME, TYPE_STRING, 1, str_payload("htop")),
            (RPMTAG_VERSION, TYPE_STRING, 1, str_payload("3.3.0")),
            (RPMTAG_RELEASE, TYPE_STRING, 1, str_payload("1.fc40")),
            (RPMTAG_PROVIDENAME, TYPE_STRING_ARRAY, 2, arr_payload(&["htop", "system-monitor"])),
            (RPMTAG_REQUIRENAME, TYPE_STRING_ARRAY, 4, requires),
            (RPMTAG_REQUIREFLAGS, TYPE_INT32, 4, require_flags),
            (RPMTAG_REQUIREVERSION, TYPE_STRING_ARRAY, 4, require_versions),
        ]));
        rpm
    }

    #[test]
    fn test_parse_primary_xml() {
        let native = parse_primary_xml(PRIMARY).unwrap();
        assert_eq!(native.name, "htop");
        assert_eq!(native.version, "3.3.0-1.fc40");
        assert!(native.aliases.contains(&"system-monitor".to_string()));
        assert!(native.libraries.iter().any(|lib| lib.starts_with("libhtop.so.1")));
        assert!(native.requires.contains(&NativeDep::Package {
            name: "glibc".into(),
            constraint: Some(">=2.38".into())
        }));
        assert!(native
            .requires
            .iter()
            .any(|dep| matches!(dep, NativeDep::Capability(cap) if cap.starts_with("libc.so.6"))));
        assert!(native
            .requires
            .iter()
            .any(|dep| dep == &NativeDep::Resource("/bin/sh".into())));
        // rpmlib() pseudo-requirements are dropped.
        assert!(!native
            .requires
            .iter()
            .any(|dep| matches!(dep, NativeDep::Package { name, .. } if name.starts_with("rpmlib"))));
    }

    #[test]
    fn test_parse_binary_rpm() {
        let bytes = build_test_rpm();
        let native = parse_binary_rpm(&bytes).unwrap();
        assert_eq!(native.name, "htop");
        assert_eq!(native.version, "3.3.0-1.fc40");
        assert!(native.aliases.contains(&"system-monitor".to_string()));
        assert!(native.requires.contains(&NativeDep::Package {
            name: "glibc".into(),
            constraint: Some(">=2.38".into())
        }));
        assert!(native
            .requires
            .iter()
            .any(|dep| dep == &NativeDep::Resource("/bin/sh".into())));
    }

    #[test]
    fn test_translate_bytes_dispatches_on_magic() {
        let native = RpmPlugin::translate_bytes(&build_test_rpm()).unwrap();
        assert_eq!(native.name, "htop");

        let native = RpmPlugin::translate_bytes(PRIMARY.as_bytes()).unwrap();
        assert_eq!(native.name, "htop");
    }

    #[test]
    fn test_truncated_and_malformed_inputs() {
        assert!(parse_binary_rpm(&LEAD_MAGIC).is_err());

        let mut broken = build_test_rpm();
        broken.truncate(broken.len() - 8);
        assert!(parse_binary_rpm(&broken).is_err());

        assert!(RpmPlugin::translate_bytes(&[0xFF, 0xFE, 0x00]).is_err());
        assert!(parse_primary_xml("<package></package>").is_err());
    }

    #[test]
    fn test_flags_constraint() {
        let version = "2.38".to_string();
        assert_eq!(
            rpm_flags_constraint(RPMSENSE_GREATER | RPMSENSE_EQUAL, Some(&version)),
            Some(">=2.38".into())
        );
        assert_eq!(
            rpm_flags_constraint(RPMSENSE_LESS, Some(&version)),
            Some("<2.38".into())
        );
        assert_eq!(rpm_flags_constraint(RPMSENSE_EQUAL, Some(&version)), None);
        assert_eq!(rpm_flags_constraint(0, None), None);
        // An empty header parses to zero entries and an empty data store.
        let empty = build_header(&[]);
        let header = Header::parse(&empty).unwrap();
        assert_eq!(header.data_size(), 0);
        assert!(header.entries.is_empty());
    }
}
