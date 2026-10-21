//! Repository metadata parsing for the RPM fetcher (PLAN 3.4.3).
//!
//! A dnf/yum repository publishes, under `<mirror>/repodata/`:
//!
//! ```text
//! repomd.xml            <- signed entry point (records + checksums)
//! repodata/*-primary.xml.gz   <- one row per binary package
//! repomd.xml.asc        <- detached OpenPGP signature over repomd.xml
//! repomd.xml.key        <- the release key (for out-of-band trust setup)
//! ```
//!
//! This module parses the two XML documents with the crate's existing
//! namespace-agnostic tokenizer (`crate::rosetta::common::xml_tokens`, the
//! same scanner the Rosetta RPM translator uses), so no XML dependency is
//! added. Only the elements ExtOS consumes are read:
//!
//! * `repomd.xml` — `<revision>` and one [`RepomdRecord`] per `<data>` entry
//!   (`type`, `checksum`, `open-checksum`, `location/@href`, `size`);
//! * `primary.xml` — one [`PrimaryPackage`] per `<package>`: `name`, `arch`,
//!   `<version epoch/ver/rel>`, `<checksum>`, `<size package>`,
//!   `<location href>`, and the `rpm:provides`/`rpm:requires` capability
//!   names.
//!
//! Malformed input never panics: missing required fields surface as
//! [`ExtosError::RosettaPlugin`] with the document name and the offending
//! package, and a document with zero packages parses to an empty vector that
//! the caller treats as "empty repository" (logged, not silently trusted).
//!
//! Note the division of labour with [`crate::rosetta::rpm`]: its
//! `parse_primary_xml` translates the *first* package into a dependency
//! manifest for the translator pipeline, while [`parse_primary`] keeps every
//! row with the checksum/location/size the fetcher needs. The binary-header
//! parser from that module *is* reused verbatim as the no-librpm fallback.
//!
//! Decompression of `*-primary.xml.{gz,zst,xz}` shells out to the matching
//! tool (`gzip`, `zstd`, `xz`) — the same policy the extraction pipeline uses
//! for archives. A missing tool is a typed error naming it.

use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};

use sha2::{Digest, Sha256, Sha512};

use crate::error::ExtosError;
use crate::rosetta::common::{XmlToken, attr, xml_tokens, xml_unescape};

use super::Nvra;

/// Origin label used in errors.
const PLUGIN: &str = "rpm";

/// Upper bound on a single buffered index body (2 GiB).
///
/// A `primary.xml` for a large distribution is tens of megabytes; the cap only
/// exists so a hostile mirror cannot exhaust memory.
pub const MAX_INDEX_BYTES: u64 = 2 * 1024 * 1024 * 1024;

// ─── Digests ────────────────────────────────────────────────────

/// Digest algorithms accepted from `repomd.xml`.
///
/// Repositories in the wild use `sha256` (Fedora, openSUSE) and `sha512`
/// (some RHEL rebuilds); anything else is rejected rather than ignored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestAlgo {
    /// SHA-256 (`sha` and `sha256` in `repomd.xml`).
    Sha256,
    /// SHA-512.
    Sha512,
}

impl DigestAlgo {
    /// Parse a `repomd.xml` `type=` attribute.
    pub fn parse(name: &str) -> Option<Self> {
        match name.trim().to_ascii_lowercase().as_str() {
            "sha" | "sha256" => Some(Self::Sha256),
            "sha512" => Some(Self::Sha512),
            _ => None,
        }
    }

    /// Canonical name as written in `repomd.xml`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
            Self::Sha512 => "sha512",
        }
    }

    /// Lowercase hexadecimal digest of `bytes`.
    pub fn of_bytes(self, bytes: &[u8]) -> String {
        match self {
            Self::Sha256 => hex::encode(Sha256::digest(bytes)),
            Self::Sha512 => hex::encode(Sha512::digest(bytes)),
        }
    }

    /// Lowercase hexadecimal digest of a file, streamed.
    pub fn of_file(self, path: &Path) -> Result<String, ExtosError> {
        let mut file = std::fs::File::open(path)?;
        let mut buf = [0u8; 64 * 1024];
        match self {
            Self::Sha256 => {
                let mut hasher = Sha256::new();
                loop {
                    let read = file.read(&mut buf)?;
                    if read == 0 {
                        break;
                    }
                    hasher.update(&buf[..read]);
                }
                Ok(hex::encode(hasher.finalize()))
            }
            Self::Sha512 => {
                let mut hasher = Sha512::new();
                loop {
                    let read = file.read(&mut buf)?;
                    if read == 0 {
                        break;
                    }
                    hasher.update(&buf[..read]);
                }
                Ok(hex::encode(hasher.finalize()))
            }
        }
    }
}

/// A digest plus the algorithm that produced it, as published in the index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checksum {
    /// Algorithm the repository used.
    pub algo: DigestAlgo,
    /// Lowercase hexadecimal digest.
    pub hex: String,
}

impl Checksum {
    /// Verify an in-memory body against this checksum.
    ///
    /// # Errors
    ///
    /// [`ExtosError::CasIntegrity`] on mismatch, naming `what` and both values.
    pub fn verify_bytes(&self, bytes: &[u8], what: &str) -> Result<(), ExtosError> {
        let actual = self.algo.of_bytes(bytes);
        if actual.eq_ignore_ascii_case(&self.hex) {
            return Ok(());
        }
        Err(ExtosError::CasIntegrity {
            expected: format!("{}({what}) = {}", self.algo.as_str(), self.hex),
            actual: format!("{}({what}) = {actual}", self.algo.as_str()),
        })
    }

    /// Verify a file against this checksum, streaming.
    ///
    /// # Errors
    ///
    /// [`ExtosError::CasIntegrity`] on mismatch, [`ExtosError::Io`] when the
    /// file cannot be read.
    pub fn verify_file(&self, path: &Path, what: &str) -> Result<(), ExtosError> {
        let actual = self.algo.of_file(path)?;
        if actual.eq_ignore_ascii_case(&self.hex) {
            return Ok(());
        }
        Err(ExtosError::CasIntegrity {
            expected: format!("{}({what}) = {}", self.algo.as_str(), self.hex),
            actual: format!("{}({what}) = {actual}", self.algo.as_str()),
        })
    }
}

// ─── repomd.xml ─────────────────────────────────────────────────

/// One `<data type="...">` record of `repomd.xml`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepomdRecord {
    /// Record kind: `primary`, `filelists`, `other`, `primary_db`, …
    pub data_type: String,
    /// Checksum over the file as served (compressed bytes).
    pub checksum: Option<Checksum>,
    /// Checksum over the uncompressed payload (`open-checksum`).
    pub open_checksum: Option<Checksum>,
    /// Path relative to the mirror base, e.g. `repodata/abc-primary.xml.gz`.
    pub href: Option<String>,
    /// Size of the served file in bytes.
    pub size: Option<u64>,
}

/// Parsed `repomd.xml`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Repomd {
    /// Repository revision string, when published.
    pub revision: String,
    /// Every `<data>` record, in document order.
    pub records: Vec<RepomdRecord>,
}

impl Repomd {
    /// The `primary` record, if the repository has one.
    pub fn primary(&self) -> Option<&RepomdRecord> {
        self.records
            .iter()
            .find(|record| record.data_type == "primary")
    }
}

/// Parse a `repomd.xml` document.
///
/// # Errors
///
/// [`ExtosError::RosettaPlugin`] when the document contains no `<data>`
/// records at all (an empty or truncated `repomd.xml`).
pub fn parse_repomd(text: &str) -> Result<Repomd, ExtosError> {
    let tokens = xml_tokens(text);
    let mut repomd = Repomd::default();
    let mut current: Option<RepomdRecord> = None;

    for (index, token) in tokens.iter().enumerate() {
        match token {
            XmlToken::Open { name, attrs } => match name.as_str() {
                "revision" => {
                    if repomd.revision.is_empty()
                        && let Some(value) = text_after(&tokens, index)
                    {
                        repomd.revision = xml_unescape(value);
                    }
                }
                "data" => {
                    current = Some(RepomdRecord {
                        data_type: attr(attrs, "type").unwrap_or_default().to_string(),
                        checksum: None,
                        open_checksum: None,
                        href: None,
                        size: None,
                    });
                }
                "checksum" => {
                    if let Some(record) = current.as_mut()
                        && let Some(value) = text_after(&tokens, index)
                    {
                        record.checksum = parse_checksum(attrs, value);
                    }
                }
                "open-checksum" => {
                    if let Some(record) = current.as_mut()
                        && let Some(value) = text_after(&tokens, index)
                    {
                        record.open_checksum = parse_checksum(attrs, value);
                    }
                }
                "location" => {
                    if let Some(record) = current.as_mut() {
                        record.href = attr(attrs, "href").map(str::to_string);
                    }
                }
                "size" => {
                    if let Some(record) = current.as_mut()
                        && let Some(value) = text_after(&tokens, index)
                    {
                        record.size = value.trim().parse::<u64>().ok();
                    }
                }
                _ => {}
            },
            XmlToken::Close(name) if name == "data" => {
                if let Some(record) = current.take() {
                    repomd.records.push(record);
                }
            }
            _ => {}
        }
    }
    // A truncated document may deliver the last record without its closing tag.
    if let Some(record) = current.take() {
        repomd.records.push(record);
    }

    if repomd.records.is_empty() {
        return Err(plugin_error(
            "repomd.xml contains no <data> records (empty or truncated document)",
        ));
    }
    Ok(repomd)
}

/// Build a [`Checksum`] from a `type=` attribute and a text node.
///
/// An unknown algorithm yields `None`; the caller decides whether a missing
/// checksum is fatal (it is for `primary`).
fn parse_checksum(attrs: &[(String, String)], value: &str) -> Option<Checksum> {
    let algo = DigestAlgo::parse(attr(attrs, "type").unwrap_or("sha256"))?;
    let hex = xml_unescape(value).trim().to_ascii_lowercase();
    if hex.is_empty() {
        return None;
    }
    Some(Checksum { algo, hex })
}

// ─── primary.xml ────────────────────────────────────────────────

/// One `<package>` row of `primary.xml`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrimaryPackage {
    /// Name/epoch/version/release/arch.
    pub nvra: Nvra,
    /// Package checksum (`pkgid`), over the `.rpm` file.
    pub checksum: Option<Checksum>,
    /// `size/@package` — the size of the `.rpm` file.
    pub size: u64,
    /// `location/@href` — path relative to the mirror base.
    pub href: String,
    /// `rpm:provides` entry names, verbatim.
    pub provides: Vec<String>,
    /// `rpm:requires` entry names, verbatim.
    pub requires: Vec<String>,
}

/// Parse a `primary.xml` document into one row per package.
///
/// Packages missing `<name>` or `<location href>` are rejected (they cannot be
/// downloaded); everything else is optional and defaults sensibly (`epoch=0`,
/// `size=0` = unknown, `arch=""`).
///
/// # Errors
///
/// [`ExtosError::RosettaPlugin`] when a package is missing a required field.
pub fn parse_primary(text: &str) -> Result<Vec<PrimaryPackage>, ExtosError> {
    let tokens = xml_tokens(text);
    let mut packages = Vec::new();
    let mut current: Option<PartialPackage> = None;
    let mut section = String::new();

    for (index, token) in tokens.iter().enumerate() {
        match token {
            XmlToken::Open { name, attrs } => match name.as_str() {
                "package" => {
                    current = Some(PartialPackage::default());
                    section.clear();
                }
                "name" => {
                    if let Some(builder) = current.as_mut()
                        && builder.name.is_empty()
                        && let Some(value) = text_after(&tokens, index)
                    {
                        builder.name = xml_unescape(value);
                    }
                }
                "arch" => {
                    if let Some(builder) = current.as_mut()
                        && builder.arch.is_empty()
                        && let Some(value) = text_after(&tokens, index)
                    {
                        builder.arch = xml_unescape(value);
                    }
                }
                "version" => {
                    if let Some(builder) = current.as_mut()
                        && builder.version.is_empty()
                        && let Some(value) = attr(attrs, "ver")
                    {
                        builder.version = value.to_string();
                        builder.epoch = attr(attrs, "epoch")
                            .and_then(|epoch| epoch.trim().parse::<u32>().ok())
                            .unwrap_or(0);
                        builder.release = attr(attrs, "rel").unwrap_or_default().to_string();
                    }
                }
                "checksum" => {
                    if let Some(builder) = current.as_mut()
                        && builder.checksum.is_none()
                        && let Some(value) = text_after(&tokens, index)
                    {
                        builder.checksum = parse_checksum(attrs, value);
                    }
                }
                "size" => {
                    if let Some(builder) = current.as_mut()
                        && let Some(value) = attr(attrs, "package")
                    {
                        builder.size = value.trim().parse::<u64>().unwrap_or(0);
                    }
                }
                "location" => {
                    if let Some(builder) = current.as_mut()
                        && builder.href.is_empty()
                        && let Some(value) = attr(attrs, "href")
                    {
                        builder.href = value.to_string();
                    }
                }
                "rpm:provides" | "provides" => section = "provides".to_string(),
                "rpm:requires" | "requires" => section = "requires".to_string(),
                "rpm:entry" | "entry" => {
                    if let Some(builder) = current.as_mut() {
                        let entry = attr(attrs, "name").unwrap_or_default();
                        if !entry.is_empty() {
                            match section.as_str() {
                                "provides" => builder.provides.push(entry.to_string()),
                                "requires" => builder.requires.push(entry.to_string()),
                                _ => {}
                            }
                        }
                    }
                }
                _ => {}
            },
            XmlToken::Close(name) => match name.as_str() {
                "package" => {
                    if let Some(builder) = current.take() {
                        packages.push(builder.finish()?);
                    }
                    section.clear();
                }
                "rpm:provides" | "rpm:requires" | "provides" | "requires" => section.clear(),
                _ => {}
            },
            XmlToken::Text(_) => {}
        }
    }
    // Tolerate a document whose last </package> is missing.
    if let Some(builder) = current.take() {
        packages.push(builder.finish()?);
    }
    Ok(packages)
}

/// Accumulator for one `<package>` element.
#[derive(Debug, Default)]
struct PartialPackage {
    name: String,
    arch: String,
    epoch: u32,
    version: String,
    release: String,
    checksum: Option<Checksum>,
    size: u64,
    href: String,
    provides: Vec<String>,
    requires: Vec<String>,
}

impl PartialPackage {
    /// Validate required fields and produce a [`PrimaryPackage`].
    fn finish(self) -> Result<PrimaryPackage, ExtosError> {
        if self.name.is_empty() {
            return Err(plugin_error(
                "primary.xml contains a <package> without a <name>",
            ));
        }
        if self.href.is_empty() {
            return Err(plugin_error(format!(
                "primary.xml package '{}' has no <location href>",
                self.name
            )));
        }
        Ok(PrimaryPackage {
            nvra: Nvra {
                name: self.name,
                epoch: self.epoch,
                version: self.version,
                release: self.release,
                arch: self.arch,
            },
            checksum: self.checksum,
            size: self.size,
            href: self.href,
            provides: self.provides,
            requires: self.requires,
        })
    }
}

// ─── Decoding ───────────────────────────────────────────────────

/// Decode a repository index body according to its advertised filename.
///
/// `.gz`, `.zst` and `.xz` bodies are piped through `gzip -dc`, `zstd -dc` and
/// `xz -dc` respectively; anything else is treated as plain XML.
///
/// # Errors
///
/// [`ExtosError::ConfigParse`] when the tool is missing or fails,
/// [`ExtosError::CasIntegrity`] when the body exceeds [`MAX_INDEX_BYTES`].
pub fn decode_index(href: &str, data: Vec<u8>) -> Result<Vec<u8>, ExtosError> {
    let tool = if href.ends_with(".gz") {
        Some("gzip")
    } else if href.ends_with(".zst") {
        Some("zstd")
    } else if href.ends_with(".xz") {
        Some("xz")
    } else {
        None
    };

    let Some(tool) = tool else {
        if data.len() as u64 > MAX_INDEX_BYTES {
            return Err(integrity(
                format!("an index under {MAX_INDEX_BYTES} bytes"),
                format!("{} bytes for {href}", data.len()),
            ));
        }
        return Ok(data);
    };

    let mut child = Command::new(tool)
        .arg("-dc")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| {
            config_parse(
                tool,
                format!(
                    "cannot run '{tool}' to decompress {href}: {err}; install '{tool}' \
                     or mirror an uncompressed index"
                ),
            )
        })?;

    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| config_parse(tool, format!("cannot open stdin of '{tool}'")))?;
    let writer = std::thread::spawn(move || {
        if let Err(err) = stdin.write_all(&data) {
            tracing::debug!("writing to '{tool}' failed: {err}");
        }
    });

    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| config_parse(tool, format!("cannot open stdout of '{tool}'")))?;
    let mut out = Vec::new();
    let read_result = stdout.read_to_end(&mut out);

    let mut err_buf = String::new();
    if let Some(mut stderr) = child.stderr.take() {
        let _ = stderr.read_to_string(&mut err_buf);
    }
    let status = child.wait()?;
    let _ = writer.join();
    read_result?;

    if !status.success() {
        return Err(config_parse(
            href,
            format!("{tool} -dc failed ({status}): {}", err_buf.trim()),
        ));
    }
    if out.len() as u64 > MAX_INDEX_BYTES {
        return Err(integrity(
            format!("a decoded index under {MAX_INDEX_BYTES} bytes"),
            format!("{} bytes for {href}", out.len()),
        ));
    }
    Ok(out)
}

// ─── Helpers ────────────────────────────────────────────────────

/// Text node that immediately follows `tokens[index]`, if any.
fn text_after(tokens: &[XmlToken], index: usize) -> Option<&str> {
    match tokens.get(index + 1) {
        Some(XmlToken::Text(text)) => Some(text.as_str()),
        _ => None,
    }
}

/// Build a typed metadata error.
fn plugin_error(message: impl Into<String>) -> ExtosError {
    ExtosError::RosettaPlugin {
        plugin: PLUGIN.to_string(),
        message: message.into(),
    }
}

/// Build a [`ExtosError::CasIntegrity`].
fn integrity(expected: impl Into<String>, actual: impl Into<String>) -> ExtosError {
    ExtosError::CasIntegrity {
        expected: expected.into(),
        actual: actual.into(),
    }
}

/// Build a [`ExtosError::ConfigParse`].
fn config_parse(path: impl Into<String>, message: impl Into<String>) -> ExtosError {
    ExtosError::ConfigParse {
        path: path.into(),
        line: 0,
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REPOMD: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<repomd xmlns="http://linux.duke.edu/metadata/repo">
  <revision>1700000000</revision>
  <data type="primary">
    <checksum type="sha256">aa11</checksum>
    <open-checksum type="sha256">bb22</open-checksum>
    <location href="repodata/aa11-primary.xml.gz"/>
    <timestamp>1700000000</timestamp>
    <size>1234</size>
  </data>
  <data type="filelists">
    <checksum type="sha512">cc33</checksum>
    <location href="repodata/cc33-filelists.xml.gz"/>
    <size>99</size>
  </data>
</repomd>
"#;

    const PRIMARY: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<metadata xmlns="http://linux.duke.edu/metadata/common"
          xmlns:rpm="http://linux.duke.edu/metadata/rpm" packages="2">
  <package type="rpm">
    <name>hello</name>
    <arch>x86_64</arch>
    <version epoch="1" ver="1.0" rel="2.fc41"/>
    <checksum type="sha256" pkgid="YES">dd44</checksum>
    <summary>Hello</summary>
    <size package="4096" installed="1024" archive="5120"/>
    <location href="Packages/h/hello-1.0-2.fc41.x86_64.rpm"/>
    <format>
      <rpm:provides>
        <rpm:entry name="hello" flags="EQ" epoch="1" ver="1.0" rel="2.fc41"/>
      </rpm:provides>
      <rpm:requires>
        <rpm:entry name="glibc" flags="GE" ver="2.38"/>
      </rpm:requires>
    </format>
  </package>
  <package type="rpm">
    <name>world</name>
    <arch>noarch</arch>
    <version epoch="0" ver="2.0" rel="1"/>
    <checksum type="sha256">ee55</checksum>
    <size package="2048"/>
    <location href="Packages/w/world-2.0-1.noarch.rpm"/>
  </package>
</metadata>
"#;

    #[test]
    fn repomd_records_are_parsed() {
        let repomd = parse_repomd(REPOMD).expect("valid repomd");
        assert_eq!(repomd.revision, "1700000000");
        assert_eq!(repomd.records.len(), 2);
        let primary = repomd.primary().expect("primary record");
        assert_eq!(
            primary.href.as_deref(),
            Some("repodata/aa11-primary.xml.gz")
        );
        assert_eq!(primary.size, Some(1234));
        assert_eq!(
            primary.checksum,
            Some(Checksum {
                algo: DigestAlgo::Sha256,
                hex: "aa11".into()
            })
        );
        assert_eq!(
            primary.open_checksum.as_ref().map(|sum| sum.hex.as_str()),
            Some("bb22")
        );
        let filelists = &repomd.records[1];
        assert_eq!(filelists.data_type, "filelists");
        assert_eq!(
            filelists.checksum.as_ref().map(|sum| sum.algo),
            Some(DigestAlgo::Sha512)
        );
    }

    #[test]
    fn empty_repomd_is_rejected() {
        let err = parse_repomd("<repomd></repomd>").expect_err("no records");
        assert!(matches!(err, ExtosError::RosettaPlugin { .. }));
    }

    #[test]
    fn primary_rows_are_parsed() {
        let rows = parse_primary(PRIMARY).expect("valid primary");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].nvra.name, "hello");
        assert_eq!(rows[0].nvra.epoch, 1);
        assert_eq!(rows[0].nvra.evr(), "1:1.0-2.fc41");
        assert_eq!(rows[0].size, 4096);
        assert_eq!(rows[0].href, "Packages/h/hello-1.0-2.fc41.x86_64.rpm");
        assert_eq!(rows[0].provides, vec!["hello".to_string()]);
        assert_eq!(rows[0].requires, vec!["glibc".to_string()]);
        assert_eq!(rows[1].nvra.arch, "noarch");
        assert_eq!(rows[1].nvra.evr(), "0:2.0-1");
        assert!(rows[1].provides.is_empty());
    }

    #[test]
    fn package_without_location_is_rejected() {
        let xml = "<metadata><package><name>x</name></package></metadata>";
        let err = parse_primary(xml).expect_err("location is required");
        assert!(err.to_string().contains("no <location href>"));
    }

    #[test]
    fn package_without_name_is_rejected() {
        let xml = r#"<metadata><package><location href="x.rpm"/></package></metadata>"#;
        let err = parse_primary(xml).expect_err("name is required");
        assert!(err.to_string().contains("without a <name>"));
    }

    #[test]
    fn unknown_digest_algorithm_is_not_silently_accepted() {
        assert_eq!(DigestAlgo::parse("sha256"), Some(DigestAlgo::Sha256));
        assert_eq!(DigestAlgo::parse("SHA"), Some(DigestAlgo::Sha256));
        assert_eq!(DigestAlgo::parse("sha512"), Some(DigestAlgo::Sha512));
        assert_eq!(DigestAlgo::parse("md5"), None);
    }

    #[test]
    fn checksum_verifies_and_reports_mismatches() {
        let sum = Checksum {
            algo: DigestAlgo::Sha256,
            hex: DigestAlgo::Sha256.of_bytes(b"abc"),
        };
        sum.verify_bytes(b"abc", "payload")
            .expect("matching digest");
        let err = sum.verify_bytes(b"abd", "payload").expect_err("mismatch");
        assert!(matches!(err, ExtosError::CasIntegrity { .. }));
    }

    #[test]
    fn checksum_verifies_a_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("payload.bin");
        std::fs::write(&path, b"hello world").expect("write");
        let sum = Checksum {
            algo: DigestAlgo::Sha512,
            hex: DigestAlgo::Sha512.of_file(&path).expect("hash"),
        };
        sum.verify_file(&path, "payload").expect("matching digest");
    }

    #[test]
    fn plain_index_is_returned_unchanged() {
        let data = b"<metadata/>".to_vec();
        assert_eq!(
            decode_index("repodata/x-primary.xml", data.clone()).expect("plain"),
            data
        );
    }
}
