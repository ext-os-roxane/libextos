//! Parsers for the Debian repository metadata formats (PLAN 3.3.2).
//!
//! Three formats are handled here, all plain text (never blobs, never a
//! committed fixture):
//!
//! - **clearsigned `InRelease`** — RFC 4880 ASCII armour wrapping the same
//!   control-file payload; [`clearsign_payload`] strips the armour so the
//!   signed text can be parsed after `gpg --verify` accepted it,
//! - **`Release` / `InRelease` payload** — a Debian control paragraph with the
//!   `Distribution`/`Suite`/`Codename` header fields and the `SHA256:`
//!   stanza listing every index file with its hash and size; [`parse_release`]
//!   returns these as [`ReleaseDoc`],
//! - **`Packages`** — one control paragraph per binary package;
//!   [`parse_packages`] turns each stanza into a row carrying the fields the
//!   fetcher needs to download and verify the `.deb`
//!   (`Package`, `Version`, `Architecture`, `Size`, `SHA256`, `Filename`).
//!
//! Parsing is deliberately lenient about unknown fields (Debian keeps adding
//! them) and strict about the fields that carry integrity guarantees: a row
//! whose `SHA256` is not 64 hexadecimal characters, or whose `Size` is not a
//! number, is dropped with a `tracing::debug!` instead of being trusted.

/// One entry of the `SHA256:` stanza of a `Release` document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ChecksumEntry {
    /// Lowercase hexadecimal SHA-256 of the referenced file.
    pub(crate) sha256: String,
    /// Size of the referenced file in bytes.
    pub(crate) size: u64,
    /// Index path relative to `dists/<suite>/`, e.g.
    /// `main/binary-amd64/Packages.gz`.
    pub(crate) path: String,
}

/// The parsed payload of an `InRelease` / `Release` document.
#[derive(Debug, Clone, Default)]
pub(crate) struct ReleaseDoc {
    /// `Distribution:` field (empty on repositories that only use Suite).
    pub(crate) distribution: String,
    /// `Suite:` field, e.g. `sid`.
    pub(crate) suite: String,
    /// `Codename:` field, e.g. `bookworm`.
    pub(crate) codename: String,
    /// `Components:` list, e.g. `["main", "contrib"]`.
    pub(crate) components: Vec<String>,
    /// `Architectures:` list, e.g. `["amd64", "i386"]`.
    pub(crate) architectures: Vec<String>,
    /// Entries of the `SHA256:` stanza, in document order.
    pub(crate) checksums: Vec<ChecksumEntry>,
}

impl ReleaseDoc {
    /// Best human-readable name for the suite, preferring `Distribution`, then
    /// `Suite`, then `Codename`.
    pub(crate) fn suite_name(&self) -> String {
        for candidate in [&self.distribution, &self.suite, &self.codename] {
            if !candidate.is_empty() {
                return candidate.clone();
            }
        }
        String::new()
    }
}

/// Strip the ASCII armour from a clearsigned document and return the signed
/// payload.
///
/// Returns `None` when `doc` is not a clearsigned message (no
/// `-----BEGIN PGP SIGNED MESSAGE-----` line, or no payload at all). The
/// dash-escape required by RFC 4880 (`- ` prefix on payload lines starting
/// with `-`) is undone, so the result is byte-identical to the document the
/// signer fed to `gpg --clearsign`.
///
/// This function does **not** verify anything; callers must run
/// `gpg --verify` first and only then trust the returned text.
pub(crate) fn clearsign_payload(doc: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(doc);
    let mut lines = text.lines();

    // Find the armour header; anything before it is not part of the payload.
    let mut found_header = false;
    for line in lines.by_ref() {
        if line.trim_end() == "-----BEGIN PGP SIGNED MESSAGE-----" {
            found_header = true;
            break;
        }
    }
    if !found_header {
        return None;
    }

    // Armour headers (`Hash: ...`) are separated from the payload by an empty
    // line.
    let mut in_payload = false;
    for line in lines.by_ref() {
        if line.trim().is_empty() {
            in_payload = true;
            break;
        }
    }
    if !in_payload {
        return None;
    }

    let mut payload = String::new();
    for line in lines {
        if line.trim_end() == "-----BEGIN PGP SIGNATURE-----" {
            return Some(payload);
        }
        if let Some(unescaped) = line.strip_prefix("- ") {
            payload.push_str(unescaped);
        } else {
            payload.push_str(line);
        }
        payload.push('\n');
    }
    // A clearsigned body always terminates with the signature header; running
    // off the end means the armour is truncated.
    None
}

/// Parse an unsigned `Release` document (or the payload of a clearsigned
/// `InRelease`).
///
/// Unknown fields and continuation lines of non-checksum fields are ignored.
pub(crate) fn parse_release(text: &str) -> ReleaseDoc {
    let normalized = normalize(text);
    let mut doc = ReleaseDoc::default();
    let mut current_key: Option<&str> = None;

    for line in normalized.lines() {
        if line.trim().is_empty() {
            current_key = None;
            continue;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            if current_key == Some("SHA256")
                && let Some(entry) = parse_checksum_line(line)
            {
                doc.checksums.push(entry);
            }
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();
        current_key = Some(key);
        match key {
            "Distribution" => doc.distribution = value.to_string(),
            "Suite" => doc.suite = value.to_string(),
            "Codename" => doc.codename = value.to_string(),
            "Components" => doc.components = split_words(value),
            "Architectures" => doc.architectures = split_words(value),
            _ => {}
        }
    }
    doc
}

/// One `SHA256:` stanza line: `<sha256> <size> <path>`.
fn parse_checksum_line(line: &str) -> Option<ChecksumEntry> {
    let mut parts = line.split_whitespace();
    let sha256 = parts.next()?.to_ascii_lowercase();
    let size = parts.next()?.parse::<u64>().ok()?;
    let path = parts.next()?;
    if !is_sha256_hex(&sha256) || parts.next().is_some() {
        return None;
    }
    Some(ChecksumEntry {
        sha256,
        size,
        path: path.to_string(),
    })
}

/// Parse a `Packages` index into the rows the fetcher needs.
///
/// Each stanza must carry `Package`, `Version`, `Size`, `SHA256` and
/// `Filename`; stanzas missing any of them (or with a malformed hash/size) are
/// skipped. `Architecture` is optional and defaults to the empty string.
///
/// The caller is expected to have verified the bytes of `text` against the
/// `SHA256:` entry of the signed `Release` document; this function only
/// translates text into rows.
pub(crate) fn parse_packages(text: &str, component: &str) -> Vec<super::DebPackage> {
    let normalized = normalize(text);
    let mut rows = Vec::new();

    for stanza in normalized.split("\n\n") {
        if stanza.trim().is_empty() {
            continue;
        }
        let mut package = None;
        let mut version = None;
        let mut architecture = String::new();
        let mut size = None;
        let mut sha256 = None;
        let mut filename = None;

        for line in stanza.lines() {
            if line.starts_with(' ') || line.starts_with('\t') {
                continue;
            }
            let Some((key, value)) = line.split_once(':') else {
                continue;
            };
            let value = value.trim();
            match key.trim() {
                "Package" => package = Some(value.to_string()),
                "Version" => version = Some(value.to_string()),
                "Architecture" => architecture = value.to_string(),
                "Size" => size = value.parse::<u64>().ok(),
                "SHA256" => sha256 = Some(value.to_ascii_lowercase()),
                "Filename" => filename = Some(value.to_string()),
                _ => {}
            }
        }

        let (Some(package), Some(version), Some(size), Some(sha256), Some(filename)) =
            (package, version, size, sha256, filename)
        else {
            tracing::debug!("skipping incomplete Packages stanza (missing required field)");
            continue;
        };
        if !is_sha256_hex(&sha256) {
            tracing::debug!("skipping Packages stanza for {package}: malformed SHA256");
            continue;
        }
        rows.push(super::DebPackage {
            package,
            version,
            architecture,
            size,
            sha256,
            filename,
            component: component.to_string(),
        });
    }
    rows
}

/// Normalize line endings so the parsers see plain `\n`.
fn normalize(text: &str) -> String {
    text.replace("\r\n", "\n")
}

/// `true` when `value` is exactly 64 lowercase hexadecimal characters.
fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// Split a whitespace-separated list field.
fn split_words(value: &str) -> Vec<String> {
    value
        .split_whitespace()
        .map(ToString::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const PACKAGES: &str = "\
Package: hello
Version: 1.0.0-1
Architecture: amd64
Maintainer: ExtOS Test <test@extos.invalid>
Size: 4096
SHA256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Filename: pool/main/h/hello/hello_1.0.0-1_amd64.deb
Description: test package
 continuation line that must not be parsed
Description-md5: 00000000000000000000000000000000

Package: incomplete
Version: 2.0
";

    #[test]
    fn clearsign_payload_strips_armour_and_dash_escapes() {
        let signed = "\
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

Suite: sid
- -dash escaped line
SHA256:
 abc 12 main/binary-amd64/Packages
-----BEGIN PGP SIGNATURE-----

iQIzBAEBCgAdFiEE...
-----END PGP SIGNATURE-----
";
        let payload = clearsign_payload(signed.as_bytes()).expect("payload");
        assert_eq!(
            payload,
            "Suite: sid\n-dash escaped line\nSHA256:\n abc 12 main/binary-amd64/Packages\n"
        );
        assert!(!payload.contains("BEGIN PGP SIGNATURE"));
    }

    #[test]
    fn clearsign_payload_rejects_unsigned_text() {
        assert!(clearsign_payload(b"Suite: sid\n").is_none());
        // Truncated armour: no signature header.
        let truncated = "\
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

Suite: sid
";
        assert!(clearsign_payload(truncated.as_bytes()).is_none());
    }

    #[test]
    fn parse_release_reads_header_fields_and_checksums() {
        let doc = "\
Origin: Debian
Label: Debian
Suite: sid
Codename: sid
Architectures: amd64 i386
Components: main contrib
Date: Wed, 21 Oct 2026 00:00:00 UTC
SHA256:
 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb 512 main/binary-amd64/Packages
 cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc 256 main/binary-amd64/Packages.gz
 malformed-line
";
        let parsed = parse_release(doc);
        assert_eq!(parsed.suite_name(), "sid");
        assert_eq!(parsed.components, vec!["main", "contrib"]);
        assert_eq!(parsed.architectures, vec!["amd64", "i386"]);
        assert_eq!(parsed.checksums.len(), 2);
        assert_eq!(parsed.checksums[1].size, 256);
        assert_eq!(parsed.checksums[0].path, "main/binary-amd64/Packages");
    }

    #[test]
    fn parse_release_survives_absent_distribution_field() {
        let parsed = parse_release("Suite: bookworm\nCodename: bookworm\n");
        assert_eq!(parsed.suite_name(), "bookworm");
        assert!(parsed.checksums.is_empty());
    }

    #[test]
    fn parse_packages_extracts_required_fields_and_skips_broken_stanzas() {
        let rows = parse_packages(PACKAGES, "main");
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(row.package, "hello");
        assert_eq!(row.version, "1.0.0-1");
        assert_eq!(row.architecture, "amd64");
        assert_eq!(row.size, 4096);
        assert_eq!(row.component, "main");
        assert_eq!(row.relpath(), "pool/main/h/hello/hello_1.0.0-1_amd64.deb");
        assert!(row.sha256.starts_with("aaaa"));
    }

    #[test]
    fn parse_packages_rejects_malformed_hash() {
        let text = "Package: hello\nVersion: 1\nSize: 1\nSHA256: not-a-hash\n\
                    Filename: pool/h.deb\n";
        assert!(parse_packages(text, "main").is_empty());
    }

    #[test]
    fn parse_packages_tolerates_crlf_and_leading_blank_lines() {
        let crlf = PACKAGES.replace('\n', "\r\n");
        let rows = parse_packages(&format!("\r\n{crlf}"), "main");
        assert_eq!(rows.len(), 1);
    }
}
