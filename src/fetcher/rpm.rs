//! RPM fetcher on the `librpm-extos` fork (PLAN sub-phase 3.4).
//!
//! # Scope
//!
//! [`RpmFetcher`] speaks the dnf/yum repository protocol directly: it syncs the
//! signed index of a `<mirror>/repodata/` tree ([`RpmFetcher::sync_db`]) and
//! downloads individual `.rpm` files with size + digest verification
//! ([`RpmFetcher::download`]). Ingestion into the CAS stays the job of
//! `crate::ingest` (wiring is PLAN 3.4.5, a later single-writer task — this
//! module is API-complete and deliberately unwired).
//!
//! # Backend decision record (PLAN 3.4.2)
//!
//! | Candidate | Assessment |
//! |---|---|
//! | **Raw librpm FFI from Rust** | `rpmReadPackageFile` needs an `rpmts`, `FD_t` and the opaque `rpmtd` tag container; `rpmTagData` is a hand-rolled layout that changes with the soname. Guessing it in `extern "C"` declarations is a silent-corruption risk on any rpm upgrade. |
//! | **Shell out to `rpm -qp`** | Cheapest, but it verifies nothing: `rpm -qp` reads the header without checking package signatures, and a host `rpm` binary makes the result depend on the build host's rpm version and configuration. |
//! | **Fork-side C bridge (`extos-bridge.c`) + `dlopen`** | The C compiler checks the bridge against the fork's real headers, the ABI crossing into Rust is three primitive functions, and the bridge can use the full librpm API (`rpmReadPackageFile`, keyring import, `headerGet`) without exporting any struct layout. Loading is dynamic, so `libextos` keeps building on hosts without rpm. |
//!
//! **Decision: C bridge**, shipped as
//! `inherited/librpm-extos/extos/extos-bridge.c` and built by
//! `inherited/librpm-extos/extos/build-bridge.sh`. [`bridge::RpmBridge`]
//! `dlopen`s it at run time; no build-time link flags are added, so
//! `cargo build` never depends on librpm being installed.
//!
//! When the bridge is absent the fetcher still works for *metadata*: index
//! parsing is pure Rust, and package headers fall back to the dependency-free
//! parser in [`crate::rosetta::rpm`] (the Phase-2 translator). Signature
//! verification genuinely requires librpm and reports a typed error instead of
//! pretending to have checked anything.
//!
//! # Trust chain
//!
//! ```text
//! repomd.xml  --gpg-->  verified entry point
//!   └─ <data type="primary"> checksum + open-checksum  --digest-->
//!        primary.xml[.gz]
//!          └─ <package><checksum> + <size package>  --digest-->  *.rpm
//!               └─ rpmReadPackageFile + repo key  -->  package signature
//! ```
//!
//! Every arrow is enforced before the next document is trusted:
//!
//! 1. [`RpmFetcher::sync_db`] verifies `repodata/repomd.xml.asc` with a
//!    caller-supplied release key (when given), then checks the downloaded
//!    `primary` file against the `checksum`, `size` and `open-checksum`
//!    advertised in that signed document.
//! 2. [`RpmFetcher::download`] checks the `.rpm` against the `checksum`/`size`
//!    of its `primary.xml` row, and with [`SigCheck::Key`] re-verifies the
//!    stored `repomd.xml` and hands the package to librpm with the release key
//!    in a private keyring.
//!
//! Passing `None` / [`SigCheck::Skip`] downgrades the chain to hash-only
//! integrity and logs a warning: meant for local fixtures and offline mirrors,
//! never for a public repository.
//!
//! # External tools
//!
//! | Tool | Needed for | Absence |
//! |---|---|---|
//! | `gpg` | `repomd.xml.asc` verification | typed [`ExtosError::ConfigParse`] naming the tool |
//! | `gzip` / `zstd` / `xz` | compressed `primary.xml` | typed error; mirror a plain index instead |
//! | `libextos-rpm-bridge.so` | package signature verification | metadata falls back to the embedded parser; [`SigCheck::Key`] reports a typed error |

pub mod bridge;
pub mod index;

mod gpg;

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::error::ExtosError;
use crate::rosetta::rpm::parse_binary_rpm;

pub use bridge::{BRIDGE_ENV, BridgeHeader, BridgeRequirement, RpmBridge};
pub use index::{
    Checksum, DigestAlgo, PrimaryPackage, Repomd, RepomdRecord, parse_primary, parse_repomd,
};

/// Origin namespace this fetcher belongs to; also the `EXTOS_MIRRORS_*`
/// suffix used by [`RpmFetcher::from_env`].
pub const DEFAULT_ORIGIN: &str = "rpm";

/// Repository entry point, relative to the mirror base.
pub const REPOMD_PATH: &str = "repodata/repomd.xml";

/// Detached signature over [`REPOMD_PATH`], relative to the mirror base.
pub const REPOMD_SIG_PATH: &str = "repodata/repomd.xml.asc";

/// Default HTTP timeout for a single mirror request, in seconds.
const DEFAULT_DOWNLOAD_TIMEOUT_SECS: u64 = 300;

/// Default TCP connect timeout for a mirror, in seconds.
const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 30;

/// Hard cap on a single buffered response body (index or `.rpm`).
///
/// Downloads are buffered so they can be verified before touching the cache;
/// 2 GiB is far above any real RPM payload and keeps a hostile mirror from
/// exhausting memory.
const MAX_BODY_BYTES: u64 = 2 * 1024 * 1024 * 1024;

// ─── Public data types ──────────────────────────────────────────

/// Name/epoch/version/release/architecture of one RPM package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nvra {
    /// `NAME`, e.g. `hello`.
    pub name: String,
    /// `EPOCH`; `0` when the package has none.
    pub epoch: u32,
    /// `VERSION`, e.g. `1.0`.
    pub version: String,
    /// `RELEASE`, e.g. `2.fc41`.
    pub release: String,
    /// `ARCH`, e.g. `x86_64`; empty when the index did not carry one.
    pub arch: String,
}

impl Nvra {
    /// `epoch:version-release` — the canonical RPM EVR string.
    pub fn evr(&self) -> String {
        format!("{}:{}-{}", self.epoch, self.version, self.release)
    }

    /// `version-release`, the spelling `primary.xml` publishes.
    pub fn vr(&self) -> String {
        format!("{}-{}", self.version, self.release)
    }

    /// `name-epoch:version-release.arch`, the NEVRA spelling used by rpm/dnf.
    pub fn nevra(&self) -> String {
        let mut out = format!("{}-{}", self.name, self.evr());
        if !self.arch.is_empty() {
            out.push('.');
            out.push_str(&self.arch);
        }
        out
    }

    /// Whether `wanted` names this package's version.
    ///
    /// Accepts `1.0`, `1.0-2.fc41`, `0:1.0-2.fc41` and `1:...`, so callers can
    /// pass whatever a CLI or manifest produced.
    pub fn matches_version(&self, wanted: &str) -> bool {
        let wanted = wanted.trim();
        wanted == self.version || wanted == self.vr() || wanted == self.evr()
    }
}

/// One binary package row from a `primary.xml` index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpmPackage {
    /// Name/epoch/version/release/arch.
    pub nvra: Nvra,
    /// Digest of the `.rpm` file, from `<checksum pkgid="YES">`.
    pub checksum: Option<Checksum>,
    /// Size of the `.rpm` file in bytes (`<size package>`), `0` when unknown.
    pub size: u64,
    /// `<location href>`: path relative to the mirror base,
    /// e.g. `Packages/h/hello-1.0-2.fc41.x86_64.rpm`.
    pub relpath: String,
    /// `rpm:provides` capability names, verbatim.
    pub provides: Vec<String>,
    /// `rpm:requires` capability names, verbatim.
    pub requires: Vec<String>,
}

impl RpmPackage {
    /// Absolute download URL for this row on `mirror_base`.
    pub fn url(&self, mirror_base: &str) -> String {
        format!(
            "{}/{}",
            mirror_base.trim_end_matches('/'),
            self.relpath.trim_start_matches('/')
        )
    }
}

/// A synced RPM index: verified `primary.xml` rows plus the provenance needed
/// to keep verifying later downloads.
///
/// Constructed only by [`RpmFetcher::sync_db`]; the `repomd.xml` bytes and
/// signature stay private so a caller cannot fabricate a "verified" index.
#[derive(Debug, Clone)]
pub struct RpmIndex {
    /// Mirror base URL the rows came from.
    pub mirror_base: String,
    /// `repomd.xml` `<revision>` (empty when not published).
    pub revision: String,
    /// SHA-256 of the `repomd.xml` bytes that were parsed.
    pub repomd_sha256: String,
    /// `location href` of the primary record.
    pub primary_href: String,
    /// Digest of the primary file that was parsed, as advertised (verified).
    pub primary_checksum: Checksum,
    /// Parsed package rows.
    pub packages: Vec<RpmPackage>,
    /// Whether `repomd.xml` passed `gpg` verification when synced.
    signature_verified: bool,
    /// Raw `repomd.xml` bytes, kept for re-verification during `download`.
    repomd_doc: Vec<u8>,
    /// Detached signature bytes, kept for re-verification during `download`.
    repomd_sig: Option<Vec<u8>>,
}

impl RpmIndex {
    /// Whether `repomd.xml` was signature-verified with a supplied key.
    pub fn signature_verified(&self) -> bool {
        self.signature_verified
    }

    /// Raw `repomd.xml` document this index was parsed from.
    pub fn repomd_doc(&self) -> &[u8] {
        &self.repomd_doc
    }

    /// Detached `repomd.xml.asc` bytes, when the mirror served them.
    pub fn repomd_signature(&self) -> Option<&[u8]> {
        self.repomd_sig.as_deref()
    }

    /// Find the row for `name` and any accepted version spelling.
    ///
    /// When several rows match (same name, several arches), the first in
    /// document order wins; callers that care about architecture must filter
    /// [`RpmIndex::packages`] themselves.
    pub fn find(&self, name: &str, version: &str) -> Option<&RpmPackage> {
        self.packages
            .iter()
            .find(|row| row.nvra.name == name && row.nvra.matches_version(version))
    }

    /// All rows for a package name, in document order.
    pub fn package(&self, name: &str) -> Vec<&RpmPackage> {
        self.packages
            .iter()
            .filter(|row| row.nvra.name == name)
            .collect()
    }
}

/// Where a package header was read from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderSource {
    /// `rpmReadPackageFile` through the `librpm-extos` bridge.
    LibrpmBridge,
    /// The dependency-free header parser in [`crate::rosetta::rpm`].
    EmbeddedParser,
}

/// Outcome of the OpenPGP check on a package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureStatus {
    /// A signature entry exists and validated against the supplied key.
    Verified,
    /// The package carries no OpenPGP signature (digests may still be fine).
    Unsigned,
    /// The package is signed but no key (or no matching key) was available.
    NoKey,
    /// The signature is present and did not validate.
    Rejected(String),
    /// No verification was attempted.
    NotChecked,
}

/// Metadata read back from a package file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderReport {
    /// Name/epoch/version/release/arch.
    pub nvra: Nvra,
    /// Which reader produced this report.
    pub source: HeaderSource,
    /// `PROVIDENAME` capabilities (bridge only; empty for the embedded parser
    /// which filters `/` and `rpmlib(...)` entries).
    pub provides: Vec<String>,
    /// `REQUIRENAME` capabilities (bridge only).
    pub requires: Vec<String>,
    /// Signature outcome.
    pub signature: SignatureStatus,
    /// `rpmReadConfigFiles` result inside the bridge; `None` for the embedded
    /// parser.
    pub librpm_config_rc: Option<i32>,
}

/// Signature policy for [`RpmFetcher::download`].
#[derive(Debug, Clone, Copy)]
pub enum SigCheck<'a> {
    /// Full chain: re-verify the stored `repomd.xml` with this ASCII-armoured
    /// release key, then verify the package signature with librpm using the
    /// same key. Requires the `librpm-extos` bridge.
    Key(&'a [u8]),
    /// Hash-only: the `.rpm` is checked against the size and digest recorded in
    /// the index. The header is still parsed (bridge when reachable, embedded
    /// parser otherwise) to confirm the file really is the indexed package.
    Skip,
}

/// An `.rpm` that was downloaded and verified.
#[derive(Debug, Clone)]
pub struct DownloadedRpm {
    /// Where the verified `.rpm` lives in the fetcher's cache directory.
    pub path: PathBuf,
    /// Name/epoch/version/release/arch from the index row.
    pub nvra: Nvra,
    /// Verified size in bytes.
    pub size: u64,
    /// SHA-256 of the file on disk, lowercase hexadecimal.
    pub sha256: String,
    /// URL the file was fetched from.
    pub source_url: String,
    /// Header read back from the downloaded file, when one could be read.
    pub header: Option<HeaderReport>,
    /// Signature outcome.
    pub signature: SignatureStatus,
}

/// Host capabilities relevant to RPM fetching.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackendReport {
    /// Pure-Rust index handling is compiled in (always `true`).
    pub pure_rust: bool,
    /// A `librpm-extos` bridge could be loaded.
    pub librpm_bridge: bool,
    /// A `gpg` executable is on `PATH`.
    pub gpg: bool,
}

/// Probe the host for the transports RPM fetching can use.
///
/// Never fails: a probe that cannot run simply reports `false`.
pub fn backend_report() -> BackendReport {
    BackendReport {
        pure_rust: true,
        librpm_bridge: bridge_available(),
        gpg: gpg::available(),
    }
}

/// Whether a `librpm-extos` bridge can be loaded right now.
pub fn bridge_available() -> bool {
    bridge::RpmBridge::discover().is_ok()
}

/// Whether RPM fetching works at all on this host.
///
/// Index syncing and hash-verified downloads are pure Rust, so this is
/// unconditionally `true`; signature verification needs the bridge and is
/// reported per call.
pub fn is_available() -> bool {
    true
}

// ─── Header reading ─────────────────────────────────────────────

/// Read an RPM header, preferring the librpm bridge.
///
/// Falls back to [`crate::rosetta::rpm::parse_binary_rpm`] when no bridge is
/// loadable, so metadata works on hosts without librpm. Signature status is
/// [`SignatureStatus::NotChecked`] for the embedded parser.
///
/// # Errors
///
/// [`ExtosError::ConfigParse`] when neither reader can make sense of the file.
pub fn read_header(rpm: &Path) -> Result<HeaderReport, ExtosError> {
    match bridge::RpmBridge::discover() {
        Ok(bridge) => match bridge.read(rpm, None) {
            Ok(raw) => Ok(report_from_bridge(raw, None)),
            Err(err) => {
                tracing::debug!(
                    "librpm could not read {} ({err}); falling back to the embedded RPM parser",
                    rpm.display()
                );
                read_header_embedded(rpm)
            }
        },
        Err(err) => {
            tracing::debug!(
                "librpm bridge unavailable ({err}); falling back to the embedded RPM parser"
            );
            read_header_embedded(rpm)
        }
    }
}

/// Read an RPM header through an explicit bridge, optionally verifying the
/// package signature against `sigkey` (a path to an ASCII-armoured key).
///
/// # Errors
///
/// [`ExtosError::ConfigParse`] when the bridge cannot be loaded, the key cannot
/// be staged, or the file is not an RPM.
pub fn read_header_with_bridge(
    bridge_path: &Path,
    rpm: &Path,
    sigkey: Option<&[u8]>,
) -> Result<HeaderReport, ExtosError> {
    let bridge = bridge::RpmBridge::open(bridge_path)?;
    let staged = stage_key(sigkey)?;
    let key_path = staged.as_ref().map(|(_, path)| path.as_path());
    let raw = bridge.read(rpm, key_path)?;
    Ok(report_from_bridge(raw, sigkey))
}

/// Header report built from the embedded, dependency-free parser.
fn read_header_embedded(rpm: &Path) -> Result<HeaderReport, ExtosError> {
    let bytes = fs::read(rpm)?;
    let manifest = parse_binary_rpm(&bytes)?;
    // The embedded parser composes `epoch:version-release` (omitting a zero
    // epoch) without the arch; split it back into an NVRA.
    let (epoch, rest) = match manifest.version.split_once(':') {
        Some((epoch, rest)) => (epoch.parse::<u32>().unwrap_or(0), rest),
        None => (0, manifest.version.as_str()),
    };
    let (version, release) = rest
        .rsplit_once('-')
        .map(|(version, release)| (version.to_string(), release.to_string()))
        .unwrap_or_else(|| (rest.to_string(), String::new()));
    Ok(HeaderReport {
        nvra: Nvra {
            name: manifest.name,
            epoch,
            version,
            release,
            arch: String::new(),
        },
        source: HeaderSource::EmbeddedParser,
        provides: manifest.aliases,
        requires: Vec::new(),
        signature: SignatureStatus::NotChecked,
        librpm_config_rc: None,
    })
}

/// Convert a raw bridge header into a [`HeaderReport`].
fn report_from_bridge(raw: BridgeHeader, sigkey: Option<&[u8]>) -> HeaderReport {
    let signature = if !raw.signed {
        SignatureStatus::Unsigned
    } else {
        match raw.rpmrc {
            0 if sigkey.is_some() => SignatureStatus::Verified,
            0 => SignatureStatus::NoKey,
            4 => SignatureStatus::NoKey,
            _ => SignatureStatus::Rejected(format!("{} (rpmrc {})", raw.rpmrc_name, raw.rpmrc)),
        }
    };
    HeaderReport {
        nvra: raw.nvra,
        source: HeaderSource::LibrpmBridge,
        provides: raw.provides,
        requires: raw.requires.into_iter().map(|entry| entry.name).collect(),
        signature,
        librpm_config_rc: Some(raw.config_rc),
    }
}

/// Write a caller-supplied key into a throwaway directory so librpm can import
/// it from a path (`rpmPubkeyRead` takes a filename).
fn stage_key(sigkey: Option<&[u8]>) -> Result<Option<(gpg::TempDir, PathBuf)>, ExtosError> {
    let Some(key) = sigkey else {
        return Ok(None);
    };
    let home = gpg::TempDir::new("rpm-key")?;
    let path = home.path().join("repo-key.asc");
    fs::write(&path, key)?;
    Ok(Some((home, path)))
}

// ─── Fetcher ────────────────────────────────────────────────────

/// RPM repository fetcher (PLAN 3.4.3 / 3.4.4).
///
/// A fetcher is bound to one mirror base, one cache directory and optionally an
/// explicit bridge path. Cloning is cheap: the inner [`reqwest::blocking::Client`]
/// is reference-counted.
#[derive(Debug, Clone)]
pub struct RpmFetcher {
    mirror_base: String,
    cache_dir: PathBuf,
    origin: String,
    bridge_path: Option<PathBuf>,
    client: reqwest::blocking::Client,
}

impl RpmFetcher {
    /// Create a fetcher for `mirror_base` (a repository base URL such as
    /// `https://mirror.example/fedora/41/Everything/x86_64/os`, no trailing
    /// slash required).
    ///
    /// # Errors
    ///
    /// [`ExtosError::ConfigParse`] if the base URL is empty or the HTTP client
    /// cannot be built.
    pub fn new(
        mirror_base: impl Into<String>,
        cache_dir: impl Into<PathBuf>,
    ) -> Result<Self, ExtosError> {
        let mirror_base = mirror_base.into().trim_end_matches('/').to_string();
        if mirror_base.is_empty() {
            return Err(config_parse(
                "mirror_base",
                "the RPM mirror base URL must not be empty",
            ));
        }
        Ok(Self {
            mirror_base,
            cache_dir: cache_dir.into(),
            origin: DEFAULT_ORIGIN.to_string(),
            bridge_path: None,
            client: build_http_client()?,
        })
    }

    /// Create a fetcher from `EXTOS_MIRRORS_RPM`.
    ///
    /// The variable follows the `EXTOS_MIRRORS_<ORIGIN>` convention documented
    /// on [`crate::ingest::mirror_env_var`]: comma-separated base URLs, the
    /// first usable entry wins. No network access happens here.
    ///
    /// # Errors
    ///
    /// [`ExtosError::ConfigParse`] when the variable is unset or empty.
    pub fn from_env(cache_dir: impl Into<PathBuf>) -> Result<Self, ExtosError> {
        let base = mirror_from_env(DEFAULT_ORIGIN)?;
        Self::new(base, cache_dir)
    }

    /// Override the origin label used in errors (default [`DEFAULT_ORIGIN`]).
    pub fn with_origin(mut self, origin: impl Into<String>) -> Self {
        self.origin = origin.into();
        self
    }

    /// Use an explicit bridge library instead of discovery.
    ///
    /// Discovery itself is documented on [`bridge::RpmBridge::discover`]; this
    /// hook keeps tests and packagers from having to mutate the process
    /// environment.
    pub fn with_bridge(mut self, path: impl Into<PathBuf>) -> Self {
        self.bridge_path = Some(path.into());
        self
    }

    /// Mirror base URL this fetcher talks to.
    pub fn mirror_base(&self) -> &str {
        &self.mirror_base
    }

    /// Directory downloads are cached in.
    pub fn cache_dir(&self) -> &Path {
        &self.cache_dir
    }

    /// Sync and verify the repository index (PLAN 3.4.3).
    ///
    /// Fetches `repodata/repomd.xml`, verifies `repodata/repomd.xml.asc`
    /// against `sigkey_gpg` when a key is given, then fetches the `primary`
    /// record it advertises and confirms its `checksum`, `size` and
    /// `open-checksum`.
    ///
    /// # Errors
    ///
    /// - [`ExtosError::PackageNotFound`] when the mirror serves no `repomd.xml`,
    /// - [`ExtosError::CasIntegrity`] when the signature or a digest fails, or
    ///   the mirror serves `repomd.xml` without a signature while a key was
    ///   supplied,
    /// - [`ExtosError::ConfigParse`] on transport failures, a missing
    ///   decompressor, or a `repomd.xml` without a usable `primary` record,
    /// - [`ExtosError::RosettaPlugin`] when the XML is malformed.
    pub fn sync_db(&self, sigkey_gpg: Option<&[u8]>) -> Result<RpmIndex, ExtosError> {
        let repomd_url = self.url(REPOMD_PATH);
        let Some(repomd_doc) = self.get(&repomd_url)? else {
            return Err(ExtosError::PackageNotFound {
                origin: self.origin.clone(),
                name: self.mirror_base.clone(),
                version: REPOMD_PATH.to_string(),
            });
        };

        let repomd_sig = match sigkey_gpg {
            Some(key) => {
                let sig_url = self.url(REPOMD_SIG_PATH);
                let Some(sig) = self.get(&sig_url)? else {
                    return Err(ExtosError::CasIntegrity {
                        expected: format!("a detached signature at {sig_url}"),
                        actual: "the mirror serves repomd.xml without repomd.xml.asc".to_string(),
                    });
                };
                gpg::verify_detached(&repomd_doc, &sig, key)?;
                Some(sig)
            }
            None => {
                tracing::warn!(
                    "signature verification skipped for {repomd_url}: no release key supplied"
                );
                None
            }
        };

        let text = std::str::from_utf8(&repomd_doc).map_err(|err| {
            config_parse(&repomd_url, format!("repomd.xml is not valid UTF-8: {err}"))
        })?;
        let repomd = parse_repomd(text)?;

        let primary = repomd.primary().ok_or_else(|| {
            config_parse(
                &repomd_url,
                "repomd.xml advertises no <data type=\"primary\"> record",
            )
        })?;
        let href = primary
            .href
            .clone()
            .ok_or_else(|| config_parse(&repomd_url, "primary record has no <location href>"))?;
        let checksum = primary.checksum.clone().ok_or_else(|| {
            config_parse(
                &repomd_url,
                format!("primary record {href} has no checksum; refusing an unverified index"),
            )
        })?;

        let primary_url = self.url(&href);
        let Some(body) = self.get(&primary_url)? else {
            return Err(ExtosError::PackageNotFound {
                origin: self.origin.clone(),
                name: self.mirror_base.clone(),
                version: href.clone(),
            });
        };
        if let Some(expected) = primary.size
            && body.len() as u64 != expected
        {
            return Err(ExtosError::CasIntegrity {
                expected: format!("{expected} bytes for {href}"),
                actual: format!("{} bytes", body.len()),
            });
        }
        checksum.verify_bytes(&body, &href)?;

        let decoded = index::decode_index(&href, body)?;
        if let Some(open) = &primary.open_checksum {
            open.verify_bytes(&decoded, &format!("{href} (decoded)"))?;
        }
        let text = String::from_utf8(decoded).map_err(|err| {
            config_parse(
                &primary_url,
                format!("primary index is not valid UTF-8: {err}"),
            )
        })?;
        let rows = parse_primary(&text)?;
        if rows.is_empty() {
            tracing::warn!("primary index {primary_url} contains no packages");
        }

        let packages: Vec<RpmPackage> = rows
            .into_iter()
            .map(|row| RpmPackage {
                nvra: row.nvra,
                checksum: row.checksum,
                size: row.size,
                relpath: row.href,
                provides: row.provides,
                requires: row.requires,
            })
            .collect();

        tracing::info!(
            "synced {} packages from {primary_url} ({} bytes)",
            packages.len(),
            text.len()
        );

        Ok(RpmIndex {
            mirror_base: self.mirror_base.clone(),
            revision: repomd.revision,
            repomd_sha256: DigestAlgo::Sha256.of_bytes(&repomd_doc),
            primary_href: href,
            primary_checksum: checksum,
            packages,
            signature_verified: repomd_sig.is_some(),
            repomd_doc,
            repomd_sig,
        })
    }

    /// Download and verify one `.rpm` (PLAN 3.4.4).
    ///
    /// The file is fetched from the `location href` of its index row, checked
    /// against the row's size and digest, and stored atomically in
    /// [`RpmFetcher::cache_dir`]. A cached copy is reused only after its digest
    /// is re-checked; a corrupted cache entry is deleted and refetched.
    ///
    /// `sigcheck` selects the trust level: [`SigCheck::Key`] re-verifies the
    /// signed `repomd.xml` and the package signature, [`SigCheck::Skip`] only
    /// enforces the digests recorded in the index.
    ///
    /// # Errors
    ///
    /// - [`ExtosError::PackageNotFound`] when the row or the file is missing,
    /// - [`ExtosError::CasIntegrity`] on a size/digest/identity/signature
    ///   mismatch,
    /// - [`ExtosError::ConfigParse`] on transport failures or when
    ///   [`SigCheck::Key`] is requested without a loadable librpm bridge.
    pub fn download(
        &self,
        index: &RpmIndex,
        package: &str,
        version: &str,
        sigcheck: SigCheck<'_>,
    ) -> Result<DownloadedRpm, ExtosError> {
        let row = index
            .find(package, version)
            .ok_or_else(|| ExtosError::PackageNotFound {
                origin: self.origin.clone(),
                name: package.to_string(),
                version: version.to_string(),
            })?;

        if let SigCheck::Key(key) = sigcheck {
            verify_index(index, key)?;
        }

        let url = row.url(&index.mirror_base);
        let dest = self.cache_dir.join(file_name_of(&row.relpath));
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }

        if dest.is_file() && file_matches(&dest, row)? {
            tracing::debug!("rpm cache hit: {}", dest.display());
        } else {
            if dest.is_file() {
                tracing::debug!(
                    "cached rpm failed verification, refetching: {}",
                    dest.display()
                );
                fs::remove_file(&dest)?;
            }
            let Some(bytes) = self.get(&url)? else {
                return Err(ExtosError::PackageNotFound {
                    origin: self.origin.clone(),
                    name: package.to_string(),
                    version: version.to_string(),
                });
            };
            if row.size != 0 && bytes.len() as u64 != row.size {
                return Err(ExtosError::CasIntegrity {
                    expected: format!("{} bytes for {}", row.size, row.relpath),
                    actual: format!("{} bytes", bytes.len()),
                });
            }
            let checksum = row
                .checksum
                .clone()
                .ok_or_else(|| ExtosError::CasIntegrity {
                    expected: format!("a digest for {} in the index", row.relpath),
                    actual: "the index row carries no checksum".to_string(),
                })?;
            checksum.verify_bytes(&bytes, &row.relpath)?;
            write_atomically(&dest, &bytes)?;
            tracing::info!("downloaded {} → {}", url, dest.display());
        }

        let (header, signature) = match sigcheck {
            SigCheck::Key(key) => {
                let report = self.read_via_bridge(&dest, Some(key))?;
                ensure_identity(&row.nvra, &report)?;
                match &report.signature {
                    SignatureStatus::Verified => {}
                    SignatureStatus::Unsigned => {
                        return Err(ExtosError::CasIntegrity {
                            expected: format!("a signed package for {}", row.nvra.nevra()),
                            actual: "the package carries no OpenPGP signature".to_string(),
                        });
                    }
                    other => {
                        return Err(ExtosError::CasIntegrity {
                            expected: format!("a valid signature for {}", row.nvra.nevra()),
                            actual: format!("{other:?}"),
                        });
                    }
                }
                let status = report.signature.clone();
                (Some(report), status)
            }
            SigCheck::Skip => {
                // Auditor G-L11 note 1: the sync_db(None) arm warns about a
                // downgraded chain, so the download arm must not be the silent
                // half of the same policy.
                tracing::warn!(
                    "signature verification skipped for {url}: SigCheck::Skip requested explicitly"
                );
                let report = self.try_read_any_header(&dest)?;
                ensure_identity(&row.nvra, &report)?;
                let status = report.signature.clone();
                (Some(report), status)
            }
        };

        if let Some(verified) = &row.checksum {
            tracing::debug!(
                "verified {} against {} {}",
                dest.display(),
                verified.algo.as_str(),
                verified.hex
            );
        }

        let sha256 = DigestAlgo::Sha256.of_file(&dest)?;
        let size = fs::metadata(&dest)?.len();

        Ok(DownloadedRpm {
            path: dest,
            nvra: row.nvra.clone(),
            size,
            sha256,
            source_url: url,
            header,
            signature,
        })
    }

    /// Read a header through the bridge (explicit path or discovery).
    fn read_via_bridge(
        &self,
        rpm: &Path,
        sigkey: Option<&[u8]>,
    ) -> Result<HeaderReport, ExtosError> {
        let staged = stage_key(sigkey)?;
        let key_path = staged.as_ref().map(|(_, path)| path.as_path());
        let bridge = match &self.bridge_path {
            Some(path) => bridge::RpmBridge::open(path)?,
            None => bridge::RpmBridge::discover()?,
        };
        let raw = bridge.read(rpm, key_path)?;
        Ok(report_from_bridge(raw, sigkey))
    }

    /// Read a header with whatever reader is available (bridge, else embedded).
    ///
    /// The bridge is tried first when it is reachable; a file librpm refuses
    /// (hand-built test images, foreign payloads) is retried with the embedded
    /// parser instead of failing the download, because hash verification has
    /// already established that the bytes are the indexed ones.
    fn try_read_any_header(&self, rpm: &Path) -> Result<HeaderReport, ExtosError> {
        let bridge = match &self.bridge_path {
            Some(path) => Some(bridge::RpmBridge::open(path)?),
            None => bridge::RpmBridge::discover().ok(),
        };
        if let Some(bridge) = bridge {
            match bridge.read(rpm, None) {
                Ok(raw) => return Ok(report_from_bridge(raw, None)),
                Err(err) => {
                    tracing::debug!(
                        "librpm could not read {} ({err}); verifying the header with the embedded parser",
                        rpm.display()
                    );
                }
            }
        }
        read_header_embedded(rpm)
    }

    /// Absolute URL for a path relative to [`RpmFetcher::mirror_base`].
    fn url(&self, relpath: &str) -> String {
        format!(
            "{}/{}",
            self.mirror_base.trim_end_matches('/'),
            relpath.trim_start_matches('/')
        )
    }

    /// GET `url`, returning `None` on 404/410 and the body otherwise.
    fn get(&self, url: &str) -> Result<Option<Vec<u8>>, ExtosError> {
        let mut response = self
            .client
            .get(url)
            .send()
            .map_err(|err| config_parse(url, format!("request failed: {err}")))?;

        let status = response.status();
        if status == reqwest::StatusCode::NOT_FOUND || status == reqwest::StatusCode::GONE {
            return Ok(None);
        }
        if !status.is_success() {
            return Err(config_parse(url, format!("mirror answered HTTP {status}")));
        }
        if let Some(len) = response.content_length()
            && len > MAX_BODY_BYTES
        {
            return Err(config_parse(
                url,
                format!("refusing a {len}-byte response (cap is {MAX_BODY_BYTES} bytes)"),
            ));
        }

        let mut body = Vec::new();
        response
            .read_to_end(&mut body)
            .map_err(|err| config_parse(url, format!("cannot read response body: {err}")))?;
        if body.len() as u64 > MAX_BODY_BYTES {
            return Err(config_parse(
                url,
                format!(
                    "refusing a {}-byte response (cap is {MAX_BODY_BYTES} bytes)",
                    body.len()
                ),
            ));
        }
        Ok(Some(body))
    }
}

/// Sync an RPM index without keeping a fetcher around (PLAN 3.4.3 signature).
///
/// Uses [`default_cache_dir`].
pub fn sync_db(mirror_base: &str, sigkey_gpg: Option<&[u8]>) -> Result<RpmIndex, ExtosError> {
    RpmFetcher::new(mirror_base, default_cache_dir())?.sync_db(sigkey_gpg)
}

/// Download a `.rpm` from a previously synced index (PLAN 3.4.4 signature).
///
/// The mirror base is taken from the index so rows cannot be mixed across
/// mirrors.
pub fn download(
    index: &RpmIndex,
    package: &str,
    version: &str,
    sigcheck: SigCheck<'_>,
) -> Result<DownloadedRpm, ExtosError> {
    RpmFetcher::new(index.mirror_base.clone(), default_cache_dir())?
        .download(index, package, version, sigcheck)
}

/// Default cache directory used by the free [`sync_db`] / [`download`]
/// helpers: `$EXTOS_CACHE_DIR`, else `<temp>/extos-rpm-cache`.
///
/// A caller that owns a CAS repository should pass
/// `<repository>/cache/<origin>` to [`RpmFetcher::new`] instead.
pub fn default_cache_dir() -> PathBuf {
    match std::env::var("EXTOS_CACHE_DIR") {
        Ok(dir) if !dir.trim().is_empty() => PathBuf::from(dir),
        _ => std::env::temp_dir().join("extos-rpm-cache"),
    }
}

// ─── Internals ──────────────────────────────────────────────────

/// Re-verify the `repomd.xml` stored in `index` with `key`.
fn verify_index(index: &RpmIndex, key: &[u8]) -> Result<(), ExtosError> {
    match &index.repomd_sig {
        Some(sig) => gpg::verify_detached(&index.repomd_doc, sig, key),
        None => Err(ExtosError::CasIntegrity {
            expected: "a signature-verified RPM repository".to_string(),
            actual: "the index was synced without a key; re-run sync_db with one".to_string(),
        }),
    }
}

/// Confirm that a downloaded file really is the indexed package.
fn ensure_identity(expected: &Nvra, report: &HeaderReport) -> Result<(), ExtosError> {
    if report.nvra.name != expected.name {
        return Err(ExtosError::CasIntegrity {
            expected: format!("package name {}", expected.name),
            actual: format!("header name {}", report.nvra.name),
        });
    }
    let matches = match report.source {
        HeaderSource::LibrpmBridge => report.nvra.evr() == expected.evr(),
        // The embedded parser omits a zero epoch, so compare the version in
        // every spelling the index might use.
        HeaderSource::EmbeddedParser => {
            let reported = if report.nvra.release.is_empty() {
                report.nvra.version.clone()
            } else {
                report.nvra.vr()
            };
            expected.matches_version(&reported)
                || reported == expected.evr()
                || (expected.epoch == 0 && reported == expected.vr())
        }
    };
    if !matches {
        return Err(ExtosError::CasIntegrity {
            expected: format!("package version {}", expected.evr()),
            actual: format!(
                "header version {}{}",
                report.nvra.evr(),
                if report.nvra.arch.is_empty() {
                    String::new()
                } else {
                    format!(".{}", report.nvra.arch)
                }
            ),
        });
    }
    Ok(())
}

/// `true` when the cached file still matches the index row.
fn file_matches(path: &Path, row: &RpmPackage) -> Result<bool, ExtosError> {
    let metadata = fs::metadata(path)?;
    if row.size != 0 && metadata.len() != row.size {
        return Ok(false);
    }
    match &row.checksum {
        Some(checksum) => Ok(checksum
            .algo
            .of_file(path)?
            .eq_ignore_ascii_case(&checksum.hex)),
        None => Ok(false),
    }
}

/// Write `bytes` to `dest` via a `.part` sibling renamed on success.
fn write_atomically(dest: &Path, bytes: &[u8]) -> Result<(), ExtosError> {
    let mut name = dest
        .file_name()
        .map(|name| name.to_os_string())
        .unwrap_or_else(|| "download".into());
    name.push(".part");
    let part = dest.with_file_name(name);
    {
        let mut file = fs::File::create(&part)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    if let Err(err) = fs::rename(&part, dest) {
        let _ = fs::remove_file(&part);
        return Err(err.into());
    }
    Ok(())
}

/// Last path component of a `location href`.
fn file_name_of(relpath: &str) -> String {
    relpath
        .rsplit('/')
        .next()
        .filter(|name| !name.is_empty())
        .unwrap_or("package.rpm")
        .to_string()
}

/// Build the blocking HTTP client used for index and package downloads.
fn build_http_client() -> Result<reqwest::blocking::Client, ExtosError> {
    let timeout = std::env::var("EXTOS_DOWNLOAD_TIMEOUT_SECS")
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|secs| *secs > 0)
        .unwrap_or(DEFAULT_DOWNLOAD_TIMEOUT_SECS);

    reqwest::blocking::Client::builder()
        .user_agent(concat!("pkt/", env!("CARGO_PKG_VERSION")))
        .connect_timeout(Duration::from_secs(DEFAULT_CONNECT_TIMEOUT_SECS))
        .timeout(Duration::from_secs(timeout))
        .build()
        .map_err(|err| config_parse("http", format!("cannot create HTTP client: {err}")))
}

/// First configured mirror from `EXTOS_MIRRORS_<ORIGIN>`.
///
/// The variable name comes from [`crate::ingest::mirror_env_var`], so the RPM
/// fetcher cannot drift from the convention used by `pkt -S`.
fn mirror_from_env(origin: &str) -> Result<String, ExtosError> {
    let var = crate::ingest::mirror_env_var(origin);
    let raw = std::env::var(&var).map_err(|_| {
        config_parse(
            &var,
            format!("no RPM mirror configured; set {var} to one or more comma-separated base URLs"),
        )
    })?;
    raw.split(',')
        .map(|entry| entry.trim().trim_end_matches('/'))
        .find(|entry| !entry.is_empty())
        .map(str::to_string)
        .ok_or_else(|| config_parse(&var, format!("{var} contains no usable mirror URL")))
}

/// [`ExtosError::ConfigParse`] helper (fetching has no dedicated error variant;
/// `ingest` reports mirror failures the same way).
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

    fn nvra(name: &str, epoch: u32, version: &str, release: &str) -> Nvra {
        Nvra {
            name: name.to_string(),
            epoch,
            version: version.to_string(),
            release: release.to_string(),
            arch: "x86_64".to_string(),
        }
    }

    #[test]
    fn nvra_spellings() {
        let nvra = nvra("hello", 1, "1.0", "2.fc41");
        assert_eq!(nvra.evr(), "1:1.0-2.fc41");
        assert_eq!(nvra.vr(), "1.0-2.fc41");
        assert_eq!(nvra.nevra(), "hello-1:1.0-2.fc41.x86_64");
    }

    #[test]
    fn version_matching_accepts_all_spellings() {
        let nvra = nvra("hello", 0, "1.0", "2.fc41");
        assert!(nvra.matches_version("1.0"));
        assert!(nvra.matches_version("1.0-2.fc41"));
        assert!(nvra.matches_version("0:1.0-2.fc41"));
        assert!(!nvra.matches_version("1.1"));
        assert!(!nvra.matches_version("1:1.0-2.fc41"));
    }

    #[test]
    fn file_name_of_uses_last_component() {
        assert_eq!(
            file_name_of("Packages/h/hello-1.0-1.x86_64.rpm"),
            "hello-1.0-1.x86_64.rpm"
        );
        assert_eq!(file_name_of(""), "package.rpm");
    }

    #[test]
    fn empty_mirror_base_is_rejected() {
        let err = RpmFetcher::new("", std::env::temp_dir());
        assert!(matches!(err, Err(ExtosError::ConfigParse { .. })));
    }

    #[test]
    fn pure_rust_backend_is_always_available() {
        assert!(is_available());
        assert!(backend_report().pure_rust);
    }

    #[test]
    fn signature_status_maps_unsigned_packages() {
        let raw = BridgeHeader {
            bridge_abi: "extos-bridge/1".into(),
            nvra: nvra("hello", 0, "1.0", "1"),
            source_rpm: None,
            rpmrc: 0,
            rpmrc_name: "OK".into(),
            config_rc: 0,
            provides: Vec::new(),
            requires: Vec::new(),
            signed: false,
        };
        let report = report_from_bridge(raw, Some(b"key"));
        assert_eq!(report.signature, SignatureStatus::Unsigned);
        assert_eq!(report.source, HeaderSource::LibrpmBridge);
    }

    #[test]
    fn signature_status_maps_rejections() {
        let raw = BridgeHeader {
            bridge_abi: "extos-bridge/1".into(),
            nvra: nvra("hello", 0, "1.0", "1"),
            source_rpm: None,
            rpmrc: 3,
            rpmrc_name: "NOTTRUSTED".into(),
            config_rc: 0,
            provides: Vec::new(),
            requires: Vec::new(),
            signed: true,
        };
        let report = report_from_bridge(raw, Some(b"key"));
        assert!(matches!(report.signature, SignatureStatus::Rejected(_)));
    }

    #[test]
    fn identity_check_rejects_a_different_package() {
        let expected = nvra("hello", 0, "1.0", "1");
        let mut report = HeaderReport {
            nvra: nvra("world", 0, "1.0", "1"),
            source: HeaderSource::LibrpmBridge,
            provides: Vec::new(),
            requires: Vec::new(),
            signature: SignatureStatus::NotChecked,
            librpm_config_rc: Some(0),
        };
        assert!(matches!(
            ensure_identity(&expected, &report),
            Err(ExtosError::CasIntegrity { .. })
        ));
        report.nvra = nvra("hello", 0, "1.0", "1");
        assert!(ensure_identity(&expected, &report).is_ok());
    }

    #[test]
    fn embedded_identity_ignores_the_epoch_prefix() {
        let expected = nvra("hello", 0, "1.0", "1");
        let report = HeaderReport {
            nvra: Nvra {
                name: "hello".into(),
                epoch: 0,
                version: "1.0".into(),
                release: "1".into(),
                arch: String::new(),
            },
            source: HeaderSource::EmbeddedParser,
            provides: Vec::new(),
            requires: Vec::new(),
            signature: SignatureStatus::NotChecked,
            librpm_config_rc: None,
        };
        assert!(ensure_identity(&expected, &report).is_ok());
    }

    #[test]
    fn an_unsynced_index_cannot_be_reverified() {
        let index = RpmIndex {
            mirror_base: "http://127.0.0.1:1".into(),
            revision: String::new(),
            repomd_sha256: String::new(),
            primary_href: String::new(),
            primary_checksum: Checksum {
                algo: DigestAlgo::Sha256,
                hex: String::new(),
            },
            packages: Vec::new(),
            signature_verified: false,
            repomd_doc: Vec::new(),
            repomd_sig: None,
        };
        assert!(matches!(
            verify_index(&index, b"key"),
            Err(ExtosError::CasIntegrity { .. })
        ));
    }
}
