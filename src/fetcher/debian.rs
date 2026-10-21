//! Debian fetcher on APT infrastructure (PLAN sub-phase 3.3).
//!
//! # Scope
//!
//! [`DebianFetcher`] speaks the APT repository protocol directly: it syncs the
//! signed index of a `dists/<suite>` tree ([`DebianFetcher::sync_db`]) and
//! downloads individual `.deb` files with size + SHA-256 verification
//! ([`DebianFetcher::download`]). It returns plain rows and a path; ingestion
//! into the CAS remains the job of `ingest` (wiring is PLAN 3.3.4, a later
//! single-writer task — this module is API-complete and deliberately unwired).
//!
//! # Backend decision record (PLAN 3.3.1)
//!
//! Three ways to talk to Debian were evaluated:
//!
//! | Candidate | Assessment |
//! |---|---|
//! | **C++ FFI to `libapt-pkg`** | Gives the richest semantics (`pkgCacheFile`, pinning, `Acquire` queues) but requires the C++ ABI, `apt-pkg` headers at build time, a matching `libstdc++` at run time, and a global `_apt` configuration to initialise. On the reference build host (CachyOS/Arch) `libapt-pkg` is **not installed**, so a hard link would simply fail to build there; a `dlopen` variant would ship an API that is unreachable on the very distributions ExtOS targets for everything else. It also drags Debian's GPG trust model into-process, which conflicts with ExtOS's "verify in a child process, own the policy" stance. |
//! | **Shell out to `apt-get download`** | Lowest effort, but silently depends on the *host* having APT configured: sources.list, pinning, proxy settings, `_apt` sandbox user, keyrings in `/etc/apt/trusted.gpg.d`. That makes a "Debian" fetch behave differently on Arch (where `apt-get` is absent — also true on the reference host) and blocks per-origin mirrors, cross-architecture fetches, and hermetic tests. It also cannot report structured index rows. |
//! | **Pure Rust on `reqwest` blocking + `gpg` subprocess** | Only uses dependencies the crate already has (`reqwest` with rustls, `sha2`, `hex`). Works on every host, keeps the signature decision in a throwaway `GNUPGHOME`, makes the mirror URL explicit (so it composes with `EXTOS_MIRRORS_*`), and is fully testable against a loopback fixture. Decompression of `Packages.gz`/`Packages.xz` shells out to `gzip`/`xz`, which every base system carries. |
//!
//! **Decision: pure Rust**, with the other two backends recognised but not
//! implemented. [`available_backend`] reports what is actually usable, and
//! [`backend_report`] surfaces the host probes (`libapt_pkg_available`,
//! `apt_get_available`) so a future lane can add an FFI backend without
//! changing this decision record. The door stays open: the public surface is
//! `sync_db` + `download` on [`DebianFetcher`], which any backend could
//! satisfy.
//!
//! # Trust chain
//!
//! ```text
//! InRelease (clearsigned)  --gpg-->  verified payload
//!   └─ SHA256: stanza  --sha256-->  Packages[.gz|.xz]
//!        └─ per-stanza SHA256 + Size  --sha256-->  pool/**.deb
//! ```
//!
//! Each arrow is enforced before the next one is trusted:
//!
//! 1. [`DebianFetcher::sync_db`] verifies the clearsignature over `InRelease`
//!    (or the detached `Release.gpg` over `Release`) when a key is supplied,
//!    then checks the downloaded `Packages` bytes against the size and SHA-256
//!    advertised in the *signed* document ([`ExtosError::CasIntegrity`] on
//!    mismatch).
//! 2. [`DebianFetcher::download`] checks the `.deb` against the `Size` /
//!    `SHA256` fields of its `Packages` stanza, and can re-verify the stored
//!    release document with the caller's key ([`SigCheck::Key`]) before
//!    trusting the index at all.
//!
//! Passing `None` / [`SigCheck::Skip`] downgrades the chain to hash-only
//! integrity and logs a warning: it is meant for local fixtures and offline
//! mirrors, never for the public archive.
//!
//! # External tools
//!
//! | Tool | Needed for | Absence |
//! |---|---|---|
//! | `gpg` | signature verification | typed [`ExtosError::ConfigParse`] naming the tool |
//! | `gzip` | `Packages.gz` only | typed error; mirror a plain or `.xz` index instead |
//! | `xz` | `Packages.xz` only | typed error; mirror a plain or `.gz` index instead |
//!
//! Plain `Packages` is tried first, so a repository that serves it needs no
//! decompression tool at all. All three tool names are resolved through
//! `PATH`; no absolute path is ever hardcoded.

mod gpg;
mod index;

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use sha2::{Digest, Sha256};

use crate::error::ExtosError;

/// Default architecture when the caller has no preference.
pub const DEFAULT_ARCH: &str = "amd64";

/// Origin namespace this fetcher belongs to; also the `EXTOS_MIRRORS_*`
/// suffix used by [`DebianFetcher::from_env`].
pub const DEFAULT_ORIGIN: &str = "debian";

/// Default HTTP timeout for a single mirror request, in seconds.
const DEFAULT_DOWNLOAD_TIMEOUT_SECS: u64 = 300;

/// Default TCP connect timeout for a mirror, in seconds.
const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 30;

/// Hard cap on a single buffered response body (index or `.deb`).
///
/// Downloads are buffered so they can be verified before touching the cache;
/// 2 GiB is far above any real Debian package and keeps a hostile mirror from
/// exhausting memory.
const MAX_BODY_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// Candidate `Packages` filenames inside `dists/<suite>/<component>/binary-<arch>/`,
/// in preference order: plain text first (no tool needed), then the compressed
/// variants.
const PACKAGES_CANDIDATES: [&str; 3] = ["Packages", "Packages.gz", "Packages.xz"];

// ─── Backend selection (PLAN 3.3.1) ─────────────────────────────

/// Transport a Debian fetcher could use.
///
/// Only [`DebianBackend::PureRust`] is implemented; the other variants exist so
/// [`available_backend`] and [`backend_report`] can describe the host honestly
/// and a future lane can add them behind the same [`DebianFetcher`] surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DebianBackend {
    /// `reqwest` blocking + `gpg` subprocess (the implemented backend).
    PureRust,
    /// Direct C++ FFI to `libapt-pkg` — recognised, not implemented.
    LibAptPkg,
    /// Shelling out to `apt-get download` — recognised, not implemented.
    AptGetShellout,
}

/// Result of probing the host for every Debian transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackendReport {
    /// Whether the pure-Rust backend is compiled in (always `true`).
    pub pure_rust: bool,
    /// Whether `libapt-pkg` is visible to the dynamic loader.
    pub libapt_pkg: bool,
    /// Whether an `apt-get` executable is on `PATH`.
    pub apt_get: bool,
    /// Whether `gpg` can be executed (needed for signature verification).
    pub gpg: bool,
}

/// Probe the host for every Debian transport, plus the `gpg` tool the
/// pure-Rust backend needs for signature checks.
///
/// Never fails: a probe that cannot run simply reports `false`.
pub fn backend_report() -> BackendReport {
    BackendReport {
        pure_rust: true,
        libapt_pkg: libapt_pkg_available(),
        apt_get: apt_get_available(),
        gpg: gpg_available(),
    }
}

/// Whether a working `gpg` executable is on `PATH`.
///
/// Signature verification needs it; [`DebianFetcher::sync_db`] reports its
/// absence as a typed error only when a key is actually supplied, so an
/// unsigned offline mirror keeps working on hosts without GnuPG.
pub fn gpg_available() -> bool {
    gpg::available()
}

/// The backend this build would use.
///
/// Always [`DebianBackend::PureRust`]: it is the only implemented transport and
/// the only one that works on hosts without APT (including the reference build
/// host, where both `libapt-pkg` and `apt-get` are absent).
pub fn available_backend() -> DebianBackend {
    DebianBackend::PureRust
}

/// Whether a Debian fetcher can run here.
///
/// The pure-Rust backend needs no compile-time or link-time library, so this is
/// unconditionally `true`; the per-request tools (`gpg`, `gzip`, `xz`) are
/// reported as typed errors at the point of use instead.
pub fn is_available() -> bool {
    true
}

/// Whether `libapt-pkg` appears in the dynamic loader cache.
///
/// Runs `ldconfig -p` and greps for `libapt-pkg`; a missing `ldconfig` or a
/// non-zero exit reports `false`. This is a *probe*, not a build dependency —
/// no FFI backend consumes it yet.
pub fn libapt_pkg_available() -> bool {
    let Ok(output) = Command::new("ldconfig")
        .arg("-p")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
    else {
        return false;
    };
    output.status.success()
        && String::from_utf8_lossy(&output.stdout)
            .lines()
            .any(|line| line.contains("libapt-pkg"))
}

/// Whether an `apt-get` executable answers `--version` on `PATH`.
pub fn apt_get_available() -> bool {
    Command::new("apt-get")
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

// ─── Public data types ──────────────────────────────────────────

/// Which document carried the signed repository metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseKind {
    /// `InRelease` — clearsigned payload (`gpg --verify InRelease`).
    InRelease,
    /// `Release` + `Release.gpg` — detached signature.
    ReleaseDetached,
    /// Unsigned `Release`, accepted only when the caller passed no key.
    ReleaseUnsigned,
}

/// One binary package row from a `Packages` index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DebPackage {
    /// `Package:` field, e.g. `hello`.
    pub package: String,
    /// `Version:` field, e.g. `2.10-3`.
    pub version: String,
    /// `Architecture:` field, e.g. `amd64`.
    pub architecture: String,
    /// `Size:` field in bytes.
    pub size: u64,
    /// `SHA256:` field, lowercase hexadecimal.
    pub sha256: String,
    /// `Filename:` field: path of the `.deb` relative to the mirror base,
    /// e.g. `pool/main/h/hello/hello_2.10-3_amd64.deb`.
    pub filename: String,
    /// Component the row was found in (`main`, `contrib`, …).
    pub component: String,
}

impl DebPackage {
    /// The `.deb` path relative to the mirror base — the same value as
    /// [`DebPackage::filename`], spelled for callers that think in terms of
    /// `Release` checksum paths.
    pub fn relpath(&self) -> &str {
        &self.filename
    }

    /// Absolute download URL for this row on `mirror_base`.
    pub fn url(&self, mirror_base: &str) -> String {
        format!(
            "{}/{}",
            mirror_base.trim_end_matches('/'),
            self.filename.trim_start_matches('/')
        )
    }
}

/// A synced Debian index: the verified `Packages` rows plus the provenance
/// needed to keep verifying later downloads.
///
/// Constructed only by [`DebianFetcher::sync_db`]; the release document is
/// private so a caller cannot fabricate a "verified" index.
#[derive(Debug, Clone)]
pub struct DebIndex {
    /// Distribution/suite requested from the mirror (`bookworm`, `sid`, …).
    pub distro: String,
    /// Component requested (`main`, `contrib`, …).
    pub component: String,
    /// Architecture requested (`amd64`, `arm64`, …).
    pub architecture: String,
    /// Mirror base URL the rows came from.
    pub mirror_base: String,
    /// Human-readable suite name from the signed document
    /// (`Distribution`, else `Suite`, else `Codename`).
    pub distribution: String,
    /// Path of the `Packages` file inside `dists/<suite>/`,
    /// e.g. `main/binary-amd64/Packages.gz`.
    pub packages_file: String,
    /// Size of that file in bytes, as advertised by the signed `SHA256:` stanza.
    pub packages_size: u64,
    /// SHA-256 of that file, as advertised by the signed `SHA256:` stanza and
    /// verified against the bytes actually parsed.
    pub packages_sha256: String,
    /// Parsed package rows.
    pub packages: Vec<DebPackage>,
    /// Whether the release document was signature-verified.
    signature_verified: bool,
    /// Shape of the release document.
    release_kind: ReleaseKind,
    /// Raw bytes of the release document (`InRelease` or `Release`).
    release_doc: Vec<u8>,
    /// Detached signature bytes (`Release.gpg`); `None` for clearsigned
    /// `InRelease`.
    release_sig: Option<Vec<u8>>,
}

impl DebIndex {
    /// Whether the release document passed `gpg` verification when synced.
    pub fn signature_verified(&self) -> bool {
        self.signature_verified
    }

    /// Shape of the release document that produced this index.
    pub fn release_kind(&self) -> ReleaseKind {
        self.release_kind
    }

    /// Raw release document, retained so [`DebianFetcher::download`] can
    /// re-verify the chain without another HTTP round trip.
    pub fn release_doc(&self) -> &[u8] {
        &self.release_doc
    }

    /// Find the row for an exact `package`/`version` pair.
    pub fn find(&self, package: &str, version: &str) -> Option<&DebPackage> {
        self.packages
            .iter()
            .find(|row| row.package == package && row.version == version)
    }

    /// The first row for `package` (highest version is *not* resolved; callers
    /// that need ordering must sort [`DebIndex::packages`] themselves).
    pub fn package(&self, package: &str) -> Option<&DebPackage> {
        self.packages.iter().find(|row| row.package == package)
    }
}

/// Signature policy for [`DebianFetcher::download`].
#[derive(Debug, Clone, Copy)]
pub enum SigCheck<'a> {
    /// Re-verify the stored release document with this ASCII-armoured public
    /// key before trusting its rows (full chain).
    Key(&'a [u8]),
    /// Skip the release re-verification. The `.deb` is still checked against
    /// the size and SHA-256 recorded in the index; use this only for local
    /// fixtures or an already-verified index that was synced without a key.
    Skip,
}

/// A `.deb` that was downloaded and verified.
#[derive(Debug, Clone)]
pub struct DownloadedDeb {
    /// Where the verified `.deb` lives in the fetcher's cache directory.
    pub path: PathBuf,
    /// Package name from the index row.
    pub package: String,
    /// Version from the index row.
    pub version: String,
    /// Architecture from the index row.
    pub architecture: String,
    /// Verified size in bytes.
    pub size: u64,
    /// Verified lowercase hexadecimal SHA-256.
    pub sha256: String,
    /// URL the file was fetched from.
    pub source_url: String,
}

// ─── Fetcher ────────────────────────────────────────────────────

/// Debian/Ubuntu repository fetcher (pure-Rust backend, PLAN 3.3.2/3.3.3).
///
/// A fetcher is bound to one mirror base, one architecture and one cache
/// directory. Create it once per origin; cloning is cheap because the inner
/// [`reqwest::blocking::Client`] is reference-counted.
#[derive(Debug, Clone)]
pub struct DebianFetcher {
    mirror_base: String,
    architecture: String,
    cache_dir: PathBuf,
    origin: String,
    client: reqwest::blocking::Client,
}

impl DebianFetcher {
    /// Create a fetcher for `mirror_base` (a base URL such as
    /// `http://deb.debian.org/debian`, no trailing slash required).
    ///
    /// # Errors
    ///
    /// [`ExtosError::ConfigParse`] if the base URL is empty or the HTTP client
    /// cannot be built.
    pub fn new(
        mirror_base: impl Into<String>,
        architecture: impl Into<String>,
        cache_dir: impl Into<PathBuf>,
    ) -> Result<Self, ExtosError> {
        let mirror_base = mirror_base.into().trim_end_matches('/').to_string();
        if mirror_base.is_empty() {
            return Err(config_parse(
                "mirror_base",
                "the Debian mirror base URL must not be empty",
            ));
        }
        let architecture = architecture.into();
        if architecture.is_empty() {
            return Err(config_parse(
                "architecture",
                "the Debian architecture must not be empty",
            ));
        }
        Ok(Self {
            mirror_base,
            architecture,
            cache_dir: cache_dir.into(),
            origin: DEFAULT_ORIGIN.to_string(),
            client: build_http_client()?,
        })
    }

    /// Create a fetcher from `EXTOS_MIRRORS_DEBIAN`.
    ///
    /// The variable follows the `EXTOS_MIRRORS_<ORIGIN>` convention documented
    /// on [`crate::ingest::mirror_env_var`]: comma-separated base URLs, the
    /// first usable entry wins. No network access happens here.
    ///
    /// # Errors
    ///
    /// [`ExtosError::ConfigParse`] when the variable is unset or empty.
    pub fn from_env(
        architecture: impl Into<String>,
        cache_dir: impl Into<PathBuf>,
    ) -> Result<Self, ExtosError> {
        let base = mirror_from_env(DEFAULT_ORIGIN)?;
        Self::new(base, architecture, cache_dir)
    }

    /// Override the origin label used in errors and for `EXTOS_MIRRORS_*`
    /// lookup bookkeeping (default [`DEFAULT_ORIGIN`]).
    pub fn with_origin(mut self, origin: impl Into<String>) -> Self {
        self.origin = origin.into();
        self
    }

    /// Mirror base URL this fetcher talks to.
    pub fn mirror_base(&self) -> &str {
        &self.mirror_base
    }

    /// Architecture requested from the mirror.
    pub fn architecture(&self) -> &str {
        &self.architecture
    }

    /// Directory downloads are cached in.
    pub fn cache_dir(&self) -> &Path {
        &self.cache_dir
    }

    /// Sync and verify the `Packages` index of `<mirror>/dists/<distro>` for
    /// one component (PLAN 3.3.2).
    ///
    /// Fetches `InRelease` (falling back to `Release` + `Release.gpg` when the
    /// mirror has no `InRelease`), verifies it with `sigkey_gpg` when a key is
    /// given, then fetches the first available `Packages` variant advertised in
    /// the signed `SHA256:` stanza and confirms its size and hash.
    ///
    /// # Errors
    ///
    /// - [`ExtosError::PackageNotFound`] when the mirror serves neither
    ///   `InRelease` nor `Release` for `distro`,
    /// - [`ExtosError::CasIntegrity`] when the signature or an index hash does
    ///   not verify,
    /// - [`ExtosError::ConfigParse`] on transport failures, a missing
    ///   `gpg`/`gzip`/`xz` tool, or a release document without a `SHA256:`
    ///   stanza.
    pub fn sync_db(
        &self,
        distro: &str,
        component: &str,
        sigkey_gpg: Option<&[u8]>,
    ) -> Result<DebIndex, ExtosError> {
        validate_segment("distro", distro)?;
        validate_segment("component", component)?;

        let release = self.fetch_release(distro, sigkey_gpg)?;
        let payload = match release.kind {
            ReleaseKind::InRelease => index::clearsign_payload(&release.doc).ok_or_else(|| {
                config_parse(
                    format!("{}/dists/{distro}/InRelease", self.mirror_base),
                    "clearsigned armour could not be stripped (truncated or not a \
                     clearsigned document)",
                )
            })?,
            ReleaseKind::ReleaseDetached | ReleaseKind::ReleaseUnsigned => {
                String::from_utf8_lossy(&release.doc).into_owned()
            }
        };

        let parsed = index::parse_release(&payload);
        if parsed.checksums.is_empty() {
            return Err(config_parse(
                format!("{}/dists/{distro}", self.mirror_base),
                "release document has no SHA256 stanza; refusing an index with no integrity data",
            ));
        }
        if !parsed.components.is_empty() && !parsed.components.iter().any(|c| c == component) {
            tracing::warn!(
                "component '{component}' is not advertised by {} (advertised: {}); trying anyway",
                parsed.suite_name(),
                parsed.components.join(", ")
            );
        }
        if !parsed.architectures.is_empty()
            && !parsed.architectures.iter().any(|a| a == &self.architecture)
        {
            tracing::warn!(
                "architecture '{}' is not advertised by {} (advertised: {})",
                self.architecture,
                parsed.suite_name(),
                parsed.architectures.join(", ")
            );
        }

        for candidate in PACKAGES_CANDIDATES {
            let relpath = format!(
                "{component}/binary-{}/{candidate}",
                self.architecture
            );
            let Some(entry) = parsed.checksums.iter().find(|row| row.path == relpath) else {
                continue;
            };
            let url = format!("{}/dists/{distro}/{relpath}", self.mirror_base);
            let Some(bytes) = self.get(&url)? else {
                tracing::debug!("advertised index not served by the mirror: {url}");
                continue;
            };
            verify_bytes(&bytes, entry.size, &entry.sha256, &relpath)?;
            let decompressed = decompress(candidate, bytes)?;
            let text = String::from_utf8(decompressed).map_err(|err| {
                config_parse(&url, format!("Packages index is not valid UTF-8: {err}"))
            })?;
            let packages = index::parse_packages(&text, component);
            if packages.is_empty() {
                tracing::warn!("Packages index for {component}/{} is empty", self.architecture);
            }
            tracing::debug!(
                "synced {} packages from {url} ({} bytes)",
                packages.len(),
                entry.size
            );
            return Ok(DebIndex {
                distro: distro.to_string(),
                component: component.to_string(),
                architecture: self.architecture.clone(),
                mirror_base: self.mirror_base.clone(),
                distribution: parsed.suite_name(),
                packages_file: relpath,
                packages_size: entry.size,
                packages_sha256: entry.sha256.clone(),
                packages,
                signature_verified: release.verified,
                release_kind: release.kind,
                release_doc: release.doc,
                release_sig: release.sig,
            });
        }

        Err(config_parse(
            format!("{}/dists/{distro}", self.mirror_base),
            format!(
                "no signed Packages index for component '{component}' and architecture '{}' \
                 (looked for {})",
                self.architecture,
                PACKAGES_CANDIDATES
                    .iter()
                    .map(|name| format!("{component}/binary-{}/{name}", self.architecture))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        ))
    }

    /// Download and verify one `.deb` (PLAN 3.3.3).
    ///
    /// The file is fetched from the `Filename:` path of the index row, checked
    /// against the row's `Size` and `SHA256`, and stored atomically in
    /// [`DebianFetcher::cache_dir`]. A cached copy is reused only after its
    /// hash is re-checked; a corrupted cache entry is deleted and refetched.
    ///
    /// `sigcheck` re-verifies the release document the index was built from;
    /// pass [`SigCheck::Key`] for the full chain.
    ///
    /// # Errors
    ///
    /// - [`ExtosError::PackageNotFound`] when the row or the file is missing,
    /// - [`ExtosError::CasIntegrity`] on a size/hash/signature mismatch,
    /// - [`ExtosError::ConfigParse`] on transport failures.
    pub fn download(
        &self,
        index: &DebIndex,
        package: &str,
        version: &str,
        sigcheck: SigCheck<'_>,
    ) -> Result<DownloadedDeb, ExtosError> {
        let row = index.find(package, version).ok_or_else(|| {
            not_found(&self.origin, package, version)
        })?;
        validate_relative_path("Filename", &row.filename)?;

        if let SigCheck::Key(key) = sigcheck {
            verify_index(index, key)?;
        }

        let url = row.url(&index.mirror_base);
        let dest = self.cache_dir.join(file_name_of(&row.filename));
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }

        if dest.is_file() {
            if file_matches(&dest, row)? {
                tracing::debug!("deb cache hit: {}", dest.display());
                return Ok(downloaded(dest, row, url));
            }
            tracing::debug!(
                "cached deb failed verification, refetching: {}",
                dest.display()
            );
            fs::remove_file(&dest)?;
        }

        let Some(bytes) = self.get(&url)? else {
            return Err(not_found(&self.origin, package, version));
        };
        verify_bytes(&bytes, row.size, &row.sha256, &row.filename)?;
        write_atomically(&dest, &bytes)?;
        tracing::info!("downloaded {} → {}", url, dest.display());
        Ok(downloaded(dest, row, url))
    }

    /// Fetch `InRelease`, or `Release` (+ `Release.gpg`) as a fallback.
    fn fetch_release(
        &self,
        distro: &str,
        sigkey_gpg: Option<&[u8]>,
    ) -> Result<FetchedRelease, ExtosError> {
        let dists = format!("{}/dists/{distro}", self.mirror_base);
        let inrelease_url = format!("{dists}/InRelease");
        if let Some(doc) = self.get(&inrelease_url)? {
            let verified = match sigkey_gpg {
                Some(key) => {
                    gpg::verify_clearsigned(&doc, key)?;
                    true
                }
                None => {
                    tracing::warn!(
                        "signature verification skipped for {inrelease_url}: no key supplied"
                    );
                    false
                }
            };
            return Ok(FetchedRelease {
                doc,
                kind: ReleaseKind::InRelease,
                sig: None,
                verified,
            });
        }

        let release_url = format!("{dists}/Release");
        let Some(doc) = self.get(&release_url)? else {
            return Err(ExtosError::PackageNotFound {
                origin: self.origin.clone(),
                name: distro.to_string(),
                version: "InRelease".to_string(),
            });
        };

        match sigkey_gpg {
            Some(key) => {
                let sig_url = format!("{dists}/Release.gpg");
                let Some(sig) = self.get(&sig_url)? else {
                    return Err(ExtosError::CasIntegrity {
                        expected: format!("a detached signature at {sig_url}"),
                        actual: "the mirror serves Release without Release.gpg".to_string(),
                    });
                };
                gpg::verify_detached(&doc, &sig, key)?;
                Ok(FetchedRelease {
                    doc,
                    kind: ReleaseKind::ReleaseDetached,
                    sig: Some(sig),
                    verified: true,
                })
            }
            None => {
                tracing::warn!("signature verification skipped for {release_url}: no key supplied");
                Ok(FetchedRelease {
                    doc,
                    kind: ReleaseKind::ReleaseUnsigned,
                    sig: None,
                    verified: false,
                })
            }
        }
    }

    /// GET `url`, returning `None` on 404/410 and the body otherwise.
    fn get(&self, url: &str) -> Result<Option<Vec<u8>>, ExtosError> {
        let mut response = self.client.get(url).send().map_err(|err| {
            config_parse(url, format!("request failed: {err}"))
        })?;

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

/// Sync a Debian index without keeping a fetcher around (PLAN 3.3.2 signature).
///
/// Uses architecture [`DEFAULT_ARCH`] and [`default_cache_dir`].
pub fn sync_db(
    mirror_base: &str,
    distro: &str,
    component: &str,
    sigkey_gpg: Option<&[u8]>,
) -> Result<DebIndex, ExtosError> {
    let fetcher = DebianFetcher::new(mirror_base, DEFAULT_ARCH, default_cache_dir())?;
    fetcher.sync_db(distro, component, sigkey_gpg)
}

/// Download a `.deb` from a previously synced index (PLAN 3.3.3 signature).
///
/// Uses the architecture stored on `index` and [`default_cache_dir`]; the
/// mirror base is taken from the index so rows cannot be mixed across mirrors.
pub fn download(
    index: &DebIndex,
    package: &str,
    version: &str,
    sigcheck: SigCheck<'_>,
) -> Result<DownloadedDeb, ExtosError> {
    let fetcher = DebianFetcher::new(
        index.mirror_base.clone(),
        index.architecture.clone(),
        default_cache_dir(),
    )?;
    fetcher.download(index, package, version, sigcheck)
}

/// Default cache directory used by the free [`sync_db`] / [`download`]
/// helpers: `$EXTOS_CACHE_DIR`, else `<temp>/extos-deb-cache`.
///
/// A caller that owns a CAS repository should pass
/// `<repository>/cache/<origin>` to [`DebianFetcher::new`] instead.
pub fn default_cache_dir() -> PathBuf {
    match std::env::var("EXTOS_CACHE_DIR") {
        Ok(dir) if !dir.trim().is_empty() => PathBuf::from(dir),
        _ => std::env::temp_dir().join("extos-deb-cache"),
    }
}

// ─── Internals ──────────────────────────────────────────────────

/// Release document plus the material needed to verify it again later.
struct FetchedRelease {
    doc: Vec<u8>,
    kind: ReleaseKind,
    sig: Option<Vec<u8>>,
    verified: bool,
}

/// Re-verify the release document stored in `index` with `key`.
fn verify_index(index: &DebIndex, key: &[u8]) -> Result<(), ExtosError> {
    match (index.release_kind, &index.release_sig) {
        (ReleaseKind::InRelease, _) => gpg::verify_clearsigned(&index.release_doc, key),
        (ReleaseKind::ReleaseDetached, Some(sig)) => {
            gpg::verify_detached(&index.release_doc, sig, key)
        }
        (ReleaseKind::ReleaseDetached, None) => Err(ExtosError::CasIntegrity {
            expected: "a detached signature for the release document".to_string(),
            actual: "the index carries no Release.gpg bytes".to_string(),
        }),
        (ReleaseKind::ReleaseUnsigned, _) => Err(ExtosError::CasIntegrity {
            expected: "a signature-verified Debian index".to_string(),
            actual: "the index was synced without a key; re-run sync_db with one".to_string(),
        }),
    }
}

/// Compare `bytes` against an advertised size and SHA-256.
fn verify_bytes(
    bytes: &[u8],
    expected_size: u64,
    expected_sha256: &str,
    what: &str,
) -> Result<(), ExtosError> {
    if bytes.len() as u64 != expected_size {
        return Err(ExtosError::CasIntegrity {
            expected: format!("{expected_size} bytes for {what}"),
            actual: format!("{} bytes", bytes.len()),
        });
    }
    let actual = sha256_hex(bytes);
    if !actual.eq_ignore_ascii_case(expected_sha256) {
        return Err(ExtosError::CasIntegrity {
            expected: format!("sha256 {expected_sha256} for {what}"),
            actual: format!("sha256 {actual}"),
        });
    }
    Ok(())
}

/// `true` when the cached file still matches the index row.
fn file_matches(path: &Path, row: &DebPackage) -> Result<bool, ExtosError> {
    if fs::metadata(path)?.len() != row.size {
        return Ok(false);
    }
    Ok(hash_file(path)?.eq_ignore_ascii_case(&row.sha256))
}

/// Streaming SHA-256 of a file, lowercase hexadecimal.
fn hash_file(path: &Path) -> Result<String, ExtosError> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buf)?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Lowercase hexadecimal SHA-256 of a byte slice.
fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
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

/// Decompress an index body when its filename says it is compressed.
///
/// Plain `Packages` is returned unchanged; `.gz`/`.xz` are piped through the
/// corresponding system tool. A missing tool is a typed error naming it, never
/// a silent skip.
fn decompress(name: &str, data: Vec<u8>) -> Result<Vec<u8>, ExtosError> {
    if name.ends_with(".gz") {
        run_decompressor("gzip", data, name)
    } else if name.ends_with(".xz") {
        run_decompressor("xz", data, name)
    } else {
        Ok(data)
    }
}

/// Maximum allowed inflation ratio of a decompressed index body.
///
/// A hostile mirror can serve a few kilobytes of `.gz` that expand to gigabytes
/// (a zip bomb), so the decompressor never gets to allocate without a bound:
/// at most [`INFLATE_RATIO`] times the compressed size, clamped below to
/// [`MIN_INFLATE_BYTES`] and above to [`MAX_BODY_BYTES`] (the same ceiling a
/// buffered download already respects).
const INFLATE_RATIO: u64 = 64;

/// Floor for the decompression cap; real `Packages` indexes are a few MiB.
const MIN_INFLATE_BYTES: u64 = 16 * 1024 * 1024;

/// Inflation cap for an index body of `compressed_len` bytes (auditor R1).
fn inflate_cap(compressed_len: u64) -> u64 {
    compressed_len
        .saturating_mul(INFLATE_RATIO)
        .clamp(MIN_INFLATE_BYTES, MAX_BODY_BYTES)
}

/// Pipe `data` through `<tool> -dc`, refusing output larger than [`inflate_cap`].
///
/// The child is always `wait`ed for, including on the over-cap path, so no
/// zombie survives a hostile index.
fn run_decompressor(tool: &str, data: Vec<u8>, name: &str) -> Result<Vec<u8>, ExtosError> {
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
                    "cannot run '{tool}' to decompress {name}: {err}; install '{tool}' \
                     or mirror a plain Packages index"
                ),
            )
        })?;

    let compressed_len = data.len() as u64;
    let cap = inflate_cap(compressed_len);

    let mut stdin = child.stdin.take().ok_or_else(|| {
        config_parse(tool, format!("cannot open stdin of '{tool}'"))
    })?;
    let tool_name = tool.to_string();
    let writer = std::thread::spawn(move || {
        if let Err(err) = stdin.write_all(&data) {
            tracing::debug!("writing to '{tool_name}' failed: {err}");
        }
    });

    let stdout = child.stdout.take().ok_or_else(|| {
        config_parse(tool, format!("cannot open stdout of '{tool}'"))
    })?;
    let mut out = Vec::new();
    // One byte past the cap is enough to tell "at the cap" from "over it"
    // without ever buffering the whole inflation.
    let mut limited = stdout.take(cap.saturating_add(1));
    let read_result = limited.read_to_end(&mut out);
    drop(limited);

    let over_cap = out.len() as u64 > cap;
    if over_cap || read_result.is_err() {
        // Stop the tool before draining stderr: a child still writing to a
        // full stdout pipe would otherwise never close stderr and we would
        // deadlock instead of reporting the cap violation.
        let _ = child.kill();
    }

    let mut err_buf = String::new();
    if let Some(mut stderr) = child.stderr.take() {
        let _ = stderr.read_to_string(&mut err_buf);
    }
    let status = child.wait()?;
    let _ = writer.join();
    if over_cap {
        return Err(config_parse(
            name,
            format!(
                "{tool} -dc inflated {name} past its {cap}-byte cap \
                 ({INFLATE_RATIO}x the {compressed_len}-byte compressed body); \
                 refusing a possible decompression bomb"
            ),
        ));
    }
    read_result?;

    if !status.success() {
        return Err(config_parse(
            name,
            format!("{tool} -dc failed ({status}): {}", err_buf.trim()),
        ));
    }
    Ok(out)
}

/// Reject path traversal in `distro` / `component` before they enter a URL.
fn validate_segment(kind: &str, value: &str) -> Result<(), ExtosError> {
    let valid = !value.is_empty()
        && !value.starts_with('/')
        && !value.contains("..")
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '+' | '~'));
    if valid {
        Ok(())
    } else {
        Err(config_parse(
            kind,
            format!("invalid Debian {kind} name '{value}'"),
        ))
    }
}

/// Reject a `Filename:` path that is absolute or escapes the mirror root.
///
/// Only the basename is ever used as the cache destination, but the full path
/// still enters a URL, so a hostile index must not be able to redirect a fetch
/// to another host path.
fn validate_relative_path(kind: &str, value: &str) -> Result<(), ExtosError> {
    let valid = !value.is_empty()
        && !value.starts_with('/')
        && !value.contains('\\')
        && !value.split('/').any(|segment| segment == "..");
    if valid {
        Ok(())
    } else {
        Err(config_parse(
            kind,
            format!("refusing a non-relative Debian package path '{value}'"),
        ))
    }
}

/// Last path component of a `Filename:` field.
fn file_name_of(filename: &str) -> String {
    filename
        .rsplit('/')
        .next()
        .filter(|name| !name.is_empty())
        .unwrap_or("package.deb")
        .to_string()
}

/// Build the [`DownloadedDeb`] result for a verified cached file.
fn downloaded(path: PathBuf, row: &DebPackage, source_url: String) -> DownloadedDeb {
    DownloadedDeb {
        path,
        package: row.package.clone(),
        version: row.version.clone(),
        architecture: row.architecture.clone(),
        size: row.size,
        sha256: row.sha256.clone(),
        source_url,
    }
}

/// [`ExtosError::PackageNotFound`] helper.
fn not_found(origin: &str, name: &str, version: &str) -> ExtosError {
    ExtosError::PackageNotFound {
        origin: origin.to_string(),
        name: name.to_string(),
        version: version.to_string(),
    }
}

/// [`ExtosError::ConfigParse`] helper (Debian fetching has no dedicated error
/// variant; `ingest` reports mirror failures the same way).
fn config_parse(path: impl Into<String>, message: impl Into<String>) -> ExtosError {
    ExtosError::ConfigParse {
        path: path.into(),
        line: 0,
        message: message.into(),
    }
}

/// First configured mirror from `EXTOS_MIRRORS_<ORIGIN>`.
///
/// The variable name comes from [`crate::ingest::mirror_env_var`], so the
/// Debian fetcher cannot drift from the convention used by `pkt -S`; the list
/// parsing itself lives here (comma-separated, whitespace-trimmed, trailing
/// slashes dropped, first entry wins).
fn mirror_from_env(origin: &str) -> Result<String, ExtosError> {
    let var = crate::ingest::mirror_env_var(origin);
    mirror_from_lookup(&var, |key| std::env::var(key).ok())
}

/// Lookup-injectable form of [`mirror_from_env`] (unit-testable without
/// mutating the process environment).
fn mirror_from_lookup<F>(var: &str, lookup: F) -> Result<String, ExtosError>
where
    F: Fn(&str) -> Option<String>,
{
    let raw = lookup(var).ok_or_else(|| {
        config_parse(
            var,
            format!(
                "no Debian mirror configured; set {var} to one or more comma-separated base URLs"
            ),
        )
    })?;
    raw.split(',')
        .map(|entry| entry.trim().trim_end_matches('/'))
        .find(|entry| !entry.is_empty())
        .map(str::to_string)
        .ok_or_else(|| config_parse(var, format!("{var} contains no usable mirror URL")))
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

#[cfg(test)]
mod tests {
    use super::*;

    /// `true` when `tool` answers `--version`.
    fn have_tool(tool: &str) -> bool {
        Command::new(tool)
            .arg("--version")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
    }

    #[test]
    fn sha256_hex_matches_known_vector() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn validate_segment_blocks_traversal() {
        assert!(validate_segment("distro", "bookworm").is_ok());
        assert!(validate_segment("distro", "bookworm-updates").is_ok());
        assert!(validate_segment("distro", "trixie/updates").is_err());
        assert!(validate_segment("distro", "../etc").is_err());
        assert!(validate_segment("distro", "/etc/passwd").is_err());
        assert!(validate_segment("component", "").is_err());
        assert!(validate_segment("component", "main non-free").is_err());
    }

    #[test]
    fn file_name_of_uses_last_component() {
        assert_eq!(
            file_name_of("pool/main/h/hello/hello_1.0_amd64.deb"),
            "hello_1.0_amd64.deb"
        );
        assert_eq!(file_name_of(""), "package.deb");
    }

    #[test]
    fn validate_relative_path_blocks_escapes() {
        assert!(validate_relative_path("Filename", "pool/main/h/hello/h.deb").is_ok());
        assert!(validate_relative_path("Filename", "../etc/passwd").is_err());
        assert!(validate_relative_path("Filename", "/etc/passwd").is_err());
        assert!(validate_relative_path("Filename", "pool/../../x.deb").is_err());
        assert!(validate_relative_path("Filename", "").is_err());
    }

    #[test]
    fn mirror_lookup_takes_the_first_usable_entry() {
        let base = mirror_from_lookup("EXTOS_MIRRORS_DEBIAN", |key| {
            assert_eq!(key, "EXTOS_MIRRORS_DEBIAN");
            Some(" http://a/debian/ , http://b/debian ".to_string())
        })
        .expect("mirror resolved");
        assert_eq!(base, "http://a/debian");

        let err = mirror_from_lookup("EXTOS_MIRRORS_DEBIAN", |_| None)
            .expect_err("unset variable must fail");
        assert!(matches!(err, ExtosError::ConfigParse { .. }));

        let err = mirror_from_lookup("EXTOS_MIRRORS_DEBIAN", |_| Some(" , ".to_string()))
            .expect_err("empty list must fail");
        assert!(matches!(err, ExtosError::ConfigParse { .. }));
    }

    #[test]
    fn pure_rust_backend_is_always_available() {
        assert_eq!(available_backend(), DebianBackend::PureRust);
        assert!(is_available());
        assert!(backend_report().pure_rust);
    }

    #[test]
    fn plain_index_is_returned_unchanged() {
        let data = b"Package: hello\n".to_vec();
        assert_eq!(decompress("Packages", data.clone()).unwrap(), data);
    }

    #[test]
    fn gzip_index_is_decompressed_when_tool_present() {
        if !have_tool("gzip") {
            eprintln!("skipping: gzip not available");
            return;
        }
        let original = b"Package: hello\nVersion: 1\n".to_vec();
        let mut child = Command::new("gzip")
            .arg("-c")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn gzip");
        child
            .stdin
            .take()
            .expect("gzip stdin")
            .write_all(&original)
            .expect("write gzip input");
        let compressed = child.wait_with_output().expect("gzip output").stdout;
        assert_ne!(compressed, original);
        assert_eq!(
            decompress("Packages.gz", compressed).unwrap(),
            original
        );
    }

    #[test]
    fn xz_index_is_decompressed_when_tool_present() {
        if !have_tool("xz") {
            eprintln!("skipping: xz not available");
            return;
        }
        let original = b"Package: hello\nVersion: 1\n".to_vec();
        let mut child = Command::new("xz")
            .arg("-c")
            .arg("-z")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn xz");
        child
            .stdin
            .take()
            .expect("xz stdin")
            .write_all(&original)
            .expect("write xz input");
        let compressed = child.wait_with_output().expect("xz output").stdout;
        assert_eq!(decompress("Packages.xz", compressed).unwrap(), original);
    }

    #[test]
    fn gzip_bomb_is_rejected_at_the_inflation_cap() {
        if !have_tool("gzip") {
            eprintln!("skipping: gzip not available");
            return;
        }
        // 32 MiB of zeros compresses to a few KiB, so it is the 16 MiB floor
        // of the cap that the inflation must cross: a textbook zip bomb.
        const BOMB_MIB: u64 = 32;
        let mut child = Command::new("gzip")
            .arg("-c")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn gzip");
        {
            let mut stdin = child.stdin.take().expect("gzip stdin");
            let chunk = [0u8; 1024 * 1024];
            for _ in 0..BOMB_MIB {
                stdin.write_all(&chunk).expect("write gzip input");
            }
        }
        let compressed = child.wait_with_output().expect("gzip output").stdout;
        let cap = inflate_cap(compressed.len() as u64);
        assert!(
            cap < BOMB_MIB * 1024 * 1024,
            "fixture must exceed the cap (cap {cap}, bomb {} bytes)",
            BOMB_MIB * 1024 * 1024
        );

        let err = decompress("Packages.gz", compressed).unwrap_err();
        match &err {
            ExtosError::ConfigParse { message, .. } => assert!(
                message.contains("-byte cap"),
                "the error must name the cap, got: {message}"
            ),
            other => panic!("a bomb must be a typed ConfigParse error, got {other}"),
        }
    }

    #[test]
    fn missing_decompressor_is_a_typed_error() {
        let err = decompress("Packages.gz", b"not really gzip".to_vec()).unwrap_err();
        // Either the tool is missing (ConfigParse on the tool name) or it
        // rejects the bogus input; both are typed.
        assert!(matches!(
            err,
            ExtosError::ConfigParse { .. } | ExtosError::Io(_)
        ));
    }

    #[test]
    fn empty_mirror_base_is_rejected() {
        let err = DebianFetcher::new("", "amd64", std::env::temp_dir());
        assert!(matches!(err, Err(ExtosError::ConfigParse { .. })));
    }

    #[test]
    fn verify_bytes_reports_size_and_hash_mismatches() {
        let data = b"hello";
        let sha = sha256_hex(data);
        assert!(verify_bytes(data, 5, &sha, "x").is_ok());
        assert!(matches!(
            verify_bytes(data, 6, &sha, "x"),
            Err(ExtosError::CasIntegrity { .. })
        ));
        assert!(matches!(
            verify_bytes(data, 5, &"0".repeat(64), "x"),
            Err(ExtosError::CasIntegrity { .. })
        ));
    }
}
