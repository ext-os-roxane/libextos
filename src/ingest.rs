//! Package ingestion pipeline (M3.5 — Hash & Commit to CAS).
//!
//! Orchestrates the full pipeline:
//! 1. Extract archive → staging (M3.2 / plugin EXTRACT)
//! 2. Parse metadata → identity (M3.4 / plugin PARSE)
//! 3. Translate deps → DependencySpec (M4 / plugin TRANSLATE)
//! 4. Scan ELF binaries → capabilities (M3.3)
//! 5. Hash content → commit to CAS objects (M3.5)
//! 6. Create refs symlinks
//!
//! # Phase 3 fetcher wiring
//!
//! The Phase-3 fetchers ([`crate::fetcher::alpm`], [`crate::fetcher::debian`],
//! [`crate::fetcher::rpm`]) are opt-in transports for *artifact acquisition
//! only*. They are wired at exactly one seam: [`download_from_mirror_to`] (and
//! its convenience wrapper [`download_from_mirror`]) — the step that turns
//! `origin/name=version` into a verified local archive path. Everything after
//! that (extract → manifest → ELF scan → CAS commit → refs) is the unchanged
//! pipeline below; the fetchers never re-implement it.
//!
//! | PLAN task | transport | code seam |
//! |---|---|---|
//! | 3.2.6 | libalpm (`AlpmFetch`) | [`download_from_mirror_to`] → `download_via_alpm` |
//! | 3.3.4 | APT infrastructure (`DebianFetcher`) | [`download_from_mirror_to`] → `download_via_debian` |
//! | 3.4.5 | RPM repository (`RpmFetcher`) | [`download_from_mirror_to`] → `download_via_rpm` |
//!
//! Selection is explicit and per origin: `EXTOS_FETCHER_<ORIGIN>` (see
//! [`fetcher_env_var`]) accepts `alpm`, `debian`, `rpm` or `http`. Unset means
//! the Phase-2 mirror chain ([`mirror_urls`] + `reqwest`), which stays the
//! default for every origin. There is deliberately **no auto-detection** of
//! transports: a fetcher needs a loadable transport library (`libalpm`) or an
//! external tool (`gpg`), neither of which is hermetically present, so the
//! default path stays transport-light. An unknown value is a typed
//! [`ExtosError::ConfigParse`]; it never silently falls back to HTTP. Likewise,
//! a missing transport library is a typed error naming what is absent — falling
//! back is always an explicit user action
//! (`EXTOS_FETCHER_<ORIGIN>=http`).
//!
//! `EXTOS_MIRRORS_<ORIGIN>` keeps its meaning under every transport: it is
//! where the base URL(s) come from. For `alpm` the first entry must point at a
//! repository directory (`.../core/os/x86_64`); for `debian` at the archive
//! root (`https://deb.debian.org/debian`); for `rpm` at the repository root
//! (`.../Everything/x86_64/os`).

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::cas::CasRepository;
use crate::elf_scan;
use crate::error::ExtosError;
use crate::extract::{self, ArchiveKind, ExtractedPackage};
use crate::manifest::{Capabilities, PackageIdentity};
use crate::rosetta::registry::RosettaRegistry;
use crate::rosetta::{PluginCapability, RosettaPlugin};
use crate::types::PackageFormat;

/// Default HTTP timeout for a single mirror download, in seconds.
const DEFAULT_DOWNLOAD_TIMEOUT_SECS: u64 = 300;

/// Default TCP connect timeout for a mirror, in seconds.
const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 30;

/// Result of a successful ingestion.
#[derive(Debug)]
pub struct IngestResult {
    /// The CAS object hash (algo-prefixed)
    pub hash: String,
    /// The origin namespace used for refs
    pub origin: String,
    /// The package name
    pub name: String,
    /// The package version
    pub version: String,
    /// Auto-discovered capabilities
    pub capabilities: Capabilities,
    /// Whether a Rosetta plugin was used for metadata translation
    pub rosetta_translated: bool,
    /// setuid/setgid bits stripped from regular files during sanitization
    /// (PLAN 6.1.1). Always `0` when the payload carried none.
    pub sanitized_bits: usize,
}

/// Default origin namespace used when only the archive format is known.
///
/// This is the auto-detection table used by `pkt -U` for local files and by
/// [`ingest_local_archive`].
pub fn default_origin_for_archive(kind: ArchiveKind) -> &'static str {
    match kind {
        ArchiveKind::PkgTarZst | ArchiveKind::PkgTarXz => "archlinux",
        ArchiveKind::Deb => "debian",
        ArchiveKind::Apk => "alpine",
        ArchiveKind::PktTarXz => "scratch",
    }
}

/// Ingest a local package archive, auto-detecting its origin.
///
/// Native `.pkt.tar.xz` archives are handed to [`ingest_native_package`]
/// (they carry their own `manifest.nix`); every other format runs the standard
/// pipeline with the origin implied by [`default_origin_for_archive`]. No
/// Rosetta plugin is consulted — use [`ingest_local_archive_with_rosetta`] when
/// an origin-specific plugin should parse the metadata.
pub fn ingest_local_archive(
    repo: &CasRepository,
    archive_path: &Path,
) -> Result<IngestResult, ExtosError> {
    let kind = detect_archive_kind(archive_path)?;
    if kind == ArchiveKind::PktTarXz {
        return ingest_native_package(repo, archive_path);
    }
    ingest_local_archive_with_rosetta(
        repo,
        archive_path,
        default_origin_for_archive(kind),
        None,
    )
}

/// Ingest a local package archive under an explicit origin, with optional
/// Rosetta plugin dispatch.
///
/// This is the single entry point for the extract → parse identity → ELF scan →
/// manifest → CAS commit pipeline:
///
/// 1. extract to `<repository>/_staging/<archive>`
/// 2. resolve identity + `manifest.nix` (plugin `PARSE`, or built-in fallback)
/// 3. scan ELF binaries for capabilities
/// 4. `cas::store_directory` + `cas::write_manifest`
/// 5. create `refs/<origin>/<name>/<version>` and `<version>/current`
///
/// A `.pkt.tar.xz` archive is always delegated to [`ingest_native_package`],
/// because its embedded manifest is authoritative.
pub fn ingest_local_archive_with_rosetta(
    repo: &CasRepository,
    archive_path: &Path,
    origin: &str,
    registry: Option<&RosettaRegistry>,
) -> Result<IngestResult, ExtosError> {
    if detect_archive_kind(archive_path)? == ArchiveKind::PktTarXz {
        return ingest_native_package(repo, archive_path);
    }
    run_pipeline(repo, archive_path, origin, registry)
}

/// Ingest a package archive into the CAS repository (legacy, no plugin).
///
/// Full pipeline: extract → scan → manifest stub → hash → commit → refs.
pub fn ingest_package(
    repo: &CasRepository,
    archive_path: &Path,
    origin: &str,
) -> Result<IngestResult, ExtosError> {
    ingest_package_with_rosetta(repo, archive_path, origin, None)
}

/// Ingest a package archive with optional Rosetta plugin dispatch.
///
/// If a plugin is provided and supports the required capabilities,
/// the plugin handles metadata parsing, dependency translation, and
/// optionally extraction. Otherwise falls back to built-in logic.
///
/// Thin wrapper over [`ingest_local_archive_with_rosetta`].
pub fn ingest_package_with_rosetta(
    repo: &CasRepository,
    archive_path: &Path,
    origin: &str,
    registry: Option<&RosettaRegistry>,
) -> Result<IngestResult, ExtosError> {
    ingest_local_archive_with_rosetta(repo, archive_path, origin, registry)
}

fn detect_archive_kind(archive_path: &Path) -> Result<ArchiveKind, ExtosError> {
    ArchiveKind::detect(archive_path).ok_or_else(|| ExtosError::ConfigParse {
        path: archive_path.to_string_lossy().into(),
        line: 0,
        message: format!(
            "unrecognized archive format (expected .pkg.tar.zst, .pkg.tar.xz, .deb, .apk or .pkt.tar.xz): {}",
            archive_path.display()
        ),
    })
}

/// Run the extraction → manifest → CAS pipeline in a per-archive staging dir.
///
/// The staging directory is always removed, including on failure, so a parse
/// error never leaves a half-extracted tree behind.
fn run_pipeline(
    repo: &CasRepository,
    archive_path: &Path,
    origin: &str,
    registry: Option<&RosettaRegistry>,
) -> Result<IngestResult, ExtosError> {
    let staging_dir = repo.root.join("_staging");
    let pkg_staging = staging_dir.join(staging_key(archive_path));
    fs::create_dir_all(&pkg_staging)?;

    let outcome = pipeline_inner(repo, archive_path, origin, registry, &pkg_staging);
    let _ = fs::remove_dir_all(&pkg_staging);
    outcome
}

/// Unique-ish staging directory name: `<file stem>-<pid>`.
fn staging_key(archive_path: &Path) -> String {
    let stem = archive_path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "package".to_string());
    format!("{stem}-{}", std::process::id())
}

fn pipeline_inner(
    repo: &CasRepository,
    archive_path: &Path,
    origin: &str,
    registry: Option<&RosettaRegistry>,
    pkg_staging: &Path,
) -> Result<IngestResult, ExtosError> {
    // Look up plugin for this origin
    let plugin: Option<std::sync::Arc<dyn RosettaPlugin>> = registry.and_then(|r| r.get(origin));

    // Step 1: Extract (plugin EXTRACT or built-in M3.2)
    let extracted = match plugin.as_deref() {
        Some(p) if p.capabilities().contains(PluginCapability::EXTRACT) => {
            let metadata_dir = pkg_staging.join("metadata");
            let content_dir = pkg_staging.join("content");
            fs::create_dir_all(&metadata_dir)?;
            fs::create_dir_all(&content_dir)?;
            p.extract(archive_path, pkg_staging)?;
            // Normalize ownership after plugin extraction
            crate::extract::normalize_ownership_if_root(&content_dir)?;
            ExtractedPackage {
                staging_dir: pkg_staging.to_path_buf(),
                metadata_dir,
                content_dir,
                kind: ArchiveKind::detect(archive_path).unwrap_or(ArchiveKind::PkgTarZst),
            }
        }
        _ => extract::extract_package(archive_path, pkg_staging)?,
    };

    // Step 1b: CAS sanitizer (PLAN 6.1.1) — strip setuid/setgid from every
    // regular file before the content tree is hashed and committed, so the
    // stored object can never carry them.
    let sanitized_bits = sanitize_permissions(&extracted.content_dir)?;

    // Step 2: Parse metadata → identity + manifest.nix (plugin PARSE or built-in)
    let (identity, manifest_nix, rosetta_translated) =
        build_identity_and_manifest(&extracted, origin, plugin.as_deref())?;

    // Step 3: ELF scan (always — supplements plugin output)
    let capabilities = elf_scan::scan_capabilities(&extracted.content_dir)?;

    // Step 4: Write manifest to staging
    fs::write(extracted.metadata_dir.join("manifest.nix"), &manifest_nix)?;

    // Step 5: Hash & commit content tree to CAS (M3.5)
    let hash = repo.store_directory(&extracted.content_dir)?;
    repo.write_manifest(&hash, &manifest_nix)?;

    // Step 6: Create refs
    repo.create_ref(origin, &identity.name, &identity.version, &hash)?;
    repo.update_current(origin, &identity.name, &identity.version)?;

    Ok(IngestResult {
        hash,
        origin: origin.to_string(),
        name: identity.name,
        version: identity.version,
        capabilities,
        rosetta_translated,
        sanitized_bits,
    })
}

/// Strip the setuid (`0o4000`) and setgid (`0o2000`) bits from every regular
/// file under `content_dir`, returning how many files were changed
/// (PLAN 6.1.1, the "CAS sanitizer" of `design/ARCHITECTURE.md`).
///
/// The CAS is the immutable substrate every roof is woven from; privilege
/// bits must therefore never enter it. Directories keep their setgid bit
/// (legitimate for shared drop-boxes); symlinks carry no modes and are
/// skipped. Escalated privilege re-enters declaratively at weave time via
/// file capabilities (PLAN 6.1.2, `security::filecaps`).
pub fn sanitize_permissions(content_dir: &Path) -> Result<usize, ExtosError> {
    use std::os::unix::fs::PermissionsExt;

    let mut stripped = 0usize;
    let mut stack = vec![content_dir.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            let meta = entry.metadata()?; // stat the link target for files
            if meta.is_dir() {
                stack.push(path);
                continue;
            }
            if !meta.is_file() {
                continue;
            }
            let mode = meta.permissions().mode();
            if mode & 0o6000 != 0 {
                fs::set_permissions(&path, fs::Permissions::from_mode(mode & !0o6000))?;
                stripped += 1;
            }
        }
    }
    if stripped > 0 {
        tracing::info!("CAS sanitizer stripped {stripped} setuid/setgid file(s)");
    }
    Ok(stripped)
}

/// Resolve package identity and a `manifest.nix` body for an extracted package.
///
/// Returns `(identity, manifest_nix, rosetta_translated)`. A plugin that
/// advertises `PARSE` is tried first; if it fails or yields an unparseable
/// manifest, the built-in stub generator is used instead so ingestion never
/// depends on a plugin being installed.
fn build_identity_and_manifest(
    extracted: &ExtractedPackage,
    origin: &str,
    plugin: Option<&dyn RosettaPlugin>,
) -> Result<(PackageIdentity, String, bool), ExtosError> {
    if let Some(p) = plugin {
        if p.capabilities().contains(PluginCapability::PARSE) {
            let manifest_nix = p.parse_metadata(&extracted.metadata_dir)?;
            let parsed = crate::config::parse_nix(&manifest_nix)
                .ok()
                .and_then(|nix_val| crate::manifest::PackageManifest::from_nix(&nix_val).ok());
            if let Some(manifest) = parsed {
                return Ok((manifest.identity, manifest_nix, true));
            }
            tracing::warn!(
                "Rosetta plugin for '{origin}' produced an unparseable manifest; \
                 falling back to the built-in stub manifest"
            );
        }
    }

    let identity = parse_identity_from_metadata(extracted, origin)?;
    let capabilities = elf_scan::scan_capabilities(&extracted.content_dir)?;
    let stub = generate_stub_manifest(&identity, &capabilities, extracted);
    Ok((identity, format_manifest_nix(&stub), false))
}

// ─── Mirror resolution & download (PLAN 2.1.2) ──────────────────

/// Environment variable name holding the mirror list for an origin.
///
/// `archlinux` → `EXTOS_MIRRORS_ARCHLINUX`. Non-alphanumeric characters in the
/// origin become `_`, so `shadichy-labs` → `EXTOS_MIRRORS_SHADICHY_LABS`.
pub fn mirror_env_var(origin: &str) -> String {
    let mut out = String::from("EXTOS_MIRRORS_");
    for ch in origin.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_uppercase());
        } else {
            out.push('_');
        }
    }
    out
}

/// Split a comma-separated mirror list, trimming whitespace and trailing `/`.
///
/// Empty entries are dropped and duplicates removed (first occurrence wins),
/// so `" a/ , b ,, a/ "` → `["a", "b"]`.
pub fn parse_mirrors(raw: &str) -> Vec<String> {
    let mut mirrors: Vec<String> = Vec::new();
    for candidate in raw.split(',') {
        let base = candidate.trim().trim_end_matches('/');
        if base.is_empty() {
            continue;
        }
        if !mirrors.iter().any(|m| m == base) {
            mirrors.push(base.to_string());
        }
    }
    mirrors
}

/// Resolve the configured mirror base URLs for `origin`.
///
/// Reads `EXTOS_MIRRORS_<ORIGIN>` (see [`mirror_env_var`]). Returns
/// [`ExtosError::ConfigParse`] when the variable is unset or contains no usable
/// entries — no network access happens here.
pub fn mirrors_for_origin(origin: &str) -> Result<Vec<String>, ExtosError> {
    mirrors_from_lookup(origin, |key| std::env::var(key).ok())
}

/// Lookup-injectable form of [`mirrors_for_origin`] (used by unit tests).
fn mirrors_from_lookup<F>(origin: &str, lookup: F) -> Result<Vec<String>, ExtosError>
where
    F: Fn(&str) -> Option<String>,
{
    let var = mirror_env_var(origin);
    let raw = lookup(&var).ok_or_else(|| unconfigured_mirror(origin, &var))?;
    let mirrors = parse_mirrors(&raw);
    if mirrors.is_empty() {
        return Err(ExtosError::ConfigParse {
            path: var,
            line: 0,
            message: format!(
                "no usable mirror configured for origin '{origin}': the variable is empty"
            ),
        });
    }
    Ok(mirrors)
}

fn unconfigured_mirror(origin: &str, var: &str) -> ExtosError {
    ExtosError::ConfigParse {
        path: var.to_string(),
        line: 0,
        message: format!(
            "no mirror configured for origin '{origin}'; \
             set {var} to one or more comma-separated base URLs \
             (entries may use {{origin}}, {{name}} and {{version}} placeholders)"
        ),
    }
}

/// Archive filename convention for an origin.
///
/// Used to build mirror URLs when a mirror entry is a plain base URL:
///
/// | origin | filename |
/// |---|---|
/// | `archlinux` | `<name>-<version>-x86_64.pkg.tar.zst` |
/// | `debian` | `<name>_<version>_amd64.deb` |
/// | `alpine` | `<name>-<version>.apk` |
/// | `scratch` / `extos` | `<name>-<version>.pkt.tar.xz` |
/// | anything else | `<name>-<version>.pkg.tar.xz` |
pub fn package_filename(origin: &str, name: &str, version: &str) -> String {
    match origin {
        "archlinux" | "arch" => format!("{name}-{version}-x86_64.pkg.tar.zst"),
        "debian" | "ubuntu" => format!("{name}_{version}_amd64.deb"),
        "alpine" => format!("{name}-{version}.apk"),
        "scratch" | "extos" => format!("{name}-{version}.pkt.tar.xz"),
        _ => format!("{name}-{version}.pkg.tar.xz"),
    }
}

/// Build the candidate download URLs for every configured mirror.
///
/// A mirror entry containing `{` is treated as a full URL template and gets
/// `{origin}`, `{name}` and `{version}` expanded. Every other entry is a base
/// URL to which `/<filename>` is appended (see [`package_filename`]).
pub fn mirror_urls(
    mirrors: &[String],
    origin: &str,
    name: &str,
    version: &str,
) -> Vec<String> {
    let filename = package_filename(origin, name, version);
    mirrors
        .iter()
        .map(|base| {
            if base.contains('{') {
                base.replace("{origin}", origin)
                    .replace("{name}", name)
                    .replace("{version}", version)
            } else {
                format!("{}/{}", base.trim_end_matches('/'), filename)
            }
        })
        .collect()
}

/// Where a downloaded archive is cached: `<cache_dir>/<origin>/<filename>`.
pub fn cache_path_for(
    cache_dir: &Path,
    origin: &str,
    name: &str,
    version: &str,
) -> PathBuf {
    cache_dir
        .join(origin)
        .join(package_filename(origin, name, version))
}

/// Default download cache when no repository is available:
/// `$EXTOS_CACHE_DIR`, else the platform temp dir + `extos-cache`.
///
/// `pkt` always passes its own `<repository>/cache` via
/// [`download_from_mirror_to`] instead of relying on this default.
pub fn default_cache_dir() -> PathBuf {
    match std::env::var("EXTOS_CACHE_DIR") {
        Ok(dir) if !dir.trim().is_empty() => PathBuf::from(dir),
        _ => std::env::temp_dir().join("extos-cache"),
    }
}

/// Download `<origin>/<name>/<version>` from the configured mirrors into the
/// default cache directory (see [`default_cache_dir`]).
///
/// Convenience wrapper over [`download_from_mirror_to`]; prefer the latter when
/// a CAS repository is open so the archive lands in `<repository>/cache`.
pub fn download_from_mirror(
    origin: &str,
    name: &str,
    version: &str,
) -> Result<PathBuf, ExtosError> {
    download_from_mirror_to(origin, name, version, &default_cache_dir())
}

/// Download `<origin>/<name>/<version>` into `cache_dir/<origin>/`.
///
/// The transport is chosen by `EXTOS_FETCHER_<ORIGIN>` (see [`FetcherKind`]);
/// unset selects [`FetcherKind::Http`]. The mirror base URLs always come from
/// `EXTOS_MIRRORS_<ORIGIN>` (see [`mirrors_for_origin`]).
///
/// With the default HTTP transport the mirrors are tried in order. The archive
/// is streamed to a `.part` file and renamed only after a complete, successful
/// transfer, so a partial download can never be mistaken for a valid package.
/// An already-cached file is reused without network access.
///
/// With a Phase-3 fetcher (`alpm`, `debian`, `rpm`) the fetcher owns transfer
/// and caching: it may re-sync its repository index before handing back a
/// cache-hit, and every returned path has already been size-checked and
/// (according to the configured policy) signature-verified. A missing transport
/// library is a typed error naming it — never a silent HTTP fallback.
///
/// Errors:
/// - [`ExtosError::ConfigParse`] — no mirror configured, an unknown
///   `EXTOS_FETCHER_<ORIGIN>` value, a missing transport library/tool, or every
///   mirror failed for a non-404 reason (message lists each attempted URL)
/// - [`ExtosError::PackageNotFound`] — every mirror answered 404, or the
///   repository/index does not carry the requested package/version
/// - [`ExtosError::CasIntegrity`] — a fetcher size/signature verification failed
pub fn download_from_mirror_to(
    origin: &str,
    name: &str,
    version: &str,
    cache_dir: &Path,
) -> Result<PathBuf, ExtosError> {
    match fetcher_for_origin(origin)? {
        FetcherKind::Http => download_via_http(origin, name, version, cache_dir),
        FetcherKind::Alpm => download_via_alpm(origin, name, version, cache_dir),
        FetcherKind::Debian => download_via_debian(origin, name, version, cache_dir),
        FetcherKind::Rpm => download_via_rpm(origin, name, version, cache_dir),
    }
}

/// Transport that acquires an artifact for an origin (PLAN 3.2.6 / 3.3.4 / 3.4.5).
///
/// Selected per origin by `EXTOS_FETCHER_<ORIGIN>`; see [`fetcher_env_var`].
/// [`FetcherKind::Http`] is the default and reproduces the Phase-2 mirror
/// chain byte for byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetcherKind {
    /// Phase-2 `EXTOS_MIRRORS_<ORIGIN>` + blocking `reqwest` transfer.
    Http,
    /// `libalpm` sync database + package resolution ([`crate::fetcher::alpm`]).
    Alpm,
    /// APT `InRelease`/`Packages` chain ([`crate::fetcher::debian`]).
    Debian,
    /// RPM `repomd.xml`/`primary` chain ([`crate::fetcher::rpm`]).
    Rpm,
}

impl FetcherKind {
    /// Every accepted value of `EXTOS_FETCHER_<ORIGIN>`, in help order.
    pub const ACCEPTED: [&'static str; 4] = ["http", "alpm", "debian", "rpm"];

    /// Stable lowercase spelling accepted by `EXTOS_FETCHER_<ORIGIN>`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Alpm => "alpm",
            Self::Debian => "debian",
            Self::Rpm => "rpm",
        }
    }

    /// Parse a configured fetcher name.
    ///
    /// Surrounding whitespace and ASCII case are ignored; an empty value means
    /// "unset" and selects [`FetcherKind::Http`]. Every accepted value is listed
    /// in [`FetcherKind::ACCEPTED`]. Anything else is a typed
    /// [`ExtosError::ConfigParse`] — never a silent HTTP fallback.
    ///
    /// # Errors
    ///
    /// [`ExtosError::ConfigParse`] for an unrecognized transport name.
    pub fn parse(raw: &str) -> Result<Self, ExtosError> {
        let value = raw.trim().to_ascii_lowercase();
        match value.as_str() {
            "" | "http" => Ok(Self::Http),
            "alpm" => Ok(Self::Alpm),
            "debian" => Ok(Self::Debian),
            "rpm" => Ok(Self::Rpm),
            _ => Err(ExtosError::ConfigParse {
                path: "EXTOS_FETCHER_*".to_string(),
                line: 0,
                message: format!(
                    "unknown fetcher '{raw}'; accepted values are: {}",
                    Self::ACCEPTED.join(", ")
                ),
            }),
        }
    }
}

/// Environment variable naming the fetcher for an origin.
///
/// Follows the same sanitization as [`mirror_env_var`]: `archlinux` →
/// `EXTOS_FETCHER_ARCHLINUX`, `shadichy-labs` → `EXTOS_FETCHER_SHADICHY_LABS`.
#[must_use]
pub fn fetcher_env_var(origin: &str) -> String {
    let mut out = String::from("EXTOS_FETCHER_");
    for ch in origin.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_uppercase());
        } else {
            out.push('_');
        }
    }
    out
}

/// Resolve the configured [`FetcherKind`] for `origin`.
///
/// Reads `EXTOS_FETCHER_<ORIGIN>` ([`fetcher_env_var`]). Unset or empty means
/// [`FetcherKind::Http`]; an unknown value is a typed error from
/// [`FetcherKind::parse`].
///
/// # Errors
///
/// [`ExtosError::ConfigParse`] for an unrecognized transport name.
pub fn fetcher_for_origin(origin: &str) -> Result<FetcherKind, ExtosError> {
    fetcher_from_lookup(origin, |key| std::env::var(key).ok())
}

/// Lookup-injectable form of [`fetcher_for_origin`] (used by unit tests).
///
/// On an unknown name the error path is rewritten to the concrete environment
/// variable so the message names the knob to fix.
fn fetcher_from_lookup<F>(origin: &str, lookup: F) -> Result<FetcherKind, ExtosError>
where
    F: Fn(&str) -> Option<String>,
{
    let var = fetcher_env_var(origin);
    match lookup(&var) {
        None => Ok(FetcherKind::Http),
        Some(raw) => FetcherKind::parse(&raw).map_err(|err| match err {
            ExtosError::ConfigParse { message, .. } => ExtosError::ConfigParse {
                path: var,
                line: 0,
                message: format!("origin '{origin}': {message}"),
            },
            other => other,
        }),
    }
}

/// Phase-2 mirror chain: `EXTOS_MIRRORS_<ORIGIN>` + blocking HTTP download.
fn download_via_http(
    origin: &str,
    name: &str,
    version: &str,
    cache_dir: &Path,
) -> Result<PathBuf, ExtosError> {
    let dest = cache_path_for(cache_dir, origin, name, version);
    if dest.is_file() {
        tracing::debug!("cache hit: {}", dest.display());
        return Ok(dest);
    }

    let mirrors = mirrors_for_origin(origin)?;
    let urls = mirror_urls(&mirrors, origin, name, version);
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)?;
    }

    let client = build_http_client()?;
    let mut only_not_found = true;
    let mut failures: Vec<String> = Vec::new();

    for url in &urls {
        match fetch_url(&client, url, &dest) {
            Ok(()) => {
                tracing::info!("downloaded {} → {}", url, dest.display());
                return Ok(dest);
            }
            Err(FetchFailure::NotFound(status)) => {
                tracing::debug!("mirror miss ({status}): {url}");
                failures.push(format!("{url}: {status}"));
            }
            Err(FetchFailure::Transport(message)) => {
                only_not_found = false;
                tracing::warn!("mirror failure: {url}: {message}");
                failures.push(format!("{url}: {message}"));
            }
        }
    }

    if only_not_found {
        return Err(ExtosError::PackageNotFound {
            origin: origin.to_string(),
            name: name.to_string(),
            version: version.to_string(),
        });
    }
    Err(ExtosError::ConfigParse {
        path: mirror_env_var(origin),
        line: 0,
        message: format!(
            "all mirrors failed for {origin}/{name}/{version}: {}",
            failures.join("; ")
        ),
    })
}

// ─── Phase 3 fetcher transports (PLAN 3.2.6 / 3.3.4 / 3.4.5) ────

/// Environment variable naming the alpm repository tree (`core`, `extra`, ...).
const ALPM_REPO_ENV: &str = "EXTOS_ALPM_REPO";

/// Environment variable tightening the alpm signature policy (`required`).
const ALPM_SIGCHECK_ENV: &str = "EXTOS_ALPM_SIGCHECK";

/// Environment variable naming the Debian suite/codename (`stable`, `bookworm`).
const DEBIAN_DISTRO_ENV: &str = "EXTOS_DEBIAN_DISTRO";

/// Environment variable naming the Debian component (`main`, `contrib`, ...).
const DEBIAN_COMPONENT_ENV: &str = "EXTOS_DEBIAN_COMPONENT";

/// Environment variable naming the Debian architecture (`amd64`, `arm64`, ...).
const DEBIAN_ARCH_ENV: &str = "EXTOS_DEBIAN_ARCH";

/// Environment variable naming an ASCII-armoured Debian release key file.
const DEBIAN_SIGNING_KEY_ENV: &str = "EXTOS_DEBIAN_SIGNING_KEY";

/// Environment variable naming an ASCII-armoured RPM release key file.
const RPM_SIGNING_KEY_ENV: &str = "EXTOS_RPM_SIGNING_KEY";

/// Default Debian suite used when [`DEBIAN_DISTRO_ENV`] is unset.
const DEFAULT_DEBIAN_DISTRO: &str = "stable";

/// Default Debian component used when [`DEBIAN_COMPONENT_ENV`] is unset.
const DEFAULT_DEBIAN_COMPONENT: &str = "main";

/// Non-empty, trimmed value of an environment variable.
fn env_text(var: &str) -> Option<String> {
    std::env::var(var)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

/// First configured mirror base for `origin`.
///
/// [`mirrors_for_origin`] guarantees a non-empty list, so the `None` branch is
/// unreachable in practice; it exists to avoid indexing.
fn first_mirror(origin: &str) -> Result<String, ExtosError> {
    mirrors_for_origin(origin)?
        .into_iter()
        .next()
        .ok_or_else(|| unconfigured_mirror(origin, &mirror_env_var(origin)))
}

/// Read an ASCII-armoured signing key named by `var`, if configured.
///
/// # Errors
///
/// [`ExtosError::ConfigParse`] when the variable is set but the file cannot be
/// read — a configured trust anchor must never be ignored silently.
fn read_signing_key(var: &str) -> Result<Option<Vec<u8>>, ExtosError> {
    let Some(path) = env_text(var) else {
        return Ok(None);
    };
    let bytes = fs::read(&path).map_err(|error| ExtosError::ConfigParse {
        path: var.to_string(),
        line: 0,
        message: format!("cannot read signing key '{path}': {error}"),
    })?;
    Ok(Some(bytes))
}

/// `libalpm`-backed acquisition (PLAN 3.2.6).
///
/// Syncs `<mirror>/<repo>.db` through [`crate::fetcher::alpm::AlpmFetch`], then
/// resolves `name`/`version` in the loaded database and downloads the archive
/// to `<cache_dir>/<origin>/`. The returned path is size-checked and, under the
/// configured signature policy, PGP-verified by the fetcher.
fn download_via_alpm(
    origin: &str,
    name: &str,
    version: &str,
    cache_dir: &Path,
) -> Result<PathBuf, ExtosError> {
    use crate::fetcher::alpm::{AlpmFetch, SigCheck, DEFAULT_REPO};

    let base = first_mirror(origin)?;
    let repo = env_text(ALPM_REPO_ENV).unwrap_or_else(|| DEFAULT_REPO.to_string());
    let sigcheck = match env_text(ALPM_SIGCHECK_ENV)
        .map(|value| value.to_ascii_lowercase())
        .as_deref()
    {
        None | Some("optional") => SigCheck::Optional,
        Some("required") => SigCheck::Required,
        Some(other) => {
            return Err(ExtosError::ConfigParse {
                path: ALPM_SIGCHECK_ENV.to_string(),
                line: 0,
                message: format!(
                    "unknown signature policy '{other}'; accepted values are: optional, required"
                ),
            });
        }
    };

    // libalpm maps a sync database to <dbpath>/sync/<repo>.db; the private
    // database lives next to the package cache and never leaks into the CAS.
    let dbpath = cache_dir.join("alpm-db");
    let mut fetcher = AlpmFetch::new(&dbpath)
        .and_then(|fetcher| fetcher.with_repo(&repo))
        .map_err(|error| alpm_error(origin, name, version, error))?;
    fetcher = fetcher.with_cache_dir(cache_dir.join(origin));
    fetcher
        .sync_db(&base, sigcheck)
        .and_then(|_db| fetcher.download(name, Some(version), sigcheck))
        .map_err(|error| alpm_error(origin, name, version, error))
}

/// Convert an [`crate::fetcher::alpm::AlpmFetchError`] into the crate error.
///
/// Transport-library absence is reported as a configuration error that names
/// the missing library and the escape hatch; integrity and lookup failures keep
/// their own variants.
fn alpm_error(
    origin: &str,
    name: &str,
    version: &str,
    error: crate::fetcher::alpm::AlpmFetchError,
) -> ExtosError {
    use crate::fetcher::alpm::{AlpmFetchError as E, ALPM_LIB_ENV, PACMAN_BUILD_DIR_ENV};

    match &error {
        E::NotAvailable { .. } => ExtosError::ConfigParse {
            path: fetcher_env_var(origin),
            line: 0,
            message: format!(
                "{error}; provide libalpm via {ALPM_LIB_ENV} or {PACMAN_BUILD_DIR_ENV}, \
                 or retry with {}=http",
                fetcher_env_var(origin)
            ),
        },
        E::PackageNotFound { .. } | E::VersionNotFound { .. } => ExtosError::PackageNotFound {
            origin: origin.to_string(),
            name: name.to_string(),
            version: version.to_string(),
        },
        E::MissingSignature { .. } | E::Signature { .. } | E::SizeMismatch { .. } => {
            ExtosError::CasIntegrity {
                expected: format!("a verified {origin} artifact for {name} {version}"),
                actual: error.to_string(),
            }
        }
        _ => ExtosError::ConfigParse {
            path: mirror_env_var(origin),
            line: 0,
            message: error.to_string(),
        },
    }
}

/// APT-backed acquisition (PLAN 3.3.4).
///
/// Fetches `dists/<distro>/InRelease` (or `Release` + `Release.gpg`), verifies
/// it with [`DEBIAN_SIGNING_KEY_ENV`] when configured, syncs the `Packages`
/// index for `component`/`architecture`, then downloads the `.deb` and checks
/// its size and SHA-256. Without a signing key the index is hash-checked but
/// unsigned; that is logged, never hidden.
fn download_via_debian(
    origin: &str,
    name: &str,
    version: &str,
    cache_dir: &Path,
) -> Result<PathBuf, ExtosError> {
    use crate::fetcher::debian::{DebianFetcher, SigCheck, DEFAULT_ARCH};

    let base = first_mirror(origin)?;
    let arch = env_text(DEBIAN_ARCH_ENV).unwrap_or_else(|| DEFAULT_ARCH.to_string());
    let distro =
        env_text(DEBIAN_DISTRO_ENV).unwrap_or_else(|| DEFAULT_DEBIAN_DISTRO.to_string());
    let component =
        env_text(DEBIAN_COMPONENT_ENV).unwrap_or_else(|| DEFAULT_DEBIAN_COMPONENT.to_string());

    let fetcher = DebianFetcher::new(base, arch, cache_dir.join(origin))?.with_origin(origin);
    let key = read_signing_key(DEBIAN_SIGNING_KEY_ENV)?;
    let index = fetcher.sync_db(&distro, &component, key.as_deref())?;
    let downloaded = match key.as_deref() {
        Some(key) => fetcher.download(&index, name, version, SigCheck::Key(key))?,
        None => {
            tracing::warn!(
                origin = %origin,
                "no Debian release key configured; {DEBIAN_SIGNING_KEY_ENV} is unset, \
                 so the index is only hash-checked"
            );
            fetcher.download(&index, name, version, SigCheck::Skip)?
        }
    };
    Ok(downloaded.path)
}

/// RPM-repository-backed acquisition (PLAN 3.4.5).
///
/// Fetches `repodata/repomd.xml`, verifies it with [`RPM_SIGNING_KEY_ENV`] when
/// configured, syncs the `primary` record, then downloads the `.rpm` and checks
/// its size and digest. Without a key the transfer is hash-verified only (the
/// fetcher logs that); with a key the package signature is checked through the
/// `librpm-extos` bridge, whose absence is a typed error.
///
/// Note the pipeline boundary: the returned artifact is a verified `.rpm`, but
/// archive *extraction* currently has no `.rpm` unpacker, so a full `-S` ingest
/// of an RPM origin stops honestly at `ingest_local_archive_with_rosetta`
/// (download-only `-S -w` succeeds). Adding the unpacker is Phase 4 work.
fn download_via_rpm(
    origin: &str,
    name: &str,
    version: &str,
    cache_dir: &Path,
) -> Result<PathBuf, ExtosError> {
    use crate::fetcher::rpm::{RpmFetcher, SigCheck};

    let base = first_mirror(origin)?;
    let fetcher = RpmFetcher::new(base, cache_dir.join(origin))?.with_origin(origin);
    let key = read_signing_key(RPM_SIGNING_KEY_ENV)?;
    let index = fetcher.sync_db(key.as_deref())?;
    let downloaded = match key.as_deref() {
        Some(key) => fetcher.download(&index, name, version, SigCheck::Key(key))?,
        None => {
            tracing::warn!(
                origin = %origin,
                "no RPM release key configured; {RPM_SIGNING_KEY_ENV} is unset, \
                 so the package is only hash-checked"
            );
            fetcher.download(&index, name, version, SigCheck::Skip)?
        }
    };
    Ok(downloaded.path)
}

/// Outcome of a single mirror request; keeps "not found" distinct from
/// transport failures so the caller can report the right error class.
enum FetchFailure {
    /// The mirror answered 404/410 — package genuinely absent there.
    NotFound(String),
    /// DNS/TCP/TLS/HTTP/IO failure — worth trying the next mirror.
    Transport(String),
}

fn build_http_client() -> Result<reqwest::blocking::Client, ExtosError> {
    let timeout = std::env::var("EXTOS_DOWNLOAD_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|secs| *secs > 0)
        .unwrap_or(DEFAULT_DOWNLOAD_TIMEOUT_SECS);

    reqwest::blocking::Client::builder()
        .user_agent(concat!("pkt/", env!("CARGO_PKG_VERSION")))
        .connect_timeout(Duration::from_secs(DEFAULT_CONNECT_TIMEOUT_SECS))
        .timeout(Duration::from_secs(timeout))
        .build()
        .map_err(|e| ExtosError::ConfigParse {
            path: "EXTOS_DOWNLOAD_TIMEOUT_SECS".to_string(),
            line: 0,
            message: format!("cannot create HTTP client: {e}"),
        })
}

/// Stream one URL to `dest` via a `.part` temporary file.
fn fetch_url(
    client: &reqwest::blocking::Client,
    url: &str,
    dest: &Path,
) -> Result<(), FetchFailure> {
    let mut response = client
        .get(url)
        .send()
        .map_err(|e| FetchFailure::Transport(format!("request failed: {e}")))?;

    let status = response.status();
    if !status.is_success() {
        let reason = format!("HTTP {status}");
        return if status == reqwest::StatusCode::NOT_FOUND
            || status == reqwest::StatusCode::GONE
        {
            Err(FetchFailure::NotFound(reason))
        } else {
            Err(FetchFailure::Transport(reason))
        };
    }

    let part = part_path(dest);
    let mut file = fs::File::create(&part).map_err(|e| {
        FetchFailure::Transport(format!("cannot create {}: {e}", part.display()))
    })?;
    if let Err(e) = io::copy(&mut response, &mut file) {
        let _ = fs::remove_file(&part);
        return Err(FetchFailure::Transport(format!("transfer interrupted: {e}")));
    }
    if let Err(e) = file.sync_all() {
        let _ = fs::remove_file(&part);
        return Err(FetchFailure::Transport(format!("cannot flush download: {e}")));
    }
    drop(file);

    fs::rename(&part, dest).map_err(|e| {
        let _ = fs::remove_file(&part);
        FetchFailure::Transport(format!("cannot finalize {}: {e}", dest.display()))
    })
}

/// `<dest>.part` sibling path used for atomic downloads.
fn part_path(dest: &Path) -> PathBuf {
    let mut name = dest
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_else(|| "download".into());
    name.push(".part");
    dest.with_file_name(name)
}

/// Ingest a `.pkt.tar.xz` package (which already contains a `manifest.nix`).
///
/// For native ExtOS archives, we trust the included manifest rather than
/// generating a stub.
pub fn ingest_native_package(
    repo: &CasRepository,
    archive_path: &Path,
) -> Result<IngestResult, ExtosError> {
    let staging_dir = repo.root.join("_staging");
    let pkg_staging = staging_dir.join(
        archive_path
            .file_stem()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string(),
    );
    fs::create_dir_all(&pkg_staging)?;

    let extracted = extract::extract_package(archive_path, &pkg_staging)?;

    // Read the included manifest.nix
    let manifest_path = extracted.metadata_dir.join("manifest.nix");
    let manifest_nix = if manifest_path.exists() {
        fs::read_to_string(&manifest_path)?
    } else {
        return Err(ExtosError::ConfigParse {
            path: archive_path.to_string_lossy().into(),
            line: 0,
            message: "native .pkt.tar.xz missing metadata/manifest.nix".into(),
        });
    };

    // Parse the manifest for identity
    let nix_val = crate::config::parse_nix(&manifest_nix)?;
    let manifest = crate::manifest::PackageManifest::from_nix(&nix_val)?;

    // CAS sanitizer (PLAN 6.1.1) — same invariant as the generic pipeline:
    // privilege bits never enter the CAS, whatever the transport.
    let sanitized_bits = sanitize_permissions(&extracted.content_dir)?;

    let hash = repo.store_directory(&extracted.content_dir)?;
    repo.write_manifest(&hash, &manifest_nix)?;

    let origin = &manifest.identity.origin;
    let name = &manifest.identity.name;
    let version = &manifest.identity.version;

    repo.create_ref(origin, name, version, &hash)?;
    repo.update_current(origin, name, version)?;

    let capabilities = manifest.capabilities.clone();
    let result = IngestResult {
        hash,
        origin: origin.clone(),
        name: name.clone(),
        version: version.clone(),
        capabilities,
        rosetta_translated: false, // native packages already have a manifest
        sanitized_bits,
    };

    let _ = fs::remove_dir_all(&pkg_staging);
    Ok(result)
}

// ─── Identity Extraction ────────────────────────────────────────

/// Parse package identity from upstream metadata files.
///
/// This is a best-effort parser — full Rosetta translation happens in M4.
fn parse_identity_from_metadata(
    extracted: &ExtractedPackage,
    origin: &str,
) -> Result<PackageIdentity, ExtosError> {
    match extracted.kind {
        ArchiveKind::PkgTarZst | ArchiveKind::PkgTarXz => {
            parse_pkginfo_identity(&extracted.metadata_dir, origin)
        }
        ArchiveKind::Deb => parse_deb_control_identity(&extracted.metadata_dir, origin),
        ArchiveKind::Apk => parse_pkginfo_identity(&extracted.metadata_dir, origin),
        ArchiveKind::PktTarXz => {
            // Native packages have a full manifest — shouldn't reach here
            Ok(PackageIdentity {
                origin: origin.to_string(),
                name: "unknown".to_string(),
                version: "0.0.0".to_string(),
                aliases: vec![],
            })
        }
    }
}

/// Parse identity from a pacman/Alpine .PKGINFO (stored as `metadata/PKGINFO`).
fn parse_pkginfo_identity(
    metadata_dir: &Path,
    origin: &str,
) -> Result<PackageIdentity, ExtosError> {
    let pkginfo_path = metadata_dir.join("PKGINFO");
    if !pkginfo_path.exists() {
        return Ok(PackageIdentity {
            origin: origin.to_string(),
            name: "unknown".to_string(),
            version: "0.0.0".to_string(),
            aliases: vec![],
        });
    }

    let content = fs::read_to_string(&pkginfo_path)?;
    let mut name = String::from("unknown");
    let mut version = String::from("0.0.0");
    let mut aliases = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if let Some(val) = line.strip_prefix("pkgname = ") {
            name = val.trim().to_string();
        } else if let Some(val) = line.strip_prefix("pkgver = ") {
            version = val.trim().to_string();
        } else if let Some(val) = line.strip_prefix("provides = ") {
            // Strip version constraint: "foo=1.0" → "foo"
            let alias = val.split('=').next().unwrap_or(val).trim().to_string();
            if alias != name {
                aliases.push(alias);
            }
        } else if let Some(val) = line.strip_prefix("replaces = ") {
            let alias = val.split('=').next().unwrap_or(val).trim().to_string();
            if alias != name && !aliases.contains(&alias) {
                aliases.push(alias);
            }
        }
    }

    Ok(PackageIdentity {
        origin: origin.to_string(),
        name,
        version,
        aliases,
    })
}

/// Parse identity from a Debian `control` file.
fn parse_deb_control_identity(
    metadata_dir: &Path,
    origin: &str,
) -> Result<PackageIdentity, ExtosError> {
    let control_path = metadata_dir.join("control");
    if !control_path.exists() {
        return Ok(PackageIdentity {
            origin: origin.to_string(),
            name: "unknown".to_string(),
            version: "0.0.0".to_string(),
            aliases: vec![],
        });
    }

    let content = fs::read_to_string(&control_path)?;
    let mut name = String::from("unknown");
    let mut version = String::from("0.0.0");
    let mut aliases = Vec::new();

    for line in content.lines() {
        if let Some(val) = line.strip_prefix("Package: ") {
            name = val.trim().to_string();
        } else if let Some(val) = line.strip_prefix("Version: ") {
            version = val.trim().to_string();
        } else if let Some(val) = line.strip_prefix("Provides: ") {
            for p in val.split(',') {
                let alias = p.split('(').next().unwrap_or(p).trim().to_string();
                if !alias.is_empty() && alias != name && !aliases.contains(&alias) {
                    aliases.push(alias);
                }
            }
        } else if let Some(val) = line.strip_prefix("Replaces: ") {
            for p in val.split(',') {
                let alias = p.split('(').next().unwrap_or(p).trim().to_string();
                if !alias.is_empty() && alias != name && !aliases.contains(&alias) {
                    aliases.push(alias);
                }
            }
        }
    }

    Ok(PackageIdentity {
        origin: origin.to_string(),
        name,
        version,
        aliases,
    })
}

// ─── Stub Manifest Generator (M3.4 Placeholder) ────────────────

/// Generate a stub `manifest.nix` with identity + auto-discovered capabilities.
///
/// The full manifest (with dependency translation) is deferred to M4 (Rosetta).
fn generate_stub_manifest(
    identity: &PackageIdentity,
    capabilities: &Capabilities,
    _extracted: &ExtractedPackage,
) -> StubManifest {
    StubManifest {
        identity: identity.clone(),
        format: PackageFormat::ExtractedTree,
        capabilities: capabilities.clone(),
    }
}

struct StubManifest {
    identity: PackageIdentity,
    format: PackageFormat,
    capabilities: Capabilities,
}

/// Format a stub manifest as Nix syntax.
fn format_manifest_nix(manifest: &StubManifest) -> String {
    let mut out = String::from("{\n");

    // Identity block
    out.push_str("  identity = {\n");
    out.push_str(&format!(
        "    origin = \"{}\";\n",
        manifest.identity.origin
    ));
    out.push_str(&format!("    name = \"{}\";\n", manifest.identity.name));
    out.push_str(&format!(
        "    version = \"{}\";\n",
        manifest.identity.version
    ));
    if !manifest.identity.aliases.is_empty() {
        let aliases: Vec<String> = manifest
            .identity
            .aliases
            .iter()
            .map(|a| format!("\"{}\"", a))
            .collect();
        out.push_str(&format!("    aliases = [ {} ];\n", aliases.join(" ")));
    }
    out.push_str("  };\n\n");

    // Format
    out.push_str(&format!("  format = \"{}\";\n\n", manifest.format));

    // Capabilities
    out.push_str("  capabilities = {\n");
    if !manifest.capabilities.binaries.is_empty() {
        let bins: Vec<String> = manifest
            .capabilities
            .binaries
            .iter()
            .map(|b| format!("\"{}\"", b))
            .collect();
        out.push_str(&format!("    binaries = [ {} ];\n", bins.join(" ")));
    }
    if !manifest.capabilities.libraries.is_empty() {
        let libs: Vec<String> = manifest
            .capabilities
            .libraries
            .iter()
            .map(|l| format!("\"{}\"", l))
            .collect();
        out.push_str(&format!("    libraries = [ {} ];\n", libs.join(" ")));
    }
    if !manifest.capabilities.resources.is_empty() {
        let res: Vec<String> = manifest
            .capabilities
            .resources
            .iter()
            .map(|r| format!("\"{}\"", r))
            .collect();
        out.push_str(&format!("    resources = [ {} ];\n", res.join(" ")));
    }
    out.push_str("  };\n\n");

    // Dependencies placeholder
    out.push_str("  # TODO(M4): Rosetta will populate requires/suggests/buildRequires\n");
    out.push_str("  requires = [];\n");

    out.push_str("}\n");
    out
}

// ─── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::HashAlgorithm;

    #[test]
    fn test_parse_pkginfo_identity() {
        let tmpdir = tempfile::tempdir().unwrap();
        let meta = tmpdir.path();
        fs::write(
            meta.join("PKGINFO"),
            "pkgname = htop\npkgver = 3.3.0-1\nprovides = htop-legacy\nreplaces = htop-osx\n",
        )
        .unwrap();

        let id = parse_pkginfo_identity(meta, "archlinux").unwrap();
        assert_eq!(id.name, "htop");
        assert_eq!(id.version, "3.3.0-1");
        assert_eq!(id.origin, "archlinux");
        assert!(id.aliases.contains(&"htop-legacy".to_string()));
        assert!(id.aliases.contains(&"htop-osx".to_string()));
    }

    #[test]
    fn test_parse_deb_control_identity() {
        let tmpdir = tempfile::tempdir().unwrap();
        let meta = tmpdir.path();
        fs::write(
            meta.join("control"),
            "Package: vim\nVersion: 9.1.0-1\nProvides: editor, vi\nReplaces: vim-tiny\n",
        )
        .unwrap();

        let id = parse_deb_control_identity(meta, "debian").unwrap();
        assert_eq!(id.name, "vim");
        assert_eq!(id.version, "9.1.0-1");
        assert_eq!(id.origin, "debian");
        assert!(id.aliases.contains(&"editor".to_string()));
        assert!(id.aliases.contains(&"vi".to_string()));
        assert!(id.aliases.contains(&"vim-tiny".to_string()));
    }

    #[test]
    fn test_stub_manifest_generation() {
        let identity = PackageIdentity {
            origin: "archlinux".into(),
            name: "htop".into(),
            version: "3.3.0-1".into(),
            aliases: vec!["htop-legacy".into()],
        };
        let caps = Capabilities {
            binaries: vec!["htop".into()],
            libraries: vec![],
            virtual_caps: vec![],
            resources: vec!["/usr/share/applications/htop.desktop".into()],
        };
        let stub = StubManifest {
            identity,
            format: PackageFormat::ExtractedTree,
            capabilities: caps,
        };
        let nix = format_manifest_nix(&stub);

        assert!(nix.contains("name = \"htop\""));
        assert!(nix.contains("origin = \"archlinux\""));
        assert!(nix.contains("version = \"3.3.0-1\""));
        assert!(nix.contains("aliases = [ \"htop-legacy\" ]"));
        assert!(nix.contains("binaries = [ \"htop\" ]"));
        assert!(nix.contains("resources = [ \"/usr/share/applications/htop.desktop\" ]"));
        assert!(nix.contains("requires = []"));
    }

    #[test]
    fn test_full_ingest_pipeline() {
        use std::process::Command;

        // Create a mock .pkt.tar.xz archive with proper manifest
        let tmpdir = tempfile::tempdir().unwrap();
        let archive_src = tmpdir.path().join("pkg_src");
        fs::create_dir_all(archive_src.join("metadata")).unwrap();
        fs::create_dir_all(archive_src.join("content/usr/bin")).unwrap();
        fs::write(
            archive_src.join("metadata/manifest.nix"),
            r#"{
                identity = {
                    origin = "scratch";
                    name = "hello";
                    version = "1.0.0";
                };
                format = "extracted-tree";
                capabilities = {
                    binaries = [ "hello" ];
                };
                requires = [];
            }"#,
        )
        .unwrap();
        fs::write(
            archive_src.join("content/usr/bin/hello"),
            "#!/bin/sh\necho hello",
        )
        .unwrap();

        let archive_path = tmpdir.path().join("hello-1.0.0.pkt.tar.xz");
        let status = Command::new("tar")
            .args(["--xz", "-cf"])
            .arg(&archive_path)
            .arg("-C")
            .arg(&archive_src)
            .args(["metadata", "content"])
            .status()
            .unwrap();
        assert!(status.success());

        // Create a CAS repo and ingest
        let cas_dir = tmpdir.path().join("repository");
        let repo =
            CasRepository::open(&cas_dir, HashAlgorithm::Blake3).unwrap();
        let result = ingest_native_package(&repo, &archive_path).unwrap();

        assert_eq!(result.origin, "scratch");
        assert_eq!(result.name, "hello");
        assert_eq!(result.version, "1.0.0");
        assert!(!result.hash.is_empty());
        assert!(result.hash.starts_with("BLAKE3-"));

        // Verify the object exists in CAS
        assert!(repo.object_path(&result.hash).exists());

        // Verify refs were created
        let resolved = repo
            .resolve_ref("scratch", "hello", "1.0.0")
            .unwrap();
        assert_eq!(resolved, result.hash);

        let current = repo
            .resolve_ref("scratch", "hello", "current")
            .unwrap();
        assert_eq!(current, result.hash);
    }

    // ─── Mirror / download plumbing (no network) ────────────────

    #[test]
    fn test_mirror_env_var_naming() {
        assert_eq!(mirror_env_var("archlinux"), "EXTOS_MIRRORS_ARCHLINUX");
        assert_eq!(
            mirror_env_var("shadichy-labs"),
            "EXTOS_MIRRORS_SHADICHY_LABS"
        );
    }

    #[test]
    fn test_parse_mirrors_trims_dedups_and_strips_slashes() {
        let mirrors = parse_mirrors(" https://a.example/x/ , https://b.example ,, https://a.example/x ");
        assert_eq!(
            mirrors,
            vec!["https://a.example/x", "https://b.example"]
        );
        assert!(parse_mirrors(" , , ").is_empty());
    }

    #[test]
    fn test_unconfigured_mirror_is_config_error() {
        let err = mirrors_from_lookup("archlinux", |_| None).unwrap_err();
        let message = err.to_string();
        assert!(message.contains("EXTOS_MIRRORS_ARCHLINUX"), "{message}");
        assert!(message.contains("no mirror configured"), "{message}");
    }

    #[test]
    fn test_configured_mirror_lookup() {
        let mirrors = mirrors_from_lookup("archlinux", |key| {
            (key == "EXTOS_MIRRORS_ARCHLINUX").then(|| "https://mirror.example/arch".to_string())
        })
        .unwrap();
        assert_eq!(mirrors, vec!["https://mirror.example/arch"]);
    }

    #[test]
    fn test_empty_mirror_list_is_config_error() {
        let err = mirrors_from_lookup("alpine", |_| Some("  ,  ".to_string())).unwrap_err();
        assert!(err.to_string().contains("is empty"), "{err}");
    }

    #[test]
    fn test_package_filename_conventions() {
        assert_eq!(
            package_filename("archlinux", "htop", "3.3.0-1"),
            "htop-3.3.0-1-x86_64.pkg.tar.zst"
        );
        assert_eq!(
            package_filename("debian", "vim", "9.1.0-1"),
            "vim_9.1.0-1_amd64.deb"
        );
        assert_eq!(
            package_filename("alpine", "busybox", "1.36.1-r0"),
            "busybox-1.36.1-r0.apk"
        );
        assert_eq!(
            package_filename("scratch", "hello", "1.0.0"),
            "hello-1.0.0.pkt.tar.xz"
        );
        assert_eq!(
            package_filename("void", "xz", "5.4.0_1"),
            "xz-5.4.0_1.pkg.tar.xz"
        );
    }

    #[test]
    fn test_mirror_urls_from_bases_and_templates() {
        let mirrors = vec![
            "https://mirror.example/arch".to_string(),
            "https://cdn.example/{origin}/{version}/{name}.tar.zst".to_string(),
        ];
        let urls = mirror_urls(&mirrors, "archlinux", "htop", "3.3.0-1");
        assert_eq!(
            urls,
            vec![
                "https://mirror.example/arch/htop-3.3.0-1-x86_64.pkg.tar.zst",
                "https://cdn.example/archlinux/3.3.0-1/htop.tar.zst",
            ]
        );
    }

    #[test]
    fn test_cache_path_plumbing() {
        let tmpdir = tempfile::tempdir().unwrap();
        let cache = tmpdir.path().join("cache");
        let path = cache_path_for(&cache, "archlinux", "htop", "3.3.0-1");
        assert_eq!(
            path,
            cache
                .join("archlinux")
                .join("htop-3.3.0-1-x86_64.pkg.tar.zst")
        );
        let dest = cache.join("htop.pkg.tar.zst");
        assert_eq!(part_path(&dest), cache.join("htop.pkg.tar.zst.part"));
    }

    // ─── Phase 3 fetcher dispatch (PLAN 3.2.6 / 3.3.4 / 3.4.5) ──

    #[test]
    fn test_fetcher_env_var_naming() {
        assert_eq!(fetcher_env_var("archlinux"), "EXTOS_FETCHER_ARCHLINUX");
        assert_eq!(fetcher_env_var("rpm"), "EXTOS_FETCHER_RPM");
        assert_eq!(
            fetcher_env_var("shadichy-labs.os"),
            "EXTOS_FETCHER_SHADICHY_LABS_OS"
        );
    }

    #[test]
    fn test_fetcher_kind_parse_accepts_documented_values() {
        assert_eq!(FetcherKind::parse("").unwrap(), FetcherKind::Http);
        assert_eq!(FetcherKind::parse("http").unwrap(), FetcherKind::Http);
        assert_eq!(FetcherKind::parse(" HTTP ").unwrap(), FetcherKind::Http);
        assert_eq!(FetcherKind::parse("alpm").unwrap(), FetcherKind::Alpm);
        assert_eq!(FetcherKind::parse("Debian").unwrap(), FetcherKind::Debian);
        assert_eq!(FetcherKind::parse("RPM").unwrap(), FetcherKind::Rpm);
        assert_eq!(FetcherKind::Http.as_str(), "http");
        assert_eq!(FetcherKind::Alpm.as_str(), "alpm");
        assert_eq!(FetcherKind::Debian.as_str(), "debian");
        assert_eq!(FetcherKind::Rpm.as_str(), "rpm");
        for value in FetcherKind::ACCEPTED {
            assert!(FetcherKind::parse(value).is_ok(), "{value}");
        }
    }

    #[test]
    fn test_fetcher_kind_unknown_value_is_typed_error() {
        let err = FetcherKind::parse("wget").unwrap_err();
        assert!(matches!(err, ExtosError::ConfigParse { .. }), "{err}");
        let message = err.to_string();
        assert!(message.contains("unknown fetcher 'wget'"), "{message}");
        assert!(message.contains("http, alpm, debian, rpm"), "{message}");
    }

    #[test]
    fn test_fetcher_lookup_defaults_to_http_when_unset() {
        let kind = fetcher_from_lookup("archlinux", |_| None).unwrap();
        assert_eq!(kind, FetcherKind::Http);
        let kind = fetcher_from_lookup("archlinux", |_| Some(String::new())).unwrap();
        assert_eq!(kind, FetcherKind::Http);
    }

    #[test]
    fn test_fetcher_lookup_reads_origin_scoped_variable_only() {
        let kind = fetcher_from_lookup("shadichy-labs", |key| {
            (key == "EXTOS_FETCHER_SHADICHY_LABS").then(|| "alpm".to_string())
        })
        .unwrap();
        assert_eq!(kind, FetcherKind::Alpm);
    }

    #[test]
    fn test_fetcher_lookup_error_names_the_origin_variable() {
        let err = fetcher_from_lookup("shadichy-labs", |_| Some("apt".to_string())).unwrap_err();
        let message = err.to_string();
        assert!(
            message.contains("EXTOS_FETCHER_SHADICHY_LABS"),
            "error must name the env var: {message}"
        );
        assert!(message.contains("origin 'shadichy-labs'"), "{message}");
        assert!(message.contains("unknown fetcher 'apt'"), "{message}");
    }

    #[test]
    fn test_download_unconfigured_origin_makes_no_request() {
        // An origin that cannot plausibly have a mirror configured: the error
        // must be raised before any HTTP client is built.
        let tmpdir = tempfile::tempdir().unwrap();
        let err = download_from_mirror_to(
            "l1-never-configured",
            "hello",
            "1.0.0",
            &tmpdir.path().join("cache"),
        )
        .unwrap_err();
        assert!(matches!(err, ExtosError::ConfigParse { .. }), "{err}");
        // Nothing may have been written for an unconfigured origin.
        assert!(!tmpdir.path().join("cache").exists());
    }
}
