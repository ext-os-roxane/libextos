//! Capability index — `SONAME → provider(s)` resolution over CAS metadata.
//!
//! PLAN Sub-phase 5.2 tasks 5.2.1 (the index), 5.2.2 (population from the CAS)
//! and the supply side of 5.2.3 (Tier-3 resolution via the index; the resolver
//! seam itself lives in [`crate::dependency`]).
//!
//! # Where the SONAME data comes from
//!
//! Ingestion scans every extracted `content/` tree with
//! [`crate::elf_scan::scan_capabilities`] (`src/ingest.rs:245` for the Rosetta
//! pipeline, `src/ingest.rs:296` for the plain one) and serializes the result
//! into `manifest.nix` under `capabilities.libraries` — `src/ingest.rs:252`
//! commits that file to `<repository>/objects/<hash>/metadata/manifest.nix`.
//! [`PackageManifest::from_nix`](crate::manifest::PackageManifest::from_nix)
//! reads the same field back (`parse_capabilities`, `src/manifest.rs:897`).
//!
//! This module therefore never opens an ELF file and never shells out to
//! `readelf`: it is a pure reader of the CAS ref table
//! ([`CasRepository::list_refs`]) plus each ref's committed manifest
//! ([`CasRepository::read_manifest`]). Population is offline, needs no root and
//! no network.
//!
//! # Ordering (deterministic, and consistent with anchor bidding)
//!
//! Provider lists are stored and returned best-first under one documented rule:
//!
//! 1. `origin` — ascending (lexicographic);
//! 2. `name` — ascending (lexicographic);
//! 3. `version` — **descending** [`compare_versions`] order, i.e. the newest ref
//!    first (`3.10` outranks `3.9`). This is the same numeric-aware comparison,
//!    in the same newest-wins polarity, that [`crate::anchor`] uses to rank
//!    SONAME bids — consistency beats a second opinion;
//! 4. `version` raw string, then `object` hash — ascending, so the order is
//!    total even when [`compare_versions`] calls two spellings equal.
//!
//! # Scope boundary
//!
//! Lookups are **exact SONAME matches only**. Prefix and glob queries are
//! deliberately out of scope for PLAN 5.2 — a capability request is a precise
//! `DT_NEEDED` string, not a pattern, and a fuzzy match would make Tier-3
//! resolution non-deterministic for no benefit.
//!
//! # Path safety
//!
//! SONAMEs and ref components come from third-party package metadata, so they
//! are hostile input: [`validate_soname`] rejects path separators, NUL and
//! other control characters, whitespace and the path-traversal components `.`
//! and `..` with a typed [`ExtosError::ConfigParse`] *before* anything is
//! stored. The index is a lookup table keyed by opaque strings, but rejecting
//! the hostile shapes at the boundary means a future consumer can never be
//! tricked into treating a "soname" as a path.
//!
//! # Examples
//!
//! ```
//! use libextos::caps::CapabilityIndex;
//!
//! let mut index = CapabilityIndex::new();
//! index
//!     .insert(libextos::caps::CapabilityProvider::new(
//!         "archlinux",
//!         "openssl",
//!         "3.3.1",
//!         None,
//!         vec!["libssl.so.3".to_string()],
//!     ))
//!     .expect("valid capability row");
//!
//! let providers = index.providers_of("libssl.so.3");
//! assert_eq!(providers.len(), 1);
//! assert_eq!(providers[0].ref_id(), "archlinux/openssl/3.3.1");
//! ```

use std::collections::BTreeMap;
use std::fmt;

use crate::anchor::compare_versions;
use crate::cas::CasRepository;
use crate::config;
use crate::dependency::CapabilityRequest;
use crate::error::ExtosError;
use crate::manifest::PackageManifest;

/// Longest SONAME / capability key accepted by [`validate_soname`].
///
/// 255 bytes is the POSIX `NAME_MAX` bound: every real SONAME is far shorter,
/// so anything longer is metadata abuse rather than a library name.
pub const MAX_SONAME_LEN: usize = 255;

/// The manifest field capability keys are read from (for error paths).
const CAPABILITIES_FIELD: &str = "capabilities.libraries";

// ─── Validation ─────────────────────────────────────────────────

/// Reject hostile capability keys (PLAN 5.2.1).
///
/// A SONAME is an opaque identifier — chiefly `DT_NEEDED` / `DT_SONAME`
/// strings such as `libssl.so.3` — but it arrives from third-party package
/// metadata. This function accepts exactly the shapes such a name can take and
/// rejects everything that could be mistaken for a filesystem path:
///
/// - the empty string;
/// - anything longer than [`MAX_SONAME_LEN`] bytes;
/// - the path-traversal components `.` and `..`;
/// - `/` and `\` (path separators — a library directory must never smuggle
///   itself into a key);
/// - NUL and any other control character;
/// - any whitespace.
///
/// # Errors
///
/// [`ExtosError::ConfigParse`] with `path = "capabilities.libraries"` and a
/// message naming the offending string. (`error.rs` is frozen for Phase 5 —
/// this is the crate's structured malformed-input variant, and no new variant
/// is introduced.)
pub fn validate_soname(soname: &str) -> Result<(), ExtosError> {
    fn reject(soname: &str, reason: &str) -> ExtosError {
        ExtosError::ConfigParse {
            path: CAPABILITIES_FIELD.to_string(),
            line: 0,
            message: format!("invalid capability SONAME {soname:?}: {reason}"),
        }
    }

    if soname.is_empty() {
        return Err(reject(soname, "empty"));
    }
    if soname.len() > MAX_SONAME_LEN {
        return Err(reject(
            soname,
            &format!("longer than {MAX_SONAME_LEN} bytes"),
        ));
    }
    if soname == "." || soname == ".." {
        return Err(reject(soname, "path-traversal component"));
    }
    for ch in soname.chars() {
        if ch == '/' || ch == '\\' {
            return Err(reject(soname, "path separator"));
        }
        if ch == '\0' {
            return Err(reject(soname, "NUL byte"));
        }
        if ch.is_control() {
            return Err(reject(soname, "control character"));
        }
        if ch.is_whitespace() {
            return Err(reject(soname, "whitespace"));
        }
    }
    Ok(())
}

/// Reject a hostile ref component (`origin`, `name`, `version` or
/// `ref_version`).
///
/// # Why this is a local copy rather than [`crate::cas::validate_ref_component`]
///
/// The two functions serve different boundaries and must not converge cheaply:
///
/// * **Error variant.** Capability metadata is untrusted *manifest/ref data*, so
///   the failure is [`ExtosError::ConfigParse`] — the crate's structured
///   malformed-input variant (`error.rs` is frozen for Phase 5). The CAS helper
///   reports [`ExtosError::Weave`] because it guards a write; reusing it would
///   misroute a parse failure through the weave error path.
/// * **Stricter accepted set.** This copy also rejects control characters and
///   whitespace. A ref *path* may technically contain a space on some
///   filesystems; a capability key/triple must not, because it is returned as an
///   opaque lookup id and embedded in `origin/name/version` formatting.
/// * **CAS remains the authority for ref paths.** Every provider that reaches
///   the index from [`CapabilityIndex::populate`] already came out of
///   `CasRepository::list_refs`, and the object hash is what the plan consumes;
///   this check exists to keep hostile hand-built rows out of the index, not to
///   replace [`CasRepository::resolve_ref`]'s own path handling.
fn validate_ref_component(kind: &str, value: &str) -> Result<(), ExtosError> {
    fn reject(kind: &str, value: &str, reason: &str) -> ExtosError {
        ExtosError::ConfigParse {
            path: "refs/<origin>/<name>/<version>".to_string(),
            line: 0,
            message: format!("invalid capability provider {kind} {value:?}: {reason}"),
        }
    }

    if value.is_empty() {
        return Err(reject(kind, value, "empty"));
    }
    for ch in value.chars() {
        if ch == '/' || ch == '\\' {
            return Err(reject(kind, value, "path separator"));
        }
        if ch == '\0' {
            return Err(reject(kind, value, "NUL byte"));
        }
        if ch.is_control() {
            return Err(reject(kind, value, "control character"));
        }
        if ch.is_whitespace() {
            return Err(reject(kind, value, "whitespace"));
        }
    }
    Ok(())
}

// ─── Providers ──────────────────────────────────────────────────

/// One package that provides a set of capability keys (PLAN 5.2.1).
///
/// A provider is identified by its semantic ref (`refs/<origin>/<name>/<version>`)
/// and carries the CAS object hash when the row came from the repository, so a
/// caller can go straight from a Tier-3 answer to the object it must weave.
/// Several versions of the same package are *distinct* providers; duplicates of
/// the same ref are collapsed by [`CapabilityIndex::insert`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityProvider {
    /// Origin namespace the ref lives in (`archlinux`, `debian`, `rpm`, …).
    pub origin: String,
    /// Package name as recorded by the ref.
    pub name: String,
    /// Human-readable package version (PLAN 5.2.1).
    ///
    /// [`CapabilityIndex::populate`] records the manifest's `identity.version`
    /// when it is non-empty and the ref version otherwise, so a human-curated
    /// `pkgrel` such as `3.3.1-1` is preserved. This is the string users see and
    /// the value the provider ordering ranks with [`compare_versions`]; it is
    /// deliberately **not** the ref path component.
    pub version: String,
    /// Concrete ref version component from `refs/<origin>/<name>/<version>`.
    ///
    /// [`CapabilityIndex::populate`] fills this from the CAS ref row exactly as
    /// listed; hand-built providers default it to
    /// [`CapabilityProvider::version`] via [`CapabilityProvider::new`]. Use
    /// [`CapabilityProvider::with_ref_version`] when the two differ.
    /// [`CapabilityProvider::ref_id`] composes from this field, so the id still
    /// round-trips through [`CasRepository::resolve_ref`] when the manifest
    /// version carries a `pkgrel`.
    pub ref_version: String,
    /// CAS object hash the ref resolves to, when known.
    ///
    /// [`CapabilityIndex::populate`] always fills this (a ref that does not
    /// resolve is skipped with a warning); hand-built providers may omit it.
    /// Promoting a provider into a weave plan consumes exactly this hash — never
    /// the ref id — so the plan carries the real CAS object (PLAN 5.2.3).
    pub object: Option<String>,
    /// Capability keys this provider declares, in manifest order.
    pub provides: Vec<String>,
}

impl CapabilityProvider {
    /// Build a provider.
    pub fn new(
        origin: impl Into<String>,
        name: impl Into<String>,
        version: impl Into<String>,
        object: Option<String>,
        provides: Vec<String>,
    ) -> Self {
        let version = version.into();
        Self {
            origin: origin.into(),
            name: name.into(),
            ref_version: version.clone(),
            version,
            object,
            provides,
        }
    }

    /// Override the concrete ref version component (builder form).
    ///
    /// [`CapabilityIndex::populate`] needs this because a package's manifest
    /// version and its ref version can differ (`3.3.1-1` vs `3.3.1`); hand-built
    /// providers rarely do, which is why [`CapabilityProvider::new`] defaults
    /// `ref_version` to `version`.
    pub fn with_ref_version(mut self, ref_version: impl Into<String>) -> Self {
        self.ref_version = ref_version.into();
        self
    }

    /// The semantic ref id this provider stands for: `origin/name/ref_version`.
    ///
    /// Composed from [`CapabilityProvider::ref_version`], so it is exactly the
    /// triple [`CasRepository::resolve_ref`] takes and can be fed back to the
    /// CAS without any parsing. Note that it is *not* necessarily
    /// `origin/name/version`: [`CapabilityProvider::version`] follows manifest
    /// precedence and may include a `pkgrel` (PLAN 5.2.3 fixed this
    /// round-trip).
    pub fn ref_id(&self) -> String {
        format!("{}/{}/{}", self.origin, self.name, self.ref_version)
    }

    /// The provider label used by the weaver and the DAG: `origin/name`.
    pub fn label(&self) -> String {
        format!("{}/{}", self.origin, self.name)
    }

    /// Validate the ref components (`origin`, `name`, `version`).
    ///
    /// # Errors
    ///
    /// [`ExtosError::ConfigParse`] for an empty component or one containing a
    /// path separator, NUL, a control character or whitespace.
    pub fn validate(&self) -> Result<(), ExtosError> {
        validate_ref_component("origin", &self.origin)?;
        validate_ref_component("name", &self.name)?;
        validate_ref_component("version", &self.version)?;
        validate_ref_component("ref version", &self.ref_version)?;
        Ok(())
    }
}

impl fmt::Display for CapabilityProvider {
    /// `origin/name version [object]`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.label(), self.version)?;
        if let Some(object) = &self.object {
            write!(f, " [{object}]")?;
        }
        Ok(())
    }
}

/// Sort a provider list best-first under the documented rule (see the module
/// docs): origin asc, name asc, version desc via [`compare_versions`], then the
/// raw version and object hash to make the order total.
fn sort_providers(providers: &mut [CapabilityProvider]) {
    providers.sort_by(|a, b| {
        a.origin
            .cmp(&b.origin)
            .then_with(|| a.name.cmp(&b.name))
            // Newest first: reverse the numeric-aware comparison.
            .then_with(|| compare_versions(&b.version, &a.version))
            .then_with(|| a.version.cmp(&b.version))
            .then_with(|| a.ref_version.cmp(&b.ref_version))
            .then_with(|| a.object.cmp(&b.object))
    });
}

// ─── Population results ─────────────────────────────────────────

/// One skipped CAS entry, recorded so population is never silently lossy
/// (PLAN 5.2.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityWarning {
    /// Ref id of the skipped row (`origin/name/version`).
    pub ref_id: String,
    /// What went wrong and why the row was skipped.
    pub message: String,
}

impl fmt::Display for CapabilityWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.ref_id, self.message)
    }
}

/// Structured summary of a population run (PLAN 5.2.2).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CapabilityIndexSummary {
    /// Concrete refs visited (`list_refs()` rows).
    pub refs_scanned: usize,
    /// Refs that contributed at least one capability row.
    pub packages: usize,
    /// Stored `(SONAME, provider)` rows.
    pub entries: usize,
    /// Distinct capability keys.
    pub sonames: usize,
    /// Rows that were skipped, in discovery order.
    pub warnings: Vec<CapabilityWarning>,
}

impl CapabilityIndexSummary {
    /// Whether every scanned concrete ref contributed cleanly (PLAN 5.2.2).
    ///
    /// `refs/virtual/*` pseudo-rows are not concrete refs and are excluded from
    /// the scan, so they can never make a populated repository look dirty.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.warnings.is_empty()
    }
}

/// A populated index plus its population summary (PLAN 5.2.2).
#[must_use = "a population is only useful when its index/summary are inspected"]
#[derive(Debug, Clone)]
pub struct CapabilityPopulate {
    /// The index itself. May legitimately be empty.
    pub index: CapabilityIndex,
    /// What happened while filling it.
    pub summary: CapabilityIndexSummary,
}

// ─── The index ──────────────────────────────────────────────────

/// In-memory `SONAME → provider(s)` map over CAS metadata (PLAN 5.2.1).
///
/// Backed by a [`BTreeMap`], so iteration order is the (stable, byte-wise)
/// key order and two identical repositories always produce byte-identical
/// listings. Provider lists are sorted best-first — see the module docs for the
/// rule. Cloneable and cheap to build per command; there is no daemon, no
/// cache invalidation and no on-disk state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CapabilityIndex {
    by_soname: BTreeMap<String, Vec<CapabilityProvider>>,
}

impl CapabilityIndex {
    /// A new, empty index.
    ///
    /// An empty index is a valid state: a repository with no library-bearing
    /// packages simply resolves no Tier-3 capability.
    pub fn new() -> Self {
        Self::default()
    }

    /// Populate the index from every concrete ref in `repo` (PLAN 5.2.2).
    ///
    /// Walks [`CasRepository::list_refs`] and, per ref, resolves the object and
    /// parses `metadata/manifest.nix` into a [`PackageManifest`], taking
    /// `capabilities.libraries` as the provider's keys. The provider's
    /// [`version`](CapabilityProvider::version) is the manifest's
    /// `identity.version` when non-empty and the ref version otherwise — the
    /// same precedence [`crate::weaver::plan::plan_from_refs_with_anchors`]
    /// uses, so an index row and a plan node always agree. The concrete ref
    /// component is kept separately as
    /// [`ref_version`](CapabilityProvider::ref_version) so
    /// [`CapabilityProvider::ref_id`] still resolves through
    /// [`CasRepository::resolve_ref`].
    ///
    /// # Virtual refs are not concrete refs (PLAN 5.1/5.2 boundary)
    ///
    /// `list_refs()` also reports the CAS-internal pseudo-rows that
    /// [`CasRepository::create_virtual_link`] and
    /// [`CasRepository::create_virtual_ref`] place under `refs/virtual/`:
    /// `virtual/<name>/{content,metadata}` (a link to an object directory) and
    /// `virtual/<alias>/<version>` (a link to a concrete ref). Those are
    /// pointers, not packages: indexing them would fabricate providers with
    /// `origin == "virtual"` and inflate the scan counters. Rows whose origin is
    /// `virtual` are therefore skipped **before** [`CapabilityIndexSummary::refs_scanned`]
    /// is incremented, so the summary counts only concrete
    /// `refs/<origin>/<name>/<version>` rows and [`CapabilityIndexSummary::is_clean`]
    /// reflects genuine warnings (the same `origin == "virtual"` guard the
    /// package listing uses in `core/pkt/src/main.rs`).
    ///
    /// # Failure model
    ///
    /// * Only the ref *listing* is fatal: if the CAS ref table cannot be read,
    ///   the typed [`ExtosError`] propagates.
    /// * A single bad row (dangling ref, unreadable/absent manifest, unparsable
    ///   `manifest.nix`, hostile capability key) is **skipped** and recorded in
    ///   [`CapabilityIndexSummary::warnings`] — one corrupt package cannot make
    ///   the whole repository unqueryable, and nothing is dropped silently.
    /// * An empty repository yields an empty index with an empty summary.
    ///
    /// # Errors
    ///
    /// [`ExtosError`] from the CAS ref walk (`Io`, `CasIntegrity`, …).
    pub fn populate(repo: &CasRepository) -> Result<CapabilityPopulate, ExtosError> {
        let refs = repo.list_refs()?;
        let mut index = CapabilityIndex::new();
        let mut summary = CapabilityIndexSummary::default();

        for entry in refs {
            // `refs/virtual/*` rows are CAS-internal aliases/pointers, never
            // concrete package refs (see the method docs above).
            if entry.origin == "virtual" {
                continue;
            }
            summary.refs_scanned += 1;
            let ref_id = format!("{}/{}/{}", entry.origin, entry.name, entry.version);

            let object = match repo.resolve_ref(&entry.origin, &entry.name, &entry.version) {
                Ok(hash) => hash,
                Err(err) => {
                    summary.warnings.push(CapabilityWarning {
                        ref_id,
                        message: format!("dangling ref skipped: {err}"),
                    });
                    continue;
                }
            };

            let manifest_nix = match repo.read_manifest(&object) {
                Ok(text) => text,
                Err(err) => {
                    summary.warnings.push(CapabilityWarning {
                        ref_id,
                        message: format!("manifest unreadable for object {object}, skipped: {err}"),
                    });
                    continue;
                }
            };

            let manifest_path = format!("objects/{object}/metadata/manifest.nix");
            let value = match config::parse_nix_with_path(&manifest_nix, &manifest_path) {
                Ok(value) => value,
                Err(err) => {
                    summary.warnings.push(CapabilityWarning {
                        ref_id,
                        message: format!("manifest does not parse, skipped: {err}"),
                    });
                    continue;
                }
            };

            let manifest = match PackageManifest::from_nix(&value) {
                Ok(manifest) => manifest,
                Err(err) => {
                    summary.warnings.push(CapabilityWarning {
                        ref_id,
                        message: format!("manifest is not a valid package manifest, skipped: {err}"),
                    });
                    continue;
                }
            };

            let version = if manifest.identity.version.is_empty() {
                entry.version.clone()
            } else {
                manifest.identity.version.clone()
            };

            let provider = CapabilityProvider::new(
                entry.origin.clone(),
                entry.name.clone(),
                version,
                Some(object),
                manifest.capabilities.libraries.clone(),
            )
            .with_ref_version(entry.version.clone());

            match index.insert(provider) {
                Ok(true) => summary.packages += 1,
                // No declared libraries: a package that provides no SONAME is
                // not an anomaly, it simply contributes no row.
                Ok(false) => {}
                Err(err) => summary.warnings.push(CapabilityWarning {
                    ref_id,
                    message: format!("invalid capability metadata skipped: {err}"),
                }),
            }
        }

        summary.entries = index.provider_count();
        summary.sonames = index.len();
        Ok(CapabilityPopulate { index, summary })
    }

    /// Insert one provider under every capability key it declares.
    ///
    /// Returns `Ok(true)` when at least one row was stored and `Ok(false)` when
    /// the provider declares no keys (or every row was already present). Rows
    /// are deduplicated by [`CapabilityProvider::ref_id`], and the first insert
    /// wins, so calling [`CapabilityIndex::populate`] twice over the same
    /// repository is idempotent.
    ///
    /// Validation is atomic: every ref component and every capability key is
    /// checked before the map is touched, so a rejected provider leaves the
    /// index exactly as it was.
    ///
    /// # Errors
    ///
    /// [`ExtosError::ConfigParse`] for a hostile ref component
    /// ([`CapabilityProvider::validate`]) or a hostile capability key
    /// ([`validate_soname`]).
    pub fn insert(&mut self, provider: CapabilityProvider) -> Result<bool, ExtosError> {
        provider.validate()?;
        if provider.provides.is_empty() {
            return Ok(false);
        }
        for soname in &provider.provides {
            validate_soname(soname)?;
        }

        let ref_id = provider.ref_id();
        let mut inserted = false;
        for soname in &provider.provides {
            let rows = self.by_soname.entry(soname.clone()).or_default();
            if rows.iter().any(|existing| existing.ref_id() == ref_id) {
                continue;
            }
            rows.push(provider.clone());
            sort_providers(rows);
            inserted = true;
        }
        Ok(inserted)
    }

    /// Providers of one capability key, best-first.
    ///
    /// An unknown key returns an empty slice (a miss is not an error); use
    /// [`CapabilityIndex::query`] when the key must also be well-formed.
    pub fn providers_of(&self, soname: &str) -> &[CapabilityProvider] {
        self.by_soname
            .get(soname)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    /// Validated exact lookup (the `pkt -F --soname` primitive, PLAN 5.2.4).
    ///
    /// Identical to [`CapabilityIndex::providers_of`] except that a malformed
    /// key is rejected instead of being looked up.
    ///
    /// # Errors
    ///
    /// [`ExtosError::ConfigParse`] when `soname` fails [`validate_soname`].
    pub fn query(&self, soname: &str) -> Result<&[CapabilityProvider], ExtosError> {
        validate_soname(soname)?;
        Ok(self.providers_of(soname))
    }

    /// Providers satisfying a Tier-3 [`CapabilityRequest`].
    ///
    /// Only [`CapabilityRequest::Provides`] addresses a SONAME, which is the
    /// whole scope of this index (PLAN 5.2.1: `SONAME → provider(s)`); every
    /// other request kind — executable, resource, virtual capability — returns
    /// an empty slice because those keys are not indexed here. Callers that
    /// resolve all Tier-3 kinds should use
    /// [`crate::dependency::resolve_capability`], which keeps the in-plan
    /// sources first.
    pub fn providers_for(&self, request: &CapabilityRequest) -> &[CapabilityProvider] {
        match request {
            CapabilityRequest::Provides(soname) => self.providers_of(soname),
            CapabilityRequest::Executable { .. }
            | CapabilityRequest::Resource(_)
            | CapabilityRequest::Virtual(_) => &[],
        }
    }

    /// Distinct capability keys, ascending.
    pub fn sonames(&self) -> impl Iterator<Item = &str> {
        self.by_soname.keys().map(String::as_str)
    }

    /// Every stored `(capability key, providers)` row, key-ascending.
    pub fn entries(&self) -> impl Iterator<Item = (&str, &[CapabilityProvider])> {
        self.by_soname
            .iter()
            .map(|(soname, rows)| (soname.as_str(), rows.as_slice()))
    }

    /// Distinct provider ref ids, sorted ascending.
    pub fn provider_refs(&self) -> Vec<String> {
        let mut refs: Vec<String> = self
            .by_soname
            .values()
            .flat_map(|rows| rows.iter().map(CapabilityProvider::ref_id))
            .collect();
        refs.sort();
        refs.dedup();
        refs
    }

    /// Number of distinct capability keys.
    pub fn len(&self) -> usize {
        self.by_soname.len()
    }

    /// Whether no capability key is indexed.
    pub fn is_empty(&self) -> bool {
        self.by_soname.is_empty()
    }

    /// Number of stored `(SONAME, provider)` rows.
    pub fn provider_count(&self) -> usize {
        self.by_soname.values().map(Vec::len).sum()
    }
}

// ─── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::HashAlgorithm;

    fn provider(origin: &str, name: &str, version: &str, sonames: &[&str]) -> CapabilityProvider {
        CapabilityProvider::new(
            origin,
            name,
            version,
            Some(format!("BLAKE3-{origin}-{name}-{version}")),
            sonames.iter().map(|s| s.to_string()).collect(),
        )
    }

    fn tmp_repo() -> (tempfile::TempDir, CasRepository) {
        let dir = tempfile::tempdir().unwrap();
        let repo = CasRepository::open(dir.path(), HashAlgorithm::Blake3).unwrap();
        (dir, repo)
    }

    /// Publish one package with a manifest declaring `libraries`.
    fn publish(repo: &CasRepository, origin: &str, name: &str, version: &str, libs: &[&str]) {
        let hash = repo
            .store_bytes(format!("{origin}/{name}/{version}").as_bytes())
            .unwrap();
        let list = libs
            .iter()
            .map(|lib| format!("\"{lib}\""))
            .collect::<Vec<_>>()
            .join(" ");
        let manifest = format!(
            "{{ identity = {{ origin = \"{origin}\"; name = \"{name}\"; version = \"{version}\"; }};\n\
             capabilities = {{ libraries = [ {list} ]; }}; }}"
        );
        repo.write_manifest(&hash, &manifest).unwrap();
        repo.create_ref(origin, name, version, &hash).unwrap();
    }

    // ── 5.2.1: validation ──

    #[test]
    fn test_validate_soname_accepts_real_names() {
        for soname in ["libssl.so.3", "libc.so.6", "libfoo.so", "libz.so.1"] {
            assert!(validate_soname(soname).is_ok(), "{soname}");
        }
    }

    #[test]
    fn test_validate_soname_rejects_hostile_input() {
        let too_long = "a".repeat(MAX_SONAME_LEN + 1);
        for soname in [
            "",
            ".",
            "..",
            "../../etc/passwd",
            "usr/lib/libssl.so.3",
            "/libssl.so.3",
            "lib\\ssl.so.3",
            "lib\0ssl.so.3",
            "libssl\n.so.3",
            "lib ssl.so.3",
            too_long.as_str(),
        ] {
            let err = validate_soname(soname).expect_err(soname);
            assert!(matches!(err, ExtosError::ConfigParse { .. }), "{soname}: {err}");
        }
    }

    #[test]
    fn test_insert_rejects_hostile_provider_atomically() {
        let mut index = CapabilityIndex::new();
        index.insert(provider("archlinux", "openssl", "3.3.1", &["libssl.so.3"]))
            .unwrap();

        let before = index.clone();
        let hostile = CapabilityProvider::new(
            "archlinux",
            "openssl",
            "3.3.2",
            None,
            vec!["libcrypto.so.3".to_string(), "../../evil".to_string()],
        );
        assert!(matches!(
            index.insert(hostile),
            Err(ExtosError::ConfigParse { .. })
        ));
        // Nothing was written by the rejected insert.
        assert_eq!(index, before);

        // A hostile ref component is rejected just as firmly.
        let bad_ref = CapabilityProvider::new(
            "arch/linux",
            "openssl",
            "3.3.2",
            None,
            vec!["libssl.so.3".to_string()],
        );
        assert!(matches!(
            index.insert(bad_ref),
            Err(ExtosError::ConfigParse { .. })
        ));
        assert_eq!(index, before);
    }

    // ── 5.2.1: querying and ordering ──

    #[test]
    fn test_lookup_is_exact_and_miss_is_empty() {
        let mut index = CapabilityIndex::new();
        index.insert(provider("archlinux", "openssl", "3.3.1", &["libssl.so.3"]))
            .unwrap();

        assert_eq!(index.providers_of("libssl.so.3").len(), 1);
        assert!(index.providers_of("libssl.so").is_empty());
        assert!(index.providers_of("libssl.so.30").is_empty());
        assert!(index.providers_of("").is_empty());
        // `query` validates, `providers_of` does not.
        assert!(index.query("libssl.so.3").is_ok());
        assert!(matches!(
            index.query("usr/lib/libssl.so.3"),
            Err(ExtosError::ConfigParse { .. })
        ));
    }

    #[test]
    fn test_order_is_origin_then_name_then_newest_version() {
        let mut index = CapabilityIndex::new();
        index
            .insert(provider("rpm", "openssl", "3.0.13", &["libssl.so.3"]))
            .unwrap();
        index
            .insert(provider("archlinux", "openssl", "3.9", &["libssl.so.3"]))
            .unwrap();
        index
            .insert(provider("archlinux", "openssl", "3.10", &["libssl.so.3"]))
            .unwrap();
        index
            .insert(provider("archlinux", "libressl", "4.1", &["libssl.so.3"]))
            .unwrap();

        let refs: Vec<String> = index
            .providers_of("libssl.so.3")
            .iter()
            .map(CapabilityProvider::ref_id)
            .collect();
        assert_eq!(
            refs,
            vec![
                "archlinux/libressl/4.1",
                "archlinux/openssl/3.10",
                "archlinux/openssl/3.9",
                "rpm/openssl/3.0.13",
            ]
        );
    }

    #[test]
    fn test_insert_is_idempotent_and_fans_out_over_sonames() {
        let mut index = CapabilityIndex::new();
        let row = provider(
            "archlinux",
            "openssl",
            "3.3.1",
            &["libssl.so.3", "libcrypto.so.3"],
        );
        assert!(index.insert(row.clone()).unwrap());
        assert!(!index.insert(row).unwrap(), "duplicate ref collapses");
        assert_eq!(index.provider_count(), 2);
        assert_eq!(index.len(), 2);
        assert_eq!(index.provider_refs(), vec!["archlinux/openssl/3.3.1"]);
        assert_eq!(
            index.sonames().collect::<Vec<_>>(),
            vec!["libcrypto.so.3", "libssl.so.3"]
        );

        // A provider with no keys contributes nothing.
        assert!(
            !index
                .insert(provider("archlinux", "htop", "3.3.0", &[]))
                .unwrap()
        );
        assert_eq!(index.len(), 2);
    }

    #[test]
    fn test_providers_for_only_resolves_sonames() {
        let mut index = CapabilityIndex::new();
        index.insert(provider("archlinux", "openssl", "3.3.1", &["libssl.so.3"]))
            .unwrap();

        assert_eq!(
            index
                .providers_for(&CapabilityRequest::Provides("libssl.so.3".into()))
                .len(),
            1
        );
        for request in [
            CapabilityRequest::Executable {
                name: "openssl".into(),
                version: None,
            },
            CapabilityRequest::Resource("/usr/share/x".into()),
            CapabilityRequest::Virtual("tls".into()),
        ] {
            assert!(index.providers_for(&request).is_empty());
        }
    }

    // ── 5.2.2: population ──

    #[test]
    fn test_populate_reads_manifest_capabilities() {
        let (_dir, repo) = tmp_repo();
        publish(&repo, "archlinux", "openssl", "3.3.1", &["libssl.so.3"]);
        publish(&repo, "rpm", "openssl", "3.0.13", &["libssl.so.10"]);

        let populated = CapabilityIndex::populate(&repo).unwrap();
        assert!(populated.summary.is_clean(), "{:?}", populated.summary.warnings);
        assert_eq!(populated.summary.refs_scanned, 2);
        assert_eq!(populated.summary.packages, 2);
        assert_eq!(populated.summary.sonames, 2);
        assert_eq!(populated.summary.entries, 2);
        assert_eq!(
            populated.index.providers_of("libssl.so.3")[0].label(),
            "archlinux/openssl"
        );
        assert_eq!(
            populated.index.providers_of("libssl.so.10")[0].label(),
            "rpm/openssl"
        );

        // Populating twice is idempotent (first insert wins).
        let again = CapabilityIndex::populate(&repo).unwrap();
        assert_eq!(again.index, populated.index);
    }

    #[test]
    fn test_populate_on_empty_repository_is_a_clean_empty_index() {
        let (_dir, repo) = tmp_repo();
        let populated = CapabilityIndex::populate(&repo).unwrap();
        assert!(populated.index.is_empty());
        assert_eq!(populated.summary.refs_scanned, 0);
        assert!(populated.summary.is_clean());
    }

    #[test]
    fn test_populate_skips_corrupt_rows_with_recorded_warnings() {
        let (_dir, repo) = tmp_repo();

        // 1. A healthy row.
        publish(&repo, "archlinux", "openssl", "3.3.1", &["libssl.so.3"]);

        // 2. A ref whose object has no manifest at all.
        let orphan = repo.store_bytes(b"no manifest here").unwrap();
        repo.create_ref("debian", "libssl", "3.0.13", &orphan).unwrap();

        // 3. A ref whose manifest is not parseable nix.
        let broken = repo.store_bytes(b"broken manifest").unwrap();
        repo.write_manifest(&broken, "{ this is not nix").unwrap();
        repo.create_ref("alpine", "libssl3", "3.1.4", &broken)
            .unwrap();

        // 4. A dangling ref (points at a missing object).
        repo.create_ref("void", "libressl", "4.0", "BLAKE3-missing")
            .unwrap();

        // 5. A manifest that parses but declares a hostile capability key.
        let hostile = repo.store_bytes(b"hostile soname").unwrap();
        repo.write_manifest(
            &hostile,
            "{ identity = { origin = \"rpm\"; name = \"evil\"; version = \"1.0\"; };\n\
              capabilities = { libraries = [ \"../../../etc/passwd\" ]; }; }",
        )
        .unwrap();
        repo.create_ref("rpm", "evil", "1.0", &hostile).unwrap();

        let populated = CapabilityIndex::populate(&repo).unwrap();
        assert_eq!(populated.index.len(), 1, "only the healthy row is indexed");
        assert_eq!(
            populated.index.providers_of("libssl.so.3")[0].ref_id(),
            "archlinux/openssl/3.3.1"
        );
        assert_eq!(populated.summary.refs_scanned, 5);
        assert_eq!(populated.summary.packages, 1);
        assert_eq!(populated.summary.warnings.len(), 4);
        assert!(!populated.summary.is_clean());

        let messages: Vec<&str> = populated
            .summary
            .warnings
            .iter()
            .map(|warning| warning.message.as_str())
            .collect();
        assert!(messages.iter().any(|m| m.contains("manifest unreadable")), "{messages:?}");
        assert!(messages.iter().any(|m| m.contains("does not parse")), "{messages:?}");
        assert!(messages.iter().any(|m| m.contains("dangling ref")), "{messages:?}");
        assert!(
            messages.iter().any(|m| m.contains("invalid capability metadata")),
            "{messages:?}"
        );
        // Each warning names the ref it dropped.
        for warning in &populated.summary.warnings {
            assert!(!warning.ref_id.is_empty());
        }
    }

    #[test]
    fn test_populate_prefers_manifest_version_over_ref_version() {
        let (_dir, repo) = tmp_repo();
        let hash = repo.store_bytes(b"versioned").unwrap();
        repo.write_manifest(
            &hash,
            "{ identity = { origin = \"archlinux\"; name = \"openssl\"; version = \"3.3.1-1\"; };\n\
              capabilities = { libraries = [ \"libssl.so.3\" ]; }; }",
        )
        .unwrap();
        repo.create_ref("archlinux", "openssl", "3.3.1", &hash).unwrap();

        let populated = CapabilityIndex::populate(&repo).unwrap();
        let provider = &populated.index.providers_of("libssl.so.3")[0];
        assert_eq!(provider.version, "3.3.1-1");
        assert_eq!(provider.ref_version, "3.3.1");
        assert_eq!(
            provider.ref_id(),
            "archlinux/openssl/3.3.1",
            "the ref id is the resolve triple, not the manifest version"
        );
        // ...and it really round-trips through the CAS (PLAN 5.2.3 fix).
        assert_eq!(
            repo.resolve_ref("archlinux", "openssl", "3.3.1").unwrap(),
            provider.object.clone().unwrap()
        );
        assert_eq!(
            provider.object.as_deref(),
            Some(hash.as_str())
        );
    }
}
