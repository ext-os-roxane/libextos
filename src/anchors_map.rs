//! Virtual anchor map — `anchors.nix` (PLAN 5.1.1, with the priority plumbing
//! of PLAN 5.1.3).
//!
//! An anchor map is the *declarative* half of virtual anchoring: it says which
//! concrete packages are allowed to satisfy a virtual name (a SONAME such as
//! `libssl.so.3`) and in which order they should be tried. The *resolved* half
//! lives in [`crate::anchor`] (bidding/ranking) and [`crate::vlock`] (the
//! reproducible `.lock`); this module is the single seam between them.
//!
//! The file is parsed by the crate's existing configuration parser
//! ([`crate::config::parse_nix_with_path`], so comments, `rec { }`, dotted keys
//! and optional trailing `;` all behave exactly as everywhere else in ExtOS).
//!
//! # `anchors.nix` grammar
//!
//! ```nix
//! {
//!   # Every virtual name is an attribute key; quote names containing '.'
//!   # (dotted keys mean nested attribute sets, exactly like in Nix).
//!   anchors = {
//!     "libssl.so.3" = [
//!       { origin = "fedora";    package = "openssl"; }              # priority 5
//!       { origin = "archlinux"; package = "openssl"; priority = 10; }
//!     ];
//!
//!     # A single provider is legal: the virtual simply always resolves to it.
//!     "libc.so.6" = [ { origin = "archlinux"; package = "glibc"; } ];
//!   };
//!
//!   # Optional. Origin-wide priorities, **lower wins** (same polarity as
//!   # weaver::OriginPriority). These replace the built-in origin defaults for
//!   # the listed origins only.
//!   priorities = {
//!     fedora = 5;
//!     archlinux = 10;
//!   };
//! }
//! ```
//!
//! Rules, each reported as a field-addressed
//! [`ExtosError::ConfigParse`] (`path` = the `source` string, message prefixed
//! with the exact field, e.g. `anchors."libssl.so.3"[0].origin: …`):
//!
//! * the document root is an attribute set with only `anchors` and
//!   `priorities`; `anchors` is mandatory, `priorities` is optional;
//! * a virtual key must be a valid virtual name (see
//!   [`crate::cas::validate_virtual_name`]: 1..=64 bytes of `[A-Za-z0-9._+-]`,
//!   not starting with `.` or `-`). This rejects `../`, `/`, NUL, spaces and
//!   option-looking names at parse time, before anything touches the CAS;
//! * also rejected: the same virtual declared twice (checked against the source
//!   text, because the parser's attribute maps are keyed and would otherwise
//!   silently keep the last binding), an empty provider list, the same
//!   `origin`/`package` pair listed twice under one virtual, an unknown field
//!   in a provider set, an unknown top-level key, and a priority that is not an
//!   integer in `0..=u32::MAX`;
//! * `origin` and `package` are mandatory in every provider set and must be
//!   single path components of `[A-Za-z0-9._+-]` (no `/`, no `..`).
//!
//! # Priority resolution (PLAN 5.1.3)
//!
//! [`AnchorsMap::policy`] turns the parsed map into an [`AnchorPolicy`] with
//! this precedence, highest first:
//!
//! 1. a provider `priority = …` (per `origin/package`, applies to every virtual
//!    that provider bids for);
//! 2. an origin entry in the top-level `priorities` set;
//! 3. the implicit origin order of [`crate::weaver::OriginPriority::new`]
//!    (`pkt`/`scratch` 0, `archlinux`/`arch` 10, `debian`/`ubuntu` 20,
//!    `alpine` 30, everything else 50);
//! 4. `50` for an unknown origin.
//!
//! Lower numbers win everywhere. Bidding itself stays in [`crate::anchor`]; this
//! module only resolves *which concrete version* of each provider is available
//! and then hands [`AnchorBid`]s to the existing [`AnchorTable`].
//!
//! # Version selection
//!
//! A provider is represented by its newest live ref: candidates come from
//! [`crate::cas::CasRepository::list_versions`], dangling refs are skipped, and
//! "newest" is [`crate::anchor::compare_versions`] (numeric aware, `2.10` >
//! `2.9`). Byte-wise ascending breaks the remaining ties and the greatest string
//! wins, so the answer never depends on directory order.
//!
//! # Scope
//!
//! Resolving is read-only. [`AnchorResolution::apply`] creates the
//! `refs/virtual/<name>` chain (PLAN 5.1.2) and [`crate::vlock`] serializes the
//! same resolution; neither `instanz apply` nor the in-plan bidding of
//! `weaver::plan` is touched by this module. The chain link is the single
//! alternatives-style pointer described in
//! [`crate::cas::CasRepository::create_virtual_link`] (its doc comment also
//! records how the pre-existing `list_*` accessors see it).

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use crate::anchor::{AnchorBid, AnchorPolicy, AnchorTable, compare_versions};
use crate::cas::{CasRepository, is_valid_virtual_name};
use crate::config::{NixValue, parse_nix_with_path};
use crate::error::ExtosError;

/// Attribute key holding the virtual → providers mapping.
pub const ANCHORS_KEY: &str = "anchors";

/// Attribute key holding optional origin-wide priorities.
pub const PRIORITIES_KEY: &str = "priorities";

/// One concrete provider allowed to satisfy a virtual name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorProvider {
    /// Origin namespace of the provider (`fedora`).
    pub origin: String,
    /// Package name inside that origin (`openssl`).
    pub package: String,
    /// Optional explicit priority (lower wins); overrides origin priorities.
    pub priority: Option<u32>,
}

impl AnchorProvider {
    /// Provider label as used everywhere else: `origin/package`.
    pub fn label(&self) -> String {
        format!("{}/{}", self.origin, self.package)
    }
}

/// A parsed `anchors.nix` document (PLAN 5.1.1).
///
/// Keys are sorted (the underlying map is a `BTreeMap`), so every iteration —
/// bids, virtual refs, `.lock` lines — is deterministic by construction.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AnchorsMap {
    /// Virtual name → allowed providers, in declared order.
    pub anchors: BTreeMap<String, Vec<AnchorProvider>>,
    /// Origin → priority (lower wins), declared by the optional `priorities` set.
    pub priorities: BTreeMap<String, u32>,
}

impl AnchorsMap {
    /// Parse an `anchors.nix` document. `source` names the document in errors.
    ///
    /// The duplicate-virtual check runs on the raw text (see the module docs);
    /// every other rule is checked on the parsed [`NixValue`].
    pub fn parse(input: &str, source: &str) -> Result<Self, ExtosError> {
        if let Some(duplicate) = duplicate_anchor_key(input) {
            return Err(fail(
                source,
                &format!("{ANCHORS_KEY}.\"{duplicate}\""),
                "duplicate virtual anchor: the same name is declared more than once",
            ));
        }
        let value = parse_nix_with_path(input, source)?;
        Self::from_value(&value, source)
    }

    /// Parse an `anchors.nix` file; the path doubles as the error source.
    pub fn parse_file(path: &Path) -> Result<Self, ExtosError> {
        let text = std::fs::read_to_string(path)?;
        Self::parse(&text, &path.display().to_string())
    }

    /// Validate an already-parsed [`NixValue`] against the anchors schema.
    pub fn from_value(value: &NixValue, source: &str) -> Result<Self, ExtosError> {
        let root = attrset(value, source, "document")?;
        for key in root.keys() {
            if key != ANCHORS_KEY && key != PRIORITIES_KEY {
                return Err(fail(
                    source,
                    key,
                    format!("unknown top-level key: expected {ANCHORS_KEY:?} or {PRIORITIES_KEY:?}"),
                ));
            }
        }

        let anchors_value = root.get(ANCHORS_KEY).ok_or_else(|| {
            fail(source, ANCHORS_KEY, "missing required attribute set")
        })?;
        let anchors_set = attrset(anchors_value, source, ANCHORS_KEY)?;

        let mut anchors = BTreeMap::new();
        for (virtual_name, providers_value) in anchors_set {
            let virtual_field = format!("{ANCHORS_KEY}.\"{virtual_name}\"");
            if !is_valid_virtual_name(virtual_name) {
                return Err(fail(
                    source,
                    &virtual_field,
                    format!(
                        "invalid virtual name {virtual_name:?}: expected 1..=64 bytes of \
                         [A-Za-z0-9._+-], not starting with '.' or '-' (quote names containing '.')"
                    ),
                ));
            }
            let items = providers_value.as_list().ok_or_else(|| {
                fail(
                    source,
                    &virtual_field,
                    format!("expected a list of provider sets, got {providers_value}"),
                )
            })?;
            if items.is_empty() {
                return Err(fail(
                    source,
                    &virtual_field,
                    "empty provider list: declare at least one provider",
                ));
            }

            let mut providers = Vec::with_capacity(items.len());
            for (index, item) in items.iter().enumerate() {
                providers.push(parse_provider(
                    item,
                    source,
                    &format!("{virtual_field}[{index}]"),
                )?);
            }

            let mut seen = BTreeSet::new();
            for provider in &providers {
                if !seen.insert(provider.label()) {
                    return Err(fail(
                        source,
                        &virtual_field,
                        format!("duplicate provider {:?} for this virtual", provider.label()),
                    ));
                }
            }
            anchors.insert(virtual_name.clone(), providers);
        }

        let mut priorities = BTreeMap::new();
        if let Some(value) = root.get(PRIORITIES_KEY) {
            let set = attrset(value, source, PRIORITIES_KEY)?;
            for (origin, priority_value) in set {
                let field = format!("{PRIORITIES_KEY}.{origin}");
                validate_component(origin, source, &field, "origin")?;
                let priority = parse_priority(priority_value, source, &field)?;
                priorities.insert(origin.clone(), priority);
            }
        }

        Ok(Self {
            anchors,
            priorities,
        })
    }

    /// Whether the document declares at least one virtual anchor.
    pub fn is_empty(&self) -> bool {
        self.anchors.is_empty()
    }

    /// Number of declared virtual anchors.
    pub fn len(&self) -> usize {
        self.anchors.len()
    }

    /// Declared providers for one virtual name.
    pub fn providers_of(&self, virtual_name: &str) -> Option<&[AnchorProvider]> {
        self.anchors.get(virtual_name).map(Vec::as_slice)
    }

    /// Virtual names in ascending order.
    pub fn virtuals(&self) -> impl Iterator<Item = &str> {
        self.anchors.keys().map(String::as_str)
    }

    /// Build the [`AnchorPolicy`] for this map (PLAN 5.1.3).
    ///
    /// Precedence is the one documented at module level: provider priority →
    /// declared origin priority → implicit origin order → 50. An explicit
    /// `priority = …` on a provider becomes a policy override for its
    /// `origin/package` label, so it applies to every virtual that provider
    /// bids for.
    pub fn policy(&self) -> AnchorPolicy {
        let mut overrides = BTreeMap::new();
        for providers in self.anchors.values() {
            for provider in providers {
                if let Some(priority) = provider.priority {
                    overrides.insert(provider.label(), priority);
                }
            }
        }
        AnchorPolicy::from_declarations(&self.priorities, &overrides)
    }
}

// ─── Resolution (PLAN 5.1.2 / 5.1.3) ────────────────────────────

/// One winning anchor: the virtual name and the concrete provider behind it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedAnchor {
    /// Virtual name the anchor pins (`libssl.so.3`).
    pub virtual_name: String,
    /// Winning origin.
    pub origin: String,
    /// Winning package.
    pub package: String,
    /// Concrete winning version (never `current`).
    pub version: String,
    /// CAS object id of the winning concrete ref (taken from the ref itself).
    pub object: String,
}

impl ResolvedAnchor {
    /// Winning provider label (`origin/package`).
    pub fn provider(&self) -> String {
        format!("{}/{}", self.origin, self.package)
    }

    /// Concrete ref as `origin/package/version`.
    pub fn ref_label(&self) -> String {
        format!("{}/{}/{}", self.origin, self.package, self.version)
    }
}

/// The outcome of bidding every virtual in an [`AnchorsMap`] against a CAS.
#[derive(Debug, Clone, Default)]
pub struct AnchorResolution {
    /// Winners, sorted by virtual name ascending.
    pub anchors: Vec<ResolvedAnchor>,
    /// Full bidding record (winner *and* losers per virtual), for reporting.
    pub table: AnchorTable,
}

impl AnchorResolution {
    /// Create the `refs/virtual/<name>` chain for every winner (PLAN 5.1.2).
    ///
    /// Idempotent: returns the number of links that were created or retargeted;
    /// an already-correct link contributes `0`. All links are written through
    /// [`CasRepository::create_virtual_link`], which keeps them relative and
    /// inside the repository tree.
    pub fn apply(&self, repo: &CasRepository) -> Result<usize, ExtosError> {
        let mut changed = 0;
        for anchor in &self.anchors {
            if repo.create_virtual_link(
                &anchor.virtual_name,
                &anchor.origin,
                &anchor.package,
                &anchor.version,
            )? {
                changed += 1;
            }
        }
        Ok(changed)
    }

    /// Winning anchor for one virtual name.
    pub fn get(&self, virtual_name: &str) -> Option<&ResolvedAnchor> {
        self.anchors
            .iter()
            .find(|anchor| anchor.virtual_name == virtual_name)
    }

    /// Number of resolved virtual anchors.
    pub fn len(&self) -> usize {
        self.anchors.len()
    }

    /// Whether nothing was resolved (an empty anchors map).
    pub fn is_empty(&self) -> bool {
        self.anchors.is_empty()
    }
}

/// Bid every virtual of `map` against the concrete refs of `repo`.
///
/// For each declared provider the newest live ref is bid (see module docs for
/// the selection rule); providers with no live ref simply do not bid. A virtual
/// whose whole provider list is unavailable is a typed
/// [`ExtosError::DependencyUnresolvable`] — an anchor never silently falls back
/// to "any file with that name". Ranking reuses [`AnchorTable`] and the
/// [`AnchorPolicy`] derived from the map (PLAN 5.1.3), so the documented order
/// is: priority (lower wins) → origin (ascending) → version (newest first) →
/// provider label → path.
pub fn resolve(
    repo: &CasRepository,
    map: &AnchorsMap,
) -> Result<AnchorResolution, ExtosError> {
    let policy = map.policy();
    let mut bids = Vec::new();

    for (virtual_name, providers) in &map.anchors {
        let mut available = false;
        let mut unavailable = Vec::new();
        for provider in providers {
            match newest_version(repo, &provider.origin, &provider.package)? {
                Some(version) => {
                    available = true;
                    bids.push(AnchorBid::new(
                        virtual_name.clone(),
                        provider.label(),
                        provider.origin.clone(),
                        version,
                        AnchorBid::default_path(virtual_name),
                    ));
                }
                // Declared but not ingested: it cannot bid. Skipped silently
                // only while some other provider can still satisfy the anchor.
                None => unavailable.push(provider.label()),
            }
        }
        if !available {
            return Err(ExtosError::DependencyUnresolvable(format!(
                "anchor: virtual {virtual_name:?} has no provider in the CAS (declared: {})",
                unavailable.join(", ")
            )));
        }
    }

    let table = AnchorTable::from_bids(&bids, &policy);

    let mut anchors = Vec::with_capacity(map.anchors.len());
    for virtual_name in map.anchors.keys() {
        let choice = table.get(virtual_name).ok_or_else(|| {
            ExtosError::DependencyUnresolvable(format!(
                "anchor: virtual {virtual_name:?} produced no winning bid"
            ))
        })?;
        let provider = map.anchors[virtual_name]
            .iter()
            .find(|provider| provider.label() == choice.winner)
            .ok_or_else(|| {
                ExtosError::DependencyUnresolvable(format!(
                    "anchor: winning bid {} is not a declared provider of {virtual_name:?}",
                    choice.winner
                ))
            })?;
        let version = choice.bids[0].version.clone();
        let object = repo.resolve_ref(&provider.origin, &provider.package, &version)?;
        anchors.push(ResolvedAnchor {
            virtual_name: virtual_name.clone(),
            origin: provider.origin.clone(),
            package: provider.package.clone(),
            version,
            object,
        });
    }

    Ok(AnchorResolution { anchors, table })
}

/// Newest live version of `origin/package`, or `None` when there is none.
fn newest_version(
    repo: &CasRepository,
    origin: &str,
    package: &str,
) -> Result<Option<String>, ExtosError> {
    let mut candidates: Vec<String> = repo
        .list_versions(origin, package)?
        .into_iter()
        // A dangling ref row (no object behind it) cannot be a provider.
        .filter(|version| repo.resolve_ref(origin, package, version).is_ok())
        .collect();
    // Ascending; the last element is the newest. Byte-wise order breaks the
    // remaining ties (`compare_versions("1.0", "01.0")` is `Equal`).
    candidates.sort_by(|a, b| compare_versions(a, b).then_with(|| a.cmp(b)));
    Ok(candidates.pop())
}

// ─── Provider / value helpers ───────────────────────────────────

fn parse_provider(
    item: &NixValue,
    source: &str,
    field: &str,
) -> Result<AnchorProvider, ExtosError> {
    let map = attrset(item, source, field)?;
    for key in map.keys() {
        if key != "origin" && key != "package" && key != "priority" {
            return Err(fail(
                source,
                &format!("{field}.{key}"),
                "unknown field: expected origin, package or priority",
            ));
        }
    }

    let origin_value = map
        .get("origin")
        .ok_or_else(|| fail(source, &format!("{field}.origin"), "missing required field"))?;
    let origin = string(origin_value, source, &format!("{field}.origin"))?;
    validate_component(&origin, source, &format!("{field}.origin"), "origin")?;

    let package_value = map
        .get("package")
        .ok_or_else(|| fail(source, &format!("{field}.package"), "missing required field"))?;
    let package = string(package_value, source, &format!("{field}.package"))?;
    validate_component(&package, source, &format!("{field}.package"), "package")?;

    let priority = match map.get("priority") {
        Some(value) => Some(parse_priority(value, source, &format!("{field}.priority"))?),
        None => None,
    };

    Ok(AnchorProvider {
        origin,
        package,
        priority,
    })
}

fn parse_priority(value: &NixValue, source: &str, field: &str) -> Result<u32, ExtosError> {
    let number = value
        .as_int()
        .ok_or_else(|| fail(source, field, format!("expected an integer, got {value}")))?;
    u32::try_from(number).map_err(|_| {
        fail(
            source,
            field,
            format!("priority {number} is outside 0..={}", u32::MAX),
        )
    })
}

fn attrset<'v>(
    value: &'v NixValue,
    source: &str,
    field: &str,
) -> Result<&'v BTreeMap<String, NixValue>, ExtosError> {
    value.as_attrset().ok_or_else(|| {
        fail(
            source,
            field,
            format!("expected an attribute set, got {value}"),
        )
    })
}

fn string(value: &NixValue, source: &str, field: &str) -> Result<String, ExtosError> {
    value
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| fail(source, field, format!("expected a string, got {value}")))
}

fn validate_component(
    value: &str,
    source: &str,
    field: &str,
    what: &str,
) -> Result<(), ExtosError> {
    let valid = !value.is_empty()
        && value != "."
        && value != ".."
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-'));
    if valid {
        Ok(())
    } else {
        Err(fail(
            source,
            field,
            format!(
                "invalid {what} {value:?}: expected 1..=255 bytes of [A-Za-z0-9._+-] \
                 and not '.' or '..'"
            ),
        ))
    }
}

fn fail(source: &str, field: &str, message: impl Into<String>) -> ExtosError {
    ExtosError::ConfigParse {
        path: source.to_string(),
        line: 0,
        message: format!("{field}: {}", message.into()),
    }
}

// ─── Duplicate-key pre-scan ─────────────────────────────────────

/// Duplicate detection for `anchors = { … }` keys (PLAN 5.1.1).
///
/// Attribute sets are parsed into a `BTreeMap`, which keeps the *last* binding
/// for a repeated key; Nix itself rejects the repeat, and so must we. The raw
/// text is therefore scanned with a minimal lexer that skips `#` comments and
/// quoted strings, finds the top-level `anchors = {` binding and records the
/// key of every binding directly inside it. Returns the first repeated key.
///
/// This is text-level by necessity (the parser discards the duplicate before
/// we see it) and is deliberately conservative: it never rewrites anything and
/// a false negative only means the parser's last-binding-wins behaviour, which
/// the schema still validates.
fn duplicate_anchor_key(source: &str) -> Option<String> {
    let tokens = scan_tokens(source);
    let mut depth = 0i32;
    let mut index = 0;
    while index < tokens.len() {
        match &tokens[index] {
            ScanToken::Punct('{') | ScanToken::Punct('[') => depth += 1,
            ScanToken::Punct('}') | ScanToken::Punct(']') => depth -= 1,
            ScanToken::Word(word) if depth <= 1 && word == ANCHORS_KEY => {
                // depth 1 = inside the document's outer `{ … }`; depth 0 covers
                // the brace-less "bare bindings" form the parser also accepts.
                if matches!(tokens.get(index + 1), Some(ScanToken::Punct('=')))
                    && matches!(tokens.get(index + 2), Some(ScanToken::Punct('{')))
                {
                    return duplicate_key_in_anchors_block(&tokens[index + 3..]);
                }
            }
            _ => {}
        }
        if depth < 0 {
            return None; // malformed input: the parser reports it
        }
        index += 1;
    }
    None
}

fn duplicate_key_in_anchors_block(tokens: &[ScanToken]) -> Option<String> {
    let mut seen = BTreeSet::new();
    let mut depth = 0i32;
    let mut index = 0;
    while index < tokens.len() {
        match &tokens[index] {
            ScanToken::Punct('{') | ScanToken::Punct('[') => depth += 1,
            ScanToken::Punct('}') if depth == 0 => return None, // end of anchors set
            ScanToken::Punct('}') | ScanToken::Punct(']') => depth -= 1,
            ScanToken::Word(_) | ScanToken::String(_) if depth == 0 => {
                // Read a (possibly dotted) key path, then look for `=`.
                let mut parts = Vec::new();
                let mut cursor = index;
                loop {
                    match tokens.get(cursor) {
                        Some(ScanToken::Word(part)) | Some(ScanToken::String(part)) => {
                            parts.push(part.clone())
                        }
                        _ => break,
                    }
                    cursor += 1;
                    if matches!(tokens.get(cursor), Some(ScanToken::Punct('.'))) {
                        cursor += 1;
                        continue;
                    }
                    break;
                }
                if matches!(tokens.get(cursor), Some(ScanToken::Punct('='))) {
                    let key = parts.join(".");
                    if !seen.insert(key.clone()) {
                        return Some(key);
                    }
                    index = cursor + 1;
                    continue;
                }
            }
            _ => {}
        }
        index += 1;
    }
    None
}

#[derive(Debug, PartialEq, Eq)]
enum ScanToken {
    Word(String),
    String(String),
    Punct(char),
}

fn scan_tokens(source: &str) -> Vec<ScanToken> {
    let mut tokens = Vec::new();
    let mut chars = source.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '#' => {
                for next in chars.by_ref() {
                    if next == '\n' {
                        break;
                    }
                }
            }
            '"' => {
                let mut value = String::new();
                while let Some(next) = chars.next() {
                    match next {
                        '"' => break,
                        '\\' => {
                            if let Some(escaped) = chars.next() {
                                value.push(escaped);
                            }
                        }
                        other => value.push(other),
                    }
                }
                tokens.push(ScanToken::String(value));
            }
            c if c.is_ascii_alphanumeric() || c == '_' || c == '-' => {
                let mut word = String::from(c);
                while let Some(next) = chars.peek().copied() {
                    if next.is_ascii_alphanumeric() || next == '_' || next == '-' {
                        word.push(next);
                        chars.next();
                    } else {
                        break;
                    }
                }
                tokens.push(ScanToken::Word(word));
            }
            // Everything structural is only needed as punctuation; `.` matters
            // because dotted keys are legal attribute keys.
            c if matches!(c, '{' | '}' | '[' | ']' | '=' | ';' | '.') => {
                tokens.push(ScanToken::Punct(c))
            }
            _ => {}
        }
    }
    tokens
}

// ─── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cas::CasRepository;
    use crate::types::HashAlgorithm;

    const VALID: &str = r#"{
        anchors = {
            "libssl.so.3" = [
                { origin = "fedora"; package = "openssl"; }
                { origin = "archlinux"; package = "openssl"; priority = 10; }
            ];
            "libc.so.6" = [ { origin = "archlinux"; package = "glibc"; } ];
        };
        priorities = {
            fedora = 5;
            archlinux = 10;
        };
    }"#;

    fn errors_with(err: &ExtosError, needle: &str) {
        let text = err.to_string();
        assert!(text.contains(needle), "{needle:?} not in {text:?}");
    }

    #[test]
    fn parses_the_documented_grammar() {
        let map = AnchorsMap::parse(VALID, "anchors.nix").unwrap();
        assert_eq!(map.len(), 2);
        assert!(!map.is_empty());
        assert_eq!(map.virtuals().collect::<Vec<_>>(), vec!["libc.so.6", "libssl.so.3"]);
        let providers = map.providers_of("libssl.so.3").unwrap();
        assert_eq!(providers.len(), 2);
        assert_eq!(providers[0].label(), "fedora/openssl");
        assert_eq!(providers[0].priority, None);
        assert_eq!(providers[1].priority, Some(10));
        assert_eq!(map.priorities.get("fedora"), Some(&5));
        assert!(map.providers_of("libz.so.1").is_none());
    }

    #[test]
    fn policy_precedence_provider_then_origin_then_implicit() {
        let map = AnchorsMap::parse(VALID, "anchors.nix").unwrap();
        let policy = map.policy();
        // Provider override beats the declared origin priority.
        assert_eq!(policy.priority_of("archlinux/openssl"), 10);
        // The declared origin priority beats the implicit origin order.
        assert_eq!(policy.priority_of("fedora/other"), 5);
        assert_eq!(policy.priority_of("fedora/openssl"), 5);
        // Undeclared origins keep the implicit OriginPriority order, then 50.
        assert_eq!(policy.priority_of("debian/openssl"), 20);
        assert_eq!(policy.priority_of("nixos/openssl"), 50);

        // Provider-level priority is a policy override, origin set untouched.
        let map = AnchorsMap::parse(
            r#"{
                anchors = {
                    "libz.so.1" = [
                        { origin = "debian"; package = "zlib"; priority = 1; }
                    ];
                };
            }"#,
            "anchors.nix",
        )
        .unwrap();
        assert_eq!(map.policy().priority_of("debian/zlib"), 1);
        assert_eq!(map.policy().priority_of("debian/other"), 20);
    }

    #[test]
    fn empty_and_default_maps_are_valid() {
        let map = AnchorsMap::parse("{ anchors = { }; }", "anchors.nix").unwrap();
        assert!(map.is_empty());
        assert!(map.priorities.is_empty());
        assert_eq!(map.len(), 0);
        // Bare-bindings form (no outer braces) is accepted by the parser too.
        let map = AnchorsMap::parse(
            "anchors = { \"libc.so.6\" = [ { origin = \"archlinux\"; package = \"glibc\"; } ]; };",
            "anchors.nix",
        )
        .unwrap();
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn duplicate_virtual_is_a_typed_error() {
        let err = AnchorsMap::parse(
            r#"{
                anchors = {
                    "libssl.so.3" = [ { origin = "fedora"; package = "openssl"; } ];
                    "libssl.so.3" = [ { origin = "archlinux"; package = "openssl"; } ];
                };
            }"#,
            "anchors.nix",
        )
        .unwrap_err();
        assert!(matches!(err, ExtosError::ConfigParse { .. }), "{err}");
        errors_with(&err, "duplicate virtual anchor");
        errors_with(&err, "libssl.so.3");
    }

    #[test]
    fn duplicate_key_scan_ignores_comments_and_strings() {
        let source = r#"{
            # "anchors" = { "x" = []; } inside a comment is not a duplicate
            anchors = {
                "libssl.so.3" = [ { origin = "fedora"; package = "openssl"; } ];
            };
            note = "anchors = { a = 1; a = 2; }";  # unknown key, but not a dup
        }"#;
        // No duplicate reported; the unknown key is the parser's error.
        assert_eq!(duplicate_anchor_key(source), None);
        assert!(AnchorsMap::parse(source, "anchors.nix").is_err());
    }

    #[test]
    fn duplicate_provider_empty_list_and_bad_kinds_are_typed() {
        let dup = AnchorsMap::parse(
            r#"{ anchors = { "libz.so.1" = [
                { origin = "debian"; package = "zlib"; }
                { origin = "debian"; package = "zlib"; }
            ]; }; }"#,
            "anchors.nix",
        )
        .unwrap_err();
        errors_with(&dup, "duplicate provider");

        let empty = AnchorsMap::parse(
            r#"{ anchors = { "libz.so.1" = [ ]; }; }"#,
            "anchors.nix",
        )
        .unwrap_err();
        errors_with(&empty, "empty provider list");

        for (source, needle) in [
            (r#"{ anchors = "nope"; }"#, "expected an attribute set"),
            (r#"{ anchors = { "libz.so.1" = { origin = "debian"; }; }; }"#, "expected a list"),
            (r#"{ anchors = { "libz.so.1" = [ "debian" ]; }; }"#, "expected an attribute set"),
            (
                r#"{ anchors = { "libz.so.1" = [ { origin = "debian"; } ]; }; }"#,
                "package",
            ),
            (
                r#"{ anchors = { "libz.so.1" = [ { package = "zlib"; } ]; }; }"#,
                "origin",
            ),
            (
                r#"{ anchors = { "libz.so.1" = [ { origin = 1; package = "zlib"; } ]; }; }"#,
                "expected a string",
            ),
            (
                r#"{ anchors = { "libz.so.1" = [ { origin = "debian"; package = "zlib"; bogus = 1; } ]; }; }"#,
                "unknown field",
            ),
            (
                r#"{ anchors = { "libz.so.1" = [ { origin = "debian"; package = "zlib"; priority = -1; } ]; }; }"#,
                "outside 0..=",
            ),
            (
                r#"{ anchors = { "libz.so.1" = [ { origin = "debian"; package = "zlib"; priority = "high"; } ]; }; }"#,
                "expected an integer",
            ),
            (r#"{ anchors = { }; extra = 1; }"#, "unknown top-level key"),
            (r#"{ priorities = { debian = "high"; }; anchors = { }; }"#, "expected an integer"),
            (r#"{ priorities = { "a/b" = 1; }; anchors = { }; }"#, "invalid origin"),
        ] {
            let err = AnchorsMap::parse(source, "anchors.nix").unwrap_err();
            assert!(matches!(err, ExtosError::ConfigParse { .. }), "{source} -> {err}");
            errors_with(&err, needle);
        }
    }

    #[test]
    fn hostile_virtual_names_are_rejected_at_parse_time() {
        for name in ["../evil", "a/b", "a b", "-x", ".hidden", ""] {
            let source = format!(
                "{{ anchors = {{ \"{name}\" = [ {{ origin = \"debian\"; package = \"zlib\"; }} ]; }}; }}"
            );
            let err = AnchorsMap::parse(&source, "anchors.nix").unwrap_err();
            errors_with(&err, "invalid virtual name");
        }
        // Non-string keys are the same class of error.
        let err = AnchorsMap::parse(
            r#"{ anchors = { ".." = [ { origin = "debian"; package = "zlib"; } ]; }; }"#,
            "anchors.nix",
        )
        .unwrap_err();
        errors_with(&err, "invalid virtual name");
    }

    #[test]
    fn parse_errors_and_missing_files_are_typed() {
        assert!(matches!(
            AnchorsMap::parse("{ anchors = { ", "anchors.nix").unwrap_err(),
            ExtosError::ConfigParse { .. }
        ));
        let missing = Path::new("/nonexistent/extos/anchors.nix");
        assert!(matches!(
            AnchorsMap::parse_file(missing).unwrap_err(),
            ExtosError::Io(_)
        ));
        // A file that exists but is not valid anchors.nix.
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("anchors.nix");
        std::fs::write(&path, "{ anchors = 1; }").unwrap();
        assert!(matches!(
            AnchorsMap::parse_file(&path).unwrap_err(),
            ExtosError::ConfigParse { .. }
        ));
    }

    // ── PLAN 5.1.2 / 5.1.3: resolve + apply ──

    struct World {
        _tmp: tempfile::TempDir,
        repo: CasRepository,
        fedora: String,
        arch: String,
    }

    fn world() -> World {
        let tmp = tempfile::tempdir().unwrap();
        let repo =
            CasRepository::open(tmp.path().join("repository"), HashAlgorithm::Blake3).unwrap();
        let seed = tmp.path().join("seed");
        std::fs::create_dir_all(seed.join("usr/lib")).unwrap();
        std::fs::write(seed.join("usr/lib/libssl.so.3"), b"fedora").unwrap();
        let fedora = repo.store_directory(&seed).unwrap();
        std::fs::write(seed.join("usr/lib/libssl.so.3"), b"arch").unwrap();
        let arch = repo.store_directory(&seed).unwrap();
        repo.create_ref("fedora", "openssl", "3.0.11", &fedora).unwrap();
        repo.create_ref("archlinux", "openssl", "3.3.1", &arch).unwrap();
        World {
            _tmp: tmp,
            repo,
            fedora,
            arch,
        }
    }

    const OVERRIDE: &str = r#"{
        anchors = {
            "libssl.so.3" = [
                { origin = "archlinux"; package = "openssl"; }
                { origin = "fedora"; package = "openssl"; }
            ];
        };
        priorities = { fedora = 5; archlinux = 10; };
    }"#;

    #[test]
    fn resolve_honours_priority_override_and_is_deterministic() {
        let world = world();
        let map = AnchorsMap::parse(OVERRIDE, "anchors.nix").unwrap();
        let resolution = resolve(&world.repo, &map).unwrap();
        assert_eq!(resolution.len(), 1);
        let anchor = resolution.get("libssl.so.3").unwrap();
        // fedora wins despite the lower version: the map is authoritative.
        assert_eq!(anchor.provider(), "fedora/openssl");
        assert_eq!(anchor.version, "3.0.11");
        assert_eq!(anchor.object, world.fedora);
        assert_eq!(
            resolution.table.winner_of("libssl.so.3"),
            Some("fedora/openssl")
        );
        let losers = resolution.table.get("libssl.so.3").unwrap().losers();
        assert_eq!(losers, vec!["archlinux/openssl"]);

        // Declaration order in the file does not matter: policy + ranking do.
        let reordered = OVERRIDE.replace(
            r#"{ origin = "archlinux"; package = "openssl"; }
                { origin = "fedora"; package = "openssl"; }"#,
            r#"{ origin = "fedora"; package = "openssl"; }
                { origin = "archlinux"; package = "openssl"; }"#,
        );
        let again = resolve(
            &world.repo,
            &AnchorsMap::parse(&reordered, "anchors.nix").unwrap(),
        )
        .unwrap();
        assert_eq!(again.anchors, resolution.anchors);
    }

    #[test]
    fn implicit_origin_order_decides_without_priorities() {
        let world = world();
        let map = AnchorsMap::parse(
            r#"{ anchors = { "libssl.so.3" = [
                { origin = "fedora"; package = "openssl"; }
                { origin = "archlinux"; package = "openssl"; }
            ]; }; }"#,
            "anchors.nix",
        )
        .unwrap();
        let resolution = resolve(&world.repo, &map).unwrap();
        // OriginPriority ranks archlinux (10) above unknown fedora (50).
        assert_eq!(resolution.anchors[0].provider(), "archlinux/openssl");
        assert_eq!(resolution.anchors[0].object, world.arch);
    }

    #[test]
    fn providers_without_refs_are_skipped_but_all_missing_is_typed() {
        let world = world();
        // fedora has refs, nixos does not: nixos simply does not bid.
        let map = AnchorsMap::parse(
            r#"{ anchors = { "libssl.so.3" = [
                { origin = "nixos"; package = "openssl"; }
                { origin = "fedora"; package = "openssl"; }
            ]; }; }"#,
            "anchors.nix",
        )
        .unwrap();
        let resolution = resolve(&world.repo, &map).unwrap();
        assert_eq!(resolution.anchors[0].provider(), "fedora/openssl");

        // Nothing available: typed, not a silent fallback.
        let map = AnchorsMap::parse(
            r#"{ anchors = { "libssl.so.3" = [
                { origin = "nixos"; package = "openssl"; }
            ]; }; }"#,
            "anchors.nix",
        )
        .unwrap();
        let err = resolve(&world.repo, &map).unwrap_err();
        assert!(matches!(err, ExtosError::DependencyUnresolvable(_)), "{err}");
        errors_with(&err, "nixos/openssl");
    }

    #[test]
    fn apply_creates_the_chain_idempotently() {
        let world = world();
        let map = AnchorsMap::parse(OVERRIDE, "anchors.nix").unwrap();
        let resolution = resolve(&world.repo, &map).unwrap();
        assert_eq!(resolution.apply(&world.repo).unwrap(), 1);
        assert_eq!(resolution.apply(&world.repo).unwrap(), 0);
        assert_eq!(
            world.repo.resolve_virtual_object("libssl.so.3").unwrap().1,
            world.fedora
        );
    }

    #[test]
    fn newest_version_is_numeric_aware_and_skips_dangling_refs() {
        let world = world();
        // 3.10.2 must beat 3.9.9; a dangling 4.0.0 must be ignored.
        let seed = world._tmp.path().join("seed2");
        std::fs::create_dir_all(seed.join("usr/lib")).unwrap();
        std::fs::write(seed.join("usr/lib/libssl.so.3"), b"fedora-new").unwrap();
        let new = world.repo.store_directory(&seed).unwrap();
        world.repo.create_ref("fedora", "openssl", "3.10.2", &new).unwrap();
        world.repo.create_ref("fedora", "openssl", "3.9.9", &new).unwrap();
        world.repo.create_ref("fedora", "openssl", "4.0.0", "BLAKE3-dangling").unwrap();

        let map = AnchorsMap::parse(
            r#"{ anchors = { "libssl.so.3" = [ { origin = "fedora"; package = "openssl"; } ]; }; }"#,
            "anchors.nix",
        )
        .unwrap();
        let resolution = resolve(&world.repo, &map).unwrap();
        assert_eq!(resolution.anchors[0].version, "3.10.2");
        assert_eq!(resolution.anchors[0].object, new);
    }
}
