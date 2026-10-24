//! User identity (PLAN 7.1, `design/ARCHITECTURE.md` §13).
//!
//! Users are declared in `/config/users/<name>.nix`; the universal data pool
//! lives at `/user/<name>/` with semantic per-user directories, and dotfiles
//! stay isolated per snapshot under `/runlevel/1/<system>/home/<profile>/`.
//! This module owns the declaration surface (PLAN 7.1.1), the pool
//! materialization (PLAN 7.1.2), the `pam_mount` volume rendering (PLAN 7.1.3)
//! and the ID-mapped-mount primitive for cross-system UID translation
//! ([`idmap`], PLAN 7.1.4).
//!
//! # Declaration grammar (`users/<name>.nix`)
//!
//! ```text
//! {
//!   uid = 1000;
//!   groups = [ "wheel" "audio" ];
//!   shell = "/bin/zsh";
//!   binds = [
//!     { host = "/srv/data"; target = "Projects/data"; }
//!   ];
//! }
//! ```
//!
//! `uid` is required; `shell` defaults to [`DEFAULT_SHELL`]; `groups` and
//! `binds` default to empty. User and group names must match
//! `[a-z_][a-z0-9_-]{0,31}`; bind `host` paths must be absolute and bind
//! `target` paths must be clean relative paths.
//!
//! # Honest scope
//!
//! No PAM module ships in this phase: [`ensure_user_pool`] is the
//! *first-login hook* a PAM session module would call, and [`render_pam_mount`]
//! produces the `<volume>` stanza a deployed `pam_mount.conf.xml` would
//! include. Both are pure library primitives; wiring them into a real PAM
//! stack is deferred. Likewise [`idmap::mount_setattr_idmap`] is the raw
//! kernel sequence — it requires a user namespace the caller controls.

pub mod idmap;

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use crate::config::NixValue;
use crate::error::ExtosError;

/// Shell assigned when a declaration omits `shell`.
pub const DEFAULT_SHELL: &str = "/bin/sh";

/// The standard per-user pool directories (ARCHITECTURE §13), created inside
/// `<user_root>/<name>/` by [`ensure_user_pool`].
pub const POOL_DIRS: [&str; 3] = ["Downloads", "Documents", "Projects"];

/// Maximum length of a user or group name (`[a-z_][a-z0-9_-]{0,31}`).
pub const MAX_NAME_LEN: usize = 32;

// ─── 7.1.1: declaration parsing ─────────────────────────────────

/// A parsed ExtOS user declaration (`users/<name>.nix`, PLAN 7.1.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserConfig {
    /// The user's name — the config file stem and the pool directory name.
    /// Always matches `[a-z_][a-z0-9_-]{0,31}` after parsing.
    pub name: String,
    /// The declared numeric user ID (required by the grammar).
    pub uid: u32,
    /// Supplementary group names (charset-validated).
    pub groups: Vec<String>,
    /// Login shell (defaults to [`DEFAULT_SHELL`]).
    pub shell: String,
    /// Host paths bound into the user's tree.
    pub binds: Vec<UserBind>,
}

/// One `binds` entry: an absolute host path surfaced inside the user's tree
/// at a clean relative `target`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserBind {
    /// Absolute path on the host side of the bind.
    pub host: PathBuf,
    /// Clean relative path (no `.`, no `..` components) inside the user's tree.
    pub target: String,
}

/// Parse a user declaration from an already-parsed Nix value (PLAN 7.1.1).
///
/// `name` is the declaration identity (the config file stem) and must itself
/// pass the user-name charset. `uid` is required; `shell` defaults to
/// [`DEFAULT_SHELL`]; `groups` and `binds` default to empty. Every malformed
/// shape is a typed [`ExtosError::ConfigParse`] naming the offending field —
/// never a silent fallback.
pub fn parse_user_config(name: &str, value: &NixValue) -> Result<UserConfig, ExtosError> {
    parse_user_config_with(name, value, &format!("users/{name}.nix"))
}

/// [`parse_user_config`] with an explicit error-location label (the `load`
/// path threads the real file through).
fn parse_user_config_with(
    name: &str,
    value: &NixValue,
    label: &str,
) -> Result<UserConfig, ExtosError> {
    validate_pool_name(name)
        .map_err(|message| user_err(label, format!("invalid user name '{name}': {message}")))?;

    // uid — required, integer in the u32 range.
    let uid = match value.get_path("uid") {
        None => {
            return Err(user_err(
                label,
                "required field 'uid' is missing (declared as an integer user ID)",
            ));
        }
        Some(v) => match v.as_int() {
            Some(n) if (0..=u32::MAX as i64).contains(&n) => n as u32,
            Some(n) => {
                return Err(user_err(
                    label,
                    format!("'uid' must be an integer in 0..={}, got {n}", u32::MAX),
                ));
            }
            None => {
                return Err(user_err(label, format!("'uid' must be an integer, got {v}")));
            }
        },
    };

    // shell — optional string, `/bin/sh` default.
    let shell = match value.get_path("shell") {
        None => DEFAULT_SHELL.to_string(),
        Some(v) => match v.as_str() {
            Some(s) if !s.is_empty() => s.to_string(),
            Some(_) => return Err(user_err(label, "'shell' must be a non-empty string")),
            None => return Err(user_err(label, format!("'shell' must be a string, got {v}"))),
        },
    };

    // groups — optional list of charset-validated names.
    let mut groups = Vec::new();
    if let Some(v) = value.get_path("groups") {
        let list = v.as_list().ok_or_else(|| {
            user_err(label, format!("'groups' must be a list of strings, got {v}"))
        })?;
        for item in list {
            let group = item.as_str().ok_or_else(|| {
                user_err(label, format!("'groups' entries must be strings, got {item}"))
            })?;
            validate_pool_name(group).map_err(|message| {
                user_err(label, format!("invalid group name '{group}': {message}"))
            })?;
            groups.push(group.to_string());
        }
    }

    // binds — optional list of { host; target; } attribute sets.
    let mut binds = Vec::new();
    if let Some(v) = value.get_path("binds") {
        let list = v.as_list().ok_or_else(|| {
            user_err(label, format!("'binds' must be a list of attribute sets, got {v}"))
        })?;
        for item in list {
            binds.push(parse_bind(item, label)?);
        }
    }

    Ok(UserConfig {
        name: name.to_string(),
        uid,
        groups,
        shell,
        binds,
    })
}

/// Parse one `binds` entry: `{ host = "<absolute>"; target = "<clean-rel>"; }`.
fn parse_bind(item: &NixValue, label: &str) -> Result<UserBind, ExtosError> {
    let bind: &BTreeMap<String, NixValue> = item.as_attrset().ok_or_else(|| {
        user_err(
            label,
            format!("'binds' entries must be attribute sets {{ host; target; }}, got {item}"),
        )
    })?;

    let host = bind
        .get("host")
        .and_then(|v| v.as_str())
        .ok_or_else(|| user_err(label, "each bind requires a string 'host' path"))?;
    let host = PathBuf::from(host);
    if !host.is_absolute() {
        return Err(user_err(
            label,
            format!("bind host '{}' must be an absolute path", host.display()),
        ));
    }

    let target = bind
        .get("target")
        .and_then(|v| v.as_str())
        .ok_or_else(|| user_err(label, "each bind requires a string 'target' path"))?;
    if !is_clean_relative(target) {
        return Err(user_err(
            label,
            format!(
                "bind target '{target}' must be a clean relative path \
                 (non-empty, no '.', no '..' or empty components)"
            ),
        ));
    }

    Ok(UserBind {
        host,
        target: target.to_string(),
    })
}

impl UserConfig {
    /// Load a user declaration from `users/<name>.nix` on disk (PLAN 7.1.1).
    ///
    /// The user name is the file stem; parse and validation errors carry the
    /// real file path.
    pub fn load(path: &Path) -> Result<Self, ExtosError> {
        let value = crate::config::parse_nix_file(path)?;
        let label = path.display().to_string();
        let name = path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .ok_or_else(|| {
                user_err(&label, "user config file name is not valid UTF-8".to_string())
            })?;
        parse_user_config_with(name, &value, &label)
    }
}

/// Whether `name` matches `[a-z_][a-z0-9_-]{0,31}`.
fn is_pool_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c == '_' || c.is_ascii_lowercase() => {}
        _ => return false,
    }
    let mut len = 1usize;
    for c in chars {
        if !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-') {
            return false;
        }
        len += 1;
        if len > MAX_NAME_LEN {
            return false;
        }
    }
    true
}

/// Validate a user or group name; the message explains the shape.
fn validate_pool_name(name: &str) -> Result<(), String> {
    if is_pool_name(name) {
        return Ok(());
    }
    Err(format!(
        "expected [a-z_][a-z0-9_-]{{0,{}}}",
        MAX_NAME_LEN - 1
    ))
}

/// Whether `target` is a clean relative path: non-empty, no empty segments
/// (so never absolute), no `.` and no `..` components.
fn is_clean_relative(target: &str) -> bool {
    !target.is_empty()
        && target
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

/// A `users/<name>.nix`-shaped [`ExtosError::ConfigParse`].
fn user_err(label: &str, message: impl Into<String>) -> ExtosError {
    ExtosError::ConfigParse {
        path: label.to_string(),
        line: 0,
        message: message.into(),
    }
}

// ─── 7.1.2: universal pool creation ─────────────────────────────

/// Result of one [`ensure_user_pool`] pass.
///
/// Invariant: `created.len() + present == 1 + POOL_DIRS.len()` — the pool
/// home plus each standard directory is either created by the call or was
/// already present.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PoolReport {
    /// Pool paths this call created (home first, then the standard dirs).
    pub created: Vec<PathBuf>,
    /// How many of the checked pool paths already existed.
    pub present: usize,
}

/// Materialize the universal pool for `config` under `user_root` (PLAN 7.1.2).
///
/// Creates `<user_root>/<name>/` and the [`POOL_DIRS`] subdirectories with
/// mode `0o700` (enforced after creation, so a restrictive umask cannot leak
/// the pool). Idempotent: directories that already exist are counted in
/// [`PoolReport::present`] and left untouched — their modes are not rewritten,
/// matching the non-clobbering declarative-write convention.
///
/// This is the *first-login hook* a PAM session module would call. No PAM
/// module ships in this phase: this primitive is the library contract, and it
/// creates plain directories on whatever filesystem backs `user_root`
/// (snapshot plumbing such as per-user subvolumes is the deployer's concern).
pub fn ensure_user_pool(config: &UserConfig, user_root: &Path) -> Result<PoolReport, ExtosError> {
    // Re-validate at the filesystem boundary: the name becomes a directory
    // component, so a hand-constructed `UserConfig` cannot smuggle traversal.
    validate_pool_name(&config.name)
        .map_err(|message| user_err("users", format!("invalid user name '{}': {message}", config.name)))?;

    std::fs::create_dir_all(user_root)?;

    let home = user_root.join(&config.name);
    let mut targets = vec![home.clone()];
    targets.extend(POOL_DIRS.iter().map(|dir| home.join(dir)));

    let mut report = PoolReport::default();
    for target in targets {
        match create_dir_0700(&target) {
            Ok(()) => report.created.push(target),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                if !target.is_dir() {
                    return Err(ExtosError::Io(std::io::Error::other(format!(
                        "user pool path {} exists and is not a directory",
                        target.display()
                    ))));
                }
                report.present += 1;
            }
            Err(err) => return Err(ExtosError::Io(err)),
        }
    }
    Ok(report)
}

/// Create `path` with mode `0o700`, defeating umask filtering.
fn create_dir_0700(path: &Path) -> std::io::Result<()> {
    std::fs::create_dir(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

// ─── 7.1.3: pam_mount volume rendering ──────────────────────────

/// Render the `pam_mount` volume XML that binds the user's pool into the
/// snapshot home (PLAN 7.1.3).
///
/// `pool_mountpoint` is the pool path (e.g. `/user/alice` on a deployed
/// system). The output is the single-volume `<pam_mount>` document:
///
/// ```text
/// <pam_mount>
///   <volume user="alice" mountpoint="/user/alice" path="/user/alice" fstype="none" options="bind" />
/// </pam_mount>
/// ```
///
/// Rendering is pure and byte-identical for equal inputs. Both interpolated
/// values are validated first — the user name must pass the pool-name charset
/// and the mountpoint must be free of XML-special characters — so the output
/// is XML-injection-proof: hostile inputs are typed rejections, never escaped
/// or silently rewritten.
///
/// Honest scope: no PAM module or `pam_mount.conf.xml` integration ships in
/// this phase; the returned string is the contract a deployment consumes.
pub fn render_pam_mount(config: &UserConfig, pool_mountpoint: &Path) -> Result<String, ExtosError> {
    validate_pool_name(&config.name)
        .map_err(|message| user_err("users", format!("invalid user name '{}': {message}", config.name)))?;
    let pool = pool_mountpoint.display().to_string();
    if pool.is_empty() || pool.chars().any(is_xml_hostile) {
        return Err(user_err(
            "users",
            format!(
                "pool mountpoint '{pool}' must be a non-empty path without XML-special \
                 characters (< > & \" ' or control characters)"
            ),
        ));
    }
    Ok(format!(
        "<pam_mount>\n  <volume user=\"{name}\" mountpoint=\"{pool}\" path=\"{pool}\" \
         fstype=\"none\" options=\"bind\" />\n</pam_mount>\n",
        name = config.name,
        pool = pool,
    ))
}

/// Characters that must never reach a rendered XML attribute.
fn is_xml_hostile(c: char) -> bool {
    matches!(c, '<' | '>' | '&' | '"' | '\'') || c.is_control()
}

// ─── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse_nix;

    /// A minimal valid declaration value.
    fn user_value(body: &str) -> NixValue {
        parse_nix(body).expect("test declaration parses")
    }

    // ── 7.1.1: the full grammar ──

    #[test]
    fn parses_full_grammar() {
        let value = user_value(
            r#"{
                uid = 1000;
                groups = [ "wheel" "audio" ];
                shell = "/bin/zsh";
                binds = [ { host = "/srv/data"; target = "Projects/data"; } ];
            }"#,
        );
        let config = parse_user_config("alice", &value).unwrap();
        assert_eq!(config.name, "alice");
        assert_eq!(config.uid, 1000);
        assert_eq!(config.groups, vec!["wheel", "audio"]);
        assert_eq!(config.shell, "/bin/zsh");
        assert_eq!(
            config.binds,
            vec![UserBind {
                host: PathBuf::from("/srv/data"),
                target: "Projects/data".to_string(),
            }]
        );
    }

    #[test]
    fn shell_defaults_and_empty_optional_fields() {
        let config = parse_user_config("bob", &user_value("{ uid = 0; }")).unwrap();
        assert_eq!(config.shell, DEFAULT_SHELL);
        assert!(config.groups.is_empty());
        assert!(config.binds.is_empty());
        assert_eq!(config.uid, 0);
    }

    #[test]
    fn unknown_fields_are_ignored() {
        let config =
            parse_user_config("carol", &user_value("{ uid = 1001; description = \"dev\"; }"))
                .unwrap();
        assert_eq!(config.uid, 1001);
    }

    #[test]
    fn accepts_valid_name_shapes() {
        for name in ["a", "_", "x1", "user-1", "a_b-c", &"a".repeat(MAX_NAME_LEN)] {
            parse_user_config(name, &user_value("{ uid = 1000; }"))
                .unwrap_or_else(|err| panic!("{name} must parse: {err}"));
        }
    }

    // ── 7.1.1: malformed shapes are typed rejections ──

    fn assert_parse_error(name: &str, body: &str, needle: &str) -> ExtosError {
        let err = parse_user_config(name, &user_value(body))
            .expect_err("malformed declaration must be rejected");
        assert!(
            matches!(err, ExtosError::ConfigParse { .. }),
            "typed ConfigParse expected, got: {err:?}"
        );
        assert!(
            err.to_string().contains(needle),
            "error must name the offender ({needle}), got: {err}"
        );
        err
    }

    #[test]
    fn missing_uid_is_a_typed_error() {
        assert_parse_error("alice", r#"{ shell = "/bin/sh"; }"#, "uid");
    }

    #[test]
    fn uid_type_and_range_are_enforced() {
        assert_parse_error("alice", r#"{ uid = "1000"; }"#, "uid");
        assert_parse_error("alice", "{ uid = -1; }", "uid");
        assert_parse_error("alice", "{ uid = 4294967296; }", "uid");
        assert_parse_error("alice", "{ uid = null; }", "uid");
    }

    #[test]
    fn shell_type_is_enforced() {
        assert_parse_error("alice", "{ uid = 1000; shell = 42; }", "shell");
        assert_parse_error("alice", "{ uid = 1000; shell = \"\"; }", "shell");
        assert_parse_error("alice", "{ uid = 1000; shell = null; }", "shell");
    }

    #[test]
    fn group_names_and_groups_shape_are_enforced() {
        assert_parse_error("alice", r#"{ uid = 1000; groups = "wheel"; }"#, "groups");
        assert_parse_error("alice", "{ uid = 1000; groups = [ 42 ]; }", "groups");
        assert_parse_error("alice", r#"{ uid = 1000; groups = [ "Wheel" ]; }"#, "Wheel");
        assert_parse_error("alice", r#"{ uid = 1000; groups = [ "0adm" ]; }"#, "0adm");
        assert_parse_error(
            "alice",
            r#"{ uid = 1000; groups = [ "../escape" ]; }"#,
            "../escape",
        );
        let long = "g".repeat(MAX_NAME_LEN + 1);
        assert_parse_error("alice", &format!(r#"{{ uid = 1000; groups = [ "{long}" ]; }}"#), &long);
    }

    #[test]
    fn bind_shape_and_paths_are_enforced() {
        // Not an attribute set.
        assert_parse_error(
            "alice",
            r#"{ uid = 1000; binds = [ "/srv/data" ]; }"#,
            "binds",
        );
        // Missing host / missing target.
        assert_parse_error(
            "alice",
            r#"{ uid = 1000; binds = [ { target = "data"; } ]; }"#,
            "host",
        );
        assert_parse_error(
            "alice",
            r#"{ uid = 1000; binds = [ { host = "/srv/data"; } ]; }"#,
            "target",
        );
        // Host must be absolute.
        assert_parse_error(
            "alice",
            r#"{ uid = 1000; binds = [ { host = "srv/data"; target = "data"; } ]; }"#,
            "absolute",
        );
        // Target must be clean relative: empty, absolute, dot, dot-dot,
        // interior empty segments.
        for bad in ["", "/abs", ".", "..", "../escape", "a/../b", "a//b", "a/"] {
            let body = format!(r#"{{ uid = 1000; binds = [ {{ host = "/srv/data"; target = "{bad}"; }} ]; }}"#);
            let err = assert_parse_error("alice", &body, bad);
            assert!(
                err.to_string().contains("clean relative path"),
                "target rejection explains the rule: {err}"
            );
        }
        assert_parse_error(
            "alice",
            r#"{ uid = 1000; binds = [ { host = "/srv/data"; target = 42; } ]; }"#,
            "target",
        );
    }

    #[test]
    fn hostile_user_names_are_typed_rejections() {
        for bad in [
            "",
            "Alice",
            "0leading",
            "-leading",
            "has space",
            "../escape",
            "tab\there",
            &"a".repeat(MAX_NAME_LEN + 1),
        ] {
            let err = parse_user_config(bad, &user_value("{ uid = 1000; }"))
                .expect_err("hostile name must be rejected");
            assert!(
                matches!(err, ExtosError::ConfigParse { .. }),
                "typed rejection for {bad:?}, got: {err:?}"
            );
        }
    }

    #[test]
    fn load_derives_name_from_file_stem_and_labels_errors_with_the_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("users").join("alice.nix");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            &path,
            r#"{
                uid = 1000;
                groups = [ "wheel" ];
                binds = [ { host = "/srv/data"; target = "Projects/data"; } ];
            }"#,
        )
        .unwrap();

        let config = UserConfig::load(&path).unwrap();
        assert_eq!(
            config,
            UserConfig {
                name: "alice".to_string(),
                uid: 1000,
                groups: vec!["wheel".to_string()],
                shell: DEFAULT_SHELL.to_string(),
                binds: vec![UserBind {
                    host: PathBuf::from("/srv/data"),
                    target: "Projects/data".to_string(),
                }],
            }
        );

        // Malformed load: the typed error carries the real file path.
        let bad = dir.path().join("users").join("bob.nix");
        std::fs::write(&bad, "{ shell = \"/bin/sh\"; }").unwrap();
        let err = UserConfig::load(&bad).expect_err("missing uid must fail");
        let message = err.to_string();
        assert!(
            message.contains(&dir.path().join("users").join("bob.nix").display().to_string())
                && message.contains("uid"),
            "error names the real file and the field: {message}"
        );
    }

    // ── 7.1.2: pool creation ──

    fn pool_config(name: &str) -> UserConfig {
        UserConfig {
            name: name.to_string(),
            uid: 1000,
            groups: Vec::new(),
            shell: DEFAULT_SHELL.to_string(),
            binds: Vec::new(),
        }
    }

    #[test]
    fn pool_creation_is_idempotent_with_report_and_modes() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("user");
        let config = pool_config("alice");

        let report = ensure_user_pool(&config, &root).unwrap();
        assert_eq!(report.present, 0, "fresh pool: nothing pre-existing");
        assert_eq!(report.created.len(), 1 + POOL_DIRS.len());
        assert_eq!(report.created[0], root.join("alice"));
        for (expected, created) in POOL_DIRS.iter().zip(report.created[1..].iter()) {
            assert_eq!(created, &root.join("alice").join(expected));
        }
        // Invariant: every checked path accounted for.
        assert_eq!(report.created.len() + report.present, 1 + POOL_DIRS.len());

        // Mode 0o700 on the home and every standard directory, even under a
        // hostile umask (set_permissions after create defeats the filter).
        for path in &report.created {
            let mode = std::fs::metadata(path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o700, "{} must be 0o700", path.display());
        }

        // Idempotent re-run: nothing created, everything counted present.
        let rerun = ensure_user_pool(&config, &root).unwrap();
        assert!(rerun.created.is_empty());
        assert_eq!(rerun.present, 1 + POOL_DIRS.len());
    }

    #[test]
    fn pool_creation_rejects_hostile_names_at_the_fs_boundary() {
        let dir = tempfile::tempdir().unwrap();
        let before = std::fs::read_dir(dir.path()).unwrap().count();
        let err = ensure_user_pool(&pool_config("../escape"), dir.path())
            .expect_err("traversal name must be rejected before any fs write");
        assert!(matches!(err, ExtosError::ConfigParse { .. }), "{err:?}");
        assert_eq!(
            std::fs::read_dir(dir.path()).unwrap().count(),
            before,
            "no filesystem side effects for a rejected name"
        );
    }

    #[test]
    fn pool_creation_reports_a_path_that_is_not_a_directory() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("user");
        std::fs::create_dir_all(root.join("alice")).unwrap();
        std::fs::write(root.join("alice").join("Downloads"), b"not a dir").unwrap();

        let err = ensure_user_pool(&pool_config("alice"), &root)
            .expect_err("a file squatting a pool dir must surface, not count as present");
        let message = err.to_string();
        assert!(
            message.contains("not a directory"),
            "honest error expected, got: {message}"
        );
    }

    // ── 7.1.3: pam_mount rendering ──

    #[test]
    fn pam_mount_xml_is_pinned_byte_identically() {
        let config = pool_config("alice");
        let dir = tempfile::tempdir().unwrap();
        let pool = dir.path().join("alice");
        let expected = format!(
            "<pam_mount>\n  <volume user=\"alice\" mountpoint=\"{pool}\" path=\"{pool}\" \
             fstype=\"none\" options=\"bind\" />\n</pam_mount>\n",
            pool = pool.display()
        );
        assert_eq!(render_pam_mount(&config, &pool).unwrap(), expected);
        // Byte-identical on re-run.
        assert_eq!(render_pam_mount(&config, &pool).unwrap(), expected);
    }

    #[test]
    fn pam_mount_rejects_hostile_names_and_xml_hostile_mountpoints() {
        let dir = tempfile::tempdir().unwrap();
        let hostile = pool_config("../escape");
        let err = render_pam_mount(&hostile, dir.path())
            .expect_err("hostile user name must be rejected before rendering");
        assert!(
            matches!(err, ExtosError::ConfigParse { .. }) && err.to_string().contains("../escape"),
            "{err:?}"
        );

        let config = pool_config("alice");
        for bad in ["<script>", "a&b", "quo\"te", "quo'te"] {
            let pool = dir.path().join(bad);
            let err = render_pam_mount(&config, &pool)
                .expect_err("XML-hostile mountpoint must be typed-rejected");
            assert!(
                matches!(err, ExtosError::ConfigParse { .. }),
                "typed rejection for {bad:?}, got: {err:?}"
            );
            assert!(
                err.to_string().contains("XML"),
                "rejection explains the XML contract: {err}"
            );
        }
        // The empty mountpoint is rejected too — tested directly, because
        // `Path::join("")` yields the directory itself rather than an empty
        // path.
        let err = render_pam_mount(&config, Path::new(""))
            .expect_err("empty mountpoint must be typed-rejected");
        assert!(
            matches!(err, ExtosError::ConfigParse { .. }),
            "typed rejection for the empty mountpoint, got: {err:?}"
        );
        assert!(
            err.to_string().contains("XML"),
            "rejection explains the XML contract: {err}"
        );
    }
}
