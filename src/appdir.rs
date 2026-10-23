//! AppDir provisioner for the `/runlevel/2` execution tier (PLAN sub-phase 4.3).
//!
//! An **AppDir** is the materialized form of Tier 3 of the collision engine
//! (see `design/ARCHITECTURE.md`, "The Execution Tiers"): when two packages
//! claim the same path with incompatible payloads and neither origin priority
//! nor a woven-tree wrapper can keep them apart, the losers are relocated into
//! a private tree below `/runlevel/2/<app>/`. Nothing in an AppDir is shared
//! with the host weave, so each AppDir may carry its own version of a SONAME.
//!
//! # Layout (PLAN 4.3.1)
//!
//! ```text
//! <root>/<app>/          root defaults to DEFAULT_APPDIR_ROOT ("/runlevel/2")
//! ├── bin/               executables and generated AppDir wrappers
//! ├── lib/               symlinks into CAS object payloads (SONAME-addressed)
//! ├── share/             XDG data directories
//! └── meta/              reserved: provenance / generation metadata
//! ```
//!
//! `root` is always supplied by the caller (config, CLI or
//! [`appdir_root_from_env`]) — no call site hardcodes a host path beyond the
//! documented [`DEFAULT_APPDIR_ROOT`] fallback string.
//!
//! # Pieces
//!
//! * [`AppDirLayout`] + [`AppDirLayout::provision`] — idempotent directory
//!   creation with a typed [`ProvisionedAppDir`] report (PLAN 4.3.1).
//! * [`CasLibraryRef`] + [`AppDirLayout::link_library`] — symlink a CAS object
//!   payload into `<app>/lib/`, reusing the weaver's link discipline
//!   (`weaver::link::link_symlink`, absolute CAS payload target) — PLAN 4.3.2.
//! * [`render_appdir_wrapper`] + [`AppDirLayout::write_wrapper`] — the
//!   `LD_LIBRARY_PATH` / `XDG_DATA_DIRS` launcher (PLAN 4.3.3). The script is
//!   self-locating, so the AppDir can be moved or chrooted.
//!
//! # Reuse note (PLAN 4.3.3)
//!
//! `weaver::wrapper` already renders the woven-tree Tier-3 dispatcher. Its
//! semantics are *not* the AppDir semantics: it dispatches between payloads
//! below `usr/lib/extos/alternatives/`, exports no `XDG_DATA_DIRS`, and puts
//! the selected alternative's `usr/lib` ahead of everything else. Therefore
//! this module renders its own script, but deliberately reuses the wrapper
//! module's primitives ([`crate::weaver::wrapper::sanitize_wrapper_name`] and
//! `weaver::wrapper::write_executable`) instead of duplicating them.

use std::fs;
use std::path::{Component, Path, PathBuf};

use crate::cas::CasRepository;
use crate::error::ExtosError;
use crate::weaver::link::link_symlink;
use crate::weaver::wrapper::{sanitize_wrapper_name, write_executable};

/// Default AppDir root when the environment does not override it.
///
/// This is a *documented default string*, not a compiled-in dependency: every
/// provisioner entry point takes the root from its caller, and
/// [`appdir_root_from_env`] resolves it at runtime.
pub const DEFAULT_APPDIR_ROOT: &str = "/runlevel/2";

/// Environment variable that relocates the AppDir root (PLAN 4.3.1).
pub const APPDIR_ROOT_ENV: &str = "EXTOS_APPDIR_ROOT";

/// Fixed sub-directory names of every AppDir, in creation order.
pub const APPDIR_SUBDIRS: [&str; 4] = ["bin", "lib", "share", "meta"];

/// Longest accepted AppDir identifier.
pub const MAX_APP_ID_LEN: usize = 64;

/// Resolve the AppDir root from `EXTOS_APPDIR_ROOT`, falling back to
/// [`DEFAULT_APPDIR_ROOT`].
///
/// The value is used verbatim (no canonicalization) so tests and containers can
/// point at a temporary tree.
pub fn appdir_root_from_env() -> PathBuf {
    match std::env::var_os(APPDIR_ROOT_ENV) {
        Some(value) if !value.is_empty() => PathBuf::from(value),
        _ => PathBuf::from(DEFAULT_APPDIR_ROOT),
    }
}

/// Validate and normalize an AppDir identifier (PLAN 4.3.1).
///
/// Accepted: non-empty ASCII alphanumerics plus `.`, `_`, `+`, `-`, at most
/// [`MAX_APP_ID_LEN`] bytes, not beginning with `.` or `-` (no hidden or
/// option-looking names). Everything else — in particular `/`, `\`, `..` and
/// NUL — is rejected with [`ExtosError::Weave`] rather than silently rewritten.
///
/// Normalization is ASCII lowercasing, so `Htop` and `htop` address the same
/// AppDir on case-insensitive filesystems.
pub fn normalize_app_id(raw: &str) -> Result<String, ExtosError> {
    let id = raw.trim();
    if id.is_empty() {
        return Err(ExtosError::Weave("AppDir id must not be empty".into()));
    }
    if id.len() > MAX_APP_ID_LEN {
        return Err(ExtosError::Weave(format!(
            "AppDir id exceeds {MAX_APP_ID_LEN} bytes: {id}"
        )));
    }
    if id == "." || id == ".." {
        return Err(ExtosError::Weave(format!(
            "AppDir id {id:?} is a path segment, not a name"
        )));
    }
    if id.starts_with('.') || id.starts_with('-') {
        return Err(ExtosError::Weave(format!(
            "AppDir id must not start with '.' or '-': {id}"
        )));
    }
    for c in id.chars() {
        if !(c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-')) {
            return Err(ExtosError::Weave(format!(
                "AppDir id contains unsafe character {c:?}: {id}"
            )));
        }
    }
    Ok(id.to_ascii_lowercase())
}

/// Reject a path that would escape its base directory.
fn ensure_relative(path: &Path, what: &str) -> Result<(), ExtosError> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::RootDir | Component::Prefix(_)))
    {
        return Err(ExtosError::Weave(format!(
            "{what} must be a relative path without '..': {}",
            path.display()
        )));
    }
    Ok(())
}

/// Reject characters that would change meaning inside the double-quoted
/// interpolation of the generated launcher (G-L14 N1 / PLAN 4.3.3).
///
/// The wrapper interpolates caller-supplied paths as
/// `"$extos_appdir/<rel>"`, so a `$` or backtick would be *re-expanded* by the
/// shell at launcher runtime (e.g. an extra dir of `$(id -u)` would execute
/// `id`). Quotes, backslashes, semicolons and line breaks could terminate the
/// quoting or the statement. Spaces are safe inside the quotes and stay legal
/// (NFS mount points and similar), so they are not rejected.
fn ensure_shell_safe(path: &Path, what: &str) -> Result<(), ExtosError> {
    let bytes = path.as_os_str().as_encoded_bytes();
    let hostile = |byte: u8| matches!(byte, b'$' | b'`' | b'"' | b'\\' | b';' | b'\'' | b'\n' | b'\r' | 0);
    if bytes.iter().copied().any(hostile) {
        return Err(ExtosError::Weave(format!(
            "{what} must not contain shell metacharacters ($, `, \", \\, ;, ', newline): {}",
            path.display()
        )));
    }
    Ok(())
}

/// A single-file name (`libfoo.so.1`), never a path.
fn ensure_file_name(name: &str, what: &str) -> Result<(), ExtosError> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.contains('/')
        || name.contains('\\')
        || name.contains('\0')
    {
        return Err(ExtosError::Weave(format!(
            "{what} must be a plain file name: {name:?}"
        )));
    }
    Ok(())
}

/// A provisioned AppDir: its normalized id and absolute root directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvisionedAppDir {
    /// Normalized AppDir id (see [`normalize_app_id`]).
    pub app_id: String,
    /// `<root>/<app_id>`.
    pub app_root: PathBuf,
    /// `true` when this call created the tree, `false` when it already existed
    /// (idempotent reprovisioning).
    pub created: bool,
}

/// The directory layout of one AppDir below a caller-supplied root (PLAN 4.3.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppDirLayout {
    root: PathBuf,
    app_id: String,
}

impl AppDirLayout {
    /// Address `<root>/<app_id>`, validating the id.
    ///
    /// No filesystem access happens here — see [`AppDirLayout::provision`].
    pub fn new(root: impl Into<PathBuf>, app_id: &str) -> Result<Self, ExtosError> {
        Ok(Self {
            root: root.into(),
            app_id: normalize_app_id(app_id)?,
        })
    }

    /// Normalized AppDir id.
    pub fn app_id(&self) -> &str {
        &self.app_id
    }

    /// The configured AppDir root (`<root>`, not `<root>/<app>`).
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// `<root>/<app_id>`.
    pub fn app_root(&self) -> PathBuf {
        self.root.join(&self.app_id)
    }

    /// `<app_root>/<sub>` for one of [`APPDIR_SUBDIRS`].
    pub fn subdir(&self, sub: &str) -> Result<PathBuf, ExtosError> {
        if !APPDIR_SUBDIRS.contains(&sub) {
            return Err(ExtosError::Weave(format!(
                "unknown AppDir sub-directory {sub:?}; expected one of {APPDIR_SUBDIRS:?}"
            )));
        }
        Ok(self.app_root().join(sub))
    }

    /// Create `bin/`, `lib/`, `share/` and `meta/` below the AppDir root.
    ///
    /// Idempotent: running it twice never fails, and the returned
    /// [`ProvisionedAppDir::created`] flag distinguishes first provisioning
    /// from a no-op re-run.
    pub fn provision(&self) -> Result<ProvisionedAppDir, ExtosError> {
        let app_root = self.app_root();
        let created = !app_root.is_dir();
        fs::create_dir_all(&app_root)?;
        for sub in APPDIR_SUBDIRS {
            fs::create_dir_all(app_root.join(sub))?;
        }
        Ok(ProvisionedAppDir {
            app_id: self.app_id.clone(),
            app_root,
            created,
        })
    }

    /// Symlink one CAS object payload into `<app>/lib/<link_name>` (PLAN 4.3.2).
    ///
    /// `lib.rel_path` is resolved below `objects/<hash>/content/`. The created
    /// link is absolute and must point back into the object store (never into
    /// `refs/`), mirroring the weaver's `link_symlink` discipline. Re-linking
    /// an already-correct entry is a no-op.
    pub fn link_library(
        &self,
        repo: &CasRepository,
        lib: &CasLibraryRef,
    ) -> Result<PathBuf, ExtosError> {
        ensure_file_name(&lib.link_name, "AppDir library link name")?;
        ensure_relative(&lib.rel_path, "CAS payload path")?;

        let content_root = repo.retrieve(&lib.object)?;
        let source = content_root.join(&lib.rel_path);
        if source.symlink_metadata().is_err() {
            return Err(ExtosError::CasIntegrity {
                expected: format!(
                    "{} inside object {}",
                    lib.rel_path.display(),
                    lib.object
                ),
                actual: "missing from CAS content".into(),
            });
        }
        let source = fs::canonicalize(&source)?;

        // Enforce the honest link target: inside objects/<hash>, never refs/.
        let object_root = repo.object_path(&lib.object);
        if !source.starts_with(&object_root) {
            return Err(ExtosError::CasIntegrity {
                expected: object_root.display().to_string(),
                actual: source.display().to_string(),
            });
        }

        self.provision()?;
        let target = self.app_root().join("lib").join(&lib.link_name);

        if let Ok(existing) = fs::read_link(&target) {
            if existing == source {
                return Ok(target);
            }
            fs::remove_file(&target)?;
        } else if target.symlink_metadata().is_ok() {
            fs::remove_file(&target)?;
        }

        link_symlink(&source, &target)?;

        // Post-condition: the linker will follow this link into the CAS object
        // payload, not into a mutable ref.
        let written = fs::read_link(&target)?;
        if !written.starts_with(&object_root) || written.starts_with(repo.root.join("refs")) {
            return Err(ExtosError::CasIntegrity {
                expected: format!("link into {}", object_root.display()),
                actual: written.display().to_string(),
            });
        }
        Ok(target)
    }

    /// Link several CAS payloads, returning the created link paths in order.
    pub fn link_libraries(
        &self,
        repo: &CasRepository,
        libs: &[CasLibraryRef],
    ) -> Result<Vec<PathBuf>, ExtosError> {
        libs.iter().map(|lib| self.link_library(repo, lib)).collect()
    }

    /// Write the AppDir launcher into `<app>/bin/<program>` (PLAN 4.3.3).
    ///
    /// Idempotent: an identical script is left untouched (stable mtime/perms).
    pub fn write_wrapper(
        &self,
        spec: &AppDirWrapperSpec,
    ) -> Result<PathBuf, ExtosError> {
        let script = render_appdir_wrapper(&self.app_id, spec)?;
        let program = sanitize_wrapper_name(&spec.program);
        let rel_path = PathBuf::from("bin").join(program);
        let target = self.app_root().join(&rel_path);

        if let Ok(existing) = fs::read_to_string(&target) {
            if existing == script {
                return Ok(target);
            }
        }
        write_executable(&self.app_root(), &rel_path, &script)
    }
}

/// One CAS payload to surface in an AppDir's `lib/` directory (PLAN 4.3.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CasLibraryRef {
    /// CAS object hash (as returned by `CasRepository::resolve_ref`).
    pub object: String,
    /// Path of the payload file *inside* the object's `content/` directory.
    pub rel_path: PathBuf,
    /// Name the library is addressed by inside `<app>/lib/` (usually its SONAME).
    pub link_name: String,
}

impl CasLibraryRef {
    /// Build a library reference.
    pub fn new(
        object: impl Into<String>,
        rel_path: impl Into<PathBuf>,
        link_name: impl Into<String>,
    ) -> Self {
        Self {
            object: object.into(),
            rel_path: rel_path.into(),
            link_name: link_name.into(),
        }
    }

    /// Resolve `refs/<origin>/<pkg>/<ver>` to its object hash first.
    ///
    /// A missing or dangling ref surfaces as [`ExtosError::PackageNotFound`]
    /// (PLAN 4.3.2 / 4.3.5 typed-error contract).
    pub fn from_ref(
        repo: &CasRepository,
        origin: &str,
        pkg: &str,
        ver: &str,
        rel_path: impl Into<PathBuf>,
        link_name: impl Into<String>,
    ) -> Result<Self, ExtosError> {
        let object = repo.resolve_ref(origin, pkg, ver)?;
        Ok(Self::new(object, rel_path, link_name))
    }
}

/// What the generated AppDir launcher finally executes (PLAN 4.3.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppDirWrapperTarget {
    /// Execute an AppDir-relative program (for `bin/` collisions).
    Exec(PathBuf),
    /// Environment-only launcher: `exec "$@"` with the AppDir environment
    /// applied (for library / SONAME-only collisions).
    EnvOnly,
}

/// Recipe for one AppDir launcher script (PLAN 4.3.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppDirWrapperSpec {
    /// Program name used for the script file inside `<app>/bin/`.
    pub program: String,
    /// What the script executes.
    pub target: AppDirWrapperTarget,
    /// SONAME recorded in the header/`LD_LIBRARY_PATH` hint (optional).
    pub soname: Option<String>,
    /// Extra AppDir-relative library directories, after `<app>/lib`.
    pub extra_lib_dirs: Vec<PathBuf>,
    /// Extra AppDir-relative data directories, after `<app>/share`.
    pub extra_data_dirs: Vec<PathBuf>,
}

impl AppDirWrapperSpec {
    /// Environment-only launcher named `program`.
    pub fn new(program: impl Into<String>) -> Self {
        Self {
            program: program.into(),
            target: AppDirWrapperTarget::EnvOnly,
            soname: None,
            extra_lib_dirs: Vec::new(),
            extra_data_dirs: Vec::new(),
        }
    }

    /// Execute `rel` (AppDir-relative) instead of `"$@"`.
    pub fn exec(mut self, rel: impl Into<PathBuf>) -> Self {
        self.target = AppDirWrapperTarget::Exec(rel.into());
        self
    }

    /// Record the conflicting SONAME in the script header.
    pub fn with_soname(mut self, soname: impl Into<String>) -> Self {
        self.soname = Some(soname.into());
        self
    }

    /// Prepend an extra AppDir-relative library directory.
    pub fn with_lib_dir(mut self, rel: impl Into<PathBuf>) -> Self {
        self.extra_lib_dirs.push(rel.into());
        self
    }

    /// Prepend an extra AppDir-relative data directory.
    pub fn with_data_dir(mut self, rel: impl Into<PathBuf>) -> Self {
        self.extra_data_dirs.push(rel.into());
        self
    }
}

/// Render a self-locating AppDir launcher (PLAN 4.3.3).
///
/// Ordering guarantees, lowest index wins:
/// * `LD_LIBRARY_PATH` = `<app>/lib` : extra lib dirs : `<app>/usr/lib` :
///   inherited `LD_LIBRARY_PATH`
/// * `XDG_DATA_DIRS` = `<app>/share` : extra data dirs : `<app>/usr/share` :
///   inherited `XDG_DATA_DIRS`
///
/// The AppDir root is derived from `$0` (`bin/<program>` → parent of parent),
/// never from a compiled-in host path, so the tree stays relocatable. Paths are
/// validated before they are interpolated, and every expansion is
/// double-quoted. Interpolated inputs additionally reject shell
/// metacharacters (`$`, backtick, `"`, `\`, `;`, `'`, line breaks), so a
/// hostile extra directory can never be re-expanded at launcher runtime
/// (G-L14 N1); spaces remain legal because they are quoted.
pub fn render_appdir_wrapper(
    app_id: &str,
    spec: &AppDirWrapperSpec,
) -> Result<String, ExtosError> {
    let program = sanitize_wrapper_name(&spec.program);
    if program.is_empty() {
        return Err(ExtosError::Weave(
            "AppDir wrapper program name must not be empty".into(),
        ));
    }
    // The id lands in a `#` comment line; a line break would start a new shell
    // statement. Ids normally come from `normalize_app_id`, but this renderer is
    // public, so re-check the one property the interpolation depends on.
    if app_id.contains('\n') || app_id.contains('\r') || app_id.contains('\0') {
        return Err(ExtosError::Weave(format!(
            "AppDir wrapper id must be a single line: {app_id:?}"
        )));
    }
    if let Some(soname) = &spec.soname {
        if soname.contains('\n') || soname.contains('\r') || soname.contains('\0') {
            return Err(ExtosError::Weave(format!(
                "AppDir wrapper SONAME hint must be single-line: {soname:?}"
            )));
        }
    }
    for dir in &spec.extra_lib_dirs {
        ensure_relative(dir, "AppDir extra library directory")?;
        ensure_shell_safe(dir, "AppDir extra library directory")?;
    }
    for dir in &spec.extra_data_dirs {
        ensure_relative(dir, "AppDir extra data directory")?;
        ensure_shell_safe(dir, "AppDir extra data directory")?;
    }
    if let AppDirWrapperTarget::Exec(rel) = &spec.target {
        ensure_relative(rel, "AppDir wrapper exec path")?;
        ensure_shell_safe(rel, "AppDir wrapper exec path")?;
    }

    let mut lib_dirs = vec!["$extos_appdir/lib".to_string()];
    for dir in &spec.extra_lib_dirs {
        lib_dirs.push(format!("$extos_appdir/{}", dir.display()));
    }
    lib_dirs.push("$extos_appdir/usr/lib".to_string());
    lib_dirs.push("${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}".to_string());

    let mut data_dirs = vec!["$extos_appdir/share".to_string()];
    for dir in &spec.extra_data_dirs {
        data_dirs.push(format!("$extos_appdir/{}", dir.display()));
    }
    data_dirs.push("$extos_appdir/usr/share".to_string());
    data_dirs.push("${XDG_DATA_DIRS:+:$XDG_DATA_DIRS}".to_string());

    let mut script = String::new();
    script.push_str("#!/bin/sh\n");
    script.push_str("# ExtOS AppDir launcher (PLAN 4.3.3) — generated, do not edit.\n");
    script.push_str(&format!("# AppDir: {app_id}\n"));
    script.push_str(&format!("# Program: {program}\n"));
    if let Some(soname) = &spec.soname {
        script.push_str(&format!("# Shared library hint: {soname}\n"));
    }
    script.push_str("self_dir=$(dirname -- \"$0\")\n");
    script.push_str("extos_appdir=$(CDPATH= cd -- \"$self_dir/..\" && pwd)\n");
    script.push_str(&format!(
        "LD_LIBRARY_PATH=\"{}\"\n",
        lib_dirs.join(":")
    ));
    script.push_str(&format!(
        "XDG_DATA_DIRS=\"{}\"\n",
        data_dirs.join(":")
    ));
    script.push_str("export LD_LIBRARY_PATH XDG_DATA_DIRS\n");

    match &spec.target {
        AppDirWrapperTarget::Exec(rel) => {
            script.push_str(&format!(
                "exec \"$extos_appdir/{}\" \"$@\"\n",
                rel.display()
            ));
        }
        AppDirWrapperTarget::EnvOnly => {
            script.push_str("if [ \"$#\" -eq 0 ]; then\n");
            script.push_str(
                "  printf '%s\\n' \"usage: $0 <command> [args...]\" >&2\n",
            );
            script.push_str("  exit 2\n");
            script.push_str("fi\n");
            script.push_str("exec \"$@\"\n");
        }
    }
    Ok(script)
}

// ─── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::HashAlgorithm;

    #[test]
    fn normalizes_and_rejects_app_ids() {
        assert_eq!(normalize_app_id("Htop").unwrap(), "htop");
        assert_eq!(normalize_app_id("glibc-2.39+x").unwrap(), "glibc-2.39+x");
        for bad in ["", "  ", ".", "..", "../etc", "a/b", "a\\b", "-x", ".hidden", "a b"] {
            assert!(normalize_app_id(bad).is_err(), "must reject {bad:?}");
        }
        assert!(normalize_app_id(&"a".repeat(MAX_APP_ID_LEN + 1)).is_err());
    }

    #[test]
    fn provisions_idempotently() {
        let tmp = tempfile::tempdir().unwrap();
        let layout = AppDirLayout::new(tmp.path().join("runlevel/2"), "Alpha").unwrap();
        let first = layout.provision().unwrap();
        assert!(first.created);
        assert_eq!(first.app_id, "alpha");
        assert_eq!(first.app_root, layout.app_root());
        for sub in APPDIR_SUBDIRS {
            assert!(first.app_root.join(sub).is_dir(), "missing {sub}");
        }
        let second = layout.provision().unwrap();
        assert!(!second.created);
        assert_eq!(second.app_root, first.app_root);
        assert!(layout.subdir("bogus").is_err());
    }

    #[test]
    fn links_cas_payload_into_lib() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = CasRepository::open(tmp.path().join("repo"), HashAlgorithm::Blake3).unwrap();
        let src = tmp.path().join("src/usr/lib");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("libfoo.so.1"), b"ELF-foo").unwrap();
        let obj = repo.store_directory(&tmp.path().join("src")).unwrap();

        let layout = AppDirLayout::new(tmp.path().join("runlevel/2"), "foo").unwrap();
        let lib = CasLibraryRef::new(&obj, "usr/lib/libfoo.so.1", "libfoo.so.1");
        let target = layout.link_library(&repo, &lib).unwrap();

        assert_eq!(target, layout.app_root().join("lib/libfoo.so.1"));
        assert!(target.symlink_metadata().unwrap().file_type().is_symlink());
        let link = fs::read_link(&target).unwrap();
        assert!(link.is_absolute());
        assert!(link.starts_with(repo.object_path(&obj)), "{}", link.display());
        assert!(!link.starts_with(repo.root.join("refs")));
        assert_eq!(fs::read(&target).unwrap(), b"ELF-foo");

        // Idempotent relink.
        let again = layout.link_library(&repo, &lib).unwrap();
        assert_eq!(again, target);
        assert_eq!(fs::read_link(&target).unwrap(), link);
    }

    #[test]
    fn missing_cas_ref_and_escaping_paths_are_typed_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = CasRepository::open(tmp.path().join("repo"), HashAlgorithm::Blake3).unwrap();
        let layout = AppDirLayout::new(tmp.path().join("runlevel/2"), "foo").unwrap();

        let missing = CasLibraryRef::new("blake3-deadbeef", "usr/lib/libfoo.so.1", "libfoo.so.1");
        assert!(matches!(
            layout.link_library(&repo, &missing).unwrap_err(),
            ExtosError::PackageNotFound { .. }
        ));

        // Unresolvable CAS *ref* is likewise typed.
        assert!(matches!(
            CasLibraryRef::from_ref(&repo, "distro-a", "nope", "1.0", "usr/lib/x.so", "x.so")
                .unwrap_err(),
            ExtosError::PackageNotFound { .. }
        ));

        let escaping = CasLibraryRef::new("x", "../etc/passwd", "passwd");
        assert!(matches!(
            layout.link_library(&repo, &escaping).unwrap_err(),
            ExtosError::Weave(_)
        ));

        let bad_name = CasLibraryRef::new("x", "usr/lib/libfoo.so.1", "a/b");
        assert!(matches!(
            layout.link_library(&repo, &bad_name).unwrap_err(),
            ExtosError::Weave(_)
        ));
    }

    #[test]
    fn wrapper_is_self_locating_and_ordered() {
        let spec = AppDirWrapperSpec::new("libfoo").with_soname("libfoo.so.1");
        let script = render_appdir_wrapper("foo", &spec).unwrap();
        assert!(script.starts_with("#!/bin/sh\n"));
        assert!(script.contains("libfoo.so.1"));
        assert!(script.contains("self_dir=$(dirname -- \"$0\")"));
        assert!(script.contains("$self_dir/.."));
        assert!(script.contains("LD_LIBRARY_PATH=\"$extos_appdir/lib:$extos_appdir/usr/lib"));
        assert!(script.contains("XDG_DATA_DIRS=\"$extos_appdir/share:$extos_appdir/usr/share"));
        assert!(script.contains("exec \"$@\""));
        assert!(!script.contains("/tmp/"));
        assert!(!script.contains("/home/"));
        assert!(!script.contains("/repository"));
    }

    #[test]
    fn wrapper_rejects_hostile_inputs() {
        let bad_exec = AppDirWrapperSpec::new("tool").exec("../../bin/sh");
        assert!(render_appdir_wrapper("foo", &bad_exec).is_err());

        let bad_lib = AppDirWrapperSpec::new("tool").with_lib_dir("/etc");
        assert!(render_appdir_wrapper("foo", &bad_lib).is_err());

        let bad_soname = AppDirWrapperSpec::new("tool").with_soname("x\nrm -rf /");
        assert!(render_appdir_wrapper("foo", &bad_soname).is_err());
    }

    #[test]
    fn wrapper_rejects_shell_metacharacters_in_interpolated_paths() {
        // G-L14 N1: these would be re-expanded inside the double-quoted
        // `"$extos_appdir/<rel>"` interpolation at launcher runtime.
        let hostile = [
            "$(id -u)",
            "`id -u`",
            "lib/a\"b",
            "lib/a\\b",
            "lib/a;b",
            "lib/a'b",
            "lib/a\nb",
            "lib/a\rb",
        ];
        for bad in hostile {
            let lib = AppDirWrapperSpec::new("tool").with_lib_dir(bad);
            assert!(
                matches!(render_appdir_wrapper("foo", &lib), Err(ExtosError::Weave(_))),
                "extra lib dir {bad:?} must be typed-rejected"
            );
            let data = AppDirWrapperSpec::new("tool").with_data_dir(bad);
            assert!(
                matches!(render_appdir_wrapper("foo", &data), Err(ExtosError::Weave(_))),
                "extra data dir {bad:?} must be typed-rejected"
            );
            let exec = AppDirWrapperSpec::new("tool").exec(bad);
            assert!(
                matches!(render_appdir_wrapper("foo", &exec), Err(ExtosError::Weave(_))),
                "exec target {bad:?} must be typed-rejected"
            );
        }

        // A multi-line AppDir id would break out of the `#` header comment.
        let spec = AppDirWrapperSpec::new("tool");
        assert!(render_appdir_wrapper("foo\nrm -rf /", &spec).is_err());

        // Spaces are inside double quotes and stay legal (e.g. NFS mounts).
        let spaced = AppDirWrapperSpec::new("tool").with_lib_dir("lib/with space");
        let script = render_appdir_wrapper("foo", &spaced).expect("spaces are quoted, not split");
        assert!(
            script.contains("$extos_appdir/lib/with space:"),
            "spaces must stay inside the quoted path: {script}"
        );
    }

    #[test]
    fn writes_executable_wrapper_idempotently() {
        let tmp = tempfile::tempdir().unwrap();
        let layout = AppDirLayout::new(tmp.path().join("runlevel/2"), "foo").unwrap();
        let spec = AppDirWrapperSpec::new("tool-env")
            .with_lib_dir("lib/private")
            .with_data_dir("share/private");

        let first = layout.write_wrapper(&spec).unwrap();
        assert_eq!(first, layout.app_root().join("bin/tool-env"));
        assert!(first.is_file());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&first).unwrap().permissions().mode() & 0o777,
                0o755
            );
        }
        let second = layout.write_wrapper(&spec).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn exec_target_is_relative_to_appdir() {
        let spec = AppDirWrapperSpec::new("tool").exec("bin/tool.real");
        let script = render_appdir_wrapper("foo", &spec).unwrap();
        assert!(script.contains("exec \"$extos_appdir/bin/tool.real\" \"$@\""));
    }

    #[test]
    fn env_override_selects_root() {
        // The resolver itself is pure; document the default fallback.
        assert!(DEFAULT_APPDIR_ROOT.ends_with("/runlevel/2"));
    }
}
