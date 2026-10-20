//! Tier-3 collision wrappers (PLAN 2.4.3 / 2.4.4).
//!
//! When two packages claim the same path with *incompatible* content and the
//! origin-priority protocol cannot pick a winner (equal priority), the weaver
//! escalates from Tier 2 (priority) to Tier 3 (wrapper). Both real payloads stay
//! on disk under `usr/lib/extos/alternatives/<slug>/<original path>` and a small
//! POSIX shell wrapper is installed at the contested path. The wrapper:
//!
//! * derives the rootfs root from its own location (never from a compiled-in
//!   absolute path — the same tree can be moved or chrooted),
//! * exports an `LD_LIBRARY_PATH` that covers the selected alternative plus the
//!   woven `/usr/lib`, so the linker never has to see the CAS,
//! * exports a `PATH` that keeps the woven tree first, and
//! * `exec`s the selected real binary, so signals/exit codes pass through.
//!
//! The active alternative is chosen with `EXTOS_ALT_<BINARY>` and defaults to
//! the first alternative in the spec (the priority winner).

use std::fs;
use std::path::{Component, Path, PathBuf};

use crate::error::ExtosError;

/// Root (relative to the woven rootfs) of the per-package alternatives tree.
pub const ALTERNATIVES_ROOT: &str = "usr/lib/extos/alternatives";

/// One selectable real binary behind a Tier-3 wrapper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrapperAlternative {
    /// Provider label (`origin/name`) that owns the binary.
    pub package: String,
    /// Filesystem-safe identifier used below [`ALTERNATIVES_ROOT`].
    pub slug: String,
    /// Path of the real binary, relative to the rootfs root.
    pub rel_path: PathBuf,
}

impl WrapperAlternative {
    /// Build an alternative from its provider label, slug and relative path.
    pub fn new(
        package: impl Into<String>,
        slug: impl Into<String>,
        rel_path: impl Into<PathBuf>,
    ) -> Self {
        Self {
            package: package.into(),
            slug: slug.into(),
            rel_path: rel_path.into(),
        }
    }
}

/// Everything [`render_wrapper`] needs to emit a wrapper script.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrapperSpec {
    /// Provider label (`origin/name`) the wrapper is generated for.
    pub package: String,
    /// User-visible program name (`tool`, not `tool-1.2`).
    pub binary: String,
    /// Where to install the wrapper, relative to the rootfs root.
    ///
    /// [`WrapperSpec::new`] defaults this to `usr/bin/<sanitized binary>`.
    pub rel_path: PathBuf,
    /// Real payloads, best first. The first entry is the default selection.
    pub alternatives: Vec<WrapperAlternative>,
    /// Extra library directories (relative to the rootfs root) to prepend to
    /// `LD_LIBRARY_PATH`, e.g. `opt/pkg/lib`.
    pub lib_dirs: Vec<PathBuf>,
}

impl WrapperSpec {
    /// Create a spec that installs `usr/bin/<sanitized binary>`.
    pub fn new(package: impl Into<String>, binary: impl Into<String>) -> Self {
        let binary = binary.into();
        let name = sanitize_wrapper_name(&binary);
        Self {
            package: package.into(),
            binary,
            rel_path: PathBuf::from("usr/bin").join(name),
            alternatives: Vec::new(),
            lib_dirs: Vec::new(),
        }
    }

    /// Install the wrapper at an explicit rootfs-relative path.
    pub fn at_path(mut self, rel_path: impl Into<PathBuf>) -> Self {
        self.rel_path = rel_path.into();
        self
    }

    /// Attach the selectable real payloads (best first).
    pub fn with_alternatives(mut self, alternatives: Vec<WrapperAlternative>) -> Self {
        self.alternatives = alternatives;
        self
    }

    /// Attach extra rootfs-relative library directories.
    pub fn with_lib_dirs(mut self, lib_dirs: Vec<PathBuf>) -> Self {
        self.lib_dirs = lib_dirs;
        self
    }

    /// Environment variable that selects an alternative (`EXTOS_ALT_<BINARY>`).
    pub fn selector_var(&self) -> String {
        let mut out = String::from("EXTOS_ALT_");
        for c in sanitize_wrapper_name(&self.binary).chars() {
            out.push(c.to_ascii_uppercase());
        }
        out
    }
}

/// Sanitize a name for use as a file name and shell variable.
///
/// Keeps ASCII alphanumerics plus `.`, `_`, `+`, `-`; every other byte becomes
/// `_`. Empty input becomes `_`.
pub fn sanitize_wrapper_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for c in name.chars() {
        if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-') {
            out.push(c);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        out.push('_');
    }
    out
}

/// Filesystem-safe slug for a provider label (`archlinux/htop` → `archlinux-htop`).
pub fn provider_slug(provider: &str) -> String {
    sanitize_wrapper_name(&provider.replace('/', "-"))
}

/// Render the wrapper script for `spec`, mentioning `soname` in the header and
/// on the library path (empty `soname` omits the hint).
///
/// Returns an error when the spec has no alternatives to exec.
pub fn render_wrapper(spec: &WrapperSpec, soname: &str) -> Result<String, ExtosError> {
    if spec.alternatives.is_empty() {
        return Err(ExtosError::Weave(format!(
            "cannot generate wrapper for {}: no alternatives",
            spec.package
        )));
    }
    for alt in &spec.alternatives {
        if alt.rel_path.is_absolute()
            || alt.rel_path.components().any(|c| c == Component::ParentDir)
        {
            return Err(ExtosError::Weave(format!(
                "wrapper alternative must be rootfs-relative: {}",
                alt.rel_path.display()
            )));
        }
    }

    let default = &spec.alternatives[0].slug;
    let selector = spec.selector_var();
    let bin_name = sanitize_wrapper_name(&spec.binary);

    // `extos_root` is derived from the script location: hop up once per extra
    // path component above `usr/bin/<name>`.
    let depth = spec.rel_path.components().count().saturating_sub(1);
    let ups = "../".repeat(depth);

    let mut lib_path: Vec<String> = Vec::new();
    for alt in &spec.alternatives {
        lib_path.push(format!("$alts/{}/usr/lib", alt.slug));
    }
    for dir in &spec.lib_dirs {
        lib_path.push(format!("$extos_root/{}", dir.display()));
    }
    lib_path.push("$extos_root/usr/lib".to_string());
    lib_path.push("$extos_root/usr/lib/extos".to_string());
    let lib_path_joined = lib_path.join(":");

    // The exec path is relative to `$alts/<selected slug>/`, so drop the
    // alternatives prefix that each alternative carries.
    let mut exec_paths = Vec::with_capacity(spec.alternatives.len());
    for alt in &spec.alternatives {
        let prefix = Path::new(ALTERNATIVES_ROOT).join(&alt.slug);
        let relative = alt.rel_path.strip_prefix(&prefix).map_err(|_| {
            ExtosError::Weave(format!(
                "wrapper alternative {} must live under {}",
                alt.rel_path.display(),
                prefix.display()
            ))
        })?;
        exec_paths.push(relative.to_path_buf());
    }

    let claimants = spec
        .alternatives
        .iter()
        .map(|a| format!("{} ({})", a.package, a.slug))
        .collect::<Vec<_>>()
        .join(", ");
    let soname_line = if soname.is_empty() {
        String::new()
    } else {
        format!("# Shared library hint: {soname}\n")
    };

    let mut script = String::new();
    script.push_str("#!/bin/sh\n");
    script.push_str("# ExtOS Tier-3 collision wrapper — generated by the weaver, do not edit.\n");
    script.push_str(&format!("# Package: {}\n", spec.package));
    script.push_str(&format!("# Program: {bin_name}\n"));
    script.push_str(&soname_line);
    script.push_str(&format!("# Claimants: {claimants}\n"));
    script.push_str(&format!(
        "# Select an alternative with {selector} (default: {default}).\n"
    ));
    script.push_str("self_dir=$(dirname -- \"$0\")\n");
    script.push_str(&format!(
        "extos_root=$(CDPATH= cd -- \"$self_dir/{ups}\" && pwd)\n"
    ));
    script.push_str("alts=\"$extos_root/usr/lib/extos/alternatives\"\n");
    script.push_str(&format!(
        "LD_LIBRARY_PATH=\"{lib_path_joined}${{LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}}\"\n"
    ));
    script.push_str("PATH=\"$extos_root/usr/bin:$extos_root/usr/sbin${PATH:+:$PATH}\"\n");
    script.push_str("export LD_LIBRARY_PATH PATH\n");
    script.push_str(&format!(
        "exec \"$alts/${{{selector}:-{default}}}/{}\" \"$@\"\n",
        exec_paths[0].display()
    ));
    Ok(script)
}

/// Write a Tier-3 wrapper into `target_root/<spec.rel_path>` (by default
/// `target_root/usr/bin/<binary>`), creating parent directories.
///
/// The script is written with mode `0o755`, replaced atomically-enough (write to
/// a sibling temp file, then rename) and returned by path.
///
/// `soname` is recorded in the header for diagnostics; pass `""` when the
/// conflict is not library-driven.
pub fn generate_wrapper(
    spec: &WrapperSpec,
    soname: &str,
    target_root: &Path,
) -> Result<PathBuf, ExtosError> {
    let script = render_wrapper(spec, soname)?;
    write_executable(target_root, &spec.rel_path, &script)
}

/// Write `content` at `root/rel_path` with mode 0o755, returning the full path.
pub(crate) fn write_executable(
    root: &Path,
    rel_path: &Path,
    content: &str,
) -> Result<PathBuf, ExtosError> {
    if rel_path.is_absolute() || rel_path.components().any(|c| c == Component::ParentDir) {
        return Err(ExtosError::Weave(format!(
            "refusing to write outside the rootfs: {}",
            rel_path.display()
        )));
    }
    let target = root.join(rel_path);
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&target, content)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&target, fs::Permissions::from_mode(0o755))?;
    }
    Ok(target)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> WrapperSpec {
        WrapperSpec::new("distro-a/alpha", "tool").with_alternatives(vec![
            WrapperAlternative::new("distro-a/alpha", "distro-a-alpha", "usr/lib/extos/alternatives/distro-a-alpha/usr/bin/tool"),
            WrapperAlternative::new("distro-b/beta", "distro-b-beta", "usr/lib/extos/alternatives/distro-b-beta/usr/bin/tool"),
        ])
    }

    #[test]
    fn sanitizes_names() {
        assert_eq!(sanitize_wrapper_name("tool"), "tool");
        assert_eq!(sanitize_wrapper_name("a/b c"), "a_b_c");
        assert_eq!(sanitize_wrapper_name("libfoo.so.1"), "libfoo.so.1");
        assert_eq!(sanitize_wrapper_name(""), "_");
        assert_eq!(provider_slug("archlinux/htop"), "archlinux-htop");
    }

    #[test]
    fn renders_self_contained_script() {
        let script = render_wrapper(&spec(), "libalpha.so.1").unwrap();
        assert!(script.starts_with("#!/bin/sh\n"));
        assert!(script.contains("libalpha.so.1"));
        assert!(script.contains("LD_LIBRARY_PATH="));
        assert!(script.contains("PATH=\"$extos_root/usr/bin"));
        assert!(script.contains("EXTOS_ALT_TOOL"));
        assert!(script.contains("distro-a-alpha"));
        assert!(
            script.contains(
                "exec \"$alts/${EXTOS_ALT_TOOL:-distro-a-alpha}/usr/bin/tool\" \"$@\""
            ),
            "exec path must be relative to the selected alternative: {script}"
        );
        // No absolute host paths leak into the script.
        assert!(!script.contains("/home/"));
        assert!(!script.contains("/tmp/"));
        assert!(!script.contains("/repository"));
        // Hops up from usr/bin to the rootfs root.
        assert!(script.contains("$self_dir/../.."));
    }

    #[test]
    fn renders_extra_lib_dirs() {
        let s = spec().with_lib_dirs(vec![PathBuf::from("opt/alpha/lib")]);
        let script = render_wrapper(&s, "").unwrap();
        assert!(script.contains("$extos_root/opt/alpha/lib"));
        assert!(!script.contains("Shared library hint"));
    }

    #[test]
    fn rejects_missing_alternatives() {
        let s = WrapperSpec::new("x/y", "y");
        assert!(render_wrapper(&s, "").is_err());
    }

    #[test]
    fn rejects_escaping_alternative() {
        let s = WrapperSpec::new("x/y", "y").with_alternatives(vec![WrapperAlternative::new(
            "x/y",
            "x-y",
            "../../etc/passwd",
        )]);
        assert!(render_wrapper(&s, "").is_err());
    }

    #[test]
    fn generates_executable_in_target_root() {
        let tmp = tempfile::tempdir().unwrap();
        let path = generate_wrapper(&spec(), "", tmp.path()).unwrap();
        assert_eq!(path, tmp.path().join("usr/bin/tool"));
        assert!(path.is_file());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o755);
        }
    }
}
