//! Explicit, chroot-scoped post-weave tool invocation (PLAN 2.4.5 / 2.4.6).
//!
//! These are the *strict* counterparts of [`crate::weaver::hooks`]: the hook
//! runner records "skipped" and keeps going, which is right for an optional
//! desktop-cache refresh but wrong for the two steps the linker law depends on.
//! Here a missing tool is a hard, *named* error — never a silent success.
//!
//! Everything is scoped to the woven root (`-r <root>` / `-b <root>`): the host
//! cache is never touched, and no executable from the woven `bin/` is run.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::error::ExtosError;

/// Environment variable that overrides the `ldconfig` program name.
pub const LDCONFIG_ENV: &str = "EXTOS_LDCONFIG";
/// Environment variable that overrides the `depmod` program name.
pub const DEPMOD_ENV: &str = "EXTOS_DEPMOD";

/// A post-weave tool that ran successfully.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookOutcome {
    /// Program that was executed (resolved name, not an absolute path).
    pub program: String,
    /// Full argv, program excluded.
    pub arguments: Vec<String>,
    /// Captured stderr (tools are chatty about harmless warnings).
    pub stderr: String,
    /// Root the invocation was scoped to.
    pub root: PathBuf,
}

/// Resolve a program name, honouring an environment override.
fn resolve_program(env_var: &str, default: &str) -> String {
    match std::env::var(env_var) {
        Ok(value) if !value.trim().is_empty() => value,
        _ => default.to_string(),
    }
}

/// Validate that `root` is an existing directory.
fn require_root(root: &Path, tool: &str) -> Result<(), ExtosError> {
    if !root.is_dir() {
        return Err(ExtosError::Weave(format!(
            "{tool}: rootfs root {} does not exist or is not a directory",
            root.display()
        )));
    }
    Ok(())
}

/// Spawn `program args…` and turn absence / nonzero exit into a named error.
fn invoke(
    program: &str,
    arguments: Vec<String>,
    root: &Path,
    env_var: &str,
) -> Result<HookOutcome, ExtosError> {
    if program.trim().is_empty() {
        return Err(ExtosError::Weave(format!(
            "empty program name for {env_var}"
        )));
    }

    let output = Command::new(program)
        .args(&arguments)
        .output()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                ExtosError::Weave(format!(
                    "{program} not found (set {env_var} to point at an alternative binary): {e}"
                ))
            } else {
                ExtosError::Weave(format!("failed to run {program}: {e}"))
            }
        })?;

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();

    if !output.status.success() {
        let code = output
            .status
            .code()
            .map(|c| c.to_string())
            .unwrap_or_else(|| "signal".to_string());
        return Err(ExtosError::Weave(format!(
            "{program} failed with status {code}: {stderr}"
        )));
    }

    Ok(HookOutcome {
        program: program.to_string(),
        arguments,
        stderr,
        root: root.to_path_buf(),
    })
}

/// Regenerate the shared-library cache *inside* the woven root.
///
/// Runs `ldconfig -r <rootfs_root>`, so the host `/etc/ld.so.cache` is never
/// written. A missing `ldconfig` is reported as an error (override the program
/// with [`LDCONFIG_ENV`]) — silently continuing would leave a rootfs whose
/// dynamic linker cannot resolve the woven `usr/lib`.
pub fn run_ldconfig(rootfs_root: &Path) -> Result<HookOutcome, ExtosError> {
    let program = resolve_program(LDCONFIG_ENV, "ldconfig");
    require_root(rootfs_root, &program)?;
    let arguments = vec!["-r".to_string(), rootfs_root.display().to_string()];
    invoke(&program, arguments, rootfs_root, LDCONFIG_ENV)
}

/// Rebuild module dependency metadata for `kernel_version` under the woven root.
///
/// Runs `depmod -b <rootfs_root> <kernel_version>`. `kernel_version` is a single
/// version string (`6.8.2-extos`); path separators and `..` are rejected so the
/// argument can never escape the root. A missing `depmod` is a hard error
/// (override the program with [`DEPMOD_ENV`]).
pub fn run_depmod(
    rootfs_root: &Path,
    kernel_version: &str,
) -> Result<HookOutcome, ExtosError> {
    let program = resolve_program(DEPMOD_ENV, "depmod");
    require_root(rootfs_root, &program)?;
    validate_kernel_version(kernel_version)?;
    let arguments = vec![
        "-b".to_string(),
        rootfs_root.display().to_string(),
        kernel_version.to_string(),
    ];
    invoke(&program, arguments, rootfs_root, DEPMOD_ENV)
}

/// Reject kernel versions that are not a single plain path component.
fn validate_kernel_version(kernel_version: &str) -> Result<(), ExtosError> {
    let trimmed = kernel_version.trim();
    if trimmed.is_empty() {
        return Err(ExtosError::Weave(
            "depmod: kernel version must not be empty".into(),
        ));
    }
    if trimmed != kernel_version
        || kernel_version.contains('/')
        || kernel_version.contains('\\')
        || kernel_version == ".."
        || kernel_version == "."
        || kernel_version.contains('\0')
    {
        return Err(ExtosError::Weave(format!(
            "depmod: invalid kernel version {kernel_version:?}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_root_is_an_explicit_error() {
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("does-not-exist");
        let err = run_ldconfig(&missing).unwrap_err().to_string();
        assert!(err.contains("rootfs root"), "{err}");
    }

    #[test]
    fn empty_kernel_version_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let err = run_depmod(tmp.path(), "  ").unwrap_err().to_string();
        assert!(err.contains("kernel version"), "{err}");
    }

    #[test]
    fn traversal_kernel_version_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        for bad in ["../etc", "a/b", "..", "."] {
            let err = run_depmod(tmp.path(), bad).unwrap_err().to_string();
            assert!(err.contains("invalid kernel version"), "{bad}: {err}");
        }
    }

    #[test]
    fn absent_tool_fails_explicitly() {
        // Deterministic: force a program name that cannot exist. This exercises
        // the "no silent success" contract without depending on the host.
        let tmp = tempfile::tempdir().unwrap();
        let err = invoke(
            "extos-nonexistent-ldconfig-probe",
            vec!["-r".into(), tmp.path().display().to_string()],
            tmp.path(),
            LDCONFIG_ENV,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("not found"), "{err}");
        assert!(err.contains(LDCONFIG_ENV), "{err}");
    }

    #[test]
    fn successful_tool_run_is_reported() {
        let tmp = tempfile::tempdir().unwrap();
        // `true` ignores argv and exits 0 — a portable stand-in for the tool.
        let outcome = invoke(
            "true",
            vec!["-r".into(), tmp.path().display().to_string()],
            tmp.path(),
            LDCONFIG_ENV,
        )
        .unwrap();
        assert_eq!(outcome.program, "true");
        assert_eq!(outcome.arguments, vec!["-r", tmp.path().to_str().unwrap()]);
    }

    #[test]
    fn nonzero_exit_is_an_error() {
        let tmp = tempfile::tempdir().unwrap();
        let err = invoke("false", vec![], tmp.path(), DEPMOD_ENV)
            .unwrap_err()
            .to_string();
        assert!(err.contains("failed with status"), "{err}");
    }
}
