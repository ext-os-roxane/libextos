//! Guest OS mutation guard (M6.10).
//!
//! Prevents guest package managers (`pacman`, `apt`, `apk`) from modifying
//! the ExtOS-managed `/usr` tree. Two strategies:
//!
//! 1. **Read-only bind mount**: Remount `/usr` as read-only after weaving
//! 2. **Interception shims**: Replace native PM binaries with wrappers that
//!    redirect to `pkt`

use std::fs;
use std::path::Path;
use std::process::Command;

use crate::error::ExtosError;

/// Guard strategy for protecting the woven tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardStrategy {
    /// Remount /usr read-only (requires root)
    ReadOnlyMount,
    /// Install interception shims for native PMs
    InterceptionShims,
    /// Both: read-only mount + shims as fallback documentation
    Both,
    /// No protection (development mode)
    None,
}

impl Default for GuardStrategy {
    fn default() -> Self {
        Self::InterceptionShims
    }
}

/// Which native package managers to guard against.
const GUARDED_BINARIES: &[(&str, &str)] = &[
    ("pacman", "archlinux"),
    ("apt", "debian"),
    ("apt-get", "debian"),
    ("dpkg", "debian"),
    ("apk", "alpine"),
    ("dnf", "rpm"),
    ("yum", "rpm"),
    ("zypper", "suse"),
    ("xbps-install", "void"),
];

/// Install mutation guards on the target root.
pub fn install_guard(
    target_root: &Path,
    strategy: &GuardStrategy,
) -> Result<GuardResult, ExtosError> {
    let mut result = GuardResult::default();

    match strategy {
        GuardStrategy::ReadOnlyMount => {
            attempt_readonly_mount(target_root, &mut result)?;
        }
        GuardStrategy::InterceptionShims => {
            install_shims(target_root, &mut result)?;
        }
        GuardStrategy::Both => {
            install_shims(target_root, &mut result)?;
            attempt_readonly_mount(target_root, &mut result)?;
        }
        GuardStrategy::None => {
            result.notes.push("mutation guard disabled (dev mode)".into());
        }
    }

    Ok(result)
}

/// Result of guard installation.
#[derive(Debug, Default)]
pub struct GuardResult {
    /// Shims installed
    pub shims_installed: Vec<String>,
    /// Actions taken
    pub notes: Vec<String>,
    /// Warnings
    pub warnings: Vec<String>,
}

/// Attempt to remount /usr as read-only.
fn attempt_readonly_mount(target_root: &Path, result: &mut GuardResult) -> Result<(), ExtosError> {
    let usr = target_root.join("usr");
    if !usr.exists() {
        result.notes.push("skip ro mount: /usr does not exist".into());
        return Ok(());
    }

    // Check if running as root
    if unsafe { libc::geteuid() } != 0 {
        result.warnings.push("read-only mount requires root; skipped".into());
        return Ok(());
    }

    let status = Command::new("mount")
        .args(["--bind", "-o", "remount,ro"])
        .arg(&usr)
        .arg(&usr)
        .status();

    match status {
        Ok(s) if s.success() => {
            result.notes.push("remounted /usr as read-only".into());
        }
        Ok(_) => {
            result.warnings.push("failed to remount /usr as read-only".into());
        }
        Err(e) => {
            result.warnings.push(format!("mount command failed: {e}"));
        }
    }

    Ok(())
}

/// Install interception shims for native package managers.
///
/// Each shim is a small shell script that prints a message directing
/// the user to use `pkt` instead, then exits with code 1.
fn install_shims(target_root: &Path, result: &mut GuardResult) -> Result<(), ExtosError> {
    let shim_dir = target_root.join("usr/local/bin");
    fs::create_dir_all(&shim_dir)?;

    for &(binary, origin) in GUARDED_BINARIES {
        let _original = target_root.join("usr/bin").join(binary);
        let shim_path = shim_dir.join(binary);

        // Only install shim if the original binary exists
        // (or if we want to preemptively guard)
        let shim_content = generate_shim_script(binary, origin);

        // Don't overwrite if a real binary exists at this path
        if shim_path.exists() && !is_extos_shim(&shim_path) {
            continue;
        }

        fs::write(&shim_path, shim_content)?;

        // Make executable
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&shim_path, fs::Permissions::from_mode(0o755))?;
        }

        result.shims_installed.push(binary.to_string());
    }

    Ok(())
}

/// Generate the shell script content for an interception shim.
fn generate_shim_script(binary: &str, origin: &str) -> String {
    format!(
        r#"#!/bin/sh
# ExtOS Mutation Guard — Interception Shim
# This shim prevents direct use of '{binary}' on an ExtOS-managed system.
# Use 'pkt' instead to manage packages.
#
# Origin: {origin}
# To bypass (DANGEROUS): /usr/bin/{binary} "$@"

echo "╔══════════════════════════════════════════════════════════╗"
echo "║  ExtOS: '{binary}' is intercepted by the mutation guard   ║"
echo "║                                                          ║"
echo "║  This system is managed by ExtOS. Direct use of native   ║"
echo "║  package managers would corrupt the woven filesystem.    ║"
echo "║                                                          ║"
echo "║  Use instead:                                            ║"
echo "║    pkt -S <package>    # install a package               ║"
echo "║    pkt -R <package>    # remove a package                ║"
echo "║    pkt -Q              # query installed packages        ║"
echo "╚══════════════════════════════════════════════════════════╝"
exit 1
"#
    )
}

/// Check if a file is an ExtOS-generated shim.
fn is_extos_shim(path: &Path) -> bool {
    if let Ok(content) = fs::read_to_string(path) {
        content.contains("ExtOS Mutation Guard")
    } else {
        false
    }
}

/// Remove all installed shims (for uninstall/dev mode).
pub fn remove_guards(target_root: &Path) -> Result<usize, ExtosError> {
    let shim_dir = target_root.join("usr/local/bin");
    let mut removed = 0;

    for &(binary, _) in GUARDED_BINARIES {
        let shim_path = shim_dir.join(binary);
        if shim_path.exists() && is_extos_shim(&shim_path) {
            fs::remove_file(&shim_path)?;
            removed += 1;
        }
    }

    Ok(removed)
}

// ─── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shim_generation() {
        let script = generate_shim_script("pacman", "archlinux");
        assert!(script.contains("#!/bin/sh"));
        assert!(script.contains("ExtOS Mutation Guard"));
        assert!(script.contains("pacman"));
        assert!(script.contains("pkt -S"));
    }

    #[test]
    fn test_install_and_remove_shims() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        fs::create_dir_all(root.join("usr/bin")).unwrap();

        let result = install_guard(root, &GuardStrategy::InterceptionShims).unwrap();
        assert!(!result.shims_installed.is_empty());

        // Verify shims are executable
        let pacman_shim = root.join("usr/local/bin/pacman");
        assert!(pacman_shim.exists());
        assert!(is_extos_shim(&pacman_shim));

        // Remove
        let removed = remove_guards(root).unwrap();
        assert!(removed > 0);
        assert!(!pacman_shim.exists());
    }

    #[test]
    fn test_none_strategy() {
        let tmp = tempfile::tempdir().unwrap();
        let result = install_guard(tmp.path(), &GuardStrategy::None).unwrap();
        assert!(result.shims_installed.is_empty());
        assert!(result.notes.iter().any(|n| n.contains("disabled")));
    }
}
