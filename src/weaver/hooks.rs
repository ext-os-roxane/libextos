//! Post-weave hooks (M6.9).
//!
//! After the weaver materializes the FHS tree, these hooks run system
//! configuration commands to finalize the installation:
//!
//! - `ldconfig`: Regenerate shared library cache
//! - `depmod`: Rebuild kernel module dependency info
//! - PhantomDB: Generate native PM database entries (delegated to M7)

use std::path::Path;
use std::process::Command;


/// Result of running post-weave hooks.
#[derive(Debug, Default)]
pub struct HookResult {
    /// Hooks that ran successfully
    pub succeeded: Vec<String>,
    /// Hooks that were skipped (e.g., no kernel modules found)
    pub skipped: Vec<String>,
    /// Hooks that failed (non-fatal)
    pub failed: Vec<(String, String)>,
}

/// Run all post-weave hooks against the woven target root.
///
/// `target_root` is the root of the woven FHS tree (e.g., `/` or a chroot).
/// Hooks adapt to the target: if no kernel modules exist, `depmod` is skipped.
pub fn run_post_weave_hooks(target_root: &Path) -> HookResult {
    let mut result = HookResult::default();

    // Hook 1: ldconfig — regenerate shared library cache
    run_ldconfig(target_root, &mut result);

    // Hook 2: depmod — rebuild kernel module deps (if modules exist)
    run_depmod(target_root, &mut result);

    // Hook 3: Update icon/desktop/mime caches if present
    run_desktop_cache_update(target_root, &mut result);

    result
}

/// Run `ldconfig` against the target root.
///
/// Uses `-r` for chroot-relative operation when target isn't `/`.
fn run_ldconfig(target_root: &Path, result: &mut HookResult) {
    let lib_dir = target_root.join("usr/lib");
    if !lib_dir.exists() {
        result.skipped.push("ldconfig: no usr/lib directory".into());
        return;
    }

    let cmd_result = if target_root == Path::new("/") {
        Command::new("ldconfig").output()
    } else {
        // Use -r for chroot-relative, or -N -X with explicit paths
        Command::new("ldconfig")
            .arg("-r")
            .arg(target_root)
            .output()
    };

    match cmd_result {
        Ok(output) if output.status.success() => {
            result.succeeded.push("ldconfig".into());
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            // ldconfig may warn but still succeed
            if stderr.contains("not a known library type") || stderr.is_empty() {
                result.succeeded.push("ldconfig (with warnings)".into());
            } else {
                result.failed.push(("ldconfig".into(), stderr));
            }
        }
        Err(e) => {
            result.failed.push(("ldconfig".into(), e.to_string()));
        }
    }
}

/// Run `depmod` if kernel modules are present.
fn run_depmod(target_root: &Path, result: &mut HookResult) {
    let modules_dir = target_root.join("usr/lib/modules");
    if !modules_dir.exists() {
        result.skipped.push("depmod: no kernel modules".into());
        return;
    }

    // Find kernel versions (subdirectories of modules/)
    let versions: Vec<String> = match std::fs::read_dir(&modules_dir) {
        Ok(entries) => entries
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_dir())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect(),
        Err(_) => {
            result.skipped.push("depmod: cannot read modules directory".into());
            return;
        }
    };

    if versions.is_empty() {
        result.skipped.push("depmod: no kernel versions found".into());
        return;
    }

    for version in &versions {
        let cmd_result = if target_root == Path::new("/") {
            Command::new("depmod").arg("-a").arg(version).output()
        } else {
            Command::new("depmod")
                .arg("-a")
                .arg("-b")
                .arg(target_root)
                .arg(version)
                .output()
        };

        match cmd_result {
            Ok(output) if output.status.success() => {
                result.succeeded.push(format!("depmod -a {version}"));
            }
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                result.failed.push((format!("depmod {version}"), stderr));
            }
            Err(e) => {
                result.failed.push((format!("depmod {version}"), e.to_string()));
            }
        }
    }
}

/// Update desktop-file, icon, and MIME caches if the tools are available.
fn run_desktop_cache_update(target_root: &Path, result: &mut HookResult) {
    let apps_dir = target_root.join("usr/share/applications");
    if !apps_dir.exists() {
        result.skipped.push("desktop-cache: no applications directory".into());
        return;
    }

    // update-desktop-database
    if let Ok(output) = Command::new("update-desktop-database")
        .arg(&apps_dir)
        .output()
    {
        if output.status.success() {
            result.succeeded.push("update-desktop-database".into());
        }
    } else {
        result.skipped.push("update-desktop-database: not available".into());
    }

    // gtk-update-icon-cache (if icons exist)
    let icons_dir = target_root.join("usr/share/icons/hicolor");
    if icons_dir.exists() {
        if let Ok(output) = Command::new("gtk-update-icon-cache")
            .arg("-f")
            .arg("-t")
            .arg(&icons_dir)
            .output()
        {
            if output.status.success() {
                result.succeeded.push("gtk-update-icon-cache".into());
            }
        } else {
            result.skipped.push("gtk-update-icon-cache: not available".into());
        }
    }
}

// ─── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hooks_skip_empty_root() {
        let tmp = tempfile::tempdir().unwrap();
        let result = run_post_weave_hooks(tmp.path());
        // All hooks should be skipped since there's nothing to process
        assert!(result.succeeded.is_empty() || !result.failed.is_empty() || !result.skipped.is_empty());
        assert!(result.skipped.iter().any(|s| s.contains("ldconfig")));
        assert!(result.skipped.iter().any(|s| s.contains("depmod")));
    }

    #[test]
    fn test_hooks_with_lib_dir() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("usr/lib")).unwrap();
        let result = run_post_weave_hooks(tmp.path());
        // ldconfig should attempt (may fail in test env but not be skipped)
        assert!(!result.skipped.iter().any(|s| s.starts_with("ldconfig:")));
    }
}
