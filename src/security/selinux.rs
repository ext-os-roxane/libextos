//! SELinux context labeling for woven files (PLAN 6.2.2).
//!
//! Synthesis is deliberately conservative: every file of a package shares one
//! package-domain type (`extos_<pkg>_t`), because per-file type synthesis
//! would require a full policy module — that is disclosed as the Phase-6
//! baseline, not a complete SELinux policy generator.
//!
//! Two labeling backends exist:
//!
//! * [`LabelBackend::Kernel`] — writes the `security.selinux` xattr. This is
//!   the real thing on an SELinux-enabled system; elsewhere the kernel
//!   refuses and the typed error surfaces (the weaver records an honest skip,
//!   it never pretends to label).
//! * [`LabelBackend::DryRun`] — validates and reports without touching the
//!   filesystem, for planning and tests.

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

/// Errors raised while synthesizing or applying SELinux contexts.
#[derive(Debug, thiserror::Error)]
pub enum SelinuxError {
    /// The target path contains an interior NUL and cannot address a file.
    #[error("path contains an interior NUL and cannot address a file")]
    InvalidPath,
    /// A synthesized context is not a usable SELinux context string.
    #[error("invalid SELinux context '{context}'")]
    InvalidContext {
        /// The offending synthesis.
        context: String,
    },
    /// The kernel refused to write `security.selinux` on the target
    /// (SELinux disabled, `CAP_MAC_ADMIN` missing, read-only fs, ...).
    #[error("failed to label {path} with '{context}': {source}")]
    SetXattr {
        /// The target file, displayed.
        path: String,
        /// The attempted context.
        context: String,
        /// The kernel error.
        #[source]
        source: std::io::Error,
    },
}

/// How contexts are applied to woven files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LabelBackend {
    /// Write the `security.selinux` xattr for real.
    Kernel,
    /// Validate and report without touching the filesystem.
    DryRun,
}

/// One skipped label from [`label_tree`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabelSkip {
    /// Rootfs-relative path that was not labeled.
    pub rel_path: String,
    /// The context that would have been applied.
    pub context: String,
    /// Why the kernel refused.
    pub reason: String,
}

/// Result of a [`label_tree`] pass.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LabelReport {
    /// Files actually labeled by this run.
    pub applied: usize,
    /// Files the kernel refused, with reasons (honest, never silent).
    pub skipped: Vec<LabelSkip>,
}

/// Synthesize the SELinux context for a woven file of `pkg` (PLAN 6.2.2).
///
/// The context is `system_u:object_r:extos_<pkg>_t:s0` where `<pkg>` is the
/// package label lowercased with every non-alphanumeric run collapsed to `_`
/// (and prefixed with `x` when it would not start with a letter), so hostile
/// package names cannot inject context fields.
pub fn context_for(pkg: &str) -> Result<String, SelinuxError> {
    let mut sanitized = String::new();
    let mut last_was_sep = false;
    for ch in pkg.chars() {
        if ch.is_ascii_alphanumeric() {
            sanitized.push(ch.to_ascii_lowercase());
            last_was_sep = false;
        } else if !last_was_sep && !sanitized.is_empty() {
            sanitized.push('_');
            last_was_sep = true;
        }
    }
    while sanitized.ends_with('_') {
        sanitized.pop();
    }
    if sanitized.starts_with(|c: char| !c.is_ascii_alphabetic()) {
        sanitized.insert(0, 'x');
    }
    sanitized.truncate(48);
    let context = format!("system_u:object_r:extos_{sanitized}_t:s0");
    validate_context(&context)?;
    Ok(context)
}

/// Apply one context to one file (PLAN 6.2.2).
///
/// Returns `Ok(false)` for a [`LabelBackend::DryRun`] pass. Kernel refusals
/// surface as [`SelinuxError::SetXattr`] — never a silent no-op.
pub fn label_path(path: &Path, context: &str, backend: LabelBackend) -> Result<bool, SelinuxError> {
    validate_context(context)?;
    match backend {
        LabelBackend::DryRun => Ok(false),
        LabelBackend::Kernel => {
            let c_path =
                CString::new(path.as_os_str().as_bytes()).map_err(|_| SelinuxError::InvalidPath)?;
            let c_ctx = CString::new(context.as_bytes()).map_err(|_| SelinuxError::InvalidPath)?;
            // SAFETY: both CStrings are valid and outlive the call.
            let rc = unsafe {
                libc::setxattr(
                    c_path.as_ptr(),
                    c"security.selinux".as_ptr(),
                    c_ctx.as_ptr().cast(),
                    context.len(),
                    0,
                )
            };
            if rc != 0 {
                return Err(SelinuxError::SetXattr {
                    path: path.display().to_string(),
                    context: context.to_string(),
                    source: std::io::Error::last_os_error(),
                });
            }
            Ok(true)
        }
    }
}

/// Label a set of woven files (PLAN 6.2.2).
///
/// `labels` maps rootfs-relative paths to contexts. Per-file kernel refusals
/// are collected into [`LabelReport::skipped`] (with the kernel reason) and
/// the pass continues — one hostile file must not leave the rest unlabeled
/// without a record.
pub fn label_tree(
    root: &Path,
    labels: &[(String, String)],
    backend: LabelBackend,
) -> LabelReport {
    let mut report = LabelReport::default();
    for (rel, context) in labels {
        let target = root.join(rel);
        match label_path(&target, context, backend) {
            Ok(_) => report.applied += 1,
            Err(err) => report.skipped.push(LabelSkip {
                rel_path: rel.clone(),
                context: context.clone(),
                reason: err.to_string(),
            }),
        }
    }
    report
}

/// Structural context validation: four-ish colon-separated fields, no
/// whitespace, ASCII, non-empty user/role/type fields.
fn validate_context(context: &str) -> Result<(), SelinuxError> {
    let fields: Vec<&str> = context.split(':').collect();
    let ok = context.is_ascii()
        && !context.contains(char::is_whitespace)
        && fields.len() >= 3
        && fields.iter().take(3).all(|f| !f.is_empty());
    if ok {
        Ok(())
    } else {
        Err(SelinuxError::InvalidContext {
            context: context.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthesizes_package_domain_contexts() {
        assert_eq!(
            context_for("openssl").unwrap(),
            "system_u:object_r:extos_openssl_t:s0"
        );
        assert_eq!(
            context_for("Archlinux/glibc").unwrap(),
            "system_u:object_r:extos_archlinux_glibc_t:s0"
        );
    }

    #[test]
    fn sanitizes_hostile_package_labels() {
        // Slashes, colons and dots must not inject extra context fields; the
        // sanitized label here still starts with a letter, so no prefix.
        assert_eq!(
            context_for("../../etc/passwd").unwrap(),
            "system_u:object_r:extos_etc_passwd_t:s0"
        );
        assert_eq!(
            context_for("a:b:c").unwrap(),
            "system_u:object_r:extos_a_b_c_t:s0"
        );
        // A leading digit gets the `x` prefix (type names must be letters).
        assert_eq!(
            context_for("9lives").unwrap(),
            "system_u:object_r:extos_x9lives_t:s0"
        );
        // Overflow truncates deterministically.
        let long = "p".repeat(200);
        let ctx = context_for(&long).unwrap();
        assert!(ctx.len() < 80, "{ctx}");
        assert!(ctx.ends_with("_t:s0"));
    }

    #[test]
    fn rejects_structurally_broken_contexts() {
        for bad in ["", "no-colons", "a b:c:d:e", ":x:y:z"] {
            assert!(
                matches!(
                    validate_context_inner(bad),
                    Err(SelinuxError::InvalidContext { .. })
                ),
                "{bad}"
            );
        }
    }

    fn validate_context_inner(c: &str) -> Result<(), SelinuxError> {
        super::validate_context(c)
    }

    #[test]
    fn dry_run_never_touches_the_filesystem() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("f");
        std::fs::write(&file, b"x").unwrap();
        let ctx = context_for("openssl").unwrap();

        let applied = label_path(&file, &ctx, LabelBackend::DryRun).unwrap();
        assert!(!applied);

        // Dry-run through label_tree reports every path as applied-eligible.
        let report = label_tree(
            dir.path(),
            &[("f".into(), ctx.clone())],
            LabelBackend::DryRun,
        );
        assert_eq!(report.applied, 1);
        assert!(report.skipped.is_empty());
        // The xattr was not written: even on an SELinux host the file had no
        // context before and the dry run must not have added one.
        assert!(read_selinux_xattr(&file).is_none());
    }

    fn read_selinux_xattr(path: &Path) -> Option<Vec<u8>> {
        let c_path = CString::new(path.as_os_str().as_bytes()).ok()?;
        let mut buf = [0u8; 256];
        // SAFETY: valid buffer and path for the call.
        let rc = unsafe {
            libc::getxattr(
                c_path.as_ptr(),
                c"security.selinux".as_ptr(),
                buf.as_mut_ptr().cast(),
                buf.len(),
            )
        };
        if rc < 0 {
            None
        } else {
            Some(buf[..rc as usize].to_vec())
        }
    }

    #[test]
    fn kernel_backend_refuses_honestly_on_non_selinux_hosts() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("f");
        std::fs::write(&file, b"x").unwrap();
        let ctx = context_for("openssl").unwrap();

        let result = label_path(&file, &ctx, LabelBackend::Kernel);
        let selinux_mounted = Path::new("/sys/fs/selinux").exists();
        match result {
            Ok(true) => assert!(selinux_mounted, "xattr write without SELinux?"),
            Err(err) => {
                assert!(matches!(err, SelinuxError::SetXattr { .. }), "{err:?}");
                // The label_tree pass records the refusal instead of aborting.
                let report = label_tree(
                    dir.path(),
                    &[("f".into(), ctx.clone())],
                    LabelBackend::Kernel,
                );
                assert_eq!(report.applied, 0);
                assert_eq!(report.skipped.len(), 1);
                assert_eq!(report.skipped[0].rel_path, "f");
                assert!(!report.skipped[0].reason.is_empty());
            }
            Ok(false) => panic!("Kernel backend must not report a dry run"),
        }
    }
}
