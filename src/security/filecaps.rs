//! File capabilities (PLAN 6.1.2).
//!
//! The CAS sanitizer ([`crate::ingest::sanitize_permissions`], PLAN 6.1.1)
//! strips setuid/setgid bits at ingestion; file capabilities are the
//! sanctioned replacement: a manifest's `security.capabilities` block declares
//! `path → [CAP_*]` grants that the weaver re-applies on the *woven* copy
//! after materialization. This module owns the capability-name table, the
//! on-disk `security.capability` xattr encoder and the apply primitive.
//!
//! # Encoding
//!
//! Values use the kernel's vfs-capability revision-2 layout: 20 bytes,
//! little-endian — `magic_etc = VFS_CAP_REVISION_2 | VFS_CAP_FLAGS_EFFECTIVE`,
//! then permitted word 0, inheritable word 0, permitted word 1, inheritable
//! word 1. `+ep` semantics are used (permitted set + effective flag,
//! inheritable left empty), matching `setcap <cap>+ep`.
//!
//! Writing the xattr needs `CAP_SETFCAP` in the owning user namespace. The
//! weaver applies capabilities while materializing a roof (root on real
//! systems); when the running context lacks the capability (e.g. an
//! unprivileged test host) the kernel refuses with `EPERM` and the caller
//! records an honest typed skip — the error is never swallowed.

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

/// Errors raised while parsing or applying file capabilities.
#[derive(Debug, thiserror::Error)]
pub enum FileCapsError {
    /// The target path contains an interior NUL and cannot address a file.
    #[error("path contains an interior NUL and cannot address a file")]
    InvalidPath,
    /// A name outside the kernel's capability table was declared.
    #[error(
        "unknown file capability '{name}' (expected a CAP_* name, e.g. CAP_NET_RAW; \
         see the kernel capability list)"
    )]
    UnknownCapability {
        /// The offending declaration.
        name: String,
    },
    /// The kernel refused to write `security.capability` on the target.
    #[error("failed to set file capabilities on {path}: {source}")]
    SetXattr {
        /// The target file, displayed.
        path: String,
        /// The kernel error (`EPERM` without `CAP_SETFCAP`, and so on).
        #[source]
        source: std::io::Error,
    },
    /// The kernel refused to drop `security.capability` from the target.
    #[error("failed to clear file capabilities on {path}: {source}")]
    RemoveXattr {
        /// The target file, displayed.
        path: String,
        /// The kernel error.
        #[source]
        source: std::io::Error,
    },
}

/// The kernel capability table (Linux 6.x), in bit order.
///
/// Keys are the canonical `CAP_*` spellings used by `security.capabilities`
/// declarations and `setcap`; values are the capability bit indices.
pub const CAPABILITIES: &[(&str, u64)] = &[
    ("CAP_CHOWN", 0),
    ("CAP_DAC_OVERRIDE", 1),
    ("CAP_DAC_READ_SEARCH", 2),
    ("CAP_FOWNER", 3),
    ("CAP_FSETID", 4),
    ("CAP_KILL", 5),
    ("CAP_SETGID", 6),
    ("CAP_SETUID", 7),
    ("CAP_SETPCAP", 8),
    ("CAP_LINUX_IMMUTABLE", 9),
    ("CAP_NET_BIND_SERVICE", 10),
    ("CAP_NET_BROADCAST", 11),
    ("CAP_NET_ADMIN", 12),
    ("CAP_NET_RAW", 13),
    ("CAP_IPC_LOCK", 14),
    ("CAP_IPC_OWNER", 15),
    ("CAP_SYS_MODULE", 16),
    ("CAP_SYS_RAWIO", 17),
    ("CAP_SYS_CHROOT", 18),
    ("CAP_SYS_PTRACE", 19),
    ("CAP_SYS_PACCT", 20),
    ("CAP_SYS_ADMIN", 21),
    ("CAP_SYS_BOOT", 22),
    ("CAP_SYS_NICE", 23),
    ("CAP_SYS_RESOURCE", 24),
    ("CAP_SYS_TIME", 25),
    ("CAP_SYS_TTY_CONFIG", 26),
    ("CAP_MKNOD", 27),
    ("CAP_LEASE", 28),
    ("CAP_AUDIT_WRITE", 29),
    ("CAP_AUDIT_CONTROL", 30),
    ("CAP_SETFCAP", 31),
    ("CAP_MAC_OVERRIDE", 32),
    ("CAP_MAC_ADMIN", 33),
    ("CAP_SYSLOG", 34),
    ("CAP_WAKE_ALARM", 35),
    ("CAP_BLOCK_SUSPEND", 36),
    ("CAP_AUDIT_READ", 37),
    ("CAP_PERFMON", 38),
    ("CAP_BPF", 39),
    ("CAP_CHECKPOINT_RESTORE", 40),
];

/// Look up a `CAP_*` name in [`CAPABILITIES`], returning its bit index.
///
/// The lookup is exact and case-sensitive: `CAP_NET_RAW` parses, `net_raw`
/// and `cap_net_raw` do not.
pub fn parse_cap_name(name: &str) -> Result<u64, FileCapsError> {
    CAPABILITIES
        .iter()
        .find(|(known, _)| *known == name)
        .map(|(_, bit)| *bit)
        .ok_or_else(|| FileCapsError::UnknownCapability {
            name: name.to_string(),
        })
}

/// Fold declared capability names into a permission mask (PLAN 6.1.2).
///
/// Called at plan-build time so an unknown capability fails the plan with a
/// typed error instead of surfacing as a per-file skip at weave time.
pub fn caps_mask(names: &[String]) -> Result<u64, FileCapsError> {
    let mut mask = 0u64;
    for name in names {
        mask |= 1u64 << parse_cap_name(name)?;
    }
    Ok(mask)
}

/// Encode a permission mask as a revision-2 `security.capability` xattr value
/// with `+ep` semantics (permitted set + effective flag, inheritable empty).
pub fn encode_security_capability(mask: u64) -> [u8; 20] {
    let mut out = [0u8; 20];
    // magic_etc = VFS_CAP_REVISION_2 (0x02000000) | VFS_CAP_FLAGS_EFFECTIVE (0x1)
    out[0..4].copy_from_slice(&0x0200_0001u32.to_le_bytes());
    out[4..8].copy_from_slice(&(mask as u32).to_le_bytes()); // permitted word 0
    // inheritable word 0 (bytes 8..12) stays zero
    out[12..16].copy_from_slice(&((mask >> 32) as u32).to_le_bytes()); // permitted word 1
    // inheritable word 1 (bytes 16..20) stays zero
    out
}

/// Write `security.capability` on `path` granting `names` with `+ep`
/// semantics (PLAN 6.1.2).
///
/// An empty `names` slice revokes any existing file capability instead.
/// Re-applying an identical grant is idempotent.
pub fn apply_file_caps(path: &Path, names: &[String]) -> Result<(), FileCapsError> {
    let c_path = path_to_cstring(path)?;
    if names.is_empty() {
        // Revocation: absence is already the goal.
        // SAFETY: c_path is a valid NUL-terminated string owned for the call.
        let rc = unsafe { libc::removexattr(c_path.as_ptr(), c"security.capability".as_ptr()) };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() != std::io::ErrorKind::NotFound {
                return Err(FileCapsError::RemoveXattr {
                    path: path.display().to_string(),
                    source: err,
                });
            }
        }
        return Ok(());
    }

    let mask = caps_mask(names)?;
    let value = encode_security_capability(mask);
    // SAFETY: c_path and the value buffer are valid for the duration of the call.
    let rc = unsafe {
        libc::setxattr(
            c_path.as_ptr(),
            c"security.capability".as_ptr(),
            value.as_ptr().cast(),
            value.len(),
            0,
        )
    };
    if rc != 0 {
        return Err(FileCapsError::SetXattr {
            path: path.display().to_string(),
            source: std::io::Error::last_os_error(),
        });
    }
    Ok(())
}

/// Address a path as a C string; interior NULs cannot name a file.
fn path_to_cstring(path: &Path) -> Result<CString, FileCapsError> {
    CString::new(path.as_os_str().as_bytes()).map_err(|_| FileCapsError::InvalidPath)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_known_capability_names() {
        assert_eq!(parse_cap_name("CAP_NET_RAW").unwrap(), 13);
        assert_eq!(parse_cap_name("CAP_SYS_ADMIN").unwrap(), 21);
        assert_eq!(parse_cap_name("CAP_CHECKPOINT_RESTORE").unwrap(), 40);
    }

    #[test]
    fn rejects_unknown_and_lowercase_names() {
        assert!(matches!(
            parse_cap_name("CAP_DOES_NOT_EXIST"),
            Err(FileCapsError::UnknownCapability { name }) if name == "CAP_DOES_NOT_EXIST"
        ));
        // The kernel table is the canonical spelling; loose forms are
        // rejected so declarations never silently parse to the wrong bit.
        assert!(parse_cap_name("net_raw").is_err());
        assert!(parse_cap_name("cap_net_raw").is_err());
    }

    #[test]
    fn folds_mask_from_names() {
        let mask = caps_mask(&["CAP_NET_RAW".into(), "CAP_NET_BIND_SERVICE".into()]).unwrap();
        assert_eq!(mask, (1u64 << 13) | (1u64 << 10));
    }

    #[test]
    fn encodes_revision2_effective_layout() {
        let bytes = encode_security_capability(1 << 13);
        assert_eq!(bytes.len(), 20);
        // magic_etc = revision 2 | effective flag, little-endian.
        assert_eq!(&bytes[0..4], &0x0200_0001u32.to_le_bytes());
        // permitted word 0 = the CAP_NET_RAW mask bit (1 << 13).
        assert_eq!(&bytes[4..8], &(1u32 << 13).to_le_bytes());
        // inheritable word 0 empty.
        assert_eq!(&bytes[8..12], &[0, 0, 0, 0]);
        // permitted word 1 empty (no high caps).
        assert_eq!(&bytes[12..16], &[0, 0, 0, 0]);
        // inheritable word 1 empty.
        assert_eq!(&bytes[16..20], &[0, 0, 0, 0]);
    }

    #[test]
    fn encodes_high_capability_bits_into_word_one() {
        let bytes = encode_security_capability(1u64 << 39); // CAP_BPF
        assert_eq!(&bytes[12..16], &(1u32 << 7).to_le_bytes());
        assert_eq!(&bytes[4..8], &[0, 0, 0, 0]);
    }

    #[test]
    fn apply_reports_typed_kernel_refusal_unprivileged() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("probe");
        std::fs::write(&file, b"#!/bin/sh\n").unwrap();

        let result = apply_file_caps(&file, &["CAP_NET_RAW".into()]);
        if unsafe { libc::geteuid() } == 0 {
            // Privileged context: the write succeeds.
            result.expect("root must be able to set file capabilities");
        } else {
            // Unprivileged host: EPERM must surface as a typed error, never
            // a silent pass — the weaver turns this into an honest skip.
            let err = result.expect_err("EPERM expected without CAP_SETFCAP");
            assert!(matches!(err, FileCapsError::SetXattr { .. }), "{err:?}");
        }
    }
}
