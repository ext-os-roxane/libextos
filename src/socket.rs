//! Control-socket group permissions (PLAN 8.1.5, `design/ARCHITECTURE.md`
//! §15).
//!
//! This is the single shared home for the §15 socket-group wiring: both
//! control-plane servers (`pkt serve` and `instanz serve`, PLAN 8.1.3/8.1.4)
//! call [`crate::socket::apply_socket_group`] / [`crate::socket::enforce_socket_group`] through the same
//! resolution and policy functions, so the two daemons cannot drift.
//!
//! # Group source of truth
//!
//! The §15 socket table [`crate::daemons::DEFAULT_SOCKETS`] pins
//! `(daemon, socket_path, group)`: `pkt` → `/run/extos/pkt.sock` @ `wheel`
//! and `instanz` → `/run/extos/instanz.sock` @ `extos-admin`.
//! [`crate::socket::resolve_socket_group`] turns a daemon name plus an optional operator
//! flag into [`crate::socket::ResolvedSocketGroup`]:
//!
//! * `flag == None` → [`crate::socket::ResolvedSocketGroup::Default`] with the daemon's
//!   §15 group;
//! * `flag == Some("none")` or `Some("")` →
//!   [`crate::socket::ResolvedSocketGroup::Disabled`] (the operator escape hatch: no chown
//!   is attempted at all);
//! * any other `flag` → [`crate::socket::ResolvedSocketGroup::Explicit`] with the given
//!   group name.
//!
//! # Honest typed failures, one shared policy
//!
//! [`crate::socket::enforce_socket_group`] applies one policy to a bound socket:
//!
//! * an **explicit** operator flag is a hard contract — any failure
//!   ([`crate::socket::SocketGroupError::UnknownGroup`], [`crate::socket::SocketGroupError::NotPermitted`],
//!   ...) is returned typed and the servers treat it as fatal;
//! * the **declarative default** degrades honestly where the host cannot
//!   honor it: a group that does not exist on this host, or a chgrp the
//!   daemon user is not permitted to perform (EPERM — one cannot chgrp to a
//!   group one does not belong to), are reported as
//!   [`crate::socket::SocketGroupOutcome::Skipped`] with the typed reason rendered into the
//!   message. The outcome is never silent: callers must match it and the
//!   servers log it. Every other error is fatal.
//!
//! [`crate::socket::SocketGroupOutcome::Disabled`] means the operator asked for no group
//! wiring; the mode (0660) is unaffected either way — this module never
//! touches the mode.

use std::ffi::CString;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use thiserror::Error;

/// Typed failure of the §15 socket-group wiring (PLAN 8.1.5).
///
/// Deliberately **not** a variant of [`crate::error::ExtosError`]: the
/// control-plane servers map `ExtosError` onto the gRPC `ErrorCode` enum via
/// exhaustive 1:1 matches, and a socket-permission failure is a serve-stage
/// (transport) condition, not a domain error.
#[derive(Debug, Error)]
pub enum SocketGroupError {
    /// `getgrnam` found no group with this name.
    #[error("unknown group {name:?}: no such group on this host")]
    UnknownGroup {
        /// The group name that did not resolve.
        name: String,
    },
    /// The group name is not a valid C string (interior NUL byte).
    #[error("invalid group name {name:?}: must not contain NUL bytes")]
    InvalidGroupName {
        /// The hostile group name.
        name: String,
    },
    /// The `getgrnam_r` lookup itself failed (buffer overrun, NSS error).
    #[error("cannot resolve group {name:?}: {source}")]
    GroupLookup {
        /// The group name that failed to resolve.
        name: String,
        /// Underlying OS error.
        source: io::Error,
    },
    /// The chown(2) call was refused (EPERM): the daemon user is neither the
    /// socket owner nor a member of the target group, or lacks CAP_CHOWN.
    /// The honest, typed form of the per-host skip — never silent.
    #[error(
        "cannot chown socket {path} to group {group:?} (gid {gid}): not permitted — \
         the daemon user is not a member of {group:?} and does not own the socket"
    )]
    NotPermitted {
        /// The socket path whose group could not be changed.
        path: String,
        /// The target group name.
        group: String,
        /// The resolved target gid.
        gid: u32,
        /// Underlying OS error.
        source: io::Error,
    },
    /// Any other chown(2) failure.
    #[error("cannot chown socket {path}: {source}")]
    Chown {
        /// The socket path whose group could not be changed.
        path: String,
        /// Underlying OS error.
        source: io::Error,
    },
}

/// The effective socket-group request for one daemon, after resolution
/// (PLAN 8.1.5). See [`resolve_socket_group`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedSocketGroup {
    /// The operator disabled the chown (`--group none` or an empty value).
    Disabled,
    /// The daemon's §15 group from [`crate::daemons::DEFAULT_SOCKETS`] (no
    /// operator flag was given).
    Default(String),
    /// An operator-specified group name (`--group <name>`) — a hard contract.
    Explicit(String),
}

/// The outcome of [`enforce_socket_group`] for one bound socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SocketGroupOutcome {
    /// The group was applied: the socket now belongs to the resolved group.
    Applied {
        /// The gid the socket was chowned to.
        gid: u32,
        /// The group name that resolved to `gid`.
        group: String,
    },
    /// The default wiring could not be honored on this host; the typed
    /// reason is rendered in the message. Callers must surface it (the
    /// servers log a warning) — the skip is honest, never silent.
    Skipped {
        /// The group that was requested.
        group: String,
        /// The typed reason the chown was skipped.
        reason: String,
    },
    /// No chown was attempted (`--group none` / empty).
    Disabled,
}

/// Resolve the effective socket-group request for `daemon` (PLAN 8.1.5).
///
/// `flag` is the operator's `--group` value (`None` when the flag was not
/// passed). With no flag, the daemon's group comes from the §15 table
/// [`crate::daemons::DEFAULT_SOCKETS`]; a daemon absent from that table has
/// no default (resolved as [`ResolvedSocketGroup::Disabled`], documented —
/// both shipped daemons are present).
pub fn resolve_socket_group(daemon: &str, flag: Option<&str>) -> ResolvedSocketGroup {
    match flag {
        // The operator escape hatch: `--group none` / `--group ""` disables
        // the chown entirely.
        Some("none") | Some("") => ResolvedSocketGroup::Disabled,
        Some(name) => ResolvedSocketGroup::Explicit(name.to_string()),
        None => match default_group(daemon) {
            Some(group) => ResolvedSocketGroup::Default(group.to_string()),
            None => ResolvedSocketGroup::Disabled,
        },
    }
}

/// The §15 group for `daemon` from [`crate::daemons::DEFAULT_SOCKETS`]
/// (`None` for an unknown daemon name).
pub fn default_group(daemon: &str) -> Option<&'static str> {
    crate::daemons::DEFAULT_SOCKETS
        .iter()
        .find(|(name, _, _)| *name == daemon)
        .map(|(_, _, group)| *group)
}

/// Apply the §15 group policy to one bound socket (PLAN 8.1.5).
///
/// One shared policy for both control-plane servers:
///
/// * [`ResolvedSocketGroup::Disabled`] → [`SocketGroupOutcome::Disabled`],
///   nothing is attempted;
/// * [`ResolvedSocketGroup::Explicit`] → every failure is propagated typed
///   (the operator named the group; failing silently would betray the flag);
/// * [`ResolvedSocketGroup::Default`] → [`SocketGroupError::UnknownGroup`]
///   and [`SocketGroupError::NotPermitted`] degrade to
///   [`SocketGroupOutcome::Skipped`] (the declarative default cannot be
///   honored on this host — honest, surfaced, non-fatal); every other error
///   is fatal.
///
/// The socket mode is never touched here (0660 stays the servers' job).
///
/// # Errors
///
/// [`SocketGroupError`] as per the policy above.
pub fn enforce_socket_group(
    path: &Path,
    resolved: &ResolvedSocketGroup,
) -> Result<SocketGroupOutcome, SocketGroupError> {
    let group = match resolved {
        ResolvedSocketGroup::Disabled => return Ok(SocketGroupOutcome::Disabled),
        ResolvedSocketGroup::Default(group) | ResolvedSocketGroup::Explicit(group) => group,
    };
    match apply_socket_group(path, group) {
        Ok(gid) => Ok(SocketGroupOutcome::Applied {
            gid,
            group: group.clone(),
        }),
        Err(err) => {
            // The declarative default degrades honestly where the host
            // cannot honor it; an explicit operator flag is a hard contract.
            let honest_skip = matches!(
                resolved,
                ResolvedSocketGroup::Default(_)
            ) && matches!(
                err,
                SocketGroupError::UnknownGroup { .. } | SocketGroupError::NotPermitted { .. }
            );
            if honest_skip {
                Ok(SocketGroupOutcome::Skipped {
                    group: group.clone(),
                    reason: err.to_string(),
                })
            } else {
                Err(err)
            }
        }
    }
}

/// Resolve `group` to a gid and `chown` the socket at `path` to it, leaving
/// the owning user unchanged (PLAN 8.1.5).
///
/// The name is resolved with the thread-safe `getgrnam_r`
/// ([`SocketGroupError::UnknownGroup`] when it yields nothing) and applied
/// with `chown(2)` (`uid = -1` keeps the owner). `EPERM` maps to the typed
/// [`SocketGroupError::NotPermitted`] — an unprivileged daemon cannot chgrp
/// to a group it does not belong to, and that fact is never swallowed.
///
/// Returns the applied gid.
///
/// # Errors
///
/// [`SocketGroupError`] for a hostile name, a failed lookup, or the chown.
pub fn apply_socket_group(path: &Path, group: &str) -> Result<u32, SocketGroupError> {
    let gid = group_gid(group)?;
    let path_c = CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        SocketGroupError::Chown {
            path: path.display().to_string(),
            source: io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL bytes"),
        }
    })?;
    // SAFETY: `path_c` is a valid NUL-terminated path; `uid = -1` (u32::MAX)
    // leaves the owning user unchanged — libc documents -1 as "don't change".
    let ret = unsafe { libc::chown(path_c.as_ptr(), libc::uid_t::MAX, gid as libc::gid_t) };
    if ret == -1 {
        let source = io::Error::last_os_error();
        return Err(match source.raw_os_error() {
            Some(libc::EPERM) => SocketGroupError::NotPermitted {
                path: path.display().to_string(),
                group: group.to_string(),
                gid,
                source,
            },
            _ => SocketGroupError::Chown {
                path: path.display().to_string(),
                source,
            },
        });
    }
    Ok(gid)
}

/// Resolve a group name to its gid with the thread-safe `getgrnam_r`.
///
/// [`SocketGroupError::UnknownGroup`] when the name resolves to nothing;
/// [`SocketGroupError::GroupLookup`] when the lookup itself fails. The
/// buffer starts at `sysconf(_SC_GETGR_R_SIZE_MAX)` (1024 floor) and grows
/// on `ERANGE` up to a 1 MiB cap, beyond which the overrun is reported
/// typed instead of looping forever.
///
/// # Errors
///
/// [`SocketGroupError`] as documented above.
pub fn group_gid(group: &str) -> Result<u32, SocketGroupError> {
    let name = CString::new(group).map_err(|_| SocketGroupError::InvalidGroupName {
        name: group.to_string(),
    })?;
    let mut buf = initial_group_buffer();
    loop {
        let mut grp: libc::group = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::group = std::ptr::null_mut();
        // SAFETY: `name` is NUL-terminated; `grp` and `buf` back the
        // getgrnam_r contract; `result` is written on success.
        let ret = unsafe {
            libc::getgrnam_r(
                name.as_ptr(),
                &mut grp,
                buf.as_mut_ptr().cast(),
                buf.len(),
                &mut result,
            )
        };
        if ret == 0 {
            if result.is_null() {
                return Err(SocketGroupError::UnknownGroup {
                    name: group.to_string(),
                });
            }
            // SAFETY: `result` points into `buf`/`grp`, valid per getgrnam_r.
            let gid = unsafe { (*result).gr_gid };
            return Ok(gid as u32);
        }
        if ret == libc::ERANGE && buf.len() < 1024 * 1024 {
            buf.resize(buf.len() * 2, 0);
            continue;
        }
        return Err(SocketGroupError::GroupLookup {
            name: group.to_string(),
            source: io::Error::from_raw_os_error(ret),
        });
    }
}

/// The initial `getgrnam_r` buffer: `sysconf(_SC_GETGR_R_SIZE_MAX)`, with a
/// 1024-byte floor (glibc returns the suggested size, musl returns 1024).
fn initial_group_buffer() -> Vec<u8> {
    // SAFETY: plain sysconf query, no invariants.
    let suggested = unsafe { libc::sysconf(libc::_SC_GETGR_R_SIZE_MAX) };
    let size = if suggested > 0 { suggested as usize } else { 1024 };
    vec![0; size.max(1024)]
}

// ─── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::PermissionsExt;

    /// The §15 table is the group source of truth: pkt → wheel, instanz →
    /// extos-admin (pinned here so a daemons.rs drift cannot pass silently).
    #[test]
    fn default_groups_match_the_design_table() {
        assert_eq!(default_group("pkt"), Some("wheel"));
        assert_eq!(default_group("instanz"), Some("extos-admin"));
        assert_eq!(default_group("unknown-daemon"), None);
    }

    #[test]
    fn resolve_socket_group_follows_the_flag_precedence() {
        // No flag → the §15 default for the daemon.
        assert_eq!(
            resolve_socket_group("pkt", None),
            ResolvedSocketGroup::Default("wheel".to_string())
        );
        // A flag overrides the default.
        assert_eq!(
            resolve_socket_group("pkt", Some("staff")),
            ResolvedSocketGroup::Explicit("staff".to_string())
        );
        // `none` / empty disable the chown (the operator escape hatch).
        assert_eq!(
            resolve_socket_group("pkt", Some("none")),
            ResolvedSocketGroup::Disabled
        );
        assert_eq!(
            resolve_socket_group("instanz", Some("")),
            ResolvedSocketGroup::Disabled
        );
        // An unknown daemon has no default (documented Disabled).
        assert_eq!(
            resolve_socket_group("nope", None),
            ResolvedSocketGroup::Disabled
        );
    }

    #[test]
    fn existing_group_resolves_and_missing_group_is_typed_rejected() {
        // `wheel` exists on this host (the §15 pkt group).
        let wheel = group_gid("wheel").expect("wheel must resolve on this host");
        assert!(wheel > 0, "gid {wheel} is a real group id");

        // A nonexistent group is a typed UnknownGroup, not a silent 0.
        match group_gid("extos-no-such-group-xyz") {
            Err(SocketGroupError::UnknownGroup { name }) => {
                assert_eq!(name, "extos-no-such-group-xyz");
            }
            other => panic!("expected UnknownGroup, got {other:?}"),
        }

        // A hostile name (interior NUL) is typed too.
        match group_gid("bad\0name") {
            Err(SocketGroupError::InvalidGroupName { name }) => {
                assert_eq!(name, "bad\0name");
            }
            other => panic!("expected InvalidGroupName, got {other:?}"),
        }
    }

    #[test]
    fn chown_to_wheel_succeeds_for_a_member_or_reports_not_permitted() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let file = dir.path().join("sock-or-file");
        fs::write(&file, b"probe").expect("probe file");
        let gid_before = fs::metadata(&file).expect("stat").gid();

        match apply_socket_group(&file, "wheel") {
            Ok(gid) => {
                // The apply path (this user is a wheel member on this host).
                assert_eq!(fs::metadata(&file).expect("stat").gid(), gid);
                assert_eq!(gid, group_gid("wheel").expect("wheel resolves"));
            }
            Err(SocketGroupError::NotPermitted { group, gid, .. }) => {
                // The honest typed skip (assert the variant, not a silent Ok).
                assert_eq!(group, "wheel");
                assert_eq!(gid, group_gid("wheel").expect("wheel resolves"));
                assert_eq!(fs::metadata(&file).expect("stat").gid(), gid_before);
            }
            other => panic!("expected Ok or NotPermitted, got {other:?}"),
        }
    }

    #[test]
    fn enforce_policy_explicit_is_fatal_default_degrades_honestly() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let file = dir.path().join("probe");
        fs::write(&file, b"probe").expect("probe file");

        // Explicit + unknown group → fatal, typed (the operator asked).
        let explicit = ResolvedSocketGroup::Explicit("extos-no-such-group-xyz".to_string());
        match enforce_socket_group(&file, &explicit) {
            Err(SocketGroupError::UnknownGroup { name }) => {
                assert_eq!(name, "extos-no-such-group-xyz");
            }
            other => panic!("expected fatal UnknownGroup, got {other:?}"),
        }

        // Default + unknown group → honest typed skip, non-fatal, with the
        // reason rendered (the §15 default cannot be honored on this host).
        let default = ResolvedSocketGroup::Default("extos-no-such-group-xyz".to_string());
        match enforce_socket_group(&file, &default) {
            Ok(SocketGroupOutcome::Skipped { group, reason }) => {
                assert_eq!(group, "extos-no-such-group-xyz");
                assert!(reason.contains("no such group on this host"), "{reason}");
            }
            other => panic!("expected honest Skipped, got {other:?}"),
        }

        // Disabled → Disabled, nothing touched.
        match enforce_socket_group(&file, &ResolvedSocketGroup::Disabled) {
            Ok(SocketGroupOutcome::Disabled) => {}
            other => panic!("expected Disabled, got {other:?}"),
        }

        // Explicit + a real group → the apply (or the honest EPERM skip if
        // unprivileged); never a silent anything.
        let wheel = ResolvedSocketGroup::Explicit("wheel".to_string());
        match enforce_socket_group(&file, &wheel) {
            Ok(SocketGroupOutcome::Applied { gid, group }) => {
                assert_eq!(group, "wheel");
                assert_eq!(fs::metadata(&file).expect("stat").gid(), gid);
                assert!(fs::metadata(&file).expect("mode").permissions().mode() & 0o777 > 0);
            }
            Ok(SocketGroupOutcome::Skipped { reason, .. }) => {
                assert!(reason.contains("not permitted"), "{reason}");
            }
            other => panic!("expected Applied or Skipped, got {other:?}"),
        }
    }

    #[test]
    fn mode_is_never_touched_by_the_group_wiring() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let file = dir.path().join("probe");
        fs::write(&file, b"probe").expect("probe file");
        fs::set_permissions(&file, fs::Permissions::from_mode(0o660)).expect("mode");
        let mode_before = fs::metadata(&file).expect("stat").permissions().mode() & 0o777;
        let _ = enforce_socket_group(
            &file,
            &ResolvedSocketGroup::Explicit("wheel".to_string()),
        );
        let mode_after = fs::metadata(&file).expect("stat").permissions().mode() & 0o777;
        assert_eq!(mode_before, mode_after, "group wiring must not touch mode");
    }
}
