//! PGP verification for the Arch fetcher, through the `gpg` CLI.
//!
//! PLAN 3.2.4 (repository database) and 3.2.5 (package) both require a
//! detached-signature check. Upstream pacman does this inside libalpm via
//! libgpgme. ExtOS cannot assume libgpgme exists -- the host this fork was
//! built on has none, which is why the fork is configured with
//! `-Dgpgme=disabled` -- so verification is delegated to the `gpg` binary:
//!
//! * the keyring is a GnuPG home directory supplied by the caller
//!   ([super::AlpmFetch::with_gnupg_home]) or by [`GNUPG_HOME_ENV`];
//! * `gpg --batch --status-fd 1 --verify <sig> <data>` must exit 0 *and* emit a
//!   `VALIDSIG` status line, so a zero exit alone never counts as success;
//! * nothing is written to the keyring (`--no-auto-check-trustdb` keeps the
//!   call read-only in practice) and no key is imported behind the caller's
//!   back.
//!
//! Tests point [`GNUPG_HOME_ENV`] at a throwaway home they generated at
//! runtime; production callers point it at the system pacman keyring. No
//! absolute path is compiled into this module.

use std::fmt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Environment variable naming the GnuPG home directory to verify against.
pub(super) const GNUPG_HOME_ENV: &str = "EXTOS_GPG_HOME";

/// Why a detached-signature check did not succeed.
#[derive(Debug)]
pub(super) enum GpgError {
    /// The `gpg` binary is not installed, or is not executable.
    Unavailable {
        /// Spawn error text.
        message: String,
    },
    /// `gpg` could not be asked to verify a file (missing signature, bad path).
    Io {
        /// Path whose use failed.
        path: String,
        /// Underlying I/O error text.
        message: String,
    },
    /// `gpg` ran but did not confirm a valid signature.
    Rejected {
        /// Last diagnostic line from `gpg`'s stderr, or the status-line reason.
        detail: String,
    },
}

impl fmt::Display for GpgError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable { message } => {
                write!(formatter, "gpg is unavailable: {message}")
            }
            Self::Io { path, message } => {
                write!(formatter, "cannot verify '{path}': {message}")
            }
            Self::Rejected { detail } => {
                write!(formatter, "gpg rejected the signature: {detail}")
            }
        }
    }
}

impl std::error::Error for GpgError {}

/// Verify `signature` (detached) against the exact bytes in `data`.
///
/// `home` is used when given, otherwise `EXTOS_GPG_HOME` when that is set,
/// otherwise gpg's own default home.
///
/// # Errors
///
/// [`GpgError::Unavailable`] when `gpg` cannot be spawned,
/// [`GpgError::Io`] when a path is unusable, and [`GpgError::Rejected`] for a
/// bad, missing, expired or untrusted signature.
pub(super) fn verify_detached(
    data: &Path,
    signature: &Path,
    home: Option<&Path>,
) -> Result<(), GpgError> {
    if !data.is_file() {
        return Err(GpgError::Io {
            path: data.display().to_string(),
            message: String::from("signed file does not exist"),
        });
    }
    if !signature.is_file() {
        return Err(GpgError::Io {
            path: signature.display().to_string(),
            message: String::from("detached signature does not exist"),
        });
    }

    let home = home.map(Path::to_path_buf).or_else(default_home);
    let mut command = Command::new("gpg");
    command
        .arg("--batch")
        .arg("--no-tty")
        .arg("--no-auto-check-trustdb")
        // Defense-in-depth vs ambient gpg.conf (auditor G-L9): a user or host
        // configuration must not be able to relax this verifier.
        .arg("--no-options")
        .arg("--status-fd")
        .arg("1")
        // A verifier must never inherit a terminal: with no stdin it cannot
        // block on a prompt if a key needs interaction.
        .stdin(Stdio::null());
    if let Some(home) = home {
        command.arg("--homedir").arg(home);
    }
    command.arg("--verify").arg(signature).arg(data);

    let output = command.output().map_err(|error| GpgError::Unavailable {
        message: error.to_string(),
    })?;

    if !output.status.success() {
        return Err(GpgError::Rejected {
            detail: last_stderr_line(&output.stderr),
        });
    }

    let status = String::from_utf8_lossy(&output.stdout);
    if !status
        .lines()
        .any(|line| line.starts_with("[GNUPG:] VALIDSIG"))
    {
        return Err(GpgError::Rejected {
            detail: String::from("gpg exited successfully but reported no VALIDSIG status line"),
        });
    }

    Ok(())
}

/// `EXTOS_GPG_HOME` as a path, when the caller did not pass one.
fn default_home() -> Option<PathBuf> {
    std::env::var_os(GNUPG_HOME_ENV).map(PathBuf::from)
}

/// Last non-empty line of `gpg`'s stderr, trimmed for error messages.
fn last_stderr_line(stderr: &[u8]) -> String {
    let text = String::from_utf8_lossy(stderr);
    let line = text
        .lines()
        .rev()
        .map(str::trim)
        .find(|line| !line.is_empty());
    match line {
        Some(line) => line.to_string(),
        None => String::from("gpg reported failure without a diagnostic"),
    }
}
