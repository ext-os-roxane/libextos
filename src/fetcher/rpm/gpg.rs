//! `gpg` subprocess helper for RPM repository metadata signatures
//! (PLAN 3.4.3 / 3.4.4).
//!
//! A dnf/yum repository authenticates `repodata/repomd.xml` with a detached
//! OpenPGP signature (`repodata/repomd.xml.asc`) made by the repository release
//! key. ExtOS does not link `libgpgme` or `libsequoia` here: the crate's
//! dependency policy is zero new crates, `gpg` is on every RPM-capable system,
//! and running the trust decision in a child process keeps a malformed key out
//! of the daemon's address space.
//!
//! Every verification runs against a throwaway `GNUPGHOME` that contains only
//! the single key the caller supplied (mode `0700`, deleted on drop), so
//! ambient user keyrings cannot change the answer. Absence of the `gpg`
//! executable is a typed [`ExtosError::ConfigParse`] naming the tool — never a
//! silent skip.
//!
//! The same policy is implemented for the Debian fetcher in
//! `crate::fetcher::debian`; that module is private to its lane, so this file
//! carries its own minimal copy rather than reaching across a module boundary.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::ExtosError;

/// Name of the OpenPGP implementation this module shells out to.
const GPG: &str = "gpg";

/// Per-process sequence so concurrent verifications get distinct homes.
static SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// `true` when a working `gpg` executable is reachable through `PATH`.
pub(crate) fn available() -> bool {
    Command::new(GPG)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

/// Verify the detached signature `sig` over `data` with `key`.
///
/// `key` is ASCII-armoured (or binary) OpenPGP public key material — exactly
/// the bytes a caller obtained out of band (usually `repodata/repomd.xml.key`).
///
/// # Errors
///
/// [`ExtosError::CasIntegrity`] when `gpg` rejects the signature,
/// [`ExtosError::ConfigParse`] when `gpg` cannot run or the key is empty.
pub(crate) fn verify_detached(data: &[u8], sig: &[u8], key: &[u8]) -> Result<(), ExtosError> {
    if key.is_empty() {
        return Err(ExtosError::ConfigParse {
            path: "sigkey_gpg".to_string(),
            line: 0,
            message: "the RPM repository key is empty; pass an armoured public key".to_string(),
        });
    }
    let home = TempDir::new("rpm-gpg")?;
    let key_path = home.path().join("extos-repo-key.asc");
    let data_path = home.path().join("repomd.xml");
    let sig_path = home.path().join("repomd.xml.asc");
    fs::write(&key_path, key)?;
    fs::write(&data_path, data)?;
    fs::write(&sig_path, sig)?;

    let mut import = gpg_command(&home);
    import.arg("--import").arg(&key_path);
    let imported = spawn(&mut import)?;
    if !imported.status.success() {
        return Err(ExtosError::ConfigParse {
            path: "sigkey_gpg".to_string(),
            line: 0,
            message: format!(
                "gpg --import rejected the RPM repository key: {}",
                describe(&imported)
            ),
        });
    }

    let mut verify = gpg_command(&home);
    verify.arg("--verify").arg(&sig_path).arg(&data_path);
    let verified = spawn(&mut verify)?;
    if verified.status.success() {
        return Ok(());
    }
    Err(ExtosError::CasIntegrity {
        expected: "valid OpenPGP signature from the configured RPM repository key".to_string(),
        actual: format!("gpg --verify failed: {}", describe(&verified)),
    })
}

/// A `gpg` command pinned to `home`, with deterministic, non-interactive
/// behaviour.
fn gpg_command(home: &TempDir) -> Command {
    let mut cmd = Command::new(GPG);
    cmd.arg("--homedir")
        .arg(home.path())
        .args(["--batch", "--no-tty", "--no-options", "--quiet"])
        .arg("--no-auto-key-retrieve")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd
}

/// Run a command, mapping spawn failures to a typed "tool missing" error.
fn spawn(cmd: &mut Command) -> Result<Output, ExtosError> {
    cmd.output().map_err(|err| ExtosError::ConfigParse {
        path: GPG.to_string(),
        line: 0,
        message: format!(
            "cannot run '{GPG}': {err}; install GnuPG to verify RPM repository \
             metadata (or pass no key to skip verification)"
        ),
    })
}

/// Compact, single-line rendering of a failed `gpg` run for error messages.
fn describe(output: &Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let detail = stderr
        .lines()
        .chain(stdout.lines())
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join("; ");
    let code = output
        .status
        .code()
        .map(|code| code.to_string())
        .unwrap_or_else(|| "signal".to_string());
    if detail.is_empty() {
        format!("exit {code}")
    } else {
        format!("exit {code}: {detail}")
    }
}

/// A private directory removed on drop, used as a throwaway `GNUPGHOME` and as
/// scratch space for files under verification.
///
/// `gpg` may leave `S.gpg-agent`/`keyboxd` sockets behind, so removal is
/// best-effort: a failed cleanup never masks a verification result. The
/// directory lives under the platform temp dir, never a hardcoded path.
pub(super) struct TempDir {
    path: PathBuf,
}

impl TempDir {
    /// Create a directory named `<temp>/extos-<tag>-<pid>-<nanos>-<seq>`.
    pub(super) fn new(tag: &str) -> Result<Self, ExtosError> {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or(0);
        let seq = SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("extos-{tag}-{}-{nanos}-{seq}", std::process::id()));
        fs::create_dir_all(&path)?;
        restrict(&path)?;
        Ok(Self { path })
    }

    /// The directory path.
    pub(super) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        if let Err(err) = fs::remove_dir_all(&self.path) {
            tracing::debug!(
                "could not remove temporary gpg home {}: {err}",
                self.path.display()
            );
        }
    }
}

/// Restrict a directory to its owner: `gpg` refuses group/world-readable
/// homes.
fn restrict(path: &Path) -> Result<(), ExtosError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}
