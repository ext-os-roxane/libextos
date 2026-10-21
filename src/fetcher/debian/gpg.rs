//! `gpg` subprocess wrapper for Debian repository signature verification
//! (PLAN 3.3.2 / 3.3.3).
//!
//! The Debian archive is authenticated by an OpenPGP clearsignature over the
//! `InRelease` document (or a detached `Release.gpg` over `Release`). ExtOS
//! deliberately does **not** link `libgpgme`: the crate's dependency policy is
//! zero-new-crates, `gpg` ships on every APT-capable system, and keeping the
//! trust decision in a child process means a malformed key cannot corrupt the
//! daemon's address space.
//!
//! Every verification runs against a throwaway `GNUPGHOME`
//! ([`TempDir`]-backed, mode `0700`, deleted on drop) that only ever contains
//! the single key the caller passed in. No user keyring is consulted, so
//! ambient trust settings cannot change the outcome.
//!
//! Absence of the `gpg` executable is reported as a typed
//! [`ExtosError::ConfigParse`] naming the missing tool — never a silent skip.

use std::ffi::OsString;
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
///
/// Runs `gpg --version`; a missing binary or a non-zero exit both report
/// `false`.
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

/// Verify a clearsigned document (Debian `InRelease`) with `key`.
///
/// `key` is ASCII-armoured (or binary) OpenPGP public key material — exactly
/// the bytes a caller obtained out of band. Returns
/// [`ExtosError::CasIntegrity`] when `gpg` rejects the signature, and
/// [`ExtosError::ConfigParse`] when `gpg` itself cannot be run.
pub(crate) fn verify_clearsigned(doc: &[u8], key: &[u8]) -> Result<(), ExtosError> {
    let home = TempDir::new("gpg")?;
    import_key(&home, key)?;
    let doc_path = home.path().join("InRelease");
    fs::write(&doc_path, doc)?;
    run_verify(&home, vec![doc_path.into_os_string()])
}

/// Verify a detached signature: `sig` over `data` (Debian `Release.gpg` over
/// `Release`).
pub(crate) fn verify_detached(data: &[u8], sig: &[u8], key: &[u8]) -> Result<(), ExtosError> {
    let home = TempDir::new("gpg")?;
    import_key(&home, key)?;
    let data_path = home.path().join("Release");
    let sig_path = home.path().join("Release.gpg");
    fs::write(&data_path, data)?;
    fs::write(&sig_path, sig)?;
    run_verify(
        &home,
        vec![sig_path.into_os_string(), data_path.into_os_string()],
    )
}

/// Import `key` into the throwaway home, then run `gpg --verify <args>`.
fn run_verify(home: &TempDir, args: Vec<OsString>) -> Result<(), ExtosError> {
    let mut cmd = gpg_command(home);
    cmd.arg("--verify").args(args);
    let output = spawn(&mut cmd)?;
    if output.status.success() {
        return Ok(());
    }
    Err(ExtosError::CasIntegrity {
        expected: "valid OpenPGP signature from the configured repository key".to_string(),
        actual: format!("gpg --verify failed: {}", describe(&output)),
    })
}

/// Import the caller-supplied key into the throwaway home.
fn import_key(home: &TempDir, key: &[u8]) -> Result<(), ExtosError> {
    if key.is_empty() {
        return Err(ExtosError::ConfigParse {
            path: "sigkey_gpg".to_string(),
            line: 0,
            message: "the signature key is empty; pass an armoured public key".to_string(),
        });
    }
    let key_path = home.path().join("extos-repo-key.asc");
    fs::write(&key_path, key)?;

    let mut cmd = gpg_command(home);
    cmd.arg("--import").arg(&key_path);
    let output = spawn(&mut cmd)?;
    if output.status.success() {
        return Ok(());
    }
    Err(ExtosError::ConfigParse {
        path: "sigkey_gpg".to_string(),
        line: 0,
        message: format!(
            "gpg --import rejected the repository key: {}",
            describe(&output)
        ),
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
            "cannot run '{GPG}': {err}; install GnuPG to verify Debian repository \
             signatures (or pass no key to skip verification)"
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
/// scratch space for the document under verification.
///
/// `gpg` 2.4 may leave `S.gpg-agent`/`keyboxd` sockets behind; the removal is
/// therefore best-effort (a failed cleanup never masks the verification
/// result) and the directory lives under the platform temp dir, never under a
/// hardcoded absolute path.
struct TempDir {
    path: PathBuf,
}

impl TempDir {
    /// Create a directory named `<temp>/extos-<tag>-<pid>-<nanos>-<seq>`.
    fn new(tag: &str) -> Result<Self, ExtosError> {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or(0);
        let seq = SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "extos-{tag}-{}-{nanos}-{seq}",
            std::process::id()
        ));
        fs::create_dir_all(&path)?;
        restrict(&path)?;
        Ok(Self { path })
    }

    /// The directory path.
    fn path(&self) -> &Path {
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
