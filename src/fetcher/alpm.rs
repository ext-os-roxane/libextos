//! Libalpm-backed fetcher for Arch-origin packages (PLAN 3.2.1 -- 3.2.5).
//!
//! # Surface
//!
//! [`AlpmFetch`] gives the ExtOS ingestion pipeline the two primitives an
//! Arch-origin package needs: [`AlpmFetch::sync_db`] (fetch, validate and load
//! a repository database) and [`AlpmFetch::download`] (resolve a package
//! through that database, transfer the archive, optionally check its detached
//! PGP signature). Both are synchronous: `pkt` is a CLI, so no async runtime is
//! involved (the Phase-2 style law). Wiring into `ingest` is PLAN 3.2.6 and is
//! deliberately *not* done here -- this module ships API-complete and unwired.
//!
//! # Which libalpm answers (documented precedence)
//!
//! The library is loaded at runtime with `dlopen` (`libloading`), so `build.rs`
//! needs no `-lalpm` and an ExtOS host without pacman still builds. Candidate
//! order, first success wins:
//!
//! 1. [`ALPM_LIB_ENV`] (`EXTOS_ALPM_LIB`) -- exact path to a shared object,
//!    typically a `pacman-extos` fork build.
//! 2. [`PACMAN_BUILD_DIR_ENV`] (`EXTOS_PACMAN_BUILD_DIR`) -- a meson build
//!    directory; `libalpm.so`, `libalpm.so.16`, `libalpm.so.16.0.1` and the
//!    `lib/libalpm/` variants are probed.
//! 3. The sonames `libalpm.so.16`, then `libalpm.so`, resolved by the platform
//!    loader (i.e. the distribution libalpm).
//!
//! [`AlpmFetch::with_library`] skips probing entirely and loads an explicit
//! path, which is what the integration test does so it can state honestly which
//! library it exercised. [`AlpmFetch::library_version`] reports the version
//! string returned by `alpm_version()`.
//!
//! # Honest deviation from a "libalpm does everything" design (PLAN 3.2.4)
//!
//! Upstream pacman splits this work three ways: libcurl transfers through the
//! `alpm_fetchcb` callback, libarchive parses, libgpgme verifies. ExtOS keeps
//! only the middle step inside libalpm:
//!
//! * **transfer** -- this crate already ships a blocking HTTP stack (`reqwest`,
//!   used by `ingest::download_from_mirror`), so the database and package
//!   archives are written by us;
//! * **parse/validate** -- libalpm itself: `alpm_register_syncdb()` followed by
//!   `alpm_db_get_pkgcache()` reads `<dbpath>/sync/<repo>.db` through libarchive
//!   and fails with a typed `alpm_errno_t` when the archive is not a valid sync
//!   database (wrong format, truncated, unreadable). Package resolution
//!   (`alpm_db_get_pkg`, `alpm_pkg_get_filename`, `alpm_pkg_get_size`) is
//!   likewise libalpm's;
//! * **PGP verification** -- the `gpg` CLI against a caller-supplied keyring
//!   (see the `alpm_gpg` module docs), *not* gpgme. The host may have no
//!   libgpgme at all; the fork is built with `-Dgpgme=disabled` for exactly
//!   that reason.
//!
//! Consequences, stated so nobody has to reverse-engineer them:
//!
//! * `alpm_fetchcb` is not bound. Binding it would only re-implement the
//!   transfer and pull in libcurl's callback ABI.
//! * A repository database is registered with siglevel `0`
//!   (`ALPM_SIG_USE_DEFAULT` is deliberately *not* passed): libalpm performs no
//!   PGP check, and [`SigCheck`] drives our own `gpg` verification instead.
//! * Signature failures never degrade to "trusted because downloaded".
//!
//! # Repository database layout
//!
//! libalpm resolves a sync database to `<dbpath>/sync/<treename>.db`
//! (`_alpm_db_path()` in `lib/libalpm/db.c`). [`AlpmFetch::sync_db`] therefore
//! finishes the transfer *before* registering the database, and only then lets
//! libalpm open the file. That is the smallest honest integration: no synthetic
//! `file://` mirror, no `alpm_db_update()` callback plumbing.

use std::ffi::{CStr, CString, c_char, c_int, c_long, c_void};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use libloading::Library;
use thiserror::Error;

#[path = "alpm_gpg.rs"]
mod gpg;

/// Environment variable naming the exact `libalpm` shared object to load.
pub const ALPM_LIB_ENV: &str = "EXTOS_ALPM_LIB";

/// Environment variable naming a `pacman-extos` meson build directory.
pub const PACMAN_BUILD_DIR_ENV: &str = "EXTOS_PACMAN_BUILD_DIR";

/// Environment variable overriding the root passed to `alpm_initialize()`.
pub const ALPM_ROOT_ENV: &str = "EXTOS_ALPM_ROOT";

/// Timeout (seconds) for a single HTTP transfer; 120 when unset.
const TIMEOUT_ENV: &str = "EXTOS_DOWNLOAD_TIMEOUT_SECS";

/// Filesystem root handed to libalpm when [`ALPM_ROOT_ENV`] is not set.
///
/// This is the process root, not a configuration path: libalpm only uses it for
/// path mangling during transactions, which this fetcher never starts.
const DEFAULT_ALPM_ROOT: &str = "/";

/// Extension libalpm appends to a repository tree name (`handle->dbext`).
const DB_EXT: &str = ".db";

/// Repository registered when the caller does not choose one.
pub const DEFAULT_REPO: &str = "core";

/// Sonames the loader tries, in order, after the explicit paths above.
const SONAME_CANDIDATES: [&str; 2] = ["libalpm.so.16", "libalpm.so"];

/// Files probed inside [`PACMAN_BUILD_DIR_ENV`], relative to that directory.
const BUILD_DIR_CANDIDATES: [&str; 4] = [
    "libalpm.so",
    "libalpm.so.16",
    "libalpm.so.16.0.1",
    "lib/libalpm/libalpm.so",
];

/// What to do about detached PGP signatures.
///
/// There is no `Default` implementation on purpose: every call site states its
/// policy, so a repository can never become unsigned by omission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigCheck {
    /// A `.sig` must be published for the artifact and must verify.
    Required,
    /// Verify a published `.sig`; tolerate HTTP 404/410 (unsigned mirror).
    Optional,
    /// Transfer only. Never a default, and never used by `ingest`.
    Skip,
}

impl SigCheck {
    /// True when a missing signature is an error.
    #[must_use]
    pub fn requires_signature(self) -> bool {
        matches!(self, Self::Required)
    }
}

/// Errors raised by [`AlpmFetch`].
///
/// The type is local to this module rather than a variant of
/// [`crate::error::ExtosError`]: the fetcher stack owns transport-specific
/// failure modes and callers convert at the seam they choose (PLAN 3.2.6). No
/// variant hides a partial result -- a returned `PathBuf` is always a fully
/// transferred, size-checked, (optionally) signature-verified file.
#[derive(Debug, Error)]
pub enum AlpmFetchError {
    /// No usable libalpm could be loaded; `tried` lists every candidate.
    #[error("libalpm is not available (tried: {tried}): {detail}")]
    NotAvailable {
        /// Human-readable list of candidates that were attempted.
        tried: String,
        /// Loader or symbol-resolution detail for the last candidate.
        detail: String,
    },

    /// `alpm_initialize()` returned NULL.
    #[error("alpm_initialize() failed for database path '{dbpath}': {message}")]
    Initialize {
        /// Database path handed to libalpm.
        dbpath: String,
        /// `alpm_strerror()` text for the reported `alpm_errno_t`.
        message: String,
    },

    /// `alpm_register_syncdb()` returned NULL.
    #[error("alpm_register_syncdb('{repo}') failed: {message}")]
    DatabaseRegister {
        /// Repository tree name that was registered.
        repo: String,
        /// `alpm_strerror()` text for the reported `alpm_errno_t`.
        message: String,
    },

    /// libalpm could not read the downloaded archive as a sync database.
    #[error("libalpm could not read sync database '{path}': {message}")]
    DatabaseOpen {
        /// Path of the `.db` archive that libalpm tried to open.
        path: String,
        /// `alpm_strerror()` text, or a note when libalpm reported no errno.
        message: String,
    },

    /// [`AlpmFetch::download`] was called before [`AlpmFetch::sync_db`].
    #[error("no sync database loaded; call AlpmFetch::sync_db() first")]
    NotSynced,

    /// The same repository was registered twice on one fetcher.
    #[error(
        "repository '{repo}' is already registered on this fetcher; build a new one to re-sync"
    )]
    AlreadySynced {
        /// Repository tree name.
        repo: String,
    },

    /// A caller-supplied value is unusable.
    #[error("invalid argument: {message}")]
    InvalidArgument {
        /// Explanation of the rejected value.
        message: String,
    },

    /// The blocking HTTP client could not be constructed.
    #[error("could not build the HTTP client: {message}")]
    HttpClient {
        /// `reqwest` builder error text.
        message: String,
    },

    /// The transfer itself failed (DNS, TLS, connection reset, timeout).
    #[error("HTTP request for '{url}' failed: {message}")]
    HttpRequest {
        /// Requested URL.
        url: String,
        /// Transport error text.
        message: String,
    },

    /// The mirror answered, but not with a success status.
    #[error("HTTP request for '{url}' returned status {status}")]
    HttpStatus {
        /// Requested URL.
        url: String,
        /// Numeric HTTP status (404 and 410 are the common "absent" cases).
        status: u16,
    },

    /// A local file could not be written.
    #[error("could not write '{path}': {message}")]
    Write {
        /// Local destination path.
        path: String,
        /// Underlying I/O error text.
        message: String,
    },

    /// [`SigCheck::Required`] but the mirror publishes no `.sig`.
    #[error("no detached signature published for '{artifact}' but signatures are required")]
    MissingSignature {
        /// Artifact name (database or package filename) without its `.sig`.
        artifact: String,
    },

    /// `gpg` is missing or rejected the signature.
    #[error("signature check failed for '{artifact}': {message}")]
    Signature {
        /// Artifact name (database or package filename).
        artifact: String,
        /// `gpg` diagnostic.
        message: String,
    },

    /// No package by that name exists in the loaded database.
    #[error("package '{name}' is not in repository '{repo}'")]
    PackageNotFound {
        /// Package name as requested.
        name: String,
        /// Repository tree name that was searched.
        repo: String,
    },

    /// The package exists but not in the requested version.
    #[error("package '{name}' version '{version}' is not in repository '{repo}'")]
    VersionNotFound {
        /// Package name as requested.
        name: String,
        /// Requested version string.
        version: String,
        /// Repository tree name that was searched.
        repo: String,
    },

    /// The database entry carries no usable `%FILENAME%`.
    #[error("database entry for '{pkg}' has no usable %FILENAME%: {message}")]
    PackageMetadata {
        /// Package name as stored in the database.
        pkg: String,
        /// Why the filename was rejected.
        message: String,
    },

    /// The transfer disagrees with the size recorded in the database.
    #[error(
        "size mismatch for '{artifact}': database declares {expected} bytes, transfer is {actual} bytes"
    )]
    SizeMismatch {
        /// Artifact name (database or package filename).
        artifact: String,
        /// `%CSIZE%` from the sync database.
        expected: u64,
        /// Byte count actually received.
        actual: u64,
    },
}

/// Opaque `alpm_handle_t *`.
type HandlePtr = *mut c_void;
/// Opaque `alpm_db_t *`.
type DbPtr = *mut c_void;
/// Opaque `alpm_pkg_t *`.
type PkgPtr = *mut c_void;

/// One node of libalpm's public `alpm_list_t`
/// (`data`, `prev`, `next` -- in that order; see `lib/libalpm/alpm_list.h`).
#[repr(C)]
struct AlpmListNode {
    data: *mut c_void,
    prev: *mut AlpmListNode,
    next: *mut AlpmListNode,
}

/// The bounded libalpm C surface this fetcher needs (PLAN 3.2.3).
///
/// Every member is a plain `extern "C"` function pointer copied out of the
/// loaded object, so no `Symbol` lifetime leaks into the rest of the module.
/// The list is intentionally minimal: no transaction, transaction-callback,
/// `alpm_fetchcb`, `alpm_db_update` or log callback is bound (see the module
/// docs for why).
struct AlpmApi {
    /// `alpm_handle_t *alpm_initialize(const char *root, const char *dbpath, alpm_errno_t *err)`.
    initialize: unsafe extern "C" fn(*const c_char, *const c_char, *mut c_int) -> HandlePtr,
    /// `int alpm_release(alpm_handle_t *handle)`.
    release: unsafe extern "C" fn(HandlePtr) -> c_int,
    /// `const char *alpm_version(void)`.
    version: unsafe extern "C" fn() -> *const c_char,
    /// `alpm_errno_t alpm_errno(alpm_handle_t *handle)`.
    errno: unsafe extern "C" fn(HandlePtr) -> c_int,
    /// `const char *alpm_strerror(alpm_errno_t err)`.
    strerror: unsafe extern "C" fn(c_int) -> *const c_char,
    /// `alpm_db_t *alpm_register_syncdb(alpm_handle_t *, const char *treename, int siglevel)`.
    register_syncdb: unsafe extern "C" fn(HandlePtr, *const c_char, c_int) -> DbPtr,
    /// `alpm_list_t *alpm_db_get_pkgcache(alpm_db_t *db)`.
    db_get_pkgcache: unsafe extern "C" fn(DbPtr) -> *mut AlpmListNode,
    /// `alpm_pkg_t *alpm_db_get_pkg(alpm_db_t *db, const char *name)`.
    db_get_pkg: unsafe extern "C" fn(DbPtr, *const c_char) -> PkgPtr,
    /// `const char *alpm_pkg_get_name(alpm_pkg_t *pkg)`.
    pkg_get_name: unsafe extern "C" fn(PkgPtr) -> *const c_char,
    /// `const char *alpm_pkg_get_version(alpm_pkg_t *pkg)`.
    pkg_get_version: unsafe extern "C" fn(PkgPtr) -> *const c_char,
    /// `const char *alpm_pkg_get_filename(alpm_pkg_t *pkg)`.
    pkg_get_filename: unsafe extern "C" fn(PkgPtr) -> *const c_char,
    /// `off_t alpm_pkg_get_size(alpm_pkg_t *pkg)` (`off_t` is `c_long` here).
    pkg_get_size: unsafe extern "C" fn(PkgPtr) -> c_long,
}

impl AlpmApi {
    /// Resolve every symbol in one pass.
    ///
    /// A missing symbol means the loaded object is not a usable libalpm (ABI
    /// mismatch, truncated or symbol-stripped build); the message names the
    /// first symbol that could not be resolved.
    fn load(library: &Library) -> Result<Self, String> {
        Ok(Self {
            initialize: load_symbol(library, b"alpm_initialize")?,
            release: load_symbol(library, b"alpm_release")?,
            version: load_symbol(library, b"alpm_version")?,
            errno: load_symbol(library, b"alpm_errno")?,
            strerror: load_symbol(library, b"alpm_strerror")?,
            register_syncdb: load_symbol(library, b"alpm_register_syncdb")?,
            db_get_pkgcache: load_symbol(library, b"alpm_db_get_pkgcache")?,
            db_get_pkg: load_symbol(library, b"alpm_db_get_pkg")?,
            pkg_get_name: load_symbol(library, b"alpm_pkg_get_name")?,
            pkg_get_version: load_symbol(library, b"alpm_pkg_get_version")?,
            pkg_get_filename: load_symbol(library, b"alpm_pkg_get_filename")?,
            pkg_get_size: load_symbol(library, b"alpm_pkg_get_size")?,
        })
    }
}

/// Copy one function pointer out of `library`.
///
/// # Safety
///
/// `T` must be an `extern "C"` function pointer whose signature matches the
/// symbol's real definition. Every caller in [`AlpmApi::load`] names a libalpm
/// public symbol with its exact prototype, and the enclosing [`AlpmFetch`] owns
/// `library` for longer than any copied pointer is used.
fn load_symbol<T: Copy>(library: &Library, name: &[u8]) -> Result<T, String> {
    // SAFETY: see the function contract above -- symbol name and type are pinned
    // by the caller, and the mapping outlives the copied pointer.
    unsafe { library.get::<T>(name) }
        .map(|symbol| *symbol)
        .map_err(|error| format!("symbol {}: {error}", String::from_utf8_lossy(name)))
}

/// Read a NUL-terminated C string into an owned [`String`]; `None` for NULL.
///
/// # Safety
///
/// `pointer` must be NULL or point at a NUL-terminated string that stays valid
/// for the duration of the call (libalpm returns either NULL or an internal
/// string owned by the object that was just queried).
unsafe fn c_opt_string(pointer: *const c_char) -> Option<String> {
    if pointer.is_null() {
        return None;
    }
    // SAFETY: non-NULL and NUL-terminated per the function contract.
    Some(
        unsafe { CStr::from_ptr(pointer) }
            .to_string_lossy()
            .into_owned(),
    )
}

/// Count the nodes of an `alpm_list_t` chain.
///
/// # Safety
///
/// `head` must be NULL or a list returned by libalpm and still owned by it (we
/// never mutate or free it, and the list is read while the handle is alive).
unsafe fn list_len(head: *mut AlpmListNode) -> usize {
    let mut count = 0usize;
    let mut node = head;
    while !node.is_null() {
        count += 1;
        // SAFETY: `node` is a live list node per the function contract.
        node = unsafe { (*node).next };
    }
    count
}

/// Metadata describing a database loaded by [`AlpmFetch::sync_db`].
///
/// The handle itself stays inside [`AlpmFetch`]; this value is the receipt
/// callers and tests assert on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncDb {
    repo: String,
    db_path: PathBuf,
    package_count: usize,
    base_url: String,
}

impl SyncDb {
    /// Repository tree name (`core`, `extra`, ...).
    #[must_use]
    pub fn repo(&self) -> &str {
        &self.repo
    }

    /// Local path of the `.db` archive libalpm parsed.
    #[must_use]
    pub fn db_path(&self) -> &Path {
        &self.db_path
    }

    /// Number of packages libalpm loaded from the archive.
    #[must_use]
    pub fn package_count(&self) -> usize {
        self.package_count
    }

    /// Mirror base URL the archive was transferred from (no trailing `/`).
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }
}

/// State captured by a successful [`AlpmFetch::sync_db`].
struct Synced {
    repo: String,
    db: DbPtr,
    base_url: String,
}

/// A libalpm handle plus the ExtOS transfer and PGP policy around it.
///
/// Sync-only and single-threaded by construction: libalpm handles are not
/// thread-safe, so the type holds a raw pointer and is therefore `!Send` and
/// `!Sync`. Create one fetcher per worker thread.
///
/// ```no_run
/// use libextos::fetcher::alpm::{AlpmFetch, SigCheck};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let dbpath = std::env::temp_dir().join("extos-alpm");
/// let mut fetcher = AlpmFetch::new(&dbpath)?;
/// let db = fetcher.sync_db(
///     "https://mirror.example.org/archlinux/core/os/x86_64",
///     SigCheck::Required,
/// )?;
/// println!("{} packages", db.package_count());
/// let archive = fetcher.download("coreutils", None, SigCheck::Required)?;
/// println!("{}", archive.display());
/// # Ok(())
/// # }
/// ```
pub struct AlpmFetch {
    api: AlpmApi,
    // Field order is load-bearing: Drop releases the handle, then the Library
    // mapping is dropped. Never reorder. The field is only an ownership anchor, hence the underscore.
    _library: Library,
    /// Where the loaded library came from (env var, build dir or soname).
    source: String,
    handle: HandlePtr,
    dbpath: PathBuf,
    repo: String,
    cache_dir: PathBuf,
    gnupg_home: Option<PathBuf>,
    synced: Option<Synced>,
    _not_thread_safe: std::marker::PhantomData<*mut ()>,
}

impl AlpmFetch {
    /// Load libalpm through the documented precedence and initialize a handle.
    ///
    /// `dbpath` is the private database directory: `<dbpath>/sync/` receives
    /// repository databases and `<dbpath>/pkg/` the downloaded archives. The
    /// directory is created when missing. Nothing outside it is touched.
    ///
    /// # Errors
    ///
    /// [`AlpmFetchError::NotAvailable`] when no candidate loads,
    /// [`AlpmFetchError::Initialize`] when `alpm_initialize()` fails, and
    /// [`AlpmFetchError::Write`] when `dbpath` cannot be created.
    pub fn new(dbpath: impl AsRef<Path>) -> Result<Self, AlpmFetchError> {
        let (library, source) = open_default_library()?;
        Self::from_library(library, source, dbpath.as_ref())
    }

    /// Load libalpm from an explicit shared object, bypassing discovery.
    ///
    /// Useful for a `pacman-extos` fork build and for tests that must state
    /// which library they exercised.
    ///
    /// # Errors
    ///
    /// [`AlpmFetchError::NotAvailable`] when the path cannot be loaded or lacks
    /// the required symbols, plus everything [`AlpmFetch::new`] reports.
    pub fn with_library(
        dbpath: impl AsRef<Path>,
        library_path: impl AsRef<Path>,
    ) -> Result<Self, AlpmFetchError> {
        let path = library_path.as_ref();
        // SAFETY: dlopen of a caller-chosen file. The Library is owned by the
        // returned fetcher, which keeps the mapping alive for every copied
        // function pointer.
        let library =
            unsafe { Library::new(path) }.map_err(|error| AlpmFetchError::NotAvailable {
                tried: path.display().to_string(),
                detail: error.to_string(),
            })?;
        Self::from_library(library, path.display().to_string(), dbpath.as_ref())
    }

    /// Shared constructor: bind symbols, create directories, initialize handle.
    fn from_library(
        library: Library,
        source: String,
        dbpath: &Path,
    ) -> Result<Self, AlpmFetchError> {
        let api = AlpmApi::load(&library).map_err(|detail| AlpmFetchError::NotAvailable {
            tried: String::from("a library was loaded but is not a usable libalpm"),
            detail,
        })?;

        let sync_dir = dbpath.join("sync");
        fs::create_dir_all(&sync_dir).map_err(|error| AlpmFetchError::Write {
            path: sync_dir.display().to_string(),
            message: error.to_string(),
        })?;
        let cache_dir = dbpath.join("pkg");
        fs::create_dir_all(&cache_dir).map_err(|error| AlpmFetchError::Write {
            path: cache_dir.display().to_string(),
            message: error.to_string(),
        })?;

        let dbpath_str = dbpath
            .to_str()
            .ok_or_else(|| AlpmFetchError::InvalidArgument {
                message: format!("database path '{}' is not valid UTF-8", dbpath.display()),
            })?;
        let root = std::env::var(ALPM_ROOT_ENV).unwrap_or_else(|_| DEFAULT_ALPM_ROOT.to_string());
        let c_root = c_string(&root, "alpm root")?;
        let c_dbpath = c_string(dbpath_str, "database path")?;

        let mut errno: c_int = 0;
        // SAFETY: both strings are NUL-terminated and outlive the call; libalpm
        // copies them into the handle it returns.
        let handle = unsafe { (api.initialize)(c_root.as_ptr(), c_dbpath.as_ptr(), &mut errno) };
        if handle.is_null() {
            return Err(AlpmFetchError::Initialize {
                dbpath: dbpath_str.to_string(),
                message: error_text(&api, errno),
            });
        }

        let gnupg_home = std::env::var_os(gpg::GNUPG_HOME_ENV).map(PathBuf::from);

        Ok(Self {
            api,
            _library: library,
            source,
            handle,
            dbpath: dbpath.to_path_buf(),
            repo: DEFAULT_REPO.to_string(),
            cache_dir,
            gnupg_home,
            synced: None,
            _not_thread_safe: std::marker::PhantomData,
        })
    }

    /// Version string reported by the loaded library (`alpm_version()`).
    #[must_use]
    pub fn library_version(&self) -> String {
        // SAFETY: bound symbol returning a static string owned by libalpm.
        unsafe { c_opt_string((self.api.version)()) }.unwrap_or_else(|| String::from("unknown"))
    }

    /// Where the loaded library came from, per the module-level precedence.
    ///
    /// Examples: `EXTOS_ALPM_LIB=/path/libalpm.so`,
    /// `/path/build/libalpm.so` (from `EXTOS_PACMAN_BUILD_DIR`), or
    /// `libalpm.so.16` when the platform loader resolved it.
    #[must_use]
    pub fn library_source(&self) -> &str {
        &self.source
    }

    /// Repository tree name that [`AlpmFetch::sync_db`] registers.
    #[must_use]
    pub fn repo(&self) -> &str {
        &self.repo
    }

    /// Private database directory (holds `sync/` and `pkg/`).
    #[must_use]
    pub fn dbpath(&self) -> &Path {
        &self.dbpath
    }

    /// Choose the repository tree name; the default is [`DEFAULT_REPO`].
    ///
    /// # Errors
    ///
    /// [`AlpmFetchError::InvalidArgument`] for an empty name or one containing a
    /// path separator (libalpm rejects those, and a separator would escape
    /// `<dbpath>/sync/`).
    pub fn with_repo(mut self, repo: &str) -> Result<Self, AlpmFetchError> {
        if repo.is_empty() || repo.contains('/') || repo.contains('\\') {
            return Err(AlpmFetchError::InvalidArgument {
                message: format!("invalid repository name '{repo}'"),
            });
        }
        self.repo = repo.to_string();
        Ok(self)
    }

    /// Directory that receives downloaded package archives.
    #[must_use]
    pub fn cache_dir(&self) -> &Path {
        &self.cache_dir
    }

    /// Override where downloaded archives are stored (default `<dbpath>/pkg`).
    #[must_use]
    pub fn with_cache_dir(mut self, cache_dir: impl Into<PathBuf>) -> Self {
        self.cache_dir = cache_dir.into();
        self
    }

    /// Override the `gpg` home directory used for signature checks.
    ///
    /// Defaults to the `EXTOS_GPG_HOME` environment variable when set, and
    /// otherwise to whatever `gpg` itself considers its home.
    #[must_use]
    pub fn with_gnupg_home(mut self, home: impl Into<PathBuf>) -> Self {
        self.gnupg_home = Some(home.into());
        self
    }

    /// Fetch, verify and load a repository database (PLAN 3.2.4).
    ///
    /// Steps, in order:
    ///
    /// 1. `GET <mirror_base_url>/<repo>.db` into `<dbpath>/sync/<repo>.db`
    ///    (written as `.part` and renamed, so a half transfer is never parsed);
    /// 2. if `sigcheck` is not [`SigCheck::Skip`], optionally `GET` the detached
    ///    `<repo>.db.sig` and verify it with `gpg`;
    /// 3. [`alpm_register_syncdb`](AlpmFetch) equivalent work: libalpm registers
    ///    the tree and `alpm_db_get_pkgcache()` opens the archive with libarchive,
    ///    reporting a typed errno when it is not a sync database;
    /// 4. return a [`SyncDb`] receipt carrying the package count.
    ///
    /// `mirror_base_url` must be an absolute `http://` or `https://` URL and is
    /// taken verbatim minus a trailing `/`. Sub-repositories are the caller's
    /// business: pass `.../core/os/x86_64`, not `.../core`.
    ///
    /// # Errors
    ///
    /// [`AlpmFetchError::HttpStatus`] (404 for a repo the mirror does not carry),
    /// [`AlpmFetchError::Signature`] or [`AlpmFetchError::MissingSignature`] for a
    /// bad or absent signature that policy forbids,
    /// [`AlpmFetchError::DatabaseRegister`] or [`AlpmFetchError::DatabaseOpen`]
    /// when libalpm rejects the archive, and [`AlpmFetchError::AlreadySynced`] on
    /// a second call for the same fetcher (build a new one to re-sync).
    pub fn sync_db(
        &mut self,
        mirror_base_url: &str,
        sigcheck: SigCheck,
    ) -> Result<SyncDb, AlpmFetchError> {
        let base = normalize_base_url(mirror_base_url)?;
        if let Some(synced) = &self.synced {
            return Err(AlpmFetchError::AlreadySynced {
                repo: synced.repo.clone(),
            });
        }

        let db_name = format!("{}{DB_EXT}", self.repo);
        let db_url = format!("{base}/{db_name}");
        let db_path = self.dbpath.join("sync").join(&db_name);
        let part = with_suffix(&db_path, ".part");

        let client = http_client()?;
        download_to(&client, &db_url, &part)?;
        if sigcheck != SigCheck::Skip {
            if let Err(error) = self.check_signature(&client, &db_url, &part, &db_name, sigcheck) {
                remove_quietly(&part);
                return Err(error);
            }
        }
        commit(&part, &db_path)?;

        let c_repo = c_string(&self.repo, "repository name")?;
        // siglevel 0: libalpm performs no PGP check (we did it above, or the
        // caller chose Skip). ALPM_SIG_USE_DEFAULT is intentionally not used --
        // a host-wide default must not silently enable or disable checks here.
        // SAFETY: live handle, NUL-terminated tree name.
        let db = unsafe { (self.api.register_syncdb)(self.handle, c_repo.as_ptr(), 0) };
        if db.is_null() {
            return Err(AlpmFetchError::DatabaseRegister {
                repo: self.repo.clone(),
                message: error_text(&self.api, self.errno()),
            });
        }

        // SAFETY: db was just returned by libalpm and is owned by the handle;
        // the list is only read.
        let cache = unsafe { (self.api.db_get_pkgcache)(db) };
        let errno = self.errno();
        if cache.is_null() && errno != 0 {
            return Err(AlpmFetchError::DatabaseOpen {
                path: db_path.display().to_string(),
                message: error_text(&self.api, errno),
            });
        }
        // SAFETY: cache is NULL (empty database) or a list owned by db.
        let package_count = unsafe { list_len(cache) };

        self.synced = Some(Synced {
            repo: self.repo.clone(),
            db,
            base_url: base.clone(),
        });

        Ok(SyncDb {
            repo: self.repo.clone(),
            db_path,
            package_count,
            base_url: base,
        })
    }

    /// Resolve, transfer and optionally verify one package (PLAN 3.2.5).
    ///
    /// `name` is looked up through libalpm's package cache (`alpm_db_get_pkg`),
    /// `version` narrows to an exact `%VERSION%` when given, and the archive is
    /// fetched as `<base>/<repo>/<%FILENAME%>`.
    ///
    /// Guarantees on success:
    ///
    /// * the returned path is inside the fetcher's cache directory;
    /// * its byte count equals `%CSIZE%` when the database records one (a
    ///   mismatch removes the partial file and fails with
    ///   [`AlpmFetchError::SizeMismatch`]);
    /// * under [`SigCheck::Required`] or [`SigCheck::Optional`] a published
    ///   `.sig` verified, against the bytes that were renamed into place.
    ///
    /// # Errors
    ///
    /// [`AlpmFetchError::NotSynced`] before [`AlpmFetch::sync_db`],
    /// [`AlpmFetchError::PackageNotFound`] or [`AlpmFetchError::VersionNotFound`]
    /// for a miss, [`AlpmFetchError::PackageMetadata`] when the entry has no safe
    /// filename, plus the HTTP, size and signature variants.
    pub fn download(
        &self,
        name: &str,
        version: Option<&str>,
        sigcheck: SigCheck,
    ) -> Result<PathBuf, AlpmFetchError> {
        let synced = self.synced.as_ref().ok_or(AlpmFetchError::NotSynced)?;
        if name.is_empty() {
            return Err(AlpmFetchError::InvalidArgument {
                message: String::from("package name is empty"),
            });
        }
        let c_name = c_string(name, "package name")?;
        // SAFETY: live database owned by the handle; the name is NUL-terminated.
        let pkg = unsafe { (self.api.db_get_pkg)(synced.db, c_name.as_ptr()) };
        if pkg.is_null() {
            return Err(AlpmFetchError::PackageNotFound {
                name: name.to_string(),
                repo: synced.repo.clone(),
            });
        }

        // SAFETY: pkg belongs to synced.db, which the handle keeps alive.
        let pkg_version =
            unsafe { c_opt_string((self.api.pkg_get_version)(pkg)) }.unwrap_or_default();
        if let Some(wanted) = version {
            if wanted != pkg_version {
                return Err(AlpmFetchError::VersionNotFound {
                    name: name.to_string(),
                    version: wanted.to_string(),
                    repo: synced.repo.clone(),
                });
            }
        }

        // SAFETY: same object as above.
        let stored_name = unsafe { c_opt_string((self.api.pkg_get_name)(pkg)) }
            .unwrap_or_else(|| name.to_string());
        // SAFETY: same object as above.
        let filename =
            unsafe { c_opt_string((self.api.pkg_get_filename)(pkg)) }.ok_or_else(|| {
                AlpmFetchError::PackageMetadata {
                    pkg: stored_name.clone(),
                    message: String::from("entry carries no %FILENAME%"),
                }
            })?;
        validate_package_filename(&stored_name, &filename)?;
        // SAFETY: same object as above.
        let declared_size = unsafe { (self.api.pkg_get_size)(pkg) };
        let declared_size = (declared_size > 0).then_some(declared_size as u64);

        let url = format!("{}/{}/{filename}", synced.base_url, synced.repo);
        let dest = self.cache_dir.join(&filename);
        fs::create_dir_all(&self.cache_dir).map_err(|error| AlpmFetchError::Write {
            path: self.cache_dir.display().to_string(),
            message: error.to_string(),
        })?;
        let part = with_suffix(&dest, ".part");

        let client = http_client()?;
        download_to(&client, &url, &part)?;

        let actual = fs::metadata(&part)
            .map_err(|error| AlpmFetchError::Write {
                path: part.display().to_string(),
                message: error.to_string(),
            })?
            .len();
        if let Some(expected) = declared_size {
            if expected != actual {
                remove_quietly(&part);
                return Err(AlpmFetchError::SizeMismatch {
                    artifact: filename,
                    expected,
                    actual,
                });
            }
        }

        if sigcheck != SigCheck::Skip {
            if let Err(error) = self.check_signature(&client, &url, &part, &filename, sigcheck) {
                remove_quietly(&part);
                return Err(error);
            }
        }

        commit(&part, &dest)?;
        Ok(dest)
    }

    /// Fetch and verify `<artifact_url>.sig` for the staged file at `artifact`.
    fn check_signature(
        &self,
        client: &reqwest::blocking::Client,
        artifact_url: &str,
        artifact: &Path,
        artifact_name: &str,
        sigcheck: SigCheck,
    ) -> Result<(), AlpmFetchError> {
        let sig_url = format!("{artifact_url}.sig");
        let sig_path = with_suffix(artifact, ".sig");
        if !download_if_present(client, &sig_url, &sig_path)? {
            if sigcheck.requires_signature() {
                return Err(AlpmFetchError::MissingSignature {
                    artifact: artifact_name.to_string(),
                });
            }
            tracing::warn!(
                url = %sig_url,
                "mirror publishes no detached signature; continuing under SigCheck::Optional"
            );
            return Ok(());
        }
        let verdict = gpg::verify_detached(artifact, &sig_path, self.gnupg_home.as_deref());
        // Whether it passed or not, the staged signature has done its job;
        // removing it leaves no `<artifact>.part.sig` behind in the cache.
        remove_quietly(&sig_path);
        verdict.map_err(|error| AlpmFetchError::Signature {
            artifact: artifact_name.to_string(),
            message: error.to_string(),
        })
    }

    /// Current `alpm_errno_t` of the handle.
    fn errno(&self) -> c_int {
        // SAFETY: live handle.
        unsafe { (self.api.errno)(self.handle) }
    }
}

impl Drop for AlpmFetch {
    fn drop(&mut self) {
        // SAFETY: handle came from alpm_initialize and is released exactly once.
        // Field order guarantees the Library mapping is still alive here.
        unsafe { (self.api.release)(self.handle) };
    }
}

/// Build a [`CString`], mapping interior NULs to
/// [`AlpmFetchError::InvalidArgument`].
fn c_string(value: &str, what: &str) -> Result<CString, AlpmFetchError> {
    CString::new(value).map_err(|_| AlpmFetchError::InvalidArgument {
        message: format!("{what} contains an interior NUL byte"),
    })
}

/// `alpm_strerror()` text for `errno`, or a numeric fallback.
fn error_text(api: &AlpmApi, errno: c_int) -> String {
    // SAFETY: bound symbol; libalpm owns the returned string.
    unsafe { c_opt_string((api.strerror)(errno)) }
        .filter(|message| !message.is_empty())
        .unwrap_or_else(|| format!("alpm_errno {errno}"))
}

/// Append `suffix` to a path's file name (`core.db` -> `core.db.part`).
fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|name| name.to_os_string())
        .unwrap_or_default();
    name.push(suffix);
    path.with_file_name(name)
}

/// Remove a staging file, ignoring "already gone".
fn remove_quietly(path: &Path) {
    if let Err(error) = fs::remove_file(path) {
        if error.kind() != io::ErrorKind::NotFound {
            tracing::warn!(
                path = %path.display(),
                %error,
                "could not remove staging file"
            );
        }
    }
}

/// Rename the verified staging file into its final name.
fn commit(part: &Path, dest: &Path) -> Result<(), AlpmFetchError> {
    fs::rename(part, dest).map_err(|error| AlpmFetchError::Write {
        path: dest.display().to_string(),
        message: error.to_string(),
    })
}

/// Validate a mirror base URL and strip a trailing `/`.
fn normalize_base_url(raw: &str) -> Result<String, AlpmFetchError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(AlpmFetchError::InvalidArgument {
            message: String::from("mirror base URL is empty"),
        });
    }
    if !(trimmed.starts_with("http://") || trimmed.starts_with("https://")) {
        return Err(AlpmFetchError::InvalidArgument {
            message: format!("mirror base URL '{trimmed}' must use http:// or https://"),
        });
    }
    if trimmed.chars().any(char::is_whitespace) {
        return Err(AlpmFetchError::InvalidArgument {
            message: format!("mirror base URL '{trimmed}' contains whitespace"),
        });
    }
    Ok(trimmed.trim_end_matches('/').to_string())
}

/// Reject a `%FILENAME%` that could escape the cache directory.
fn validate_package_filename(pkg: &str, filename: &str) -> Result<(), AlpmFetchError> {
    let reject = |message: &str| {
        Err(AlpmFetchError::PackageMetadata {
            pkg: pkg.to_string(),
            message: message.to_string(),
        })
    };
    if filename.is_empty() {
        return reject("empty %FILENAME%");
    }
    if filename.contains('/') || filename.contains('\\') {
        return reject("contains a path separator");
    }
    if filename == "." || filename == ".." || filename.starts_with('.') {
        return reject("starts with a dot");
    }
    if !filename.contains(".pkg.tar") {
        return reject("does not look like an Arch package archive");
    }
    Ok(())
}

/// Blocking HTTP client used for both database and package transfers.
fn http_client() -> Result<reqwest::blocking::Client, AlpmFetchError> {
    let timeout = std::env::var(TIMEOUT_ENV)
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .unwrap_or(120);
    reqwest::blocking::Client::builder()
        .user_agent(concat!("libextos-alpm/", env!("CARGO_PKG_VERSION")))
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(timeout))
        .build()
        .map_err(|error| AlpmFetchError::HttpClient {
            message: error.to_string(),
        })
}

/// Stream `url` into `dest`, failing on any non-success status.
fn download_to(
    client: &reqwest::blocking::Client,
    url: &str,
    dest: &Path,
) -> Result<(), AlpmFetchError> {
    stream_to(client, url, dest, false).map(|_| ())
}

/// Stream `url` into `dest`; `Ok(false)` when the mirror answers 404 or 410.
fn download_if_present(
    client: &reqwest::blocking::Client,
    url: &str,
    dest: &Path,
) -> Result<bool, AlpmFetchError> {
    stream_to(client, url, dest, true)
}

/// Shared transfer loop.
fn stream_to(
    client: &reqwest::blocking::Client,
    url: &str,
    dest: &Path,
    missing_is_absent: bool,
) -> Result<bool, AlpmFetchError> {
    let mut response = client
        .get(url)
        .send()
        .map_err(|error| AlpmFetchError::HttpRequest {
            url: url.to_string(),
            message: error.to_string(),
        })?;
    let status = response.status();
    if missing_is_absent
        && (status == reqwest::StatusCode::NOT_FOUND || status == reqwest::StatusCode::GONE)
    {
        return Ok(false);
    }
    if !status.is_success() {
        return Err(AlpmFetchError::HttpStatus {
            url: url.to_string(),
            status: status.as_u16(),
        });
    }
    let mut file = fs::File::create(dest).map_err(|error| AlpmFetchError::Write {
        path: dest.display().to_string(),
        message: error.to_string(),
    })?;
    io::copy(&mut response, &mut file).map_err(|error| AlpmFetchError::Write {
        path: dest.display().to_string(),
        message: error.to_string(),
    })?;
    file.sync_all().map_err(|error| AlpmFetchError::Write {
        path: dest.display().to_string(),
        message: error.to_string(),
    })?;
    Ok(true)
}

/// Probe the documented library precedence and return the first mapping.
fn open_default_library() -> Result<(Library, String), AlpmFetchError> {
    let mut tried: Vec<String> = Vec::new();
    let mut last_detail = String::from("no candidate was attempted");

    if let Some(path) = std::env::var_os(ALPM_LIB_ENV) {
        let path = PathBuf::from(path);
        let label = format!("{ALPM_LIB_ENV}={}", path.display());
        tried.push(label.clone());
        // SAFETY: dlopen of an operator-provided path; the Library is owned by
        // the caller's AlpmFetch.
        match unsafe { Library::new(&path) } {
            Ok(library) => return Ok((library, label)),
            Err(error) => last_detail = error.to_string(),
        }
    }

    if let Some(dir) = std::env::var_os(PACMAN_BUILD_DIR_ENV) {
        let dir = PathBuf::from(dir);
        for candidate in BUILD_DIR_CANDIDATES {
            let path = dir.join(candidate);
            let label = path.display().to_string();
            tried.push(label.clone());
            // SAFETY: as above.
            match unsafe { Library::new(&path) } {
                Ok(library) => return Ok((library, label)),
                Err(error) => last_detail = error.to_string(),
            }
        }
    }

    for soname in SONAME_CANDIDATES {
        tried.push(soname.to_string());
        // SAFETY: dlopen by soname; the loader resolves it through the usual
        // search path. The Library is owned by the caller's AlpmFetch.
        match unsafe { Library::new(soname) } {
            Ok(library) => return Ok((library, soname.to_string())),
            Err(error) => last_detail = error.to_string(),
        }
    }

    Err(AlpmFetchError::NotAvailable {
        tried: tried.join(", "),
        detail: last_detail,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_url_requires_a_network_scheme() {
        assert!(normalize_base_url("https://mirror.example.org/core").is_ok());
        assert!(normalize_base_url("http://127.0.0.1:8080").is_ok());
        assert!(normalize_base_url("file:///srv/repo").is_err());
        assert!(normalize_base_url("  ").is_err());
        assert!(normalize_base_url("https://mirror.example.org/a b").is_err());
    }

    #[test]
    fn base_url_drops_the_trailing_slash() {
        let normalized = normalize_base_url("https://mirror.example.org/core/").unwrap();
        assert_eq!(normalized, "https://mirror.example.org/core");
    }

    #[test]
    fn package_filenames_cannot_escape_the_cache() {
        assert!(validate_package_filename("hello", "hello-1.0-1-x86_64.pkg.tar.zst").is_ok());
        assert!(validate_package_filename("hello", "../hello-1.0-1-x86_64.pkg.tar.zst").is_err());
        assert!(validate_package_filename("hello", "sub/hello-1.0-1-x86_64.pkg.tar.zst").is_err());
        assert!(validate_package_filename("hello", ".hidden.pkg.tar.zst").is_err());
        assert!(validate_package_filename("hello", "hello-1.0-1-x86_64.tar.zst").is_err());
        assert!(validate_package_filename("hello", "").is_err());
    }

    #[test]
    fn suffix_helper_keeps_the_directory() {
        let staged = with_suffix(Path::new("/tmp/db/core.db"), ".part");
        assert_eq!(staged, PathBuf::from("/tmp/db/core.db.part"));
        let signature = with_suffix(Path::new("/tmp/db/core.db"), ".sig");
        assert_eq!(signature, PathBuf::from("/tmp/db/core.db.sig"));
    }

    #[test]
    fn sigcheck_policy_is_explicit() {
        assert!(SigCheck::Required.requires_signature());
        assert!(!SigCheck::Optional.requires_signature());
        assert!(!SigCheck::Skip.requires_signature());
    }

    #[test]
    fn unknown_library_reports_not_available() {
        let dir = tempfile::tempdir().unwrap();
        let error = AlpmFetch::with_library(dir.path(), "/nonexistent/libalpm.so")
            .err()
            .expect("a missing library must fail");
        assert!(matches!(error, AlpmFetchError::NotAvailable { .. }));
    }

    #[test]
    fn repository_names_cannot_contain_separators() {
        let dir = tempfile::tempdir().unwrap();
        // Constructing the fetcher needs libalpm; skip when the host lacks it.
        let Ok(fetcher) = AlpmFetch::new(dir.path()) else {
            println!("skip: libalpm unavailable on this host");
            return;
        };
        assert!(fetcher.with_repo("extra").is_ok());

        let dir = tempfile::tempdir().unwrap();
        let Ok(fetcher) = AlpmFetch::new(dir.path()) else {
            println!("skip: libalpm unavailable on this host");
            return;
        };
        assert!(matches!(
            fetcher.with_repo("../evil"),
            Err(AlpmFetchError::InvalidArgument { .. })
        ));
    }
}
