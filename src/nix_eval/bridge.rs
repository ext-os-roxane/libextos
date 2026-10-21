//! Raw C ABI surface of the `libexpr-extos` bridge and its loader.
//!
//! Everything `unsafe` about talking to the Nix evaluator lives in this file:
//! [`NixEvaluator`] is the only type allowed to call into the shared library,
//! and it upholds these invariants:
//!
//! - the [`libloading::Library`] stays alive for the whole lifetime of the
//!   evaluator (it is held in an [`Arc`]), so no function pointer can dangle;
//! - every returned `char *` is released exactly once with the bridge's own
//!   `extos_nix_eval_free`, never with the CRT's `free`;
//! - the C string arguments are NUL-terminated and outlive the call;
//! - the bridge never throws across the boundary (it returns codes instead),
//!   so no C++ exception can unwind into Rust.

use std::ffi::{CStr, CString, c_char, c_int};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use libloading::Library;

use crate::error::ExtosError;

/// Environment variable pointing at the bridge shared library.
///
/// Documented default: unset. ExtOS never guesses a library path — a wrong
/// guess would silently pick up a distribution Nix instead of the fork.
pub const LIB_ENV: &str = "EXTOS_NIX_EVAL_LIB";

/// Conventional file name of the bridge, for diagnostics only.
pub const LIB_FILE_NAME: &str = "libnixexprc.so";

/// `extos_nix_eval_version()`.
type VersionFn = unsafe extern "C" fn() -> *const c_char;
/// `extos_nix_eval_config(path, opts, out_json, out_err)`.
type ConfigFn = unsafe extern "C" fn(*const c_char, *const c_char, *mut *mut c_char, *mut *mut c_char) -> c_int;
/// `extos_nix_eval_free(ptr)`.
type FreeFn = unsafe extern "C" fn(*mut c_char);

/// Bridge status codes (mirrors `extos_bridge.cc`).
mod status {
    pub const OK: i32 = 0;
    pub const EINVAL: i32 = 1;
    pub const ENOENT: i32 = 2;
    pub const EVAL: i32 = 3;
    pub const EINTERNAL: i32 = 4;
}

/// A loaded `libexpr-extos` bridge.
///
/// Cloning is cheap: the shared library is reference-counted, never unloaded
/// while an evaluator is alive.
#[derive(Clone)]
pub struct NixEvalLib {
    library: Arc<Library>,
    path: PathBuf,
    version_fn: VersionFn,
    config_fn: ConfigFn,
    free_fn: FreeFn,
}

impl std::fmt::Debug for NixEvalLib {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NixEvalLib").field("version", &self.version()).finish()
    }
}

impl NixEvalLib {
    /// `dlopen` the bridge at `path` and resolve its symbols.
    ///
    /// # Errors
    ///
    /// Returns [`ExtosError::DependencyUnresolvable`] when the file cannot be
    /// loaded or does not export the ExtOS bridge symbols (for example a
    /// stock, unpatched `libnixexprc.so`).
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ExtosError> {
        let path = path.as_ref();
        // SAFETY: `Library::new` runs the library's initialisers; the bridge
        // only registers Nix's static settings and does not fork or touch the
        // caller's memory. Allowing `RTLD_LAZY`'s default is fine because
        // every symbol we use is resolved below.
        let library = unsafe { Library::new(path) }.map_err(|e| {
            ExtosError::DependencyUnresolvable(format!(
                "nix_eval: cannot load bridge library {}: {e}",
                path.display()
            ))
        })?;

        // SAFETY: each symbol is requested with the exact signature the C
        // header declares (`src/libexpr-c/extos_bridge.h`). Copying the fn
        // pointer out of the `Symbol` borrow ends before `library` moves.
        let (version_fn, config_fn, free_fn) = unsafe {
            let version_fn = *library.get::<VersionFn>(b"extos_nix_eval_version\0").map_err(|e| {
                missing_symbol(path, "extos_nix_eval_version", &e)
            })?;
            let config_fn = *library.get::<ConfigFn>(b"extos_nix_eval_config\0").map_err(|e| {
                missing_symbol(path, "extos_nix_eval_config", &e)
            })?;
            let free_fn = *library.get::<FreeFn>(b"extos_nix_eval_free\0").map_err(|e| {
                missing_symbol(path, "extos_nix_eval_free", &e)
            })?;
            (version_fn, config_fn, free_fn)
        };

        Ok(Self {
            library: Arc::new(library),
            path: path.to_path_buf(),
            version_fn,
            config_fn,
            free_fn,
        })
    }

    /// Load the bridge from `EXTOS_NIX_EVAL_LIB`.
    ///
    /// # Errors
    ///
    /// [`ExtosError::DependencyUnresolvable`] when the variable is unset or
    /// the library cannot be loaded.
    pub fn open_from_env() -> Result<Self, ExtosError> {
        let path = std::env::var_os(LIB_ENV).map(PathBuf::from).ok_or_else(|| {
            ExtosError::DependencyUnresolvable(format!(
                "nix_eval: {LIB_ENV} is not set (expected a path to {LIB_FILE_NAME})"
            ))
        })?;
        Self::open(path)
    }

    /// Whether a bridge is configured and loadable, without keeping it.
    ///
    /// Used by callers that want to degrade gracefully (e.g. `instanz`) instead
    /// of failing hard when the evaluator has not been built.
    pub fn availability() -> bool {
        Self::open_from_env().is_ok()
    }

    /// Version reported by the bridge, e.g. `2.35.0-extos.1`.
    ///
    /// # Panics
    ///
    /// Never: a bridge that returns a non-UTF-8 or NULL version is reported as
    /// the empty string rather than panicking.
    pub fn version(&self) -> String {
        // SAFETY: the bridge returns a static, NUL-terminated string that is
        // valid for the lifetime of the library, which `self` keeps alive.
        let raw = unsafe { (self.version_fn)() };
        if raw.is_null() {
            return String::new();
        }
        // SAFETY: non-null, NUL-terminated, owned by the library.
        unsafe { CStr::from_ptr(raw) }.to_string_lossy().into_owned()
    }

    /// Borrow this bridge as an evaluator handle.
    pub fn evaluator(&self) -> NixEvaluator {
        NixEvaluator {
            _library: Arc::clone(&self.library),
            path: self.path.clone(),
            config_fn: self.config_fn,
            free_fn: self.free_fn,
            version: self.version(),
        }
    }

    /// Convenience wrapper around [`NixEvaluator::evaluate`].
    ///
    /// # Errors
    ///
    /// See [`NixEvaluator::evaluate`].
    pub fn evaluate(
        &self,
        config: &Path,
        opts: &serde_json::Value,
    ) -> Result<super::EvalDag, ExtosError> {
        self.evaluator().evaluate(config, opts)
    }
}

fn missing_symbol(path: &Path, symbol: &str, err: &libloading::Error) -> ExtosError {
    ExtosError::DependencyUnresolvable(format!(
        "nix_eval: {} does not export `{symbol}` ({err}); is it the ExtOS fork of libexpr?",
        path.display()
    ))
}

/// An evaluator handle bound to a loaded bridge.
pub struct NixEvaluator {
    /// Kept alive so the function pointers below stay valid. Never read
    /// directly, hence the underscore: dropping it would `dlclose()` the
    /// bridge underneath a live call.
    _library: Arc<Library>,
    /// Path the bridge was loaded from (diagnostics only).
    path: PathBuf,
    config_fn: ConfigFn,
    free_fn: FreeFn,
    version: String,
}

impl std::fmt::Debug for NixEvaluator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NixEvaluator").field("version", &self.version).finish()
    }
}

impl NixEvaluator {
    /// Bridge version this evaluator talks to.
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Path the shared library was loaded from.
    pub fn library_path(&self) -> &Path {
        &self.path
    }

    /// Evaluate the ExtOS system config at `config` and return the typed DAG.
    ///
    /// `opts` is forwarded verbatim as the bridge's `options_json`; pass
    /// `json!({})` for defaults. Recognised keys: `strict` (bool) and
    /// `store_uri` (string) — both **accepted for forward compatibility and
    /// currently inert**; the bridge resolves the store from
    /// `EXTOS_REPOSITORY`/the upstream environment and always forces values.
    /// The returned [`super::EvalDag`] reports the effective `store_dir` and
    /// `store_dir_source`.
    ///
    /// The bridge serializes evaluations behind a process-global mutex, so
    /// calling this concurrently from several threads is safe but sequential.
    ///
    /// # Errors
    ///
    /// - [`ExtosError::Io`] when the config file does not exist;
    /// - [`ExtosError::ConfigParse`] when Nix rejects the file (syntax or
    ///   evaluation error), carrying the evaluator's message;
    /// - [`ExtosError::Serialization`] when the bridge returns a document this
    ///   crate cannot type (ABI skew);
    /// - [`ExtosError::DependencyUnresolvable`] on a bridge-internal failure.
    pub fn evaluate(
        &self,
        config: &Path,
        opts: &serde_json::Value,
    ) -> Result<super::EvalDag, ExtosError> {
        let path_display = config.display().to_string();
        if !config.is_file() {
            return Err(ExtosError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("nix_eval: config file not found: {path_display}"),
            )));
        }

        let c_path = cstring(&path_display)?;
        let opts_text = if opts.is_null() || opts.as_object().is_some_and(|o| o.is_empty()) {
            None
        } else {
            Some(serde_json::to_string(opts).map_err(|e| {
                ExtosError::Serialization(format!("nix_eval: cannot encode options: {e}"))
            })?)
        };
        let c_opts = match &opts_text {
            Some(text) => Some(cstring(text)?),
            None => None,
        };

        let mut out_json: *mut c_char = std::ptr::null_mut();
        let mut out_err: *mut c_char = std::ptr::null_mut();

        // SAFETY: both pointers come from `CString` locals that outlive the
        // call (or are NULL, which the bridge accepts); the two output
        // pointers are valid, initialised, and uniquely borrowed for the call.
        let rc = unsafe {
            (self.config_fn)(
                c_path.as_ptr(),
                c_opts.as_ref().map_or(std::ptr::null(), |s| s.as_ptr()),
                &mut out_json,
                &mut out_err,
            )
        };

        let message = self.take_string(out_err);
        let document = self.take_string(out_json);

        match rc {
            status::OK => {
                let text = document.ok_or_else(|| {
                    ExtosError::Serialization(
                        "nix_eval: bridge returned success without a document".to_string(),
                    )
                })?;
                serde_json::from_str::<super::EvalDag>(&text).map_err(|e| {
                    ExtosError::Serialization(format!(
                        "nix_eval: malformed DAG from bridge (ABI skew?): {e}"
                    ))
                })
            }
            status::ENOENT => Err(ExtosError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                message.unwrap_or_else(|| format!("nix_eval: cannot read {path_display}")),
            ))),
            status::EINVAL => Err(ExtosError::ConfigParse {
                path: path_display,
                line: 0,
                message: message.unwrap_or_else(|| "invalid argument".to_string()),
            }),
            status::EVAL => Err(ExtosError::ConfigParse {
                path: path_display,
                line: 0,
                message: message.unwrap_or_else(|| "evaluation failed".to_string()),
            }),
            status::EINTERNAL => Err(ExtosError::DependencyUnresolvable(format!(
                "nix_eval: bridge internal error: {}",
                message.unwrap_or_else(|| "unknown".to_string())
            ))),
            other => Err(ExtosError::DependencyUnresolvable(format!(
                "nix_eval: unexpected bridge status {other}"
            ))),
        }
    }

    /// Copy and release a `char *` produced by the bridge.
    ///
    /// Returns `None` for NULL and for invalid UTF-8 (the message is
    /// diagnostics only, so lossy conversion is not worth a failure path).
    fn take_string(&self, ptr: *mut c_char) -> Option<String> {
        if ptr.is_null() {
            return None;
        }
        // SAFETY: `ptr` was allocated by the bridge with `malloc` and its
        // header documents that `extos_nix_eval_free` must release it.
        let text = unsafe { CStr::from_ptr(ptr) }.to_string_lossy().into_owned();
        // SAFETY: as above; freed exactly once, and `ptr` is not used again.
        unsafe { (self.free_fn)(ptr) };
        Some(text)
    }
}

fn cstring(s: &str) -> Result<CString, ExtosError> {
    CString::new(s).map_err(|_| ExtosError::ConfigParse {
        path: String::new(),
        line: 0,
        message: "nix_eval: argument contains an interior NUL byte".to_string(),
    })
}
