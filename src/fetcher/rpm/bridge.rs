//! Dynamic binding to the `librpm-extos` C bridge (PLAN 3.4.2).
//!
//! # Why a bridge instead of raw librpm FFI
//!
//! `librpm`'s header API is C++-implemented and its tag container
//! (`rpmtd`) is an opaque struct that must be driven through accessor calls;
//! `rpmReadPackageFile` additionally imports rpm's config/macro machinery.
//! Re-declaring that surface by hand in Rust would bake a guessed
//! `rpmTagData` layout into the crate and break on every soname bump. Instead
//! the fork carries one small, stable C file
//! (`inherited/librpm-extos/extos/extos-bridge.c`) whose ABI is deliberately
//! primitive:
//!
//! ```c
//! const char *rpm_extos_bridge_version(void);
//! int rpm_extos_read(const char *path, const char *keyfile,
//!                    char **out_json, char **out_err);
//! void rpm_extos_free(char *s);
//! ```
//!
//! This module `dlopen`s that library at run time (no build-time link, no
//! `build.rs` link flags) and parses the JSON it returns.
//!
//! # Discovery
//!
//! 1. `$EXTOS_RPM_BRIDGE` — explicit path or bare library name, honoured when
//!    non-empty. This is the hook tests and packagers use.
//! 2. `libextos-rpm-bridge.so` — handed to the platform loader, so
//!    `LD_LIBRARY_PATH` and `ld.so.cache` decide. No absolute path is baked
//!    into the crate.
//!
//! Absence of the bridge is a typed [`ExtosError::ConfigParse`]; callers that
//! only need metadata can fall back to
//! [`crate::rosetta::rpm::parse_binary_rpm`], but signature verification
//! genuinely requires librpm and therefore reports the missing library.

use std::ffi::{CStr, CString, OsStr};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use libloading::Library;
use serde::Deserialize;

use crate::error::ExtosError;

use super::Nvra;

/// Environment variable that overrides bridge discovery.
pub const BRIDGE_ENV: &str = "EXTOS_RPM_BRIDGE";

/// Library name handed to the platform loader when [`BRIDGE_ENV`] is unset.
pub const BRIDGE_LIB_NAME: &str = "libextos-rpm-bridge.so";

/// Bridge ABI this module understands.
pub const SUPPORTED_ABI: u32 = 1;

/// Bridge return code: success.
const RC_OK: i32 = 0;
/// Bridge return code: the file is not a readable RPM.
const RC_NOT_RPM: i32 = 2;

/// Raw signatures of the bridge ABI.
type VersionFn = unsafe extern "C" fn() -> *const libc::c_char;
type ReadFn = unsafe extern "C" fn(
    *const libc::c_char,
    *const libc::c_char,
    *mut *mut libc::c_char,
    *mut *mut libc::c_char,
) -> libc::c_int;
type FreeFn = unsafe extern "C" fn(*mut libc::c_char);

/// One requirement entry as serialized by the bridge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgeRequirement {
    /// Capability name (`glibc`, `/bin/sh`, `libc.so.6(GLIBC_2.38)(64bit)`).
    pub name: String,
    /// Version part of the dependency (`2.38`), empty when unversioned.
    pub version: String,
    /// Raw `RPMSENSE_*` flag word (`RPMSENSE_GREATER | RPMSENSE_EQUAL` = 12).
    pub flags: u32,
}

/// Header fields read through `librpm`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgeHeader {
    /// ABI string reported by the bridge (`extos-bridge/1`).
    pub bridge_abi: String,
    /// Name/epoch/version/release/arch of the package.
    pub nvra: Nvra,
    /// `SOURCERPM` when present (absent for source packages).
    pub source_rpm: Option<String>,
    /// Raw `rpmRC` from `rpmReadPackageFile`: `0` ok, `3` not trusted,
    /// `4` no key.
    pub rpmrc: i32,
    /// Symbolic `rpmRC` (`OK`, `NOTTRUSTED`, `NOKEY`, …).
    pub rpmrc_name: String,
    /// Result of `rpmReadConfigFiles` inside the bridge (`0` when rpm's
    /// rc/macro files were found; `-1` in a stripped build).
    pub config_rc: i32,
    /// `PROVIDENAME` capabilities, verbatim.
    pub provides: Vec<String>,
    /// `REQUIRENAME`/`REQUIREVERSION`/`REQUIREFLAGS` triples, verbatim.
    pub requires: Vec<BridgeRequirement>,
    /// Whether the header carries an OpenPGP signature entry (an unsigned
    /// package still verifies its digests, so `rpmrc == 0` alone does not mean
    /// "signed").
    pub signed: bool,
}

/// A loaded `librpm-extos` bridge.
///
/// The inner [`Library`] is kept alive for the lifetime of the value; the raw
/// function pointers stay valid exactly as long as it does.
pub struct RpmBridge {
    _lib: Library,
    read: ReadFn,
    free: FreeFn,
    version: VersionFn,
}

impl std::fmt::Debug for RpmBridge {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RpmBridge")
            .field("version", &self.version_string())
            .finish()
    }
}

impl RpmBridge {
    /// Load the bridge from an explicit path or library name.
    ///
    /// # Errors
    ///
    /// [`ExtosError::ConfigParse`] when the library cannot be loaded, is
    /// missing one of the ABI symbols, or reports an ABI this crate does not
    /// understand.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ExtosError> {
        let path = path.as_ref();
        // SAFETY: loading a shared object runs its initialisers; the bridge is
        // trusted code built from the ExtOS fork, and every symbol is checked
        // immediately afterwards.
        let lib = unsafe { Library::new(path) }.map_err(|err| {
            error(format!(
                "cannot load the librpm bridge from {}: {err}",
                path.display()
            ))
        })?;
        Self::from_library(lib, &path.display().to_string())
    }

    /// Load the bridge from `$EXTOS_RPM_BRIDGE`, else `libextos-rpm-bridge.so`
    /// via the platform loader.
    ///
    /// # Errors
    ///
    /// [`ExtosError::ConfigParse`] when no bridge can be loaded; the message
    /// names both discovery steps and the `extos-bridge.c` build recipe.
    pub fn discover() -> Result<Self, ExtosError> {
        if let Some(value) = std::env::var_os(BRIDGE_ENV)
            && !value.is_empty()
        {
            return Self::open(Path::new(&value));
        }
        let lib = unsafe { Library::new(OsStr::new(BRIDGE_LIB_NAME)) }.map_err(|err| {
            error(format!(
                "no librpm bridge available: set {BRIDGE_ENV} to the built \
                 libextos-rpm-bridge.so, or put it on LD_LIBRARY_PATH \
                 (loader said: {err}); build it with \
                 inherited/librpm-extos/extos/build-bridge.sh"
            ))
        })?;
        Self::from_library(lib, BRIDGE_LIB_NAME)
    }

    /// Wrap an already-loaded library, checking the ABI contract.
    fn from_library(lib: Library, origin: &str) -> Result<Self, ExtosError> {
        // SAFETY: the symbols are read only while `lib` is owned by the value
        // being constructed, and the pointers are copied out while it is still
        // alive.
        let (read, free, version) = unsafe {
            let read: ReadFn = *lib
                .get(b"rpm_extos_read\0")
                .map_err(|err| error(format!("{origin} is not an ExtOS rpm bridge: {err}")))?;
            let free: FreeFn = *lib
                .get(b"rpm_extos_free\0")
                .map_err(|err| error(format!("{origin} is missing rpm_extos_free: {err}")))?;
            let version: VersionFn = *lib.get(b"rpm_extos_bridge_version\0").map_err(|err| {
                error(format!(
                    "{origin} is missing rpm_extos_bridge_version: {err}"
                ))
            })?;
            (read, free, version)
        };

        let bridge = Self {
            _lib: lib,
            read,
            free,
            version,
        };
        let abi = bridge.abi()?;
        if abi != SUPPORTED_ABI {
            return Err(error(format!(
                "bridge ABI {abi} is not supported (this crate speaks ABI {SUPPORTED_ABI})"
            )));
        }
        Ok(bridge)
    }

    /// ABI string reported by the loaded bridge (`extos-bridge/1`).
    pub fn version_string(&self) -> String {
        // SAFETY: the bridge returns a NUL-terminated string with static
        // storage; it is copied before returning.
        let raw = unsafe { (self.version)() };
        if raw.is_null() {
            return String::new();
        }
        unsafe { CStr::from_ptr(raw) }
            .to_string_lossy()
            .into_owned()
    }

    /// Numeric ABI parsed out of [`RpmBridge::version_string`].
    ///
    /// # Errors
    ///
    /// [`ExtosError::ConfigParse`] when the reported string is malformed.
    pub fn abi(&self) -> Result<u32, ExtosError> {
        let reported = self.version_string();
        reported
            .rsplit('/')
            .next()
            .and_then(|tail| tail.trim().parse::<u32>().ok())
            .ok_or_else(|| {
                error(format!(
                    "bridge reported an unparseable ABI string '{reported}'"
                ))
            })
    }

    /// Read an RPM header, optionally verifying its signature against `keyfile`.
    ///
    /// A verification failure is *not* an error here: the returned
    /// [`BridgeHeader`] carries `rpmrc`/`rpmrc_name` so the caller decides
    /// whether `NOKEY` (no matching key) is acceptable. Unreadable files are
    /// errors.
    ///
    /// # Errors
    ///
    /// [`ExtosError::ConfigParse`] when the bridge cannot open or parse the
    /// file, or returns malformed JSON.
    pub fn read(&self, rpm: &Path, keyfile: Option<&Path>) -> Result<BridgeHeader, ExtosError> {
        let rpm_c = c_path(rpm)?;
        let key_c = match keyfile {
            Some(path) => Some(c_path(path)?),
            None => None,
        };
        let key_ptr = key_c
            .as_ref()
            .map(|value| value.as_ptr())
            .unwrap_or(std::ptr::null());

        let mut json: *mut libc::c_char = std::ptr::null_mut();
        let mut err: *mut libc::c_char = std::ptr::null_mut();

        // SAFETY: both output pointers are valid for writes; the path strings
        // are NUL-terminated and outlive the call.
        let rc = unsafe { (self.read)(rpm_c.as_ptr(), key_ptr, &mut json, &mut err) };

        let err_text = self.take_string(err);
        let json_text = self.take_string(json);

        if rc == RC_NOT_RPM {
            return Err(error(format!(
                "{} is not a readable RPM: {}",
                rpm.display(),
                err_text.unwrap_or_else(|| "no detail".to_string())
            )));
        }
        if rc != RC_OK && rc != 3 {
            return Err(error(format!(
                "librpm bridge failed on {} (rc {rc}): {}",
                rpm.display(),
                err_text.unwrap_or_else(|| "no detail".to_string())
            )));
        }
        if rc == 3 {
            tracing::warn!(
                "librpm reported a signature/digest problem for {}: {}",
                rpm.display(),
                err_text.clone().unwrap_or_else(|| "no detail".to_string())
            );
        }

        let Some(json_text) = json_text else {
            return Err(error(format!(
                "librpm bridge returned no JSON for {}",
                rpm.display()
            )));
        };
        Self::parse_json(&json_text)
    }

    /// Free a string allocated by the bridge and copy it into Rust memory.
    fn take_string(&self, ptr: *mut libc::c_char) -> Option<String> {
        if ptr.is_null() {
            return None;
        }
        // SAFETY: the pointer came from the bridge, which guarantees a
        // NUL-terminated allocation owned by the caller.
        let text = unsafe { CStr::from_ptr(ptr) }
            .to_string_lossy()
            .into_owned();
        // SAFETY: the allocation is handed back exactly once.
        unsafe { (self.free)(ptr) };
        Some(text)
    }

    /// Deserialize the bridge's JSON document.
    fn parse_json(json: &str) -> Result<BridgeHeader, ExtosError> {
        let raw: RawBridge = serde_json::from_str(json)
            .map_err(|err| error(format!("librpm bridge returned malformed JSON: {err}")))?;
        Ok(BridgeHeader {
            bridge_abi: raw.bridge,
            nvra: Nvra {
                name: raw.name,
                epoch: u32::try_from(raw.epoch).unwrap_or(u32::MAX),
                version: raw.version,
                release: raw.release,
                arch: raw.arch,
            },
            source_rpm: if raw.sourcerpm.is_empty() {
                None
            } else {
                Some(raw.sourcerpm)
            },
            rpmrc: raw.rpmrc,
            rpmrc_name: raw.rpmrc_name,
            config_rc: raw.config_rc,
            provides: raw.provides,
            requires: raw
                .requires
                .into_iter()
                .map(|entry| BridgeRequirement {
                    name: entry.name,
                    version: entry.version,
                    flags: entry.flags,
                })
                .collect(),
            signed: raw.signed,
        })
    }
}

/// Borrow a path as a NUL-terminated C string.
fn c_path(path: &Path) -> Result<CString, ExtosError> {
    CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        error(format!(
            "path {} contains an interior NUL byte",
            path.display()
        ))
    })
}

/// Build a typed bridge error.
fn error(message: impl Into<String>) -> ExtosError {
    ExtosError::ConfigParse {
        path: BRIDGE_ENV.to_string(),
        line: 0,
        message: message.into(),
    }
}

/// Wire shape of the bridge's JSON document.
#[derive(Debug, Deserialize)]
struct RawBridge {
    #[serde(default)]
    bridge: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    epoch: u64,
    #[serde(default)]
    version: String,
    #[serde(default)]
    release: String,
    #[serde(default)]
    arch: String,
    #[serde(default)]
    sourcerpm: String,
    #[serde(default)]
    rpmrc: i32,
    #[serde(default)]
    rpmrc_name: String,
    #[serde(default)]
    config_rc: i32,
    #[serde(default)]
    provides: Vec<String>,
    #[serde(default)]
    requires: Vec<RawRequirement>,
    #[serde(default)]
    signed: bool,
}

/// Wire shape of one requirement entry.
#[derive(Debug, Deserialize)]
struct RawRequirement {
    #[serde(default)]
    name: String,
    #[serde(default)]
    version: String,
    #[serde(default)]
    flags: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_bridge_is_a_typed_error() {
        let err = RpmBridge::open("/nonexistent/extos/libextos-rpm-bridge.so")
            .expect_err("a nonexistent bridge must not load");
        assert!(matches!(err, ExtosError::ConfigParse { .. }));
        assert!(err.to_string().contains("cannot load the librpm bridge"));
    }

    #[test]
    fn json_is_parsed_into_a_header() {
        let json = r#"{
            "bridge": "extos-bridge/1",
            "name": "hello", "epoch": 0, "version": "1.0", "release": "1",
            "arch": "x86_64", "sourcerpm": "hello-1.0-1.src.rpm",
            "rpmrc": 4, "rpmrc_name": "NOKEY", "config_rc": 0, "signed": true,
            "provides": ["hello", "hello(x86-64)"],
            "requires": [{"name": "glibc", "version": "2.38", "flags": 12}]
        }"#;
        let header = RpmBridge::parse_json(json).expect("valid bridge JSON");
        assert_eq!(header.nvra.name, "hello");
        assert_eq!(header.nvra.evr(), "0:1.0-1");
        assert_eq!(header.rpmrc, 4);
        assert_eq!(header.requires.len(), 1);
        assert_eq!(header.requires[0].flags, 12);
        assert_eq!(header.source_rpm.as_deref(), Some("hello-1.0-1.src.rpm"));
        assert!(header.signed);
    }

    #[test]
    fn empty_source_rpm_becomes_none() {
        let json = r#"{"name":"x","version":"1","release":"1","arch":"noarch"}"#;
        let header = RpmBridge::parse_json(json).expect("valid bridge JSON");
        assert!(header.source_rpm.is_none());
        assert!(!header.signed);
    }

    #[test]
    fn malformed_json_is_a_typed_error() {
        let err = RpmBridge::parse_json("{not json").expect_err("must reject");
        assert!(matches!(err, ExtosError::ConfigParse { .. }));
    }
}
