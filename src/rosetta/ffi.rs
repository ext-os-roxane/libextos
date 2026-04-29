//! C ABI FFI bindings for Rosetta plugins.
//!
//! Defines the raw function pointer vtable that `.so` plugins export,
//! and the `LoadedPlugin` wrapper that implements `RosettaPlugin` around it.

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::path::Path;

use crate::error::ExtosError;
use crate::rosetta::{PluginCapability, RosettaPlugin, ROSETTA_API_VERSION};

// ─── Raw C function pointer types ───────────────────────────────

type FnOriginName = unsafe extern "C" fn() -> *const c_char;
type FnApiVersion = unsafe extern "C" fn() -> u32;
type FnCapabilities = unsafe extern "C" fn() -> u32;
type FnParseMetadata = unsafe extern "C" fn(
    metadata_path: *const c_char,
    manifest_buf: *mut c_char,
    manifest_buflen: usize,
    manifest_written: *mut usize,
) -> c_int;
type FnTranslateDeps = unsafe extern "C" fn(
    metadata_path: *const c_char,
    deps_buf: *mut c_char,
    deps_buflen: usize,
    deps_written: *mut usize,
) -> c_int;
type FnFetchPackage = unsafe extern "C" fn(
    pkg_name: *const c_char,
    version: *const c_char, // nullable
    mirror_url: *const c_char,
    dest_path: *const c_char,
) -> c_int;
type FnExtract = unsafe extern "C" fn(
    archive_path: *const c_char,
    staging_dir: *const c_char,
) -> c_int;
type FnSyncDb = unsafe extern "C" fn(
    mirror_url: *const c_char,
    cache_dir: *const c_char,
) -> c_int;
type FnPhantomWrite = unsafe extern "C" fn(
    manifest_nix_path: *const c_char,
    phantom_db_dir: *const c_char,
) -> c_int;
type FnCleanup = unsafe extern "C" fn();

/// The raw vtable loaded from a `.so` plugin.
///
/// All function pointers are `Option` because a plugin may not
/// implement every capability (checked via `capabilities` bitfield).
pub struct RosettaVTable {
    // Required symbols
    pub origin_name: FnOriginName,
    pub api_version: FnApiVersion,
    pub capabilities: FnCapabilities,

    // Optional symbols (gated by capability flags)
    pub parse_metadata: Option<FnParseMetadata>,
    pub translate_deps: Option<FnTranslateDeps>,
    pub fetch_package: Option<FnFetchPackage>,
    pub extract: Option<FnExtract>,
    pub sync_db: Option<FnSyncDb>,
    pub phantom_write: Option<FnPhantomWrite>,
    pub cleanup: Option<FnCleanup>,
}

// Safety: The vtable contains function pointers into loaded .so libraries.
// The library handle is held alive by LoadedPlugin, ensuring the pointers remain valid.
unsafe impl Send for RosettaVTable {}
unsafe impl Sync for RosettaVTable {}

/// A loaded `.so` plugin wrapping a `RosettaVTable`.
///
/// Holds the `libloading::Library` handle to keep the `.so` mapped.
pub struct LoadedPlugin {
    /// Display name (cached from `rosetta_origin_name()`)
    name: String,
    /// The raw vtable
    vtable: RosettaVTable,
    /// Library handle (must outlive vtable)
    _lib: libloading::Library,
}

impl LoadedPlugin {
    /// Create a `LoadedPlugin` from a loaded library and its vtable.
    ///
    /// # Safety
    /// The vtable's function pointers must come from `lib`.
    pub(crate) unsafe fn new(
        lib: libloading::Library,
        vtable: RosettaVTable,
    ) -> Result<Self, ExtosError> {
        let name_ptr = unsafe { (vtable.origin_name)() };
        if name_ptr.is_null() {
            return Err(ExtosError::RosettaPlugin {
                plugin: "<unknown>".into(),
                message: "rosetta_origin_name() returned null".into(),
            });
        }
        let name = unsafe { CStr::from_ptr(name_ptr) }
            .to_string_lossy()
            .into_owned();

        let version = unsafe { (vtable.api_version)() };
        if version != ROSETTA_API_VERSION {
            return Err(ExtosError::RosettaPlugin {
                plugin: name,
                message: format!(
                    "API version mismatch: plugin={version}, host={ROSETTA_API_VERSION}"
                ),
            });
        }

        Ok(Self {
            name,
            vtable,
            _lib: lib,
        })
    }
}

/// Output buffer size for plugin string returns.
const BUF_SIZE: usize = 256 * 1024; // 256 KiB

impl RosettaPlugin for LoadedPlugin {
    fn origin_name(&self) -> &str {
        &self.name
    }

    fn api_version(&self) -> u32 {
        unsafe { (self.vtable.api_version)() }
    }

    fn capabilities(&self) -> PluginCapability {
        let raw = unsafe { (self.vtable.capabilities)() };
        PluginCapability::from_bits_truncate(raw)
    }

    fn parse_metadata(&self, metadata_path: &Path) -> Result<String, ExtosError> {
        let func = self.vtable.parse_metadata.ok_or_else(|| {
            ExtosError::RosettaPlugin {
                plugin: self.name.clone(),
                message: "plugin does not support PARSE capability".into(),
            }
        })?;

        let path_c = path_to_cstring(metadata_path)?;
        let mut buf = vec![0u8; BUF_SIZE];
        let mut written: usize = 0;

        let rc = unsafe {
            func(
                path_c.as_ptr(),
                buf.as_mut_ptr() as *mut c_char,
                BUF_SIZE,
                &mut written,
            )
        };

        if rc != 0 {
            return Err(ExtosError::RosettaPlugin {
                plugin: self.name.clone(),
                message: format!("parse_metadata failed with code {rc}"),
            });
        }

        buf.truncate(written);
        String::from_utf8(buf).map_err(|e| ExtosError::RosettaPlugin {
            plugin: self.name.clone(),
            message: format!("parse_metadata returned invalid UTF-8: {e}"),
        })
    }

    fn translate_deps(&self, metadata_path: &Path) -> Result<String, ExtosError> {
        let func = self.vtable.translate_deps.ok_or_else(|| {
            ExtosError::RosettaPlugin {
                plugin: self.name.clone(),
                message: "plugin does not support TRANSLATE capability".into(),
            }
        })?;

        let path_c = path_to_cstring(metadata_path)?;
        let mut buf = vec![0u8; BUF_SIZE];
        let mut written: usize = 0;

        let rc = unsafe {
            func(
                path_c.as_ptr(),
                buf.as_mut_ptr() as *mut c_char,
                BUF_SIZE,
                &mut written,
            )
        };

        if rc != 0 {
            return Err(ExtosError::RosettaPlugin {
                plugin: self.name.clone(),
                message: format!("translate_deps failed with code {rc}"),
            });
        }

        buf.truncate(written);
        String::from_utf8(buf).map_err(|e| ExtosError::RosettaPlugin {
            plugin: self.name.clone(),
            message: format!("translate_deps returned invalid UTF-8: {e}"),
        })
    }

    fn fetch_package(
        &self,
        pkg_name: &str,
        version: Option<&str>,
        mirror_url: &str,
        dest_path: &Path,
    ) -> Result<(), ExtosError> {
        let func = self.vtable.fetch_package.ok_or_else(|| {
            ExtosError::RosettaPlugin {
                plugin: self.name.clone(),
                message: "plugin does not support FETCH capability".into(),
            }
        })?;

        let name_c = CString::new(pkg_name).map_err(|_| ExtosError::RosettaPlugin {
            plugin: self.name.clone(),
            message: "pkg_name contains NUL byte".into(),
        })?;
        let version_c = version
            .map(|v| CString::new(v))
            .transpose()
            .map_err(|_| ExtosError::RosettaPlugin {
                plugin: self.name.clone(),
                message: "version contains NUL byte".into(),
            })?;
        let mirror_c = CString::new(mirror_url).map_err(|_| ExtosError::RosettaPlugin {
            plugin: self.name.clone(),
            message: "mirror_url contains NUL byte".into(),
        })?;
        let dest_c = path_to_cstring(dest_path)?;

        let rc = unsafe {
            func(
                name_c.as_ptr(),
                version_c
                    .as_ref()
                    .map(|v| v.as_ptr())
                    .unwrap_or(std::ptr::null()),
                mirror_c.as_ptr(),
                dest_c.as_ptr(),
            )
        };

        if rc != 0 {
            return Err(ExtosError::RosettaPlugin {
                plugin: self.name.clone(),
                message: format!("fetch_package failed with code {rc}"),
            });
        }
        Ok(())
    }

    fn extract(&self, archive_path: &Path, staging_dir: &Path) -> Result<(), ExtosError> {
        let func = self.vtable.extract.ok_or_else(|| {
            ExtosError::RosettaPlugin {
                plugin: self.name.clone(),
                message: "plugin does not support EXTRACT capability".into(),
            }
        })?;

        let archive_c = path_to_cstring(archive_path)?;
        let staging_c = path_to_cstring(staging_dir)?;

        let rc = unsafe { func(archive_c.as_ptr(), staging_c.as_ptr()) };
        if rc != 0 {
            return Err(ExtosError::RosettaPlugin {
                plugin: self.name.clone(),
                message: format!("extract failed with code {rc}"),
            });
        }
        Ok(())
    }

    fn sync_db(&self, mirror_url: &str, cache_dir: &Path) -> Result<(), ExtosError> {
        let func = self.vtable.sync_db.ok_or_else(|| {
            ExtosError::RosettaPlugin {
                plugin: self.name.clone(),
                message: "plugin does not support SYNC capability".into(),
            }
        })?;

        let mirror_c = CString::new(mirror_url).map_err(|_| ExtosError::RosettaPlugin {
            plugin: self.name.clone(),
            message: "mirror_url contains NUL byte".into(),
        })?;
        let cache_c = path_to_cstring(cache_dir)?;

        let rc = unsafe { func(mirror_c.as_ptr(), cache_c.as_ptr()) };
        if rc != 0 {
            return Err(ExtosError::RosettaPlugin {
                plugin: self.name.clone(),
                message: format!("sync_db failed with code {rc}"),
            });
        }
        Ok(())
    }

    fn phantom_write(
        &self,
        manifest_nix_path: &Path,
        phantom_db_dir: &Path,
    ) -> Result<(), ExtosError> {
        let func = self.vtable.phantom_write.ok_or_else(|| {
            ExtosError::RosettaPlugin {
                plugin: self.name.clone(),
                message: "plugin does not support PHANTOM capability".into(),
            }
        })?;

        let manifest_c = path_to_cstring(manifest_nix_path)?;
        let phantom_c = path_to_cstring(phantom_db_dir)?;

        let rc = unsafe { func(manifest_c.as_ptr(), phantom_c.as_ptr()) };
        if rc != 0 {
            return Err(ExtosError::RosettaPlugin {
                plugin: self.name.clone(),
                message: format!("phantom_write failed with code {rc}"),
            });
        }
        Ok(())
    }

    fn cleanup(&self) {
        if let Some(func) = self.vtable.cleanup {
            unsafe { func() };
        }
    }
}

impl Drop for LoadedPlugin {
    fn drop(&mut self) {
        self.cleanup();
    }
}

// ─── Helpers ────────────────────────────────────────────────────

fn path_to_cstring(path: &Path) -> Result<CString, ExtosError> {
    CString::new(path.to_string_lossy().as_bytes()).map_err(|_| ExtosError::RosettaPlugin {
        plugin: "<ffi>".into(),
        message: format!("path contains NUL byte: {}", path.display()),
    })
}
