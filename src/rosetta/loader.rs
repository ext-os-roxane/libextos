//! Dynamic plugin loader using `dlopen`/`dlsym`.
//!
//! Scans plugin directories for `.so` files, loads them, validates
//! their exported symbols, and constructs `LoadedPlugin` instances.

use std::path::{Path, PathBuf};
use std::{env, fs};

use crate::error::ExtosError;
use crate::rosetta::ffi::{LoadedPlugin, RosettaVTable};

/// Default plugin search paths (in priority order).
const PLUGIN_SEARCH_PATHS: &[&str] = &[
    "/config/rosetta/plugins",
    "./config/rosetta/plugins",
];

/// Discover all `.so` plugin files from the standard search paths.
///
/// Checks:
/// 1. `$ROSETTA_PLUGIN_DIR` environment variable (if set)
/// 2. `/config/rosetta/plugins/*.so` (production)
/// 3. `./config/rosetta/plugins/*.so` (development)
pub fn discover_plugins() -> Vec<PathBuf> {
    let mut so_files = Vec::new();

    // Check env override first
    if let Ok(dir) = env::var("ROSETTA_PLUGIN_DIR") {
        collect_so_files(Path::new(&dir), &mut so_files);
    }

    // Standard paths
    for path in PLUGIN_SEARCH_PATHS {
        collect_so_files(Path::new(path), &mut so_files);
    }

    so_files
}

/// Discover plugins in a specific directory.
pub fn discover_plugins_in(dir: &Path) -> Vec<PathBuf> {
    let mut so_files = Vec::new();
    collect_so_files(dir, &mut so_files);
    so_files
}

fn collect_so_files(dir: &Path, out: &mut Vec<PathBuf>) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                if let Some(name) = path.file_name() {
                    let name = name.to_string_lossy();
                    if name.ends_with(".so") && name.starts_with("librosetta-") {
                        out.push(path);
                    }
                }
            }
        }
    }
}

/// Load a single `.so` plugin file.
///
/// Validates that:
/// 1. The required symbols (`rosetta_origin_name`, `rosetta_api_version`,
///    `rosetta_capabilities`) are present
/// 2. The API version matches [`ROSETTA_API_VERSION`](crate::rosetta::ROSETTA_API_VERSION)
/// 3. Optional symbols are loaded based on capability flags
///
/// # Safety
/// This function calls `dlopen` on the given path. The `.so` file must
/// be trusted — it runs arbitrary code in-process.
pub fn load_plugin(path: &Path) -> Result<LoadedPlugin, ExtosError> {
    let path_str = path.to_string_lossy().to_string();

    // Load the shared library
    let lib = unsafe {
        libloading::Library::new(path).map_err(|e| ExtosError::RosettaPlugin {
            plugin: path_str.clone(),
            message: format!("dlopen failed: {e}"),
        })?
    };

    // Load required symbols
    let origin_name = load_symbol(&lib, &path_str, "rosetta_origin_name")?;
    let api_version = load_symbol(&lib, &path_str, "rosetta_api_version")?;
    let capabilities = load_symbol(&lib, &path_str, "rosetta_capabilities")?;

    // Load optional symbols (don't fail if missing)
    let parse_metadata = try_load_symbol(&lib, "rosetta_parse_metadata");
    let translate_deps = try_load_symbol(&lib, "rosetta_translate_deps");
    let fetch_package = try_load_symbol(&lib, "rosetta_fetch_package");
    let extract = try_load_symbol(&lib, "rosetta_extract");
    let sync_db = try_load_symbol(&lib, "rosetta_sync_db");
    let phantom_write = try_load_symbol(&lib, "rosetta_phantom_write");
    let cleanup = try_load_symbol(&lib, "rosetta_cleanup");

    let vtable = RosettaVTable {
        origin_name,
        api_version,
        capabilities,
        parse_metadata,
        translate_deps,
        fetch_package,
        extract,
        sync_db,
        phantom_write,
        cleanup,
    };

    unsafe { LoadedPlugin::new(lib, vtable) }
}

/// Load a required symbol from a library, returning an error if not found.
///
/// # Safety
/// The caller must ensure `T` matches the actual symbol's type.
fn load_symbol<T: Copy>(
    lib: &libloading::Library,
    path: &str,
    name: &str,
) -> Result<T, ExtosError> {
    unsafe {
        let sym: libloading::Symbol<T> = lib
            .get(name.as_bytes())
            .map_err(|e| ExtosError::RosettaPlugin {
                plugin: path.to_string(),
                message: format!("missing required symbol '{name}': {e}"),
            })?;
        Ok(*sym)
    }
}

/// Try to load an optional symbol; returns `None` if not found.
fn try_load_symbol<T: Copy>(lib: &libloading::Library, name: &str) -> Option<T> {
    unsafe {
        let sym: libloading::Symbol<T> = lib.get(name.as_bytes()).ok()?;
        Some(*sym)
    }
}

// ─── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_discover_empty_dir() {
        let tmpdir = tempfile::tempdir().unwrap();
        let plugins = discover_plugins_in(tmpdir.path());
        assert!(plugins.is_empty());
    }

    #[test]
    fn test_discover_filters_so_prefix() {
        let tmpdir = tempfile::tempdir().unwrap();

        // Should be found
        fs::write(tmpdir.path().join("librosetta-arch.so"), "").unwrap();
        // Should NOT be found (wrong prefix)
        fs::write(tmpdir.path().join("libfoo.so"), "").unwrap();
        // Should NOT be found (wrong extension)
        fs::write(tmpdir.path().join("librosetta-debian.txt"), "").unwrap();

        let plugins = discover_plugins_in(tmpdir.path());
        assert_eq!(plugins.len(), 1);
        assert!(plugins[0].file_name().unwrap().to_string_lossy().contains("arch"));
    }

    #[test]
    fn test_load_nonexistent_fails() {
        let result = load_plugin(Path::new("/nonexistent/librosetta-test.so"));
        assert!(result.is_err());
    }
}
