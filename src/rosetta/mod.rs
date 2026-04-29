//! Rosetta Plugin Engine — Modular foreign origin support.
//!
//! Each foreign origin (Arch, Debian, Alpine, Void, RPM, etc.) is implemented
//! as a dynamically loadable shared object (`.so`) conforming to a stable C ABI
//! contract. Plugins handle the full lifecycle:
//!
//! - **Metadata parsing**: Upstream control files → `manifest.nix`
//! - **Dependency translation**: Native deps → ExtOS `DependencySpec`
//! - **Package fetching**: Download from upstream mirrors
//! - **Archive extraction**: Format-specific unpacking
//! - **Database sync**: Upstream package DB → local cache
//! - **PhantomDB writing**: Generate native PM database entries
//!
//! ## Plugin Discovery
//!
//! Plugins are discovered at runtime from:
//! 1. `/config/rosetta/plugins/*.so` (production)
//! 2. `./config/rosetta/plugins/*.so` (development)
//! 3. `ROSETTA_PLUGIN_DIR` environment variable
//!
//! ## C ABI Contract
//!
//! Every `.so` plugin must export these symbols:
//! ```c
//! const char* rosetta_origin_name();
//! uint32_t    rosetta_api_version();
//! uint32_t    rosetta_capabilities();
//! int rosetta_parse_metadata(const char*, char*, size_t, size_t*);
//! int rosetta_translate_deps(const char*, char*, size_t, size_t*);
//! int rosetta_fetch_package(const char*, const char*, const char*, const char*);
//! int rosetta_extract(const char*, const char*);
//! int rosetta_sync_db(const char*, const char*);
//! int rosetta_phantom_write(const char*, const char*);
//! void rosetta_cleanup();
//! ```

pub mod ffi;
pub mod loader;
pub mod registry;

use std::path::Path;

use crate::error::ExtosError;

/// Current Rosetta ABI version. Plugins must match this to be loaded.
pub const ROSETTA_API_VERSION: u32 = 1;

bitflags::bitflags! {
    /// Capability flags advertised by a plugin.
    ///
    /// A plugin may implement only a subset of the full contract.
    /// The loader checks these to know which functions are safe to call.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct PluginCapability: u32 {
        /// Can parse upstream metadata → manifest.nix
        const PARSE     = 0b0000_0001;
        /// Can translate native deps → ExtOS DependencySpec
        const TRANSLATE = 0b0000_0010;
        /// Can fetch packages from upstream mirrors
        const FETCH     = 0b0000_0100;
        /// Can extract archive formats
        const EXTRACT   = 0b0000_1000;
        /// Can sync upstream package databases
        const SYNC      = 0b0001_0000;
        /// Can write PhantomDB entries for the native PM
        const PHANTOM   = 0b0010_0000;
    }
}

/// High-level Rust trait wrapping a loaded Rosetta plugin.
///
/// This trait provides safe Rust methods around the raw C ABI.
/// Implementations may be:
/// - `LoadedPlugin` (backed by a real `.so` via dlopen)
/// - `BuiltinPlugin` (compiled into libextos for core origins)
/// - Mock implementations (for testing)
pub trait RosettaPlugin: Send + Sync {
    /// The canonical origin name (e.g., "archlinux", "debian").
    fn origin_name(&self) -> &str;

    /// API version this plugin was built against.
    fn api_version(&self) -> u32;

    /// Capability bitfield.
    fn capabilities(&self) -> PluginCapability;

    /// Parse upstream metadata into a manifest.nix string.
    ///
    /// `metadata_path` points to the extracted upstream control file
    /// (e.g., `staging/metadata/PKGINFO` for Arch).
    fn parse_metadata(&self, metadata_path: &Path) -> Result<String, ExtosError>;

    /// Translate native dependencies to ExtOS DependencySpec JSON array.
    ///
    /// Returns a JSON string: `[{"type":"provides","value":"libssl.so.3"}, ...]`
    fn translate_deps(&self, metadata_path: &Path) -> Result<String, ExtosError>;

    /// Fetch a package from upstream mirrors.
    ///
    /// Downloads the archive to `dest_path`.
    fn fetch_package(
        &self,
        pkg_name: &str,
        version: Option<&str>,
        mirror_url: &str,
        dest_path: &Path,
    ) -> Result<(), ExtosError>;

    /// Extract a package archive into a staging directory.
    ///
    /// Creates `staging_dir/{metadata/, content/}`.
    fn extract(&self, archive_path: &Path, staging_dir: &Path) -> Result<(), ExtosError>;

    /// Sync the upstream package database to a local cache directory.
    fn sync_db(&self, mirror_url: &str, cache_dir: &Path) -> Result<(), ExtosError>;

    /// Write a PhantomDB entry for the native package manager.
    ///
    /// `manifest_nix_path` points to the ExtOS manifest.
    /// `phantom_db_dir` is the native PM's database root
    /// (e.g., `/var/lib/pacman/local/`).
    fn phantom_write(
        &self,
        manifest_nix_path: &Path,
        phantom_db_dir: &Path,
    ) -> Result<(), ExtosError>;

    /// Optional cleanup hook called when the plugin is unloaded.
    fn cleanup(&self);
}

/// Check if a plugin supports a given capability.
pub fn has_capability(plugin: &dyn RosettaPlugin, cap: PluginCapability) -> bool {
    plugin.capabilities().contains(cap)
}
