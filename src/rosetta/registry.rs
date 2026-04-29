//! Plugin registry — maps origin names to loaded plugins.
//!
//! The registry is the primary interface for `pkt` and `instanz` to
//! access Rosetta functionality. It auto-discovers plugins at startup
//! and provides origin-based dispatch.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use crate::rosetta::loader;
use crate::rosetta::RosettaPlugin;

/// The global plugin registry.
///
/// Maps origin names (and aliases) to loaded plugin instances.
/// Plugins are reference-counted to support shared access across threads.
pub struct RosettaRegistry {
    /// Map from origin name/alias → plugin
    plugins: HashMap<String, Arc<dyn RosettaPlugin>>,
    /// Canonical origin names (no aliases)
    origins: Vec<String>,
}

impl RosettaRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            plugins: HashMap::new(),
            origins: Vec::new(),
        }
    }

    /// Create a registry pre-loaded with all discovered plugins.
    ///
    /// Scans standard paths and `$ROSETTA_PLUGIN_DIR` for `.so` files.
    /// Plugins that fail to load are logged as warnings but don't block startup.
    pub fn discover() -> Self {
        let mut registry = Self::new();
        let paths = loader::discover_plugins();

        for path in &paths {
            match loader::load_plugin(path) {
                Ok(plugin) => {
                    let name = plugin.origin_name().to_string();
                    tracing::info!(
                        "Loaded Rosetta plugin: {} (from {})",
                        name,
                        path.display()
                    );
                    registry.register(plugin);
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to load plugin {}: {}",
                        path.display(),
                        e
                    );
                }
            }
        }

        registry
    }

    /// Create a registry by scanning a specific directory.
    pub fn discover_in(dir: &Path) -> Self {
        let mut registry = Self::new();
        let paths = loader::discover_plugins_in(dir);

        for path in &paths {
            match loader::load_plugin(path) {
                Ok(plugin) => {
                    registry.register(plugin);
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to load plugin {}: {}",
                        path.display(),
                        e
                    );
                }
            }
        }

        registry
    }

    /// Register a plugin (any `RosettaPlugin` implementation).
    pub fn register<P: RosettaPlugin + 'static>(&mut self, plugin: P) {
        let name = plugin.origin_name().to_string();
        let arc: Arc<dyn RosettaPlugin> = Arc::new(plugin);

        if !self.origins.contains(&name) {
            self.origins.push(name.clone());
        }
        self.plugins.insert(name, arc);
    }

    /// Register a plugin with additional aliases.
    pub fn register_with_aliases<P: RosettaPlugin + 'static>(
        &mut self,
        plugin: P,
        aliases: &[&str],
    ) {
        let name = plugin.origin_name().to_string();
        let arc: Arc<dyn RosettaPlugin> = Arc::new(plugin);

        if !self.origins.contains(&name) {
            self.origins.push(name.clone());
        }
        self.plugins.insert(name, arc.clone());

        for alias in aliases {
            self.plugins.insert(alias.to_string(), arc.clone());
        }
    }

    /// Look up a plugin by origin name or alias.
    pub fn get(&self, origin: &str) -> Option<Arc<dyn RosettaPlugin>> {
        self.plugins.get(origin).cloned()
    }

    /// Check if a plugin is registered for an origin.
    pub fn has_origin(&self, origin: &str) -> bool {
        self.plugins.contains_key(origin)
    }

    /// List all canonical origin names (no aliases).
    pub fn list_origins(&self) -> &[String] {
        &self.origins
    }

    /// Total number of registered plugins (canonical origins only).
    pub fn plugin_count(&self) -> usize {
        self.origins.len()
    }
}

impl Default for RosettaRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ExtosError;
    use crate::rosetta::PluginCapability;

    /// A mock plugin for testing.
    struct MockPlugin {
        name: String,
    }

    impl MockPlugin {
        fn new(name: &str) -> Self {
            Self { name: name.to_string() }
        }
    }

    impl RosettaPlugin for MockPlugin {
        fn origin_name(&self) -> &str {
            &self.name
        }

        fn api_version(&self) -> u32 {
            crate::rosetta::ROSETTA_API_VERSION
        }

        fn capabilities(&self) -> PluginCapability {
            PluginCapability::PARSE | PluginCapability::TRANSLATE
        }

        fn parse_metadata(&self, _path: &Path) -> Result<String, ExtosError> {
            Ok(format!("{{ name = \"mock-{}\"; }}", self.name))
        }

        fn translate_deps(&self, _path: &Path) -> Result<String, ExtosError> {
            Ok("[]".to_string())
        }

        fn fetch_package(
            &self, _pkg: &str, _ver: Option<&str>, _mirror: &str, _dest: &Path,
        ) -> Result<(), ExtosError> {
            Err(ExtosError::RosettaPlugin {
                plugin: self.name.clone(),
                message: "FETCH not implemented".into(),
            })
        }

        fn extract(&self, _archive: &Path, _staging: &Path) -> Result<(), ExtosError> {
            Err(ExtosError::RosettaPlugin {
                plugin: self.name.clone(),
                message: "EXTRACT not implemented".into(),
            })
        }

        fn sync_db(&self, _mirror: &str, _cache: &Path) -> Result<(), ExtosError> {
            Err(ExtosError::RosettaPlugin {
                plugin: self.name.clone(),
                message: "SYNC not implemented".into(),
            })
        }

        fn phantom_write(&self, _manifest: &Path, _db: &Path) -> Result<(), ExtosError> {
            Err(ExtosError::RosettaPlugin {
                plugin: self.name.clone(),
                message: "PHANTOM not implemented".into(),
            })
        }

        fn cleanup(&self) {}
    }

    #[test]
    fn test_register_and_get() {
        let mut reg = RosettaRegistry::new();
        reg.register(MockPlugin::new("archlinux"));

        assert!(reg.has_origin("archlinux"));
        assert!(!reg.has_origin("debian"));
        assert_eq!(reg.plugin_count(), 1);

        let plugin = reg.get("archlinux").unwrap();
        assert_eq!(plugin.origin_name(), "archlinux");
    }

    #[test]
    fn test_register_with_aliases() {
        let mut reg = RosettaRegistry::new();
        reg.register_with_aliases(MockPlugin::new("archlinux"), &["arch", "pacman"]);

        assert!(reg.has_origin("archlinux"));
        assert!(reg.has_origin("arch"));
        assert!(reg.has_origin("pacman"));
        assert_eq!(reg.plugin_count(), 1); // Only 1 canonical origin
    }

    #[test]
    fn test_plugin_dispatch() {
        let mut reg = RosettaRegistry::new();
        reg.register(MockPlugin::new("testorigin"));

        let plugin = reg.get("testorigin").unwrap();
        let manifest = plugin.parse_metadata(Path::new("/dev/null")).unwrap();
        assert!(manifest.contains("mock-testorigin"));
    }

    #[test]
    fn test_capability_check() {
        let mut reg = RosettaRegistry::new();
        reg.register(MockPlugin::new("alpine"));

        let plugin = reg.get("alpine").unwrap();
        let caps = plugin.capabilities();
        assert!(caps.contains(PluginCapability::PARSE));
        assert!(caps.contains(PluginCapability::TRANSLATE));
        assert!(!caps.contains(PluginCapability::FETCH));
    }

    #[test]
    fn test_list_origins() {
        let mut reg = RosettaRegistry::new();
        reg.register(MockPlugin::new("archlinux"));
        reg.register(MockPlugin::new("debian"));
        reg.register(MockPlugin::new("alpine"));

        let origins = reg.list_origins();
        assert_eq!(origins.len(), 3);
        assert!(origins.contains(&"archlinux".to_string()));
        assert!(origins.contains(&"debian".to_string()));
        assert!(origins.contains(&"alpine".to_string()));
    }

    #[test]
    fn test_empty_registry() {
        let reg = RosettaRegistry::new();
        assert_eq!(reg.plugin_count(), 0);
        assert!(reg.get("anything").is_none());
    }
}
