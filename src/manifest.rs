//! Package manifest types and parsing.
//!
//! Represents the ExtOS `manifest.nix` stored at
//! `/repository/objects/<hash>/metadata/manifest.nix`.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::config::NixValue;
use crate::dependency::{CapabilityRequest, DependencySpec};
use crate::error::ExtosError;
use crate::types::PackageFormat;

/// A fully parsed ExtOS package manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageManifest {
    /// Core package identity
    pub identity: PackageIdentity,
    /// Package archive/payload format (transport)
    pub archive: Option<crate::types::ArchiveFormat>,
    /// Package installation format (layout in CAS)
    pub format: PackageFormat,
    /// Runtime dependencies (Tier 1/2/3)
    pub requires: Vec<DependencySpec>,
    /// Optional dependencies (user-activated)
    pub suggests: Vec<SuggestGroup>,
    /// Build-time dependencies (for source compilations)
    pub build_requires: Vec<DependencySpec>,
    /// What this package provides to the system
    pub capabilities: Capabilities,
    /// Security declarations (file capabilities, MAC profiles)
    pub security: Option<SecurityBlock>,
}

/// The identity block — who this package is and what it replaces.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageIdentity {
    pub origin: String,
    pub name: String,
    pub version: String,
    /// Packages this one replaces (from upstream `replaces` + `provides`)
    pub aliases: Vec<String>,
}

/// What this package advertises to the ExtOS DAG.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Capabilities {
    /// Executable binaries (e.g., `["htop", "htop-vim"]`)
    pub binaries: Vec<String>,
    /// Shared library SONAMEs (e.g., `["libssl.so.3", "libcrypto.so.3"]`)
    pub libraries: Vec<String>,
    /// Virtual capabilities (e.g., `["system-monitor", "modules/6.8.2-extos-zen"]`)
    pub virtual_caps: Vec<String>,
    /// Shared resources (e.g., `["/usr/share/applications/htop.desktop"]`)
    pub resources: Vec<String>,
}

/// A named group of optional dependencies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuggestGroup {
    pub name: String,
    pub description: Option<String>,
    pub deps: Vec<DependencySpec>,
}

/// Security declarations for the weaver to apply.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityBlock {
    /// File capabilities: path → list of caps (e.g., `"bin/ping" → ["CAP_NET_RAW"]`)
    pub capabilities: HashMap<String, Vec<String>>,
    /// MAC profile references (AppArmor/SELinux)
    pub mac_profile: Option<String>,
}

// ─── Parsing from NixValue ──────────────────────────────────────

impl PackageManifest {
    /// Parse a `PackageManifest` from a parsed `.nix` `NixValue`.
    pub fn from_nix(val: &NixValue) -> Result<Self, ExtosError> {
        let identity = parse_identity(val)?;
        let format = val
            .get_str("format")
            .unwrap_or("extracted-tree")
            .parse::<PackageFormat>()
            .map_err(|e| ExtosError::ConfigParse {
                path: String::new(),
                line: 0,
                message: e,
            })?;

        let requires = parse_dep_list(val, "requires")?;
        let build_requires = parse_dep_list(val, "buildRequires")?;
        let suggests = parse_suggests(val)?;
        let capabilities = parse_capabilities(val)?;
        let archive = val
            .get_str("archive")
            .map(|s| s.parse::<crate::types::ArchiveFormat>())
            .transpose()
            .map_err(|e| ExtosError::ConfigParse {
                path: String::new(),
                line: 0,
                message: e,
            })?;

        Ok(PackageManifest {
            identity,
            archive,
            format,
            requires,
            suggests,
            build_requires,
            capabilities,
            security: None,
        })
    }
}

fn parse_identity(val: &NixValue) -> Result<PackageIdentity, ExtosError> {
    // Support both flat and nested identity blocks:
    // Flat:   { name = "foo"; origin = "archlinux"; version = "1.0"; }
    // Nested: { identity = { name = "foo"; ... }; }
    let id_root = val.get_path("identity").unwrap_or(val);

    let origin = id_root
        .get_str("origin")
        .unwrap_or("scratch")
        .to_string();
    let name = id_root
        .get_str("name")
        .ok_or_else(|| ExtosError::ConfigParse {
            path: String::new(),
            line: 0,
            message: "manifest missing 'name' field".into(),
        })?
        .to_string();
    let version = id_root
        .get_str("version")
        .unwrap_or("0.0.0")
        .to_string();
    let aliases = id_root
        .get_str_list("aliases")
        .unwrap_or_default()
        .into_iter()
        .map(|s| s.to_string())
        .collect();

    Ok(PackageIdentity {
        origin,
        name,
        version,
        aliases,
    })
}

fn parse_dep_list(val: &NixValue, key: &str) -> Result<Vec<DependencySpec>, ExtosError> {
    let list = match val.get_path(key) {
        Some(v) => match v.as_list() {
            Some(l) => l,
            None => return Ok(vec![]),
        },
        None => return Ok(vec![]),
    };

    list.iter().map(parse_single_dep).collect()
}

fn parse_single_dep(val: &NixValue) -> Result<DependencySpec, ExtosError> {
    // Check the type of dependency by which keys are present
    if let Some(provides) = val.get_str("provides") {
        return Ok(DependencySpec::Capability(CapabilityRequest::Provides(
            provides.to_string(),
        )));
    }
    if let Some(executable) = val.get_str("executable") {
        let version = val.get_str("version").map(|s| s.to_string());
        return Ok(DependencySpec::Capability(CapabilityRequest::Executable {
            name: executable.to_string(),
            version,
        }));
    }
    if let Some(resource) = val.get_str("resource") {
        return Ok(DependencySpec::Capability(CapabilityRequest::Resource(
            resource.to_string(),
        )));
    }
    if let Some(feature) = val.get_str("feature") {
        return Ok(DependencySpec::Capability(CapabilityRequest::Virtual(
            feature.to_string(),
        )));
    }

    // If it has origin + name, it's a Tier 1/2 dep
    if let Some(name) = val.get_str("name") {
        let origin = val.get_str("origin").unwrap_or("virtual").to_string();
        let version = val.get_str("version").map(|s| s.to_string());

        // If version is an exact pin (no >= prefix), it's Tier 1
        if let Some(ref v) = version {
            if !v.starts_with(">=") && !v.starts_with("<=") && v != "current" {
                return Ok(DependencySpec::StrictPin {
                    origin,
                    name: name.to_string(),
                    version: v.clone(),
                });
            }
        }
        return Ok(DependencySpec::LooseEcosystem {
            origin,
            name: name.to_string(),
            version_constraint: version,
        });
    }

    Err(ExtosError::ConfigParse {
        path: String::new(),
        line: 0,
        message: format!("cannot parse dependency: {val:?}"),
    })
}

fn parse_suggests(val: &NixValue) -> Result<Vec<SuggestGroup>, ExtosError> {
    let suggests_map = match val.get_path("suggests") {
        Some(NixValue::AttrSet(map)) => map,
        _ => return Ok(vec![]),
    };

    let mut groups = Vec::new();
    for (name, group_val) in suggests_map {
        let deps = match group_val.as_list() {
            Some(list) => list.iter().map(parse_single_dep).collect::<Result<Vec<_>, _>>()?,
            None => vec![],
        };
        groups.push(SuggestGroup {
            name: name.clone(),
            description: None,
            deps,
        });
    }
    Ok(groups)
}

fn parse_capabilities(val: &NixValue) -> Result<Capabilities, ExtosError> {
    let caps_root = match val.get_path("capabilities") {
        Some(v) => v,
        None => return Ok(Capabilities::default()),
    };

    Ok(Capabilities {
        binaries: caps_root
            .get_str_list("binaries")
            .unwrap_or_default()
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
        libraries: caps_root
            .get_str_list("libraries")
            .unwrap_or_default()
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
        virtual_caps: caps_root
            .get_str_list("virtual")
            .unwrap_or_default()
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
        resources: caps_root
            .get_str_list("resources")
            .unwrap_or_default()
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
    })
}

// ─── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse_nix;

    #[test]
    fn test_parse_manifest_flat() {
        let input = r#"{
            name = "hyprland";
            version = "0.39.1";
            origin = "archlinux";
            format = "extracted-tree";
            requires = [
                { provides = "wayland-server"; }
                { name = "mesa"; origin = "archlinux"; }
            ];
        }"#;
        let nix = parse_nix(input).unwrap();
        let m = PackageManifest::from_nix(&nix).unwrap();
        assert_eq!(m.identity.name, "hyprland");
        assert_eq!(m.identity.origin, "archlinux");
        assert_eq!(m.format, PackageFormat::ExtractedTree);
        assert_eq!(m.requires.len(), 2);
    }

    #[test]
    fn test_parse_manifest_nested_identity() {
        let input = r#"{
            identity = {
                origin = "archlinux";
                name = "htop";
                version = "3.3.0-1";
                aliases = [ "htop-legacy" ];
            };
            format = "extracted-tree";
            capabilities = {
                binaries = [ "htop" ];
                virtual = [ "system-monitor" ];
                resources = [ "/usr/share/applications/htop.desktop" ];
            };
            requires = [
                { provides = "libncursesw.so.6"; }
                { provides = "libc.so.6"; }
            ];
            suggests = {
                lsof-support = [
                    { executable = "lsof"; }
                ];
            };
        }"#;
        let nix = parse_nix(input).unwrap();
        let m = PackageManifest::from_nix(&nix).unwrap();
        assert_eq!(m.identity.name, "htop");
        assert_eq!(m.identity.aliases, vec!["htop-legacy"]);
        assert_eq!(m.capabilities.binaries, vec!["htop"]);
        assert_eq!(m.capabilities.virtual_caps, vec!["system-monitor"]);
        assert_eq!(m.requires.len(), 2);
        assert_eq!(m.suggests.len(), 1);
        assert_eq!(m.suggests[0].name, "lsof-support");
    }

    #[test]
    fn test_parse_loop_image_format() {
        let input = r#"{
            name = "system";
            version = "14.0";
            origin = "android";
            format = "loop-image";
            requires = [
                { origin = "android"; name = "vendor"; version = "14.0"; }
            ];
        }"#;
        let nix = parse_nix(input).unwrap();
        let m = PackageManifest::from_nix(&nix).unwrap();
        assert_eq!(m.format, PackageFormat::LoopImage);
        assert_eq!(m.requires.len(), 1);
        match &m.requires[0] {
            DependencySpec::StrictPin {
                origin,
                name,
                version,
            } => {
                assert_eq!(origin, "android");
                assert_eq!(name, "vendor");
                assert_eq!(version, "14.0");
            }
            other => panic!("expected StrictPin, got: {other:?}"),
        }
    }

    #[test]
    fn test_parse_wrapper_format() {
        let input = r#"{
            name = "numpy";
            version = "1.26.0";
            origin = "pypi";
            format = "wrapper";
            requires = [
                { executable = "python3"; version = ">=3.11"; }
            ];
        }"#;
        let nix = parse_nix(input).unwrap();
        let m = PackageManifest::from_nix(&nix).unwrap();
        assert_eq!(m.format, PackageFormat::Wrapper);
        match &m.requires[0] {
            DependencySpec::Capability(CapabilityRequest::Executable { name, version }) => {
                assert_eq!(name, "python3");
                assert_eq!(version.as_deref(), Some(">=3.11"));
            }
            other => panic!("expected Capability::Executable, got: {other:?}"),
        }
    }

    #[test]
    fn test_parse_archive_format() {
        let input = r#"{
            name = "p7zip";
            version = "17.05";
            origin = "archlinux";
            format = "extracted-tree";
            archive = "pkt.tar.xz";
        }"#;
        let nix = parse_nix(input).unwrap();
        let m = PackageManifest::from_nix(&nix).unwrap();
        assert_eq!(m.archive, Some(crate::types::ArchiveFormat::PktTarXz));
    }
}
