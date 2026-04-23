//! Dependency specification types.
//!
//! Models the three-tier resolution hierarchy:
//! - **Tier 1 (Strict Pin):** Exact origin + name + version
//! - **Tier 2 (Loose Ecosystem):** Origin + name, any compatible version
//! - **Tier 3 (Capability / Duck-Typing):** SONAME, binary, resource, or virtual

use std::fmt;

use serde::{Deserialize, Serialize};

/// A dependency requirement in the ExtOS DAG.
///
/// Represents exactly one edge in the dependency graph.
/// The collision engine resolves these in order: Tier 1 → Tier 2 → Tier 3.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DependencySpec {
    /// Tier 1: Exact origin + name + version pin.
    StrictPin {
        origin: String,
        name: String,
        version: String,
    },

    /// Tier 2: Origin + name, but any compatible version.
    LooseEcosystem {
        origin: String,
        name: String,
        version_constraint: Option<String>,
    },

    /// Tier 3: Capability duck-typing.
    Capability(CapabilityRequest),
}

impl fmt::Display for DependencySpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DependencySpec::StrictPin {
                origin,
                name,
                version,
            } => write!(f, "{origin}/{name}={version}"),
            DependencySpec::LooseEcosystem {
                origin,
                name,
                version_constraint,
            } => match version_constraint {
                Some(vc) => write!(f, "{origin}/{name} ({vc})"),
                None => write!(f, "{origin}/{name}"),
            },
            DependencySpec::Capability(cap) => write!(f, "{cap}"),
        }
    }
}

/// A Tier 3 capability request — what does the package *need*?
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CapabilityRequest {
    /// Requires a shared library SONAME (e.g., `libssl.so.3`)
    Provides(String),

    /// Requires an executable binary in `$PATH` (e.g., `python3`)
    Executable {
        name: String,
        version: Option<String>,
    },

    /// Requires a filesystem resource (e.g., `/usr/share/hwdata/pci.ids`)
    Resource(String),

    /// Requires a virtual capability (e.g., `system-monitor`, `modules/6.8.2-zen`)
    Virtual(String),
}

impl fmt::Display for CapabilityRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CapabilityRequest::Provides(soname) => write!(f, "provides:{soname}"),
            CapabilityRequest::Executable { name, version } => match version {
                Some(v) => write!(f, "executable:{name} ({v})"),
                None => write!(f, "executable:{name}"),
            },
            CapabilityRequest::Resource(path) => write!(f, "resource:{path}"),
            CapabilityRequest::Virtual(cap) => write!(f, "virtual:{cap}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_display_strict_pin() {
        let dep = DependencySpec::StrictPin {
            origin: "archlinux".into(),
            name: "glibc".into(),
            version: "2.38".into(),
        };
        assert_eq!(dep.to_string(), "archlinux/glibc=2.38");
    }

    #[test]
    fn test_display_loose() {
        let dep = DependencySpec::LooseEcosystem {
            origin: "debian".into(),
            name: "openssl".into(),
            version_constraint: Some(">=3.0".into()),
        };
        assert_eq!(dep.to_string(), "debian/openssl (>=3.0)");
    }

    #[test]
    fn test_display_capability() {
        let dep = DependencySpec::Capability(CapabilityRequest::Provides("libssl.so.3".into()));
        assert_eq!(dep.to_string(), "provides:libssl.so.3");
    }

    #[test]
    fn test_display_executable() {
        let dep = DependencySpec::Capability(CapabilityRequest::Executable {
            name: "python3".into(),
            version: Some(">=3.11".into()),
        });
        assert_eq!(dep.to_string(), "executable:python3 (>=3.11)");
    }
}
