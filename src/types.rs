//! Core ExtOS type definitions.
//!
//! Enums and structs shared across `pkt`, `instanz`, and `libextos`.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// The origin ecosystem from which a package was sourced.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Origin {
    /// Arch Linux (pacman)
    Archlinux,
    /// Debian / Ubuntu (apt / dpkg)
    Debian,
    /// Alpine Linux (apk)
    Alpine,
    /// openSUSE / Fedora / CentOS (rpm / zypper / dnf)
    Suse,
    /// Void Linux (xbps)
    Void,
    /// NixOS / Nix (NAR / store)
    Nixos,
    /// Android AOSP/Treble
    Android,
    /// Python (PyPI)
    Pypi,
    /// Node.js (npm)
    Npm,
    /// Rust (crates.io)
    Crates,
    /// Go modules
    Go,
    /// Virtual meta-origin (alias layer)
    Virtual,
    /// Locally compiled / custom
    Scratch,
    /// P2P swarm-sourced
    ExtosSwarm,
    /// User-defined dynamic namespace
    Custom(String),
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Origin::Archlinux => write!(f, "archlinux"),
            Origin::Debian => write!(f, "debian"),
            Origin::Alpine => write!(f, "alpine"),
            Origin::Suse => write!(f, "suse"),
            Origin::Void => write!(f, "void"),
            Origin::Nixos => write!(f, "nixos"),
            Origin::Android => write!(f, "android"),
            Origin::Pypi => write!(f, "pypi"),
            Origin::Npm => write!(f, "npm"),
            Origin::Crates => write!(f, "crates"),
            Origin::Go => write!(f, "go"),
            Origin::Virtual => write!(f, "virtual"),
            Origin::Scratch => write!(f, "scratch"),
            Origin::ExtosSwarm => write!(f, "extos-swarm"),
            Origin::Custom(name) => write!(f, "{name}"),
        }
    }
}

impl FromStr for Origin {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "archlinux" | "arch" => Origin::Archlinux,
            "debian" | "ubuntu" => Origin::Debian,
            "alpine" => Origin::Alpine,
            "suse" | "opensuse" | "fedora" | "centos" | "rhel" => Origin::Suse,
            "void" | "voidlinux" => Origin::Void,
            "nixos" | "nix" => Origin::Nixos,
            "android" | "aosp" => Origin::Android,
            "pypi" | "pip" | "python" => Origin::Pypi,
            "npm" | "node" => Origin::Npm,
            "crates" | "cargo" | "rust" => Origin::Crates,
            "go" | "golang" => Origin::Go,
            "virtual" => Origin::Virtual,
            "scratch" | "local" => Origin::Scratch,
            "extos-swarm" | "swarm" => Origin::ExtosSwarm,
            other => Origin::Custom(other.to_string()),
        })
    }
}

/// How files are linked from CAS into the runlevel snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WeaveMode {
    /// Filesystem symlink (0 bytes, but breaks in chroot)
    Symlink,
    /// Btrfs reflink / CoW clone (looks real, zero disk cost on Btrfs)
    Reflink,
    /// Standard hardlink (shares inode, works everywhere)
    Hardlink,
}

impl fmt::Display for WeaveMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WeaveMode::Symlink => write!(f, "symlink"),
            WeaveMode::Reflink => write!(f, "reflink"),
            WeaveMode::Hardlink => write!(f, "hardlink"),
        }
    }
}

impl FromStr for WeaveMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "symlink" => Ok(WeaveMode::Symlink),
            "reflink" => Ok(WeaveMode::Reflink),
            "hardlink" => Ok(WeaveMode::Hardlink),
            other => Err(format!("unknown weave mode: '{other}'")),
        }
    }
}

/// Container isolation level (0 = maximum isolation, 4 = privileged).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum IsolationLevel {
    /// Level 0: Fully isolated. No network, no IPC, no host access.
    Isolated = 0,
    /// Level 1: CLI sandbox. PTY + CWD bind-mount.
    Cli = 1,
    /// Level 2: GUI sandbox. Wayland + PipeWire + DRI, no network.
    GuiSandbox = 2,
    /// Level 3: Networked. GUI + host network or veth bridge.
    Networked = 3,
    /// Level 4: Privileged. Host PID/Net, explicit capabilities.
    Privileged = 4,
}

impl fmt::Display for IsolationLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", *self as u8)
    }
}

impl TryFrom<i64> for IsolationLevel {
    type Error = String;

    fn try_from(v: i64) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(IsolationLevel::Isolated),
            1 => Ok(IsolationLevel::Cli),
            2 => Ok(IsolationLevel::GuiSandbox),
            3 => Ok(IsolationLevel::Networked),
            4 => Ok(IsolationLevel::Privileged),
            other => Err(format!("invalid isolation level: {other} (expected 0-4)")),
        }
    }
}

/// How the package payload is structured in the CAS.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PackageFormat {
    /// Standard extracted FHS tree (`content/usr/`, `content/lib/`, etc.)
    ExtractedTree,
    /// Raw filesystem image for loop-mounting (EROFS, ext4, SquashFS)
    LoopImage,
    /// Environment variable injection (PYTHONPATH, NODE_PATH, etc.)
    Wrapper,
}

impl fmt::Display for PackageFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PackageFormat::ExtractedTree => write!(f, "extracted-tree"),
            PackageFormat::LoopImage => write!(f, "loop-image"),
            PackageFormat::Wrapper => write!(f, "wrapper"),
        }
    }
}

impl FromStr for PackageFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "extracted-tree" => Ok(PackageFormat::ExtractedTree),
            "loop-image" => Ok(PackageFormat::LoopImage),
            "wrapper" => Ok(PackageFormat::Wrapper),
            other => Err(format!("unknown package format: '{other}'")),
        }
    }
}

/// Storage mode for the repository.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StorageMode {
    /// Content-Addressable Storage (default)
    Cas,
}

/// Hash algorithm used for CAS addressing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HashAlgorithm {
    Blake3,
    Sha256,
}

impl fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HashAlgorithm::Blake3 => write!(f, "blake3"),
            HashAlgorithm::Sha256 => write!(f, "sha256"),
        }
    }
}

impl FromStr for HashAlgorithm {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "blake3" => Ok(HashAlgorithm::Blake3),
            "sha256" | "sha-256" => Ok(HashAlgorithm::Sha256),
            other => Err(format!("unknown hash algorithm: '{other}'")),
        }
    }
}

impl Default for HashAlgorithm {
    fn default() -> Self {
        Self::Blake3
    }
}

impl Default for WeaveMode {
    fn default() -> Self {
        Self::Reflink
    }
}

impl Default for StorageMode {
    fn default() -> Self {
        Self::Cas
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_origin_roundtrip() {
        let cases = [
            ("archlinux", Origin::Archlinux),
            ("debian", Origin::Debian),
            ("alpine", Origin::Alpine),
            ("suse", Origin::Suse),
            ("void", Origin::Void),
            ("nixos", Origin::Nixos),
            ("android", Origin::Android),
            ("virtual", Origin::Virtual),
            ("scratch", Origin::Scratch),
            ("extos-swarm", Origin::ExtosSwarm),
        ];
        for (s, expected) in cases {
            let parsed: Origin = s.parse().unwrap();
            assert_eq!(parsed, expected);
            assert_eq!(parsed.to_string(), s);
        }
    }

    #[test]
    fn test_origin_aliases() {
        assert_eq!("arch".parse::<Origin>().unwrap(), Origin::Archlinux);
        assert_eq!("ubuntu".parse::<Origin>().unwrap(), Origin::Debian);
        assert_eq!("pip".parse::<Origin>().unwrap(), Origin::Pypi);
        assert_eq!("cargo".parse::<Origin>().unwrap(), Origin::Crates);
    }

    #[test]
    fn test_custom_origin() {
        let o: Origin = "shadichy-labs".parse().unwrap();
        assert_eq!(o, Origin::Custom("shadichy-labs".to_string()));
        assert_eq!(o.to_string(), "shadichy-labs");
    }

    #[test]
    fn test_weave_mode_roundtrip() {
        assert_eq!("symlink".parse::<WeaveMode>().unwrap(), WeaveMode::Symlink);
        assert_eq!("reflink".parse::<WeaveMode>().unwrap(), WeaveMode::Reflink);
        assert_eq!(WeaveMode::Hardlink.to_string(), "hardlink");
    }

    #[test]
    fn test_format_roundtrip() {
        assert_eq!(
            "extracted-tree".parse::<PackageFormat>().unwrap(),
            PackageFormat::ExtractedTree
        );
        assert_eq!(PackageFormat::LoopImage.to_string(), "loop-image");
    }

    #[test]
    fn test_isolation_level() {
        assert_eq!(IsolationLevel::try_from(0i64).unwrap(), IsolationLevel::Isolated);
        assert_eq!(IsolationLevel::try_from(4i64).unwrap(), IsolationLevel::Privileged);
        assert!(IsolationLevel::try_from(5i64).is_err());
    }
}
