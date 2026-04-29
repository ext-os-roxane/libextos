//! Package ingestion pipeline (M3.5 — Hash & Commit to CAS).
//!
//! Orchestrates the full pipeline:
//! 1. Extract archive → staging (M3.2 / plugin EXTRACT)
//! 2. Parse metadata → identity (M3.4 / plugin PARSE)
//! 3. Translate deps → DependencySpec (M4 / plugin TRANSLATE)
//! 4. Scan ELF binaries → capabilities (M3.3)
//! 5. Hash content → commit to CAS objects (M3.5)
//! 6. Create refs symlinks

use std::fs;
use std::path::Path;

use crate::cas::CasRepository;
use crate::elf_scan;
use crate::error::ExtosError;
use crate::extract::{self, ArchiveKind, ExtractedPackage};
use crate::manifest::{Capabilities, PackageIdentity};
use crate::rosetta::PluginCapability;
use crate::rosetta::registry::RosettaRegistry;
use crate::types::PackageFormat;

/// Result of a successful ingestion.
#[derive(Debug)]
pub struct IngestResult {
    /// The CAS object hash (algo-prefixed)
    pub hash: String,
    /// The origin namespace used for refs
    pub origin: String,
    /// The package name
    pub name: String,
    /// The package version
    pub version: String,
    /// Auto-discovered capabilities
    pub capabilities: Capabilities,
    /// Whether a Rosetta plugin was used for metadata translation
    pub rosetta_translated: bool,
}

/// Ingest a package archive into the CAS repository (legacy, no plugin).
///
/// Full pipeline: extract → scan → manifest stub → hash → commit → refs.
pub fn ingest_package(
    repo: &CasRepository,
    archive_path: &Path,
    origin: &str,
) -> Result<IngestResult, ExtosError> {
    ingest_package_with_rosetta(repo, archive_path, origin, None)
}

/// Ingest a package archive with optional Rosetta plugin dispatch.
///
/// If a plugin is provided and supports the required capabilities,
/// the plugin handles metadata parsing, dependency translation, and
/// optionally extraction. Otherwise falls back to built-in logic.
pub fn ingest_package_with_rosetta(
    repo: &CasRepository,
    archive_path: &Path,
    origin: &str,
    registry: Option<&RosettaRegistry>,
) -> Result<IngestResult, ExtosError> {
    // Create temporary staging directory alongside the CAS
    let staging_dir = repo.root.join("_staging");
    let pkg_staging = staging_dir.join(
        archive_path
            .file_stem()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string(),
    );
    fs::create_dir_all(&pkg_staging)?;

    // Look up plugin for this origin
    let plugin = registry.and_then(|r| r.get(origin));
    let mut rosetta_translated = false;

    // Step 1: Extract (plugin EXTRACT or built-in M3.2)
    let extracted = if let Some(ref p) = plugin {
        if p.capabilities().contains(PluginCapability::EXTRACT) {
            let metadata_dir = pkg_staging.join("metadata");
            let content_dir = pkg_staging.join("content");
            fs::create_dir_all(&metadata_dir)?;
            fs::create_dir_all(&content_dir)?;
            p.extract(archive_path, &pkg_staging)?;
            // Normalize ownership after plugin extraction
            crate::extract::normalize_ownership_if_root(&content_dir)?;
            ExtractedPackage {
                staging_dir: pkg_staging.clone(),
                metadata_dir,
                content_dir,
                kind: ArchiveKind::detect(archive_path).unwrap_or(ArchiveKind::PkgTarZst),
            }
        } else {
            extract::extract_package(archive_path, &pkg_staging)?
        }
    } else {
        extract::extract_package(archive_path, &pkg_staging)?
    };

    // Step 2: Parse metadata → identity (plugin PARSE or built-in)
    let (identity, manifest_nix) = if let Some(ref p) = plugin {
        if p.capabilities().contains(PluginCapability::PARSE) {
            // Use plugin to generate the full manifest.nix
            let manifest_nix = p.parse_metadata(&extracted.metadata_dir)?;
            rosetta_translated = true;

            // Parse identity from the generated manifest
            match crate::config::parse_nix(&manifest_nix) {
                Ok(nix_val) => {
                    match crate::manifest::PackageManifest::from_nix(&nix_val) {
                        Ok(manifest) => (manifest.identity.clone(), manifest_nix),
                        Err(_) => {
                            // Plugin manifest didn't parse — fall back
                            let identity = parse_identity_from_metadata(&extracted, origin)?;
                            let capabilities = elf_scan::scan_capabilities(&extracted.content_dir)?;
                            let stub = generate_stub_manifest(&identity, &capabilities, &extracted);
                            (identity, format_manifest_nix(&stub))
                        }
                    }
                }
                Err(_) => {
                    let identity = parse_identity_from_metadata(&extracted, origin)?;
                    let capabilities = elf_scan::scan_capabilities(&extracted.content_dir)?;
                    let stub = generate_stub_manifest(&identity, &capabilities, &extracted);
                    (identity, format_manifest_nix(&stub))
                }
            }
        } else {
            // No PARSE capability — use built-in
            let identity = parse_identity_from_metadata(&extracted, origin)?;
            let capabilities = elf_scan::scan_capabilities(&extracted.content_dir)?;
            let stub = generate_stub_manifest(&identity, &capabilities, &extracted);
            (identity, format_manifest_nix(&stub))
        }
    } else {
        // No plugin — use built-in stub
        let identity = parse_identity_from_metadata(&extracted, origin)?;
        let capabilities = elf_scan::scan_capabilities(&extracted.content_dir)?;
        let stub = generate_stub_manifest(&identity, &capabilities, &extracted);
        (identity, format_manifest_nix(&stub))
    };

    // Step 3: ELF scan (always — supplements plugin output)
    let capabilities = elf_scan::scan_capabilities(&extracted.content_dir)?;

    // Step 4: Write manifest to staging
    fs::write(extracted.metadata_dir.join("manifest.nix"), &manifest_nix)?;

    // Step 5: Hash & commit content tree to CAS (M3.5)
    let hash = repo.store_directory(&extracted.content_dir)?;
    repo.write_manifest(&hash, &manifest_nix)?;

    // Step 6: Create refs
    repo.create_ref(origin, &identity.name, &identity.version, &hash)?;
    repo.update_current(origin, &identity.name, &identity.version)?;

    // Cleanup staging
    let _ = fs::remove_dir_all(&pkg_staging);

    Ok(IngestResult {
        hash,
        origin: origin.to_string(),
        name: identity.name,
        version: identity.version,
        capabilities,
        rosetta_translated,
    })
}

/// Ingest a `.pkt.tar.xz` package (which already contains a `manifest.nix`).
///
/// For native ExtOS archives, we trust the included manifest rather than
/// generating a stub.
pub fn ingest_native_package(
    repo: &CasRepository,
    archive_path: &Path,
) -> Result<IngestResult, ExtosError> {
    let staging_dir = repo.root.join("_staging");
    let pkg_staging = staging_dir.join(
        archive_path
            .file_stem()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string(),
    );
    fs::create_dir_all(&pkg_staging)?;

    let extracted = extract::extract_package(archive_path, &pkg_staging)?;

    // Read the included manifest.nix
    let manifest_path = extracted.metadata_dir.join("manifest.nix");
    let manifest_nix = if manifest_path.exists() {
        fs::read_to_string(&manifest_path)?
    } else {
        return Err(ExtosError::ConfigParse {
            path: archive_path.to_string_lossy().into(),
            line: 0,
            message: "native .pkt.tar.xz missing metadata/manifest.nix".into(),
        });
    };

    // Parse the manifest for identity
    let nix_val = crate::config::parse_nix(&manifest_nix)?;
    let manifest = crate::manifest::PackageManifest::from_nix(&nix_val)?;

    let hash = repo.store_directory(&extracted.content_dir)?;
    repo.write_manifest(&hash, &manifest_nix)?;

    let origin = &manifest.identity.origin;
    let name = &manifest.identity.name;
    let version = &manifest.identity.version;

    repo.create_ref(origin, name, version, &hash)?;
    repo.update_current(origin, name, version)?;

    let capabilities = manifest.capabilities.clone();
    let result = IngestResult {
        hash,
        origin: origin.clone(),
        name: name.clone(),
        version: version.clone(),
        capabilities,
        rosetta_translated: false, // native packages already have a manifest
    };

    let _ = fs::remove_dir_all(&pkg_staging);
    Ok(result)
}

// ─── Identity Extraction ────────────────────────────────────────

/// Parse package identity from upstream metadata files.
///
/// This is a best-effort parser — full Rosetta translation happens in M4.
fn parse_identity_from_metadata(
    extracted: &ExtractedPackage,
    origin: &str,
) -> Result<PackageIdentity, ExtosError> {
    match extracted.kind {
        ArchiveKind::PkgTarZst | ArchiveKind::PkgTarXz => {
            parse_pkginfo_identity(&extracted.metadata_dir, origin)
        }
        ArchiveKind::Deb => parse_deb_control_identity(&extracted.metadata_dir, origin),
        ArchiveKind::Apk => parse_pkginfo_identity(&extracted.metadata_dir, origin),
        ArchiveKind::PktTarXz => {
            // Native packages have a full manifest — shouldn't reach here
            Ok(PackageIdentity {
                origin: origin.to_string(),
                name: "unknown".to_string(),
                version: "0.0.0".to_string(),
                aliases: vec![],
            })
        }
    }
}

/// Parse identity from a pacman/Alpine .PKGINFO (stored as `metadata/PKGINFO`).
fn parse_pkginfo_identity(
    metadata_dir: &Path,
    origin: &str,
) -> Result<PackageIdentity, ExtosError> {
    let pkginfo_path = metadata_dir.join("PKGINFO");
    if !pkginfo_path.exists() {
        return Ok(PackageIdentity {
            origin: origin.to_string(),
            name: "unknown".to_string(),
            version: "0.0.0".to_string(),
            aliases: vec![],
        });
    }

    let content = fs::read_to_string(&pkginfo_path)?;
    let mut name = String::from("unknown");
    let mut version = String::from("0.0.0");
    let mut aliases = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if let Some(val) = line.strip_prefix("pkgname = ") {
            name = val.trim().to_string();
        } else if let Some(val) = line.strip_prefix("pkgver = ") {
            version = val.trim().to_string();
        } else if let Some(val) = line.strip_prefix("provides = ") {
            // Strip version constraint: "foo=1.0" → "foo"
            let alias = val.split('=').next().unwrap_or(val).trim().to_string();
            if alias != name {
                aliases.push(alias);
            }
        } else if let Some(val) = line.strip_prefix("replaces = ") {
            let alias = val.split('=').next().unwrap_or(val).trim().to_string();
            if alias != name && !aliases.contains(&alias) {
                aliases.push(alias);
            }
        }
    }

    Ok(PackageIdentity {
        origin: origin.to_string(),
        name,
        version,
        aliases,
    })
}

/// Parse identity from a Debian `control` file.
fn parse_deb_control_identity(
    metadata_dir: &Path,
    origin: &str,
) -> Result<PackageIdentity, ExtosError> {
    let control_path = metadata_dir.join("control");
    if !control_path.exists() {
        return Ok(PackageIdentity {
            origin: origin.to_string(),
            name: "unknown".to_string(),
            version: "0.0.0".to_string(),
            aliases: vec![],
        });
    }

    let content = fs::read_to_string(&control_path)?;
    let mut name = String::from("unknown");
    let mut version = String::from("0.0.0");
    let mut aliases = Vec::new();

    for line in content.lines() {
        if let Some(val) = line.strip_prefix("Package: ") {
            name = val.trim().to_string();
        } else if let Some(val) = line.strip_prefix("Version: ") {
            version = val.trim().to_string();
        } else if let Some(val) = line.strip_prefix("Provides: ") {
            for p in val.split(',') {
                let alias = p.split('(').next().unwrap_or(p).trim().to_string();
                if !alias.is_empty() && alias != name && !aliases.contains(&alias) {
                    aliases.push(alias);
                }
            }
        } else if let Some(val) = line.strip_prefix("Replaces: ") {
            for p in val.split(',') {
                let alias = p.split('(').next().unwrap_or(p).trim().to_string();
                if !alias.is_empty() && alias != name && !aliases.contains(&alias) {
                    aliases.push(alias);
                }
            }
        }
    }

    Ok(PackageIdentity {
        origin: origin.to_string(),
        name,
        version,
        aliases,
    })
}

// ─── Stub Manifest Generator (M3.4 Placeholder) ────────────────

/// Generate a stub `manifest.nix` with identity + auto-discovered capabilities.
///
/// The full manifest (with dependency translation) is deferred to M4 (Rosetta).
fn generate_stub_manifest(
    identity: &PackageIdentity,
    capabilities: &Capabilities,
    _extracted: &ExtractedPackage,
) -> StubManifest {
    StubManifest {
        identity: identity.clone(),
        format: PackageFormat::ExtractedTree,
        capabilities: capabilities.clone(),
    }
}

struct StubManifest {
    identity: PackageIdentity,
    format: PackageFormat,
    capabilities: Capabilities,
}

/// Format a stub manifest as Nix syntax.
fn format_manifest_nix(manifest: &StubManifest) -> String {
    let mut out = String::from("{\n");

    // Identity block
    out.push_str("  identity = {\n");
    out.push_str(&format!(
        "    origin = \"{}\";\n",
        manifest.identity.origin
    ));
    out.push_str(&format!("    name = \"{}\";\n", manifest.identity.name));
    out.push_str(&format!(
        "    version = \"{}\";\n",
        manifest.identity.version
    ));
    if !manifest.identity.aliases.is_empty() {
        let aliases: Vec<String> = manifest
            .identity
            .aliases
            .iter()
            .map(|a| format!("\"{}\"", a))
            .collect();
        out.push_str(&format!("    aliases = [ {} ];\n", aliases.join(" ")));
    }
    out.push_str("  };\n\n");

    // Format
    out.push_str(&format!("  format = \"{}\";\n\n", manifest.format));

    // Capabilities
    out.push_str("  capabilities = {\n");
    if !manifest.capabilities.binaries.is_empty() {
        let bins: Vec<String> = manifest
            .capabilities
            .binaries
            .iter()
            .map(|b| format!("\"{}\"", b))
            .collect();
        out.push_str(&format!("    binaries = [ {} ];\n", bins.join(" ")));
    }
    if !manifest.capabilities.libraries.is_empty() {
        let libs: Vec<String> = manifest
            .capabilities
            .libraries
            .iter()
            .map(|l| format!("\"{}\"", l))
            .collect();
        out.push_str(&format!("    libraries = [ {} ];\n", libs.join(" ")));
    }
    if !manifest.capabilities.resources.is_empty() {
        let res: Vec<String> = manifest
            .capabilities
            .resources
            .iter()
            .map(|r| format!("\"{}\"", r))
            .collect();
        out.push_str(&format!("    resources = [ {} ];\n", res.join(" ")));
    }
    out.push_str("  };\n\n");

    // Dependencies placeholder
    out.push_str("  # TODO(M4): Rosetta will populate requires/suggests/buildRequires\n");
    out.push_str("  requires = [];\n");

    out.push_str("}\n");
    out
}

// ─── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::HashAlgorithm;

    #[test]
    fn test_parse_pkginfo_identity() {
        let tmpdir = tempfile::tempdir().unwrap();
        let meta = tmpdir.path();
        fs::write(
            meta.join("PKGINFO"),
            "pkgname = htop\npkgver = 3.3.0-1\nprovides = htop-legacy\nreplaces = htop-osx\n",
        )
        .unwrap();

        let id = parse_pkginfo_identity(meta, "archlinux").unwrap();
        assert_eq!(id.name, "htop");
        assert_eq!(id.version, "3.3.0-1");
        assert_eq!(id.origin, "archlinux");
        assert!(id.aliases.contains(&"htop-legacy".to_string()));
        assert!(id.aliases.contains(&"htop-osx".to_string()));
    }

    #[test]
    fn test_parse_deb_control_identity() {
        let tmpdir = tempfile::tempdir().unwrap();
        let meta = tmpdir.path();
        fs::write(
            meta.join("control"),
            "Package: vim\nVersion: 9.1.0-1\nProvides: editor, vi\nReplaces: vim-tiny\n",
        )
        .unwrap();

        let id = parse_deb_control_identity(meta, "debian").unwrap();
        assert_eq!(id.name, "vim");
        assert_eq!(id.version, "9.1.0-1");
        assert_eq!(id.origin, "debian");
        assert!(id.aliases.contains(&"editor".to_string()));
        assert!(id.aliases.contains(&"vi".to_string()));
        assert!(id.aliases.contains(&"vim-tiny".to_string()));
    }

    #[test]
    fn test_stub_manifest_generation() {
        let identity = PackageIdentity {
            origin: "archlinux".into(),
            name: "htop".into(),
            version: "3.3.0-1".into(),
            aliases: vec!["htop-legacy".into()],
        };
        let caps = Capabilities {
            binaries: vec!["htop".into()],
            libraries: vec![],
            virtual_caps: vec![],
            resources: vec!["/usr/share/applications/htop.desktop".into()],
        };
        let stub = StubManifest {
            identity,
            format: PackageFormat::ExtractedTree,
            capabilities: caps,
        };
        let nix = format_manifest_nix(&stub);

        assert!(nix.contains("name = \"htop\""));
        assert!(nix.contains("origin = \"archlinux\""));
        assert!(nix.contains("version = \"3.3.0-1\""));
        assert!(nix.contains("aliases = [ \"htop-legacy\" ]"));
        assert!(nix.contains("binaries = [ \"htop\" ]"));
        assert!(nix.contains("resources = [ \"/usr/share/applications/htop.desktop\" ]"));
        assert!(nix.contains("requires = []"));
    }

    #[test]
    fn test_full_ingest_pipeline() {
        use std::process::Command;

        // Create a mock .pkt.tar.xz archive with proper manifest
        let tmpdir = tempfile::tempdir().unwrap();
        let archive_src = tmpdir.path().join("pkg_src");
        fs::create_dir_all(archive_src.join("metadata")).unwrap();
        fs::create_dir_all(archive_src.join("content/usr/bin")).unwrap();
        fs::write(
            archive_src.join("metadata/manifest.nix"),
            r#"{
                identity = {
                    origin = "scratch";
                    name = "hello";
                    version = "1.0.0";
                };
                format = "extracted-tree";
                capabilities = {
                    binaries = [ "hello" ];
                };
                requires = [];
            }"#,
        )
        .unwrap();
        fs::write(
            archive_src.join("content/usr/bin/hello"),
            "#!/bin/sh\necho hello",
        )
        .unwrap();

        let archive_path = tmpdir.path().join("hello-1.0.0.pkt.tar.xz");
        let status = Command::new("tar")
            .args(["--xz", "-cf"])
            .arg(&archive_path)
            .arg("-C")
            .arg(&archive_src)
            .args(["metadata", "content"])
            .status()
            .unwrap();
        assert!(status.success());

        // Create a CAS repo and ingest
        let cas_dir = tmpdir.path().join("repository");
        let repo =
            CasRepository::open(&cas_dir, HashAlgorithm::Blake3).unwrap();
        let result = ingest_native_package(&repo, &archive_path).unwrap();

        assert_eq!(result.origin, "scratch");
        assert_eq!(result.name, "hello");
        assert_eq!(result.version, "1.0.0");
        assert!(!result.hash.is_empty());
        assert!(result.hash.starts_with("BLAKE3-"));

        // Verify the object exists in CAS
        assert!(repo.object_path(&result.hash).exists());

        // Verify refs were created
        let resolved = repo
            .resolve_ref("scratch", "hello", "1.0.0")
            .unwrap();
        assert_eq!(resolved, result.hash);

        let current = repo
            .resolve_ref("scratch", "hello", "current")
            .unwrap();
        assert_eq!(current, result.hash);
    }
}
