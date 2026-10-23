//! Security hardening primitives (PLAN Phase 6).
//!
//! * [`filecaps`] — file capability parsing, `security.capability` xattr
//!   encoding and application (PLAN 6.1.2; the weave-side counterpart of the
//!   CAS sanitizer from PLAN 6.1.1).
//! * [`apparmor`] — AppArmor profile synthesis from a manifest
//!   `security.mac_profile` declaration (PLAN 6.2.1).
//! * [`selinux`] — SELinux context synthesis and labeling backends for woven
//!   files (PLAN 6.2.2).

pub mod apparmor;
pub mod filecaps;
pub mod selinux;

use std::fs;
use std::path::Path;

use crate::cas::CasRepository;
use crate::error::ExtosError;

/// Result of one [`apply_roof_security`] pass.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RoofSecurityReport {
    /// AppArmor profiles written under `<roof>/etc/apparmor.d/`
    /// (profile name = file name; PLAN 6.2.1).
    pub apparmor_profiles: Vec<String>,
    /// Why a declared profile was not written (typed synthesis failures).
    pub apparmor_skipped: Vec<String>,
    /// SELinux contexts actually written by the kernel backend (PLAN 6.2.2).
    pub selinux_applied: usize,
    /// Why SELinux labeling stopped for a package — one honest entry per
    /// package, not one per file (the kernel refusal is host-wide).
    pub selinux_skipped: Vec<String>,
}

/// A resolved package as the roof-security pass needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoofPackage {
    /// Provider label (`origin/name`) — matches weaver plan providers.
    pub label: String,
    /// Concrete CAS object hash of the package.
    pub hash: String,
}

/// Apply a woven roof's declared security (PLAN 6.1.2 / 6.2 glue).
///
/// For every package whose manifest carries a `security` block:
///
/// * `security.mac_profile` synthesizes an AppArmor profile
///   ([`apparmor::AppArmorProfile`]) and writes it byte-identically to
///   `<roof>/etc/apparmor.d/<profile>` (PLAN 6.2.1);
/// * the package's woven files are labeled via
///   [`selinux::label_path`] with the package-domain context (PLAN 6.2.2) —
///   a kernel refusal (SELinux disabled) is recorded once per package and
///   stops that package's pass, never the apply.
///
/// File capabilities are *not* handled here: they ride the weave plan itself
/// as [`crate::weaver::plan::PlanOp::FileCaps`] ops.
pub fn apply_roof_security(
    repo: &CasRepository,
    packages: &[RoofPackage],
    roof: &Path,
) -> Result<RoofSecurityReport, ExtosError> {
    let mut report = RoofSecurityReport::default();
    let apparmor_dir = roof.join("etc/apparmor.d");

    for pkg in packages {
        let label = &pkg.label;
        let Some(security) = crate::weaver::plan::load_security_block(repo, &pkg.hash)? else {
            continue;
        };

        if let Some(mac_profile) = &security.mac_profile {
            match apparmor::AppArmorProfile::from_security(
                mac_profile,
                &pkg_binaries(repo, &pkg.hash)?,
                &security,
            ) {
                Ok(profile) => {
                    fs::create_dir_all(&apparmor_dir)?;
                    fs::write(apparmor_dir.join(mac_profile), profile.render())?;
                    report.apparmor_profiles.push(mac_profile.clone());
                }
                Err(err) => report
                    .apparmor_skipped
                    .push(format!("{label}: {err}")),
            }
        }

        if security.mac_profile.is_some() {
            // Label the package's woven files with its domain context. The
            // first kernel refusal ends the package's pass with one honest
            // record — a host without SELinux would otherwise spam a skip
            // per file while meaning the same thing.
            let context = selinux::context_for(&label)
                .map_err(|err| ExtosError::Weave(err.to_string()))?;
            // `retrieve` yields the content tree itself.
            let content = repo.retrieve(&pkg.hash)?;
            let mut refused: Option<String> = None;
            for rel in content_files(&content)? {
                let target = roof.join(&rel);
                if !target.exists() {
                    continue; // suppressed by a collision — nothing to label
                }
                match selinux::label_path(&target, &context, selinux::LabelBackend::Kernel) {
                    Ok(_) => report.selinux_applied += 1,
                    Err(err) => {
                        refused = Some(format!("{label}: {err}"));
                        break;
                    }
                }
            }
            if let Some(reason) = refused {
                report.selinux_skipped.push(reason);
            }
        }
    }

    Ok(report)
}

/// The manifest-declared binaries of a stored package (profile attachments).
fn pkg_binaries(repo: &CasRepository, hash: &str) -> Result<Vec<String>, ExtosError> {
    let manifest_nix = repo.read_manifest(hash)?;
    let value = crate::config::parse_nix(&manifest_nix)?;
    let manifest = crate::manifest::PackageManifest::from_nix(&value)?;
    Ok(manifest.capabilities.binaries.clone())
}

/// Rootfs-relative paths of every regular file under a CAS content tree.
fn content_files(content: &Path) -> Result<Vec<String>, ExtosError> {
    let mut out = Vec::new();
    let mut stack = vec![content.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            if entry.metadata()?.is_dir() {
                stack.push(path);
                continue;
            }
            if entry.metadata()?.is_file() {
                out.push(
                    path.strip_prefix(content)
                        .map_err(|_| {
                            ExtosError::Weave(format!(
                                "content file escaped its CAS tree: {}",
                                path.display()
                            ))
                        })?
                        .display()
                        .to_string(),
                );
            }
        }
    }
    Ok(out)
}
