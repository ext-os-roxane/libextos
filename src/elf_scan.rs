//! ELF binary scanner (M3.3).
//!
//! Scans an extracted FHS `content/` tree to auto-discover:
//! - Executable binaries (`content/usr/bin/*`, `content/usr/sbin/*`)
//! - Shared library SONAMEs (`content/usr/lib/*.so*`)
//! - Shared resources (`content/usr/share/**`)
//!
//! Uses `readelf -d` (or `objdump -p`) to extract SONAME and NEEDED tags
//! from ELF binaries.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::process::Command;

use crate::error::ExtosError;
use crate::manifest::Capabilities;

/// Scan an extracted content directory and auto-discover capabilities.
///
/// This populates `binaries`, `libraries`, and `resources` fields
/// of a [`Capabilities`] block.
pub fn scan_capabilities(content_dir: &Path) -> Result<Capabilities, ExtosError> {
    let mut binaries = BTreeSet::new();
    let mut libraries = BTreeSet::new();
    let mut resources = BTreeSet::new();

    // Scan for executables: usr/bin/*, usr/sbin/*, bin/*, sbin/*
    for bin_dir in &["usr/bin", "usr/sbin", "bin", "sbin"] {
        let dir = content_dir.join(bin_dir);
        if dir.is_dir() {
            for entry in fs::read_dir(&dir)? {
                let entry = entry?;
                if entry.path().is_file() {
                    binaries.insert(
                        entry.file_name().to_string_lossy().to_string(),
                    );
                }
            }
        }
    }

    // Scan for shared libraries: usr/lib/*.so*, lib/*.so*
    for lib_dir in &["usr/lib", "usr/lib64", "lib", "lib64"] {
        let dir = content_dir.join(lib_dir);
        if dir.is_dir() {
            scan_libraries(&dir, &mut libraries)?;
        }
    }

    // Scan for resources: usr/share/**
    let share_dir = content_dir.join("usr/share");
    if share_dir.is_dir() {
        scan_resources(&share_dir, &share_dir, &mut resources)?;
    }

    Ok(Capabilities {
        binaries: binaries.into_iter().collect(),
        libraries: libraries.into_iter().collect(),
        virtual_caps: vec![], // Filled by Rosetta (M4)
        resources: resources.into_iter().collect(),
    })
}

/// Extract the SONAME from an ELF shared object using `readelf -d`.
///
/// Returns `None` if the file is not a valid ELF or has no SONAME.
pub fn read_soname(elf_path: &Path) -> Option<String> {
    let output = Command::new("readelf")
        .args(["-d"])
        .arg(elf_path)
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    // Parse lines like: 0x000000000000000e (SONAME)  Library soname: [libssl.so.3]
    for line in stdout.lines() {
        if line.contains("(SONAME)") {
            if let Some(start) = line.find('[') {
                if let Some(end) = line.find(']') {
                    return Some(line[start + 1..end].to_string());
                }
            }
        }
    }
    None
}

/// Extract NEEDED dependencies from an ELF binary using `readelf -d`.
///
/// Returns the list of SONAME strings this binary depends on.
pub fn read_needed(elf_path: &Path) -> Vec<String> {
    let output = match Command::new("readelf")
        .args(["-d"])
        .arg(elf_path)
        .output()
    {
        Ok(o) if o.status.success() => o,
        _ => return vec![],
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut needed = Vec::new();
    for line in stdout.lines() {
        if line.contains("(NEEDED)") {
            if let Some(start) = line.find('[') {
                if let Some(end) = line.find(']') {
                    needed.push(line[start + 1..end].to_string());
                }
            }
        }
    }
    needed
}

/// Check if a file is an ELF binary by reading the magic bytes.
pub fn is_elf(path: &Path) -> bool {
    if let Ok(data) = fs::read(path) {
        data.len() >= 4 && &data[..4] == b"\x7fELF"
    } else {
        false
    }
}

// ─── Internal scanners ──────────────────────────────────────────

/// Scan a library directory for .so files and extract their SONAMEs.
fn scan_libraries(dir: &Path, libraries: &mut BTreeSet<String>) -> Result<(), ExtosError> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();

        if path.is_dir() {
            // Recurse into subdirectories (e.g., usr/lib/python3.12/)
            // but don't recurse deeper than 1 level for .so scanning
            continue;
        }

        if !name.contains(".so") {
            continue;
        }

        // Skip symlinks to avoid duplicate detection
        if path.is_symlink() {
            continue;
        }

        // Try readelf for the canonical SONAME
        if is_elf(&path) {
            if let Some(soname) = read_soname(&path) {
                libraries.insert(soname);
            } else {
                // Fallback: use filename (strip version suffixes)
                libraries.insert(extract_soname_from_filename(&name));
            }
        }
    }
    Ok(())
}

/// Scan a share directory for notable resources.
fn scan_resources(
    base: &Path,
    dir: &Path,
    resources: &mut BTreeSet<String>,
) -> Result<(), ExtosError> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            scan_resources(base, &path, resources)?;
        } else {
            let name = entry.file_name().to_string_lossy().to_string();
            // Only track "interesting" resources
            if name.ends_with(".desktop")
                || name.ends_with(".xml")
                || name.ends_with(".service")
                || name.ends_with(".timer")
                || name.ends_with(".socket")
                || name.ends_with(".conf")
                || name.ends_with(".rules")
                || name.ends_with(".policy")
            {
                let rel = path
                    .strip_prefix(base)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .to_string();
                resources.insert(format!("/usr/share/{rel}"));
            }
        }
    }
    Ok(())
}

/// Extract a SONAME-like string from a filename.
///
/// `libssl.so.3.0.2` → `libssl.so.3`
/// `libz.so.1.2.13`  → `libz.so.1`
fn extract_soname_from_filename(name: &str) -> String {
    // Find the first ".so" and keep the first version component after it
    if let Some(so_pos) = name.find(".so") {
        let after_so = &name[so_pos + 3..]; // skip ".so"
        if after_so.starts_with('.') {
            // Has version suffix: take the first number
            let version_part = &after_so[1..]; // skip the '.'
            if let Some(dot_pos) = version_part.find('.') {
                return format!("{}.so.{}", &name[..so_pos], &version_part[..dot_pos]);
            }
            return format!("{}.so.{version_part}", &name[..so_pos]);
        }
        return name[..so_pos + 3].to_string(); // just "libfoo.so"
    }
    name.to_string()
}

// ─── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_soname_extraction_from_filename() {
        assert_eq!(
            extract_soname_from_filename("libssl.so.3.0.2"),
            "libssl.so.3"
        );
        assert_eq!(
            extract_soname_from_filename("libz.so.1.2.13"),
            "libz.so.1"
        );
        assert_eq!(
            extract_soname_from_filename("libfoo.so"),
            "libfoo.so"
        );
        assert_eq!(
            extract_soname_from_filename("libncursesw.so.6"),
            "libncursesw.so.6"
        );
    }

    #[test]
    fn test_is_elf() {
        // A non-ELF file
        let tmpdir = tempfile::tempdir().unwrap();
        let script = tmpdir.path().join("hello.sh");
        fs::write(&script, "#!/bin/sh\necho hello").unwrap();
        assert!(!is_elf(&script));

        // Write ELF magic bytes
        let elf = tmpdir.path().join("fake.elf");
        let mut data = vec![0x7f, b'E', b'L', b'F'];
        data.extend_from_slice(&[0u8; 100]);
        fs::write(&elf, &data).unwrap();
        assert!(is_elf(&elf));
    }

    #[test]
    fn test_scan_capabilities_basic() {
        let tmpdir = tempfile::tempdir().unwrap();
        let content = tmpdir.path();

        // Create FHS layout
        fs::create_dir_all(content.join("usr/bin")).unwrap();
        fs::create_dir_all(content.join("usr/lib")).unwrap();
        fs::create_dir_all(content.join("usr/share/applications")).unwrap();

        fs::write(content.join("usr/bin/htop"), "binary").unwrap();
        fs::write(content.join("usr/bin/htop-vim"), "binary").unwrap();
        fs::write(content.join("usr/share/applications/htop.desktop"), "[Desktop]").unwrap();

        let caps = scan_capabilities(content).unwrap();
        assert!(caps.binaries.contains(&"htop".to_string()));
        assert!(caps.binaries.contains(&"htop-vim".to_string()));
        assert!(caps.resources.contains(&"/usr/share/applications/htop.desktop".to_string()));
    }
}
