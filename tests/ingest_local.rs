//! End-to-end ingestion tests for PLAN Sub-phase 2.1 (tasks 2.1.4 / 2.1.6 / 2.1.8).
//!
//! Every archive fixture is synthesized at test runtime with `tar` — no binary
//! blobs are committed. No test touches the network: mirror tests only exercise
//! the "unconfigured origin" and path-plumbing paths.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use libextos::cas::{CasRepository, RefEntry};
use libextos::ingest;
use libextos::rosetta::registry::RosettaRegistry;
use libextos::types::HashAlgorithm;

fn open_repo(dir: &Path) -> CasRepository {
    CasRepository::open(dir, HashAlgorithm::Blake3).expect("open CAS repository")
}

fn tar_xz(archive: &Path, src: &Path, entries: &[&str]) {
    let status = Command::new("tar")
        .arg("--xz")
        .arg("-cf")
        .arg(archive)
        .arg("-C")
        .arg(src)
        .args(entries)
        .status()
        .expect("spawn tar");
    assert!(status.success(), "failed to create {}", archive.display());
}

/// Arch-style `.pkg.tar.xz`: `.PKGINFO` plus an FHS payload.
fn arch_fixture(tmpdir: &Path) -> PathBuf {
    let src = tmpdir.join("arch_src");
    fs::create_dir_all(src.join("usr/bin")).unwrap();
    fs::create_dir_all(src.join("usr/share/doc/hello")).unwrap();
    fs::write(
        src.join(".PKGINFO"),
        "pkgname = hello\npkgver = 1.0.0-1\npkgdesc = test package\nprovides = hello-legacy\n",
    )
    .unwrap();
    fs::write(src.join("usr/bin/hello"), "#!/bin/sh\necho hello\n").unwrap();
    fs::write(src.join("usr/share/doc/hello/README"), "hello docs\n").unwrap();

    let archive = tmpdir.join("hello-1.0.0-1-x86_64.pkg.tar.xz");
    tar_xz(&archive, &src, &["."]);
    archive
}

/// Native `.pkt.tar.xz`: `metadata/manifest.nix` + `content/`.
fn native_fixture(tmpdir: &Path) -> PathBuf {
    let src = tmpdir.join("native_src");
    fs::create_dir_all(src.join("metadata")).unwrap();
    fs::create_dir_all(src.join("content/usr/bin")).unwrap();
    fs::write(
        src.join("metadata/manifest.nix"),
        r#"{
  identity = {
    origin = "scratch";
    name = "native-hello";
    version = "2.0.0";
  };
  format = "extracted-tree";
  capabilities = { binaries = [ "native-hello" ]; };
  requires = [];
}"#,
    )
    .unwrap();
    fs::write(
        src.join("content/usr/bin/native-hello"),
        "#!/bin/sh\necho native\n",
    )
    .unwrap();

    let archive = tmpdir.join("native-hello-2.0.0.pkt.tar.xz");
    tar_xz(&archive, &src, &["metadata", "content"]);
    archive
}

fn ref_target(repo: &CasRepository, origin: &str, name: &str, version: &str) -> PathBuf {
    let path = repo.ref_path(origin, name, version);
    fs::read_link(&path).unwrap_or_else(|err| panic!("{} is not a symlink: {err}", path.display()))
}

#[test]
fn ingest_local_archive_commits_object_and_refs() {
    let tmpdir = tempfile::tempdir().unwrap();
    let archive = arch_fixture(tmpdir.path());
    let repo = open_repo(&tmpdir.path().join("repository"));

    let result = ingest::ingest_local_archive(&repo, &archive).expect("ingest archive");

    assert_eq!(result.origin, "archlinux");
    assert_eq!(result.name, "hello");
    assert_eq!(result.version, "1.0.0-1");
    assert!(result.hash.starts_with("BLAKE3-"), "{}", result.hash);
    assert!(!result.rosetta_translated);

    // CAS object layout: objects/<hash>/{metadata/manifest.nix,content/...}
    let object = repo.object_path(&result.hash);
    assert!(object.is_dir());
    assert!(object.join("metadata/manifest.nix").is_file());
    assert!(object.join("content/usr/bin/hello").is_file());
    assert!(object.join("content/usr/share/doc/hello/README").is_file());
    // Metadata files must not leak into the content tree.
    assert!(!object.join("content/.PKGINFO").exists());

    // Fallback manifest keeps identity + capabilities blocks.
    let manifest = repo.read_manifest(&result.hash).unwrap();
    assert!(manifest.contains("name = \"hello\""), "{manifest}");
    assert!(manifest.contains("origin = \"archlinux\""), "{manifest}");
    assert!(manifest.contains("version = \"1.0.0-1\""), "{manifest}");
    assert!(manifest.contains("capabilities = {"), "{manifest}");

    // Refs: refs/<origin>/<name>/<version> → ../../../objects/<hash>
    assert_eq!(repo.resolve_ref("archlinux", "hello", "1.0.0-1").unwrap(), result.hash);
    assert_eq!(repo.resolve_ref("archlinux", "hello", "current").unwrap(), result.hash);
    assert_eq!(
        ref_target(&repo, "archlinux", "hello", "1.0.0-1"),
        Path::new("../../../objects").join(&result.hash)
    );

    // Ref listing (PLAN 2.1.8): concrete versions only, no `current` row.
    let rows = repo.list_refs().unwrap();
    assert_eq!(
        rows,
        vec![RefEntry {
            origin: "archlinux".into(),
            name: "hello".into(),
            version: "1.0.0-1".into(),
        }]
    );

    // Staging is cleaned up after a successful ingest.
    let staging = repo.root.join("_staging");
    let leftovers = fs::read_dir(&staging)
        .map(|entries| entries.count())
        .unwrap_or(0);
    assert_eq!(leftovers, 0, "staging directory not cleaned up");
}

#[test]
fn ingest_package_with_rosetta_falls_back_gracefully() {
    let tmpdir = tempfile::tempdir().unwrap();
    let archive = arch_fixture(tmpdir.path());
    let repo = open_repo(&tmpdir.path().join("repository"));
    let registry = RosettaRegistry::discover();

    let result =
        ingest::ingest_package_with_rosetta(&repo, &archive, "archlinux", Some(&registry))
            .expect("ingest with registry");

    assert_eq!(result.name, "hello");
    if registry.has_origin("archlinux") {
        // A plugin is installed: it must have produced a usable manifest.
        assert!(!repo.read_manifest(&result.hash).unwrap().is_empty());
    } else {
        // No upstream plugin on this host: built-in stub manifest must be used.
        assert!(!result.rosetta_translated);
        assert!(repo.read_manifest(&result.hash).unwrap().contains("name = \"hello\""));
    }
}

#[test]
fn ingest_local_archive_dispatches_native_packages() {
    let tmpdir = tempfile::tempdir().unwrap();
    let archive = native_fixture(tmpdir.path());
    let repo = open_repo(&tmpdir.path().join("repository"));

    let result = ingest::ingest_local_archive(&repo, &archive).expect("ingest native archive");

    // Identity comes from the embedded manifest, not from the caller.
    assert_eq!(result.origin, "scratch");
    assert_eq!(result.name, "native-hello");
    assert_eq!(result.version, "2.0.0");
    assert!(repo.object_path(&result.hash).join("content/usr/bin/native-hello").is_file());
    assert_eq!(repo.resolve_ref("scratch", "native-hello", "2.0.0").unwrap(), result.hash);
}

#[test]
fn ingest_local_archive_rejects_unknown_formats() {
    let tmpdir = tempfile::tempdir().unwrap();
    let bogus = tmpdir.path().join("package.zip");
    fs::write(&bogus, b"not an archive").unwrap();
    let repo = open_repo(&tmpdir.path().join("repository"));

    let err = ingest::ingest_local_archive(&repo, &bogus).unwrap_err();
    assert!(
        err.to_string().contains("unrecognized archive format"),
        "{err}"
    );
}

#[test]
fn unconfigured_mirror_is_reported_without_network() {
    // Randomized origin name so no ambient EXTOS_MIRRORS_* can interfere.
    let origin = "l1-unconfigured-origin";
    let err = ingest::mirrors_for_origin(origin).unwrap_err();
    let message = err.to_string();
    assert!(
        message.contains(&ingest::mirror_env_var(origin)),
        "error must name the env var: {message}"
    );

    let tmpdir = tempfile::tempdir().unwrap();
    let cache = tmpdir.path().join("cache");
    let err = ingest::download_from_mirror_to(origin, "hello", "1.0.0", &cache).unwrap_err();
    assert!(matches!(err, libextos::error::ExtosError::ConfigParse { .. }), "{err}");
    // Failing before any request means the cache directory is never created.
    assert!(!cache.exists());
}

#[test]
fn mirror_url_plumbing_is_pure_and_ordered() {
    let mirrors = vec![
        "https://a.example/arch".to_string(),
        "https://b.example/{name}/{version}/download".to_string(),
    ];
    let urls = ingest::mirror_urls(&mirrors, "archlinux", "hello", "1.0.0-1");
    assert_eq!(urls.len(), 2);
    assert_eq!(
        urls[0],
        "https://a.example/arch/hello-1.0.0-1-x86_64.pkg.tar.zst"
    );
    assert_eq!(urls[1], "https://b.example/hello/1.0.0-1/download");

    let tmpdir = tempfile::tempdir().unwrap();
    let path = ingest::cache_path_for(tmpdir.path(), "archlinux", "hello", "1.0.0-1");
    assert_eq!(
        path,
        tmpdir
            .path()
            .join("archlinux")
            .join("hello-1.0.0-1-x86_64.pkg.tar.zst")
    );
}
