//! Phase-3 fetcher wiring tests (PLAN 3.2.6 / 3.3.4 / 3.4.5).
//!
//! These tests cover the *dispatch seam* added to
//! [`libextos::ingest::download_from_mirror_to`]: `EXTOS_FETCHER_<ORIGIN>`
//! selects the transport, the default stays the Phase-2 mirror chain, and an
//! unknown value is a typed error instead of a silent HTTP fallback.
//!
//! Everything is fixture-local: the one full transfer test runs against a
//! std-only loopback `TcpListener` serving an archive synthesized at runtime
//! with `tar` (no committed blobs, no external network). The alpm test degrades
//! honestly: when `libalpm` cannot be loaded it asserts the typed error, and
//! when it can it only asserts the same dispatch reached the alpm chain (the
//! mirror base is a closed loopback port, so no real traffic happens).
//!
//! Every test uses its own origin name, hence its own
//! `EXTOS_FETCHER_*`/`EXTOS_MIRRORS_*` variables; no test can perturb another.

use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use libextos::cas::CasRepository;
use libextos::error::ExtosError;
use libextos::ingest::{self, FetcherKind};
use libextos::types::HashAlgorithm;

// ─── std-only loopback HTTP mirror ──────────────────────────────

/// Minimal HTTP/1.1 server answering `GET`s from an in-memory route table.
struct TestMirror {
    base_url: String,
    requests: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl TestMirror {
    fn start(routes: HashMap<String, Vec<u8>>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test mirror");
        let addr = listener.local_addr().expect("mirror address");
        listener
            .set_nonblocking(true)
            .expect("non-blocking mirror listener");

        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let routes = Arc::new(routes);

        let handle = {
            let requests = Arc::clone(&requests);
            let stop = Arc::clone(&stop);
            thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((stream, _)) => serve_one(stream, &routes, &requests),
                        Err(ref err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(5));
                        }
                        Err(_) => break,
                    }
                }
            })
        };

        Self {
            base_url: format!("http://{addr}"),
            requests,
            stop,
            handle: Some(handle),
        }
    }

    fn hits(&self, path: &str) -> usize {
        self.requests
            .lock()
            .expect("mirror request log")
            .iter()
            .filter(|seen| *seen == path)
            .count()
    }
}

impl Drop for TestMirror {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn serve_one(
    mut stream: TcpStream,
    routes: &HashMap<String, Vec<u8>>,
    requests: &Mutex<Vec<String>>,
) {
    let mut reader = BufReader::new(match stream.try_clone() {
        Ok(clone) => clone,
        Err(_) => return,
    });
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).is_err() {
        return;
    }
    let mut parts = request_line.split_whitespace();
    let _method = parts.next().unwrap_or_default();
    let path = parts.next().unwrap_or_default().to_string();
    requests.lock().expect("mirror request log").push(path.clone());

    // Drain headers so the client sees a clean response.
    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) if line == "\r\n" || line == "\n" => break,
            Ok(_) => {}
            Err(_) => break,
        }
    }

    let response = match routes.get(&path) {
        Some(body) => {
            let mut response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .into_bytes();
            response.extend_from_slice(body);
            response
        }
        None => b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            .to_vec(),
    };
    let _ = stream.write_all(&response);
    let _ = stream.flush();
}

// ─── fixtures ───────────────────────────────────────────────────

/// Environment mutation for tests. Edition 2024 marks `set_var` unsafe because
/// concurrent readers are unsound; every test here uses a uniquely named origin
/// so no other test (or thread) reads the variables it writes.
fn set_env(key: &str, value: &str) {
    // SAFETY: the variable names are test-local (`*_L12_*`) and no other thread
    // in this binary reads them; the process ends when the tests finish.
    unsafe { std::env::set_var(key, value) };
}

/// Arch-style `.pkg.tar.xz` for `hello` 1.0.0, matching the fallback filename
/// convention for an origin ingest does not know (`<name>-<version>.pkg.tar.xz`).
fn arch_fixture(tmpdir: &Path) -> PathBuf {
    let src = tmpdir.join("arch_src");
    fs::create_dir_all(src.join("usr/bin")).unwrap();
    fs::write(
        src.join(".PKGINFO"),
        "pkgname = hello\npkgver = 1.0.0\npkgdesc = wiring test package\n",
    )
    .unwrap();
    fs::write(src.join("usr/bin/hello"), "#!/bin/sh\necho hello\n").unwrap();

    let archive = tmpdir.join("hello-1.0.0.pkg.tar.xz");
    let status = Command::new("tar")
        .arg("--xz")
        .arg("-cf")
        .arg(&archive)
        .arg("-C")
        .arg(&src)
        .arg(".")
        .status()
        .expect("spawn tar");
    assert!(status.success(), "failed to create {}", archive.display());
    archive
}

/// A loopback base URL that refuses connections: bind an ephemeral port, then
/// drop the listener. Used to prove which transport ran without any traffic.
fn refused_base_url() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind probe port");
    let addr = listener.local_addr().expect("probe address");
    drop(listener);
    format!("http://{addr}")
}

fn open_repo(dir: &Path) -> CasRepository {
    CasRepository::open(dir, HashAlgorithm::Blake3).expect("open CAS repository")
}

// ─── dispatch semantics ─────────────────────────────────────────

#[test]
fn unknown_fetcher_name_is_a_typed_error_without_fallback() {
    let origin = "l12-unknown";
    set_env(&ingest::fetcher_env_var(origin), "wget");

    let tmp = tempfile::tempdir().unwrap();
    let cache = tmp.path().join("cache");
    let err = ingest::download_from_mirror_to(origin, "hello", "1.0.0", &cache).unwrap_err();

    assert!(matches!(err, ExtosError::ConfigParse { .. }), "{err}");
    let message = err.to_string();
    assert!(message.contains("EXTOS_FETCHER_L12_UNKNOWN"), "{message}");
    assert!(message.contains("unknown fetcher 'wget'"), "{message}");
    assert!(message.contains("http, alpm, debian, rpm"), "{message}");
    // Dispatch fails before the mirror chain or the cache is touched.
    assert!(!cache.exists(), "cache must not be created on a dispatch error");
}

#[test]
fn explicit_http_reaches_the_legacy_mirror_chain_end_to_end() {
    let origin = "l12-http";
    let tmp = tempfile::tempdir().unwrap();
    let archive = arch_fixture(tmp.path());
    let body = fs::read(&archive).unwrap();

    let route = "/hello-1.0.0.pkg.tar.xz";
    let mirror = TestMirror::start(HashMap::from([(route.to_string(), body.clone())]));
    set_env(&ingest::fetcher_env_var(origin), "http");
    set_env(&ingest::mirror_env_var(origin), &mirror.base_url);
    assert_eq!(ingest::fetcher_for_origin(origin).unwrap(), FetcherKind::Http);

    let cache = tmp.path().join("cache");
    let archive_path = ingest::download_from_mirror_to(origin, "hello", "1.0.0", &cache)
        .expect("download via the explicit http fetcher");

    // Same cache layout and byte-for-byte result as the Phase-2 chain.
    assert_eq!(
        archive_path,
        ingest::cache_path_for(&cache, origin, "hello", "1.0.0")
    );
    assert_eq!(fs::read(&archive_path).unwrap(), body);
    assert_eq!(mirror.hits(route), 1);

    // The artifact then feeds the unchanged extract → manifest → CAS pipeline.
    let repo = open_repo(&tmp.path().join("repository"));
    let result = ingest::ingest_local_archive_with_rosetta(&repo, &archive_path, origin, None)
        .expect("ingest the fetched archive");
    assert_eq!(result.origin, origin);
    assert_eq!(result.name, "hello");
    assert_eq!(result.version, "1.0.0");
    assert_eq!(
        repo.resolve_ref(origin, "hello", "1.0.0").unwrap(),
        result.hash
    );
    assert!(repo
        .object_path(&result.hash)
        .join("content/usr/bin/hello")
        .is_file());
}

#[test]
fn unset_fetcher_keeps_the_default_mirror_chain() {
    let origin = "l12-default";
    let tmp = tempfile::tempdir().unwrap();
    let archive = arch_fixture(tmp.path());
    let body = fs::read(&archive).unwrap();

    let route = "/hello-1.0.0.pkg.tar.xz";
    let mirror = TestMirror::start(HashMap::from([(route.to_string(), body.clone())]));
    // No EXTOS_FETCHER_L12_DEFAULT is set anywhere: the default must be http.
    set_env(&ingest::mirror_env_var(origin), &mirror.base_url);
    assert_eq!(ingest::fetcher_for_origin(origin).unwrap(), FetcherKind::Http);

    let cache = tmp.path().join("cache");
    let archive_path = ingest::download_from_mirror_to(origin, "hello", "1.0.0", &cache)
        .expect("default mirror-chain download");
    assert_eq!(fs::read(&archive_path).unwrap(), body);
    assert_eq!(mirror.hits(route), 1);
}

// ─── per-transport dispatch ────────────────────────────────────

#[test]
fn alpm_mode_dispatches_to_libalpm_or_degrades_honestly() {
    let origin = "l12-alpm";
    let tmp = tempfile::tempdir().unwrap();
    set_env(&ingest::fetcher_env_var(origin), "alpm");
    set_env(&ingest::mirror_env_var(origin), &refused_base_url());
    assert_eq!(ingest::fetcher_for_origin(origin).unwrap(), FetcherKind::Alpm);

    // Probe the transport the same way the production code does.
    let probing = libextos::fetcher::alpm::AlpmFetch::new(tmp.path().join("alpm-probe"));
    let libalpm_present = probing.is_ok();
    drop(probing);

    let cache = tmp.path().join("cache");
    let err = ingest::download_from_mirror_to(origin, "hello", "1.0.0", &cache).unwrap_err();
    let message = err.to_string();
    assert!(matches!(err, ExtosError::ConfigParse { .. }), "{message}");

    if libalpm_present {
        // The alpm chain ran and failed on the refused mirror, not on loading.
        assert!(
            message.contains("/core.db"),
            "alpm chain must request <base>/<repo>.db: {message}"
        );
        eprintln!("NOTE: libalpm is present; alpm dispatch went to the database sync step");
    } else {
        // Honest degradation: the missing library is named, and the escape
        // hatch is documented in the error itself.
        assert!(message.contains("libalpm is not available"), "{message}");
        assert!(message.contains("EXTOS_FETCHER_L12_ALPM"), "{message}");
        eprintln!("SKIP: libalpm absent; asserted the typed NotAvailable error instead");
    }
}

#[test]
fn debian_mode_dispatches_to_the_apt_release_chain() {
    let origin = "l12-debian";
    let tmp = tempfile::tempdir().unwrap();
    let base = refused_base_url();
    set_env(&ingest::fetcher_env_var(origin), "debian");
    set_env(&ingest::mirror_env_var(origin), &base);
    assert_eq!(
        ingest::fetcher_for_origin(origin).unwrap(),
        FetcherKind::Debian
    );

    let cache = tmp.path().join("cache");
    let err = ingest::download_from_mirror_to(origin, "hello", "1.0.0", &cache).unwrap_err();
    let message = err.to_string();
    assert!(matches!(err, ExtosError::ConfigParse { .. }), "{message}");
    // APT-specific first request: the signed release document, not a package URL.
    assert!(message.contains("/dists/stable/InRelease"), "{message}");
    assert!(!cache.exists(), "no cache directory for a failed sync");
}

#[test]
fn rpm_mode_dispatches_to_the_repomd_chain() {
    let origin = "l12-rpm";
    let tmp = tempfile::tempdir().unwrap();
    let base = refused_base_url();
    set_env(&ingest::fetcher_env_var(origin), "rpm");
    set_env(&ingest::mirror_env_var(origin), &base);
    assert_eq!(ingest::fetcher_for_origin(origin).unwrap(), FetcherKind::Rpm);

    let cache = tmp.path().join("cache");
    let err = ingest::download_from_mirror_to(origin, "hello", "1.0.0", &cache).unwrap_err();
    let message = err.to_string();
    assert!(matches!(err, ExtosError::ConfigParse { .. }), "{message}");
    // RPM-specific first request: repodata/repomd.xml, not a package URL.
    assert!(message.contains("/repodata/repomd.xml"), "{message}");
    assert!(!cache.exists(), "no cache directory for a failed sync");
}
