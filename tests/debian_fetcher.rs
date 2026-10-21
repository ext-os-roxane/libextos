//! Integration tests for the Debian fetcher (PLAN 3.3.5).
//!
//! Everything here is **fixture-local**: a loopback `TcpListener` serves a
//! synthetic APT repository built at test runtime, and a throwaway GnuPG home
//! generates the signing key. No committed blobs, no network. The only
//! external tools are the ones the production code itself documents (`gpg`,
//! and `gzip`/`xz` for the compressed-index cases); a test that needs a
//! missing tool prints a skip line instead of failing.
//!
//! Fixture layout served by [`TestMirror`]:
//!
//! ```text
//! /dists/extostest/InRelease                          clearsigned Release payload
//! /dists/extostest/Release      (+ /Release.gpg)      detached-signature variant
//! /dists/extostest/main/binary-amd64/Packages[.gz|.xz]
//! /pool/main/h/hello/hello_1.0.0-1_amd64.deb          minimal ar archive
//! ```
//!
//! A real-network run of `coreutils` from Debian sid is opt-in via
//! `EXTOS_TEST_DEB_FETCH=1` and stays quiet otherwise.

use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use libextos::error::ExtosError;
use libextos::fetcher::debian::{self, DebianFetcher, ReleaseKind, SigCheck};
use sha2::{Digest, Sha256};

/// Suite/codename used by the fixture repository.
const SUITE: &str = "extostest";

/// Component used by the fixture repository.
const COMPONENT: &str = "main";

/// Architecture used by the fixture repository.
const ARCH: &str = "amd64";

/// `Filename:` path of the single `.deb` in the fixture.
const DEB_PATH: &str = "pool/main/h/hello/hello_1.0.0-1_amd64.deb";

/// Package/version of the single row in the fixture index.
const PACKAGE: &str = "hello";
const VERSION: &str = "1.0.0-1";

// ─── std-only loopback HTTP mirror ──────────────────────────────

/// Minimal HTTP/1.1 server answering `GET`s from an in-memory route table.
///
/// Unknown paths get `404 Not Found`; known paths get `200 OK` with the canned
/// body. Requests are recorded so tests can assert cache behaviour.
struct TestMirror {
    base_url: String,
    requests: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl TestMirror {
    /// Start serving `routes` on an ephemeral loopback port.
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

    /// Paths requested so far, in arrival order.
    fn requests(&self) -> Vec<String> {
        self.requests.lock().expect("mirror request log").clone()
    }

    /// How many times `path` was requested.
    fn hits(&self, path: &str) -> usize {
        self.requests().iter().filter(|seen| *seen == path).count()
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

/// Read one request, answer from `routes`, close the connection.
fn serve_one(
    stream: TcpStream,
    routes: &HashMap<String, Vec<u8>>,
    requests: &Mutex<Vec<String>>,
) {
    let mut writer = match stream.try_clone() {
        Ok(writer) => writer,
        Err(_) => return,
    };
    let mut reader = BufReader::new(stream);

    let mut request_line = String::new();
    if reader.read_line(&mut request_line).is_err() {
        return;
    }
    // Drain the header block; the fixture only answers GETs with no body.
    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) if line == "\r\n" || line == "\n" => break,
            Ok(_) => {}
            Err(_) => break,
        }
    }

    let path = request_line
        .split_whitespace()
        .nth(1)
        .unwrap_or_default()
        .to_string();
    requests
        .lock()
        .expect("mirror request log")
        .push(path.clone());

    let written = match routes.get(&path) {
        Some(body) => {
            let header = format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Type: application/octet-stream\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\r\n",
                body.len()
            );
            writer
                .write_all(header.as_bytes())
                .and_then(|()| writer.write_all(body))
        }
        None => writer.write_all(
            b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        ),
    };
    let _ = written.and_then(|()| writer.flush());
}

// ─── Fixture repository ─────────────────────────────────────────

/// A synthetic APT repository, signed with a throwaway key.
struct Fixture {
    /// Keeps the throwaway GnuPG home alive for the whole test.
    _dir: tempfile::TempDir,
    /// ASCII-armoured public key of the signing key.
    pubkey: Vec<u8>,
    /// The `.deb` bytes the index advertises.
    deb: Vec<u8>,
    /// Plain-text `Packages` index.
    packages: Vec<u8>,
    /// Clearsigned `InRelease` advertising the plain `Packages`.
    inrelease_plain: Vec<u8>,
    /// `(Packages.gz bytes, InRelease advertising Packages.gz)`.
    gz: Option<(Vec<u8>, Vec<u8>)>,
    /// `(Packages.xz bytes, InRelease advertising Packages.xz)`.
    xz: Option<(Vec<u8>, Vec<u8>)>,
    /// Unsigned `Release` body (detached-signature variant).
    release: Vec<u8>,
    /// ASCII-armoured detached signature over [`Fixture::release`].
    release_gpg: Vec<u8>,
}

/// Build the fixture repository, or `None` (with a printed skip) when `gpg`
/// is unavailable.
fn fixture() -> Option<Fixture> {
    if !tool_available("gpg") {
        eprintln!("skipping Debian fetcher test: gpg is not available");
        return None;
    }

    let dir = tempfile::tempdir().expect("fixture tempdir");
    let home = dir.path().join("gnupg");
    fs::create_dir_all(&home).expect("gpg home");
    restrict_to_owner(&home);

    let keygen = gpg(
        &home,
        &[
            "--quick-gen-key",
            "ExtOS Test <test@extos.invalid>",
            "ed25519",
            "sign",
            "0",
        ],
    );
    assert!(
        keygen.status.success(),
        "gpg key generation failed: {}",
        String::from_utf8_lossy(&keygen.stderr)
    );

    let export = gpg(&home, &["--armor", "--export", "test@extos.invalid"]);
    assert!(
        export.status.success() && !export.stdout.is_empty(),
        "gpg key export failed: {}",
        String::from_utf8_lossy(&export.stderr)
    );
    let pubkey = export.stdout;

    // Minimal, spec-shaped ar archive: `!<arch>\n` then 60-byte headers.
    let deb = ar_archive(&[
        ("debian-binary", b"2.0\n"),
        ("control.tar.xz", b"\xfd7zXZ\x00fixture-control\n"),
        ("data.tar.xz", b"\xfd7zXZ\x00fixture-data\n"),
    ]);

    let packages = packages_text(&deb);
    let inrelease_plain = clearsign(
        &home,
        dir.path(),
        "plain",
        &release_payload("Packages", &packages),
    );
    let release = release_payload("Packages", &packages).into_bytes();
    let release_gpg = detach_sign(&home, dir.path(), &release);

    let gz = compress("gzip", &packages).map(|compressed| {
        let inrelease = clearsign(
            &home,
            dir.path(),
            "gz",
            &release_payload("Packages.gz", &compressed),
        );
        (compressed, inrelease)
    });
    let xz = compress("xz", &packages).map(|compressed| {
        let inrelease = clearsign(
            &home,
            dir.path(),
            "xz",
            &release_payload("Packages.xz", &compressed),
        );
        (compressed, inrelease)
    });

    Some(Fixture {
        _dir: dir,
        pubkey,
        deb,
        packages,
        inrelease_plain,
        gz,
        xz,
        release,
        release_gpg,
    })
}

/// Route table for a repository whose `InRelease` advertises `index_name`
/// with `index_body`, plus the `.deb`.
fn routes(
    inrelease: &[u8],
    index_name: &str,
    index_body: &[u8],
    deb: &[u8],
) -> HashMap<String, Vec<u8>> {
    let mut table = HashMap::new();
    table.insert(
        format!("/dists/{SUITE}/InRelease"),
        inrelease.to_vec(),
    );
    table.insert(
        format!("/dists/{SUITE}/{COMPONENT}/binary-{ARCH}/{index_name}"),
        index_body.to_vec(),
    );
    table.insert(format!("/{DEB_PATH}"), deb.to_vec());
    table
}

/// One `Packages` stanza for the fixture `.deb`.
fn packages_text(deb: &[u8]) -> Vec<u8> {
    format!(
        "Package: {PACKAGE}\n\
         Version: {VERSION}\n\
         Architecture: {ARCH}\n\
         Maintainer: ExtOS Test <test@extos.invalid>\n\
         Installed-Size: 1\n\
         Size: {}\n\
         SHA256: {}\n\
         Filename: {DEB_PATH}\n\
         Description: loopback fixture package\n\
          A continuation line the parser must ignore.\n",
        deb.len(),
        sha256_hex(deb)
    )
    .into_bytes()
}

/// Signed-document payload listing `index_name` with its hash and size.
fn release_payload(index_name: &str, index_body: &[u8]) -> String {
    format!(
        "Origin: ExtOS Test\n\
         Label: ExtOS Test\n\
         Suite: {SUITE}\n\
         Codename: {SUITE}\n\
         Date: Wed, 21 Oct 2026 00:00:00 UTC\n\
         Architectures: {ARCH}\n\
         Components: {COMPONENT}\n\
         Description: ExtOS loopback fixture\n\
         SHA256:\n\
         \x20{} {} {COMPONENT}/binary-{ARCH}/{index_name}\n",
        sha256_hex(index_body),
        index_body.len()
    )
}

/// Build a `.deb`-shaped ar archive from `(name, bytes)` members.
fn ar_archive(members: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = b"!<arch>\n".to_vec();
    for (name, data) in members {
        assert!(name.len() <= 16, "ar member name too long: {name}");
        let mut header = [b' '; 60];
        write_field(&mut header, 0, 16, &format!("{name}/"));
        write_field(&mut header, 16, 28, "0"); // mtime
        write_field(&mut header, 28, 34, "0"); // uid
        write_field(&mut header, 34, 40, "0"); // gid
        write_field(&mut header, 40, 48, "100644"); // mode
        write_field(&mut header, 48, 58, &data.len().to_string()); // size
        header[58] = b'`';
        header[59] = b'\n';
        out.extend_from_slice(&header);
        out.extend_from_slice(data);
        if data.len() % 2 == 1 {
            out.push(b'\n'); // members are 2-byte aligned
        }
    }
    out
}

/// Write `value` into `header[start..end]`, space padding the rest.
fn write_field(header: &mut [u8], start: usize, end: usize, value: &str) {
    let width = end - start;
    assert!(value.len() <= width, "ar header field overflow: {value}");
    header[start..start + value.len()].copy_from_slice(value.as_bytes());
    for byte in &mut header[start + value.len()..end] {
        *byte = b' ';
    }
}

// ─── gpg helpers (fixture side) ────────────────────────────────

/// Run `gpg` against a throwaway home with non-interactive settings.
fn gpg(home: &Path, args: &[&str]) -> Output {
    Command::new("gpg")
        .arg("--homedir")
        .arg(home)
        .args([
            "--batch",
            "--no-tty",
            "--no-options",
            "--quiet",
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            "",
        ])
        .args(args)
        .stdin(Stdio::null())
        .output()
        .expect("run gpg")
}

/// Clearsign `payload` and return the armoured document.
fn clearsign(home: &Path, dir: &Path, tag: &str, payload: &str) -> Vec<u8> {
    let payload_path = dir.join(format!("payload-{tag}"));
    let output_path = dir.join(format!("InRelease-{tag}"));
    fs::write(&payload_path, payload).expect("write payload");
    let output = gpg(
        home,
        &[
            "--local-user",
            "test@extos.invalid",
            "--armor",
            "--clearsign",
            "--output",
            output_path.to_str().expect("utf-8 fixture path"),
            payload_path.to_str().expect("utf-8 fixture path"),
        ],
    );
    assert!(
        output.status.success(),
        "gpg --clearsign failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    fs::read(&output_path).expect("read clearsigned document")
}

/// Detached-sign `data` and return the armoured signature.
fn detach_sign(home: &Path, dir: &Path, data: &[u8]) -> Vec<u8> {
    let data_path = dir.join("Release");
    let sig_path = dir.join("Release.gpg");
    fs::write(&data_path, data).expect("write Release");
    let output = gpg(
        home,
        &[
            "--local-user",
            "test@extos.invalid",
            "--armor",
            "--detach-sign",
            "--output",
            sig_path.to_str().expect("utf-8 fixture path"),
            data_path.to_str().expect("utf-8 fixture path"),
        ],
    );
    assert!(
        output.status.success(),
        "gpg --detach-sign failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    fs::read(&sig_path).expect("read detached signature")
}

/// Compress `data` with `<tool> -c`, or `None` when the tool is absent.
fn compress(tool: &str, data: &[u8]) -> Option<Vec<u8>> {
    if !tool_available(tool) {
        eprintln!("skipping {tool} fixture: {tool} is not available");
        return None;
    }
    let mut child = Command::new(tool)
        .arg("-c")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn compressor");
    child
        .stdin
        .take()
        .expect("compressor stdin")
        .write_all(data)
        .expect("write compressor input");
    let output = child.wait_with_output().expect("compressor output");
    assert!(output.status.success(), "{tool} failed");
    Some(output.stdout)
}

// ─── small utilities ───────────────────────────────────────────

/// `true` when `tool` answers `--version` on `PATH`.
fn tool_available(tool: &str) -> bool {
    Command::new(tool)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

/// `chmod 0700` — gpg refuses group/world-readable homes.
fn restrict_to_owner(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("chmod gpg home");
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

/// Lowercase hexadecimal SHA-256.
fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex_encode(&hasher.finalize())
}

/// Hex encoding without pulling `hex` into the test's imports.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A fetcher caching into a per-test directory.
fn fetcher_for(mirror: &TestMirror, cache: &Path) -> DebianFetcher {
    DebianFetcher::new(mirror.base_url.clone(), ARCH, cache.to_path_buf()).expect("build fetcher")
}

/// Index path prefix used in request assertions.
fn packages_path(name: &str) -> String {
    format!("/dists/{SUITE}/{COMPONENT}/binary-{ARCH}/{name}")
}

/// Assert `error` is a [`ExtosError::CasIntegrity`] and return its rendering.
fn assert_integrity(error: &ExtosError) {
    assert!(
        matches!(error, ExtosError::CasIntegrity { .. }),
        "expected CasIntegrity, got {error:?}"
    );
}

// ─── tests ─────────────────────────────────────────────────────

#[test]
fn sync_db_parses_a_signed_plain_packages_index() {
    let Some(fixture) = fixture() else { return };
    let mirror = TestMirror::start(routes(
        &fixture.inrelease_plain,
        "Packages",
        &fixture.packages,
        &fixture.deb,
    ));

    let index = debian::sync_db(&mirror.base_url, SUITE, COMPONENT, Some(&fixture.pubkey))
        .expect("sync signed index");

    assert_eq!(index.distro, SUITE);
    assert_eq!(index.distribution, SUITE);
    assert_eq!(index.architecture, ARCH);
    assert_eq!(index.mirror_base, mirror.base_url);
    assert!(index.signature_verified());
    assert_eq!(index.release_kind(), ReleaseKind::InRelease);
    assert_eq!(index.packages_file, format!("{COMPONENT}/binary-{ARCH}/Packages"));
    assert_eq!(index.packages_size, fixture.packages.len() as u64);

    assert_eq!(index.packages.len(), 1);
    let row = index.find(PACKAGE, VERSION).expect("row present");
    assert_eq!(row.package, PACKAGE);
    assert_eq!(row.architecture, ARCH);
    assert_eq!(row.size, fixture.deb.len() as u64);
    assert_eq!(row.sha256, sha256_hex(&fixture.deb));
    assert_eq!(row.filename, DEB_PATH);
    assert_eq!(row.relpath(), DEB_PATH);
    assert_eq!(row.component, COMPONENT);
    assert!(index.package(PACKAGE).is_some());
    assert!(index.find(PACKAGE, "9.9.9").is_none());
}

#[test]
fn download_verifies_the_full_chain_and_reuses_the_cache() {
    let Some(fixture) = fixture() else { return };
    let mirror = TestMirror::start(routes(
        &fixture.inrelease_plain,
        "Packages",
        &fixture.packages,
        &fixture.deb,
    ));
    let cache = tempfile::tempdir().expect("cache dir");
    let fetcher = fetcher_for(&mirror, cache.path());

    let index = fetcher
        .sync_db(SUITE, COMPONENT, Some(&fixture.pubkey))
        .expect("sync signed index");

    let downloaded = fetcher
        .download(&index, PACKAGE, VERSION, SigCheck::Key(&fixture.pubkey))
        .expect("download verified deb");
    assert!(downloaded.path.is_file());
    assert_eq!(downloaded.package, PACKAGE);
    assert_eq!(downloaded.version, VERSION);
    assert_eq!(downloaded.size, fixture.deb.len() as u64);
    assert_eq!(downloaded.sha256, sha256_hex(&fixture.deb));
    assert_eq!(
        fs::read(&downloaded.path).expect("read downloaded deb"),
        fixture.deb
    );
    assert_eq!(mirror.hits(&format!("/{DEB_PATH}")), 1);

    // Second call is served from the verified cache: no extra request.
    let again = fetcher
        .download(&index, PACKAGE, VERSION, SigCheck::Key(&fixture.pubkey))
        .expect("cached download");
    assert_eq!(again.path, downloaded.path);
    assert_eq!(mirror.hits(&format!("/{DEB_PATH}")), 1);
}

#[test]
fn tampered_inrelease_is_a_typed_integrity_error() {
    let Some(fixture) = fixture() else { return };
    let tampered = String::from_utf8(fixture.inrelease_plain.clone())
        .expect("armoured text")
        .replace(&format!("Suite: {SUITE}"), "Suite: evil")
        .into_bytes();
    let mirror = TestMirror::start(routes(
        &tampered,
        "Packages",
        &fixture.packages,
        &fixture.deb,
    ));

    let error = debian::sync_db(&mirror.base_url, SUITE, COMPONENT, Some(&fixture.pubkey))
        .expect_err("tampered signature must be rejected");
    assert_integrity(&error);
}

#[test]
fn unknown_distribution_is_a_package_not_found_error() {
    let Some(fixture) = fixture() else { return };
    let mirror = TestMirror::start(routes(
        &fixture.inrelease_plain,
        "Packages",
        &fixture.packages,
        &fixture.deb,
    ));

    let error = debian::sync_db(&mirror.base_url, "nosuchsuite", COMPONENT, Some(&fixture.pubkey))
        .expect_err("missing suite must fail");
    assert!(
        matches!(error, ExtosError::PackageNotFound { .. }),
        "expected PackageNotFound, got {error:?}"
    );
}

#[test]
fn gzip_packages_index_is_supported() {
    let Some(fixture) = fixture() else { return };
    let Some((compressed, inrelease)) = fixture.gz.clone() else {
        return;
    };
    let mirror = TestMirror::start(routes(
        &inrelease,
        "Packages.gz",
        &compressed,
        &fixture.deb,
    ));

    let index = debian::sync_db(&mirror.base_url, SUITE, COMPONENT, Some(&fixture.pubkey))
        .expect("sync gzip index");
    assert_eq!(index.packages_file, std::format!("{COMPONENT}/binary-{ARCH}/Packages.gz"));
    assert_eq!(index.packages.len(), 1);
    assert_eq!(index.packages[0].sha256, sha256_hex(&fixture.deb));
    // The plain variant is not advertised, so it must not be requested.
    assert_eq!(mirror.hits(&packages_path("Packages")), 0);
    assert_eq!(mirror.hits(&packages_path("Packages.gz")), 1);
}

#[test]
fn xz_packages_index_is_supported() {
    let Some(fixture) = fixture() else { return };
    let Some((compressed, inrelease)) = fixture.xz.clone() else {
        return;
    };
    let mirror = TestMirror::start(routes(
        &inrelease,
        "Packages.xz",
        &compressed,
        &fixture.deb,
    ));

    let index = debian::sync_db(&mirror.base_url, SUITE, COMPONENT, Some(&fixture.pubkey))
        .expect("sync xz index");
    assert_eq!(index.packages.len(), 1);
    assert_eq!(index.packages_file, format!("{COMPONENT}/binary-{ARCH}/Packages.xz"));
}

#[test]
fn release_and_release_gpg_fallback_is_verified() {
    let Some(fixture) = fixture() else { return };
    let mut table = HashMap::new();
    table.insert(format!("/dists/{SUITE}/Release"), fixture.release.clone());
    table.insert(
        format!("/dists/{SUITE}/Release.gpg"),
        fixture.release_gpg.clone(),
    );
    table.insert(
        format!("/dists/{SUITE}/{COMPONENT}/binary-{ARCH}/Packages"),
        fixture.packages.clone(),
    );
    table.insert(format!("/{DEB_PATH}"), fixture.deb.clone());
    let mirror = TestMirror::start(table);

    let index = debian::sync_db(&mirror.base_url, SUITE, COMPONENT, Some(&fixture.pubkey))
        .expect("sync detached-signed index");
    assert_eq!(index.release_kind(), ReleaseKind::ReleaseDetached);
    assert!(index.signature_verified());
    assert_eq!(index.packages.len(), 1);
    // No InRelease on this mirror at all.
    assert_eq!(mirror.hits(&format!("/dists/{SUITE}/InRelease")), 1);
}

#[test]
fn unsigned_sync_downgrades_to_hash_only_integrity() {
    let Some(fixture) = fixture() else { return };
    // A mirror with neither InRelease nor Release.gpg: an unsigned Release.
    let mut table = HashMap::new();
    table.insert(format!("/dists/{SUITE}/Release"), fixture.release.clone());
    table.insert(
        format!("/dists/{SUITE}/{COMPONENT}/binary-{ARCH}/Packages"),
        fixture.packages.clone(),
    );
    table.insert(format!("/{DEB_PATH}"), fixture.deb.clone());
    let mirror = TestMirror::start(table);
    let cache = tempfile::tempdir().expect("cache dir");
    let fetcher = fetcher_for(&mirror, cache.path());

    let index = fetcher
        .sync_db(SUITE, COMPONENT, None)
        .expect("unsigned sync");
    assert!(!index.signature_verified());
    assert_eq!(index.release_kind(), ReleaseKind::ReleaseUnsigned);

    // Hash chain still holds, so a skip-policy download succeeds…
    let downloaded = fetcher
        .download(&index, PACKAGE, VERSION, SigCheck::Skip)
        .expect("hash-only download");
    assert!(downloaded.path.is_file());

    // …but asking to verify an unsigned index is a typed error.
    let error = fetcher
        .download(&index, PACKAGE, VERSION, SigCheck::Key(&fixture.pubkey))
        .expect_err("unsigned index cannot satisfy a key policy");
    assert_integrity(&error);
}

#[test]
fn re_verifying_a_late_key_upgrades_an_unsigned_sync() {
    let Some(fixture) = fixture() else { return };
    let mirror = TestMirror::start(routes(
        &fixture.inrelease_plain,
        "Packages",
        &fixture.packages,
        &fixture.deb,
    ));
    let cache = tempfile::tempdir().expect("cache dir");
    let fetcher = fetcher_for(&mirror, cache.path());

    // Synced without a key (hash chain only)…
    let index = fetcher
        .sync_db(SUITE, COMPONENT, None)
        .expect("unsigned sync");
    assert!(!index.signature_verified());

    // …the stored clearsigned document can still be proven with a key later.
    let downloaded = fetcher
        .download(&index, PACKAGE, VERSION, SigCheck::Key(&fixture.pubkey))
        .expect("late signature verification");
    assert!(downloaded.path.is_file());

    // A different key cannot.
    let wrong_key = b"-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nnot a key\n-----END PGP PUBLIC KEY BLOCK-----\n";
    let error = fetcher
        .download(&index, PACKAGE, VERSION, SigCheck::Key(wrong_key))
        .expect_err("wrong key must not verify");
    assert!(
        matches!(error, ExtosError::ConfigParse { .. } | ExtosError::CasIntegrity { .. }),
        "expected a typed verification failure, got {error:?}"
    );
}

#[test]
fn corrupt_deb_is_rejected_by_size_and_hash() {
    let Some(fixture) = fixture() else { return };
    let mut corrupt = fixture.deb.clone();
    let last = corrupt.len() - 1;
    corrupt[last] ^= 0xff;
    let mirror = TestMirror::start(routes(
        &fixture.inrelease_plain,
        "Packages",
        &fixture.packages,
        &corrupt,
    ));
    let cache = tempfile::tempdir().expect("cache dir");
    let fetcher = fetcher_for(&mirror, cache.path());

    let index = fetcher
        .sync_db(SUITE, COMPONENT, Some(&fixture.pubkey))
        .expect("sync signed index");
    let error = fetcher
        .download(&index, PACKAGE, VERSION, SigCheck::Key(&fixture.pubkey))
        .expect_err("corrupt deb must be rejected");
    assert_integrity(&error);
    // Nothing unverified may be left in the cache under the final name.
    let dest = cache.path().join("hello_1.0.0-1_amd64.deb");
    assert!(!dest.exists(), "corrupt deb was written to {}", dest.display());
}

#[test]
fn missing_deb_is_a_package_not_found_error() {
    let Some(fixture) = fixture() else { return };
    let mut table = routes(
        &fixture.inrelease_plain,
        "Packages",
        &fixture.packages,
        &fixture.deb,
    );
    table.remove(&format!("/{DEB_PATH}"));
    let mirror = TestMirror::start(table);
    let cache = tempfile::tempdir().expect("cache dir");
    let fetcher = fetcher_for(&mirror, cache.path());

    let index = fetcher
        .sync_db(SUITE, COMPONENT, Some(&fixture.pubkey))
        .expect("sync signed index");
    let error = fetcher
        .download(&index, PACKAGE, VERSION, SigCheck::Key(&fixture.pubkey))
        .expect_err("404 deb must fail");
    assert!(
        matches!(error, ExtosError::PackageNotFound { .. }),
        "expected PackageNotFound, got {error:?}"
    );

    // An unknown package name is also a typed not-found.
    let error = fetcher
        .download(&index, "nosuchpkg", "1.0", SigCheck::Key(&fixture.pubkey))
        .expect_err("unknown row must fail");
    assert!(matches!(error, ExtosError::PackageNotFound { .. }));
}

#[test]
fn path_traversal_in_suite_or_component_is_rejected() {
    let Some(fixture) = fixture() else { return };
    let mirror = TestMirror::start(routes(
        &fixture.inrelease_plain,
        "Packages",
        &fixture.packages,
        &fixture.deb,
    ));

    for bad in ["../etc", "/etc", "a b"] {
        let error = debian::sync_db(&mirror.base_url, bad, COMPONENT, Some(&fixture.pubkey))
            .expect_err("traversal must be rejected");
        assert!(
            matches!(error, ExtosError::ConfigParse { .. }),
            "expected ConfigParse for {bad:?}, got {error:?}"
        );
    }
}

/// Optional live-network smoke test; skipped unless explicitly enabled.
#[test]
fn live_debian_sid_fetch_is_opt_in() {
    if std::env::var("EXTOS_TEST_DEB_FETCH").ok().as_deref() != Some("1") {
        eprintln!("skipping live Debian fetch: set EXTOS_TEST_DEB_FETCH=1 to enable");
        return;
    }
    let cache = tempfile::tempdir().expect("cache dir");
    let fetcher = DebianFetcher::new(
        "http://deb.debian.org/debian",
        ARCH,
        cache.path().to_path_buf(),
    )
    .expect("build fetcher");

    // No out-of-band key material in this test, so the index is hash-verified
    // only (SigCheck::Skip). The production path passes a key.
    let index = fetcher
        .sync_db("sid", COMPONENT, None)
        .expect("sync Debian sid");
    assert!(index.packages.len() > 1000, "suspiciously small sid index");

    let row = index.package("coreutils").expect("coreutils in sid");
    let version = row.version.clone();
    let downloaded = fetcher
        .download(&index, "coreutils", &version, SigCheck::Skip)
        .expect("download coreutils");
    assert!(downloaded.path.is_file());
    assert_eq!(downloaded.size, fs::metadata(&downloaded.path).unwrap().len());
    eprintln!(
        "downloaded {} {} ({} bytes) → {}",
        downloaded.package,
        downloaded.version,
        downloaded.size,
        downloaded.path.display()
    );
}

/// The mirror must be reachable with a plain `Stdio::null()` child too; this
/// guards against accidentally depending on an async runtime.
#[test]
fn fetcher_is_usable_from_a_plain_thread() {
    let Some(fixture) = fixture() else { return };
    let mirror = TestMirror::start(routes(
        &fixture.inrelease_plain,
        "Packages",
        &fixture.packages,
        &fixture.deb,
    ));
    let base_url = mirror.base_url.clone();
    let pubkey = fixture.pubkey.clone();
    let packages_len = fixture.packages.len();

    let handle = thread::spawn(move || {
        let index = debian::sync_db(&base_url, SUITE, COMPONENT, Some(&pubkey))
            .expect("sync from worker thread");
        (index.packages.len(), index.packages_size, packages_len)
    });
    let (rows, advertised, served) = handle.join().expect("worker thread");
    assert_eq!(rows, 1);
    assert_eq!(advertised, served as u64);
}

/// Guard: the fixture `.deb` really is an ar archive, so the test data is
/// shaped like a Debian package rather than random bytes.
#[test]
fn fixture_deb_has_ar_layout() {
    let Some(fixture) = fixture() else { return };
    assert!(fixture.deb.starts_with(b"!<arch>\n"));
    let text = String::from_utf8_lossy(&fixture.deb);
    assert!(text.contains("debian-binary"));
    assert!(text.contains("control.tar.xz"));
    assert!(text.contains("data.tar.xz"));
}
