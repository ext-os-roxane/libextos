//! Integration tests for PLAN.md Sub-phase 3.4 — the RPM fetcher.
//!
//! Everything runs against a loopback `TcpListener` started by the test itself:
//! no public network is touched, and no fixture is committed. Repository
//! metadata (`repomd.xml`, `primary.xml`) and the `.rpm` payload are synthesized
//! at run time:
//!
//! * `.rpm` — lead + empty signature header + a main header carrying
//!   `NAME`/`VERSION`/`RELEASE`/`EPOCH`/`PROVIDENAME`, i.e. the exact shape the
//!   dependency-free parser in `libextos::rosetta::rpm` understands;
//! * `primary.xml` — generated from the row under test, plain or `.gz`;
//! * `repomd.xml` — points at the primary file with its real digest.
//!
//! The GPG test generates a throwaway key in a temporary `GNUPGHOME`, so gpg's
//! user keyring is never consulted. The bridge test is gated on a built
//! `libextos-rpm-bridge.so` plus `rpmbuild`; both are host capabilities, and an
//! absent one makes the test say so instead of passing silently.

use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use libextos::error::ExtosError;
use libextos::fetcher::rpm::{
    DigestAlgo, HeaderSource, RpmFetcher, SigCheck, SignatureStatus, read_header_with_bridge,
};

// ─── loopback mirror ────────────────────────────────────────────

/// Minimal multi-route HTTP/1.1 mirror served from a loopback `TcpListener`.
struct TestMirror {
    base_url: String,
    routes: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    requests: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl TestMirror {
    /// Start an empty mirror on an ephemeral loopback port.
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test mirror");
        let addr = listener.local_addr().expect("mirror address");
        listener
            .set_nonblocking(true)
            .expect("non-blocking mirror listener");

        let routes: Arc<Mutex<HashMap<String, Vec<u8>>>> = Arc::new(Mutex::new(HashMap::new()));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));

        let handle = {
            let routes = Arc::clone(&routes);
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
            routes,
            requests,
            stop,
            handle: Some(handle),
        }
    }

    /// Serve `body` at `path` (absolute path, e.g. `/repodata/repomd.xml`).
    fn route(&self, path: &str, body: impl Into<Vec<u8>>) {
        self.routes
            .lock()
            .expect("mirror routes")
            .insert(path.to_string(), body.into());
    }

    /// Paths requested so far, in arrival order.
    fn requests(&self) -> Vec<String> {
        self.requests.lock().expect("mirror request log").clone()
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

/// Read one request and write the matching canned response.
fn serve_one(
    stream: TcpStream,
    routes: &Mutex<HashMap<String, Vec<u8>>>,
    requests: &Mutex<Vec<String>>,
) {
    let mut writer = stream.try_clone().expect("clone mirror stream");
    let mut reader = BufReader::new(stream);

    let mut request_line = String::new();
    if reader.read_line(&mut request_line).is_err() {
        return;
    }
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

    let body = routes.lock().expect("mirror routes").get(&path).cloned();
    let written = match body {
        Some(bytes) => {
            let header = format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Type: application/octet-stream\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\r\n",
                bytes.len()
            );
            writer
                .write_all(header.as_bytes())
                .and_then(|()| writer.write_all(&bytes))
        }
        None => writer
            .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"),
    };
    let _ = written.and_then(|()| writer.flush());
}

// ─── fixtures ───────────────────────────────────────────────────

const LEAD_MAGIC: [u8; 4] = [0xED, 0xAB, 0xEE, 0xDB];
const HEADER_MAGIC: [u8; 4] = [0x8E, 0xAD, 0xE8, 0x01];
const LEAD_SIZE: usize = 96;

const RPMTAG_NAME: u32 = 1000;
const RPMTAG_VERSION: u32 = 1001;
const RPMTAG_RELEASE: u32 = 1002;
const RPMTAG_EPOCH: u32 = 1003;
const RPMTAG_PROVIDENAME: u32 = 1047;
const RPMTAG_REQUIRENAME: u32 = 1049;

const TYPE_INT32: u32 = 4;
const TYPE_STRING: u32 = 6;
const TYPE_STRING_ARRAY: u32 = 8;

/// Build one RPM header (index + data store) from `(tag, type, count, payload)`.
fn build_header(entries: &[(u32, u32, u32, Vec<u8>)]) -> Vec<u8> {
    let mut index = Vec::new();
    let mut data = Vec::new();
    for (tag, data_type, count, payload) in entries {
        index.extend_from_slice(&tag.to_be_bytes());
        index.extend_from_slice(&data_type.to_be_bytes());
        index.extend_from_slice(&(data.len() as u32).to_be_bytes());
        index.extend_from_slice(&count.to_be_bytes());
        data.extend_from_slice(payload);
    }
    let mut out = Vec::new();
    out.extend_from_slice(&HEADER_MAGIC);
    out.extend_from_slice(&0u32.to_be_bytes());
    out.extend_from_slice(&(entries.len() as u32).to_be_bytes());
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(&index);
    out.extend_from_slice(&data);
    out
}

/// Encode a string tag payload.
fn str_payload(value: &str) -> Vec<u8> {
    let mut out = value.as_bytes().to_vec();
    out.push(0);
    out
}

/// Encode a string-array tag payload.
fn arr_payload(values: &[&str]) -> Vec<u8> {
    let mut out = Vec::new();
    for value in values {
        out.extend_from_slice(&str_payload(value));
    }
    out
}

/// Synthesize a minimal but parser-valid `.rpm` byte image.
fn synthetic_rpm(name: &str, version: &str, release: &str) -> Vec<u8> {
    let mut rpm = Vec::new();
    rpm.extend_from_slice(&LEAD_MAGIC);
    rpm.extend_from_slice(&[0u8; LEAD_SIZE - 4]);
    // Signature header: empty index, empty data store.
    rpm.extend_from_slice(&build_header(&[]));
    rpm.extend_from_slice(&build_header(&[
        (RPMTAG_NAME, TYPE_STRING, 1, str_payload(name)),
        (RPMTAG_VERSION, TYPE_STRING, 1, str_payload(version)),
        (RPMTAG_RELEASE, TYPE_STRING, 1, str_payload(release)),
        (RPMTAG_EPOCH, TYPE_INT32, 1, 0u32.to_be_bytes().to_vec()),
        (
            RPMTAG_PROVIDENAME,
            TYPE_STRING_ARRAY,
            1,
            arr_payload(&[name]),
        ),
        (
            RPMTAG_REQUIRENAME,
            TYPE_STRING_ARRAY,
            1,
            arr_payload(&["glibc"]),
        ),
    ]));
    rpm
}

/// One row of a generated `primary.xml`.
struct Row<'a> {
    name: &'a str,
    epoch: u32,
    version: &'a str,
    release: &'a str,
    arch: &'a str,
    href: &'a str,
    checksum: String,
    size: u64,
}

/// Render a `primary.xml` document with a single package.
fn primary_xml(row: &Row<'_>) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<metadata xmlns="http://linux.duke.edu/metadata/common"
          xmlns:rpm="http://linux.duke.edu/metadata/rpm" packages="1">
  <package type="rpm">
    <name>{name}</name>
    <arch>{arch}</arch>
    <version epoch="{epoch}" ver="{version}" rel="{release}"/>
    <checksum type="sha256" pkgid="YES">{checksum}</checksum>
    <summary>fixture</summary>
    <size package="{size}" installed="0" archive="0"/>
    <location href="{href}"/>
    <format>
      <rpm:provides>
        <rpm:entry name="{name}" flags="EQ" epoch="{epoch}" ver="{version}" rel="{release}"/>
      </rpm:provides>
      <rpm:requires>
        <rpm:entry name="glibc" flags="GE" ver="2.38"/>
      </rpm:requires>
    </format>
  </package>
</metadata>
"#,
        name = row.name,
        arch = row.arch,
        epoch = row.epoch,
        version = row.version,
        release = row.release,
        checksum = row.checksum,
        size = row.size,
        href = row.href,
    )
}

/// Render a `repomd.xml` pointing at `primary_href`.
fn repomd_xml(
    primary_href: &str,
    checksum: &str,
    size: u64,
    open_checksum: Option<&str>,
) -> String {
    let open = match open_checksum {
        Some(value) => format!("<open-checksum type=\"sha256\">{value}</open-checksum>"),
        None => String::new(),
    };
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<repomd xmlns="http://linux.duke.edu/metadata/repo">
  <revision>1700000000</revision>
  <data type="primary">
    <checksum type="sha256">{checksum}</checksum>
    {open}
    <location href="{primary_href}"/>
    <timestamp>1700000000</timestamp>
    <size>{size}</size>
  </data>
</repomd>
"#
    )
}

/// Fixture bundle: the synthesized rpm plus the primary/repomd documents.
struct Fixture {
    rpm: Vec<u8>,
    primary: String,
    repomd: String,
    href: &'static str,
}

impl Fixture {
    /// Build the standard `hello-1.0-1.x86_64` fixture.
    fn hello() -> Self {
        let rpm = synthetic_rpm("hello", "1.0", "1");
        let href = "Packages/h/hello-1.0-1.x86_64.rpm";
        let checksum = DigestAlgo::Sha256.of_bytes(&rpm);
        let row = Row {
            name: "hello",
            epoch: 0,
            version: "1.0",
            release: "1",
            arch: "x86_64",
            href,
            checksum: checksum.clone(),
            size: rpm.len() as u64,
        };
        let primary = primary_xml(&row);
        let repomd = repomd_xml(
            "repodata/abc-primary.xml",
            &DigestAlgo::Sha256.of_bytes(primary.as_bytes()),
            primary.len() as u64,
            Some(&DigestAlgo::Sha256.of_bytes(primary.as_bytes())),
        );
        Self {
            rpm,
            primary,
            repomd,
            href,
        }
    }
}

/// A fetcher bound to `mirror` with a private cache directory.
fn fetcher(mirror: &TestMirror, cache: &Path) -> RpmFetcher {
    RpmFetcher::new(mirror.base_url.clone(), cache).expect("fetcher")
}

/// `true` when `tool --version` succeeds.
fn have_tool(tool: &str) -> bool {
    Command::new(tool)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

/// `data` piped through `gzip -c`.
fn gzip(data: &[u8]) -> Option<Vec<u8>> {
    if !have_tool("gzip") {
        return None;
    }
    let mut child = Command::new("gzip")
        .arg("-c")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .ok()?;
    child.stdin.take()?.write_all(data).ok()?;
    Some(child.wait_with_output().ok()?.stdout)
}

// ─── sync_db ────────────────────────────────────────────────────

#[test]
fn sync_db_parses_a_plain_primary_index() {
    let mirror = TestMirror::start();
    let fixture = Fixture::hello();
    mirror.route("/repodata/repomd.xml", fixture.repomd.clone());
    mirror.route("/repodata/abc-primary.xml", fixture.primary.clone());
    let cache = tempfile::tempdir().expect("cache");

    let index = fetcher(&mirror, cache.path())
        .sync_db(None)
        .expect("sync_db");

    assert_eq!(index.revision, "1700000000");
    assert_eq!(index.primary_href, "repodata/abc-primary.xml");
    assert!(!index.signature_verified());
    assert_eq!(index.packages.len(), 1);
    let row = &index.packages[0];
    assert_eq!(row.nvra.name, "hello");
    assert_eq!(row.nvra.evr(), "0:1.0-1");
    assert_eq!(row.nvra.arch, "x86_64");
    assert_eq!(row.size, fixture.rpm.len() as u64);
    assert_eq!(row.relpath, fixture.href);
    assert_eq!(row.requires, vec!["glibc".to_string()]);
    assert_eq!(
        row.checksum.as_ref().map(|sum| sum.hex.clone()),
        Some(DigestAlgo::Sha256.of_bytes(&fixture.rpm))
    );

    // The index kept the repomd bytes for later re-verification.
    assert_eq!(index.repomd_doc(), fixture.repomd.as_bytes());
}

#[test]
fn sync_db_decompresses_a_gz_primary_index() {
    let mirror = TestMirror::start();
    let fixture = Fixture::hello();
    let Some(compressed) = gzip(fixture.primary.as_bytes()) else {
        eprintln!("skipping: gzip is not available");
        return;
    };
    let repomd = repomd_xml(
        "repodata/abc-primary.xml.gz",
        &DigestAlgo::Sha256.of_bytes(&compressed),
        compressed.len() as u64,
        Some(&DigestAlgo::Sha256.of_bytes(fixture.primary.as_bytes())),
    );
    mirror.route("/repodata/repomd.xml", repomd);
    mirror.route("/repodata/abc-primary.xml.gz", compressed);
    let cache = tempfile::tempdir().expect("cache");

    let index = fetcher(&mirror, cache.path())
        .sync_db(None)
        .expect("sync_db");
    assert_eq!(index.packages.len(), 1);
    assert_eq!(index.primary_href, "repodata/abc-primary.xml.gz");
}

#[test]
fn sync_db_rejects_a_tampered_primary_index() {
    let mirror = TestMirror::start();
    let mut fixture = Fixture::hello();
    // Advertise a digest that does not match the served bytes.
    let primary = fixture.primary.replace("fixture", "tampered");
    assert_ne!(primary, fixture.primary);
    fixture.primary = primary;
    mirror.route("/repodata/repomd.xml", fixture.repomd.clone());
    mirror.route("/repodata/abc-primary.xml", fixture.primary.clone());
    let cache = tempfile::tempdir().expect("cache");

    let err = fetcher(&mirror, cache.path())
        .sync_db(None)
        .expect_err("tampered index must fail");
    assert!(
        matches!(err, ExtosError::CasIntegrity { .. }),
        "expected CasIntegrity, got {err:?}"
    );
}

#[test]
fn sync_db_without_repomd_is_package_not_found() {
    let mirror = TestMirror::start();
    let cache = tempfile::tempdir().expect("cache");

    let err = fetcher(&mirror, cache.path())
        .sync_db(None)
        .expect_err("empty mirror must fail");
    assert!(
        matches!(err, ExtosError::PackageNotFound { .. }),
        "expected PackageNotFound, got {err:?}"
    );
}

#[test]
fn sync_db_requires_a_signature_when_a_key_is_supplied() {
    let mirror = TestMirror::start();
    let fixture = Fixture::hello();
    mirror.route("/repodata/repomd.xml", fixture.repomd.clone());
    mirror.route("/repodata/abc-primary.xml", fixture.primary.clone());
    let cache = tempfile::tempdir().expect("cache");

    let err = fetcher(&mirror, cache.path())
        .sync_db(Some(b"-----BEGIN PGP PUBLIC KEY BLOCK-----"))
        .expect_err("unsigned mirror must fail when a key is demanded");
    assert!(
        matches!(err, ExtosError::CasIntegrity { .. }),
        "expected CasIntegrity, got {err:?}"
    );
}

// ─── download ───────────────────────────────────────────────────

#[test]
fn download_verifies_digest_and_reads_the_header() {
    let mirror = TestMirror::start();
    let fixture = Fixture::hello();
    mirror.route("/repodata/repomd.xml", fixture.repomd.clone());
    mirror.route("/repodata/abc-primary.xml", fixture.primary.clone());
    mirror.route(&format!("/{}", fixture.href), fixture.rpm.clone());
    let cache = tempfile::tempdir().expect("cache");
    let fetcher = fetcher(&mirror, cache.path());

    let index = fetcher.sync_db(None).expect("sync_db");
    let downloaded = fetcher
        .download(&index, "hello", "1.0-1", SigCheck::Skip)
        .expect("download");

    assert!(downloaded.path.is_file());
    assert_eq!(downloaded.size, fixture.rpm.len() as u64);
    assert_eq!(downloaded.sha256, DigestAlgo::Sha256.of_bytes(&fixture.rpm));
    assert_eq!(downloaded.nvra.name, "hello");
    assert!(downloaded.source_url.ends_with(fixture.href));

    let header = downloaded.header.expect("header was read");
    assert_eq!(header.nvra.name, "hello");
    assert_eq!(header.nvra.version, "1.0");
    assert_eq!(header.nvra.release, "1");
    // Whatever reader was available, an unsigned fixture cannot be "verified".
    assert_ne!(header.signature, SignatureStatus::Verified);

    // Second call must be answered from the cache, not the mirror.
    let before = mirror.requests().len();
    let again = fetcher
        .download(&index, "hello", "0:1.0-1", SigCheck::Skip)
        .expect("cached download");
    assert_eq!(again.path, downloaded.path);
    assert_eq!(
        mirror.requests().len(),
        before,
        "a verified cache hit must not hit the mirror again"
    );
}

#[test]
fn download_rejects_a_row_with_a_wrong_digest() {
    let mirror = TestMirror::start();
    let fixture = Fixture::hello();
    let bad_checksum = "0".repeat(64);
    let row = Row {
        name: "hello",
        epoch: 0,
        version: "1.0",
        release: "1",
        arch: "x86_64",
        href: fixture.href,
        checksum: bad_checksum,
        size: fixture.rpm.len() as u64,
    };
    let primary = primary_xml(&row);
    let repomd = repomd_xml(
        "repodata/abc-primary.xml",
        &DigestAlgo::Sha256.of_bytes(primary.as_bytes()),
        primary.len() as u64,
        None,
    );
    mirror.route("/repodata/repomd.xml", repomd);
    mirror.route("/repodata/abc-primary.xml", primary);
    mirror.route(&format!("/{}", fixture.href), fixture.rpm.clone());
    let cache = tempfile::tempdir().expect("cache");
    let fetcher = fetcher(&mirror, cache.path());

    let index = fetcher.sync_db(None).expect("sync_db");
    let err = fetcher
        .download(&index, "hello", "1.0-1", SigCheck::Skip)
        .expect_err("wrong digest must fail");
    assert!(
        matches!(err, ExtosError::CasIntegrity { .. }),
        "expected CasIntegrity, got {err:?}"
    );
    // The failed download must not leave a file behind.
    assert!(!downloaded_path(cache.path(), fixture.href).exists());
}

#[test]
fn download_of_a_missing_package_is_not_found() {
    let mirror = TestMirror::start();
    let fixture = Fixture::hello();
    mirror.route("/repodata/repomd.xml", fixture.repomd.clone());
    mirror.route("/repodata/abc-primary.xml", fixture.primary.clone());
    let cache = tempfile::tempdir().expect("cache");
    let fetcher = fetcher(&mirror, cache.path());

    let index = fetcher.sync_db(None).expect("sync_db");
    let err = fetcher
        .download(&index, "hello", "1.0-1", SigCheck::Skip)
        .expect_err("404 must fail");
    assert!(
        matches!(err, ExtosError::PackageNotFound { .. }),
        "expected PackageNotFound, got {err:?}"
    );

    let err = fetcher
        .download(&index, "ghost", "1.0", SigCheck::Skip)
        .expect_err("unknown row must fail");
    assert!(matches!(err, ExtosError::PackageNotFound { .. }));
}

/// Where a relpath is cached.
fn downloaded_path(cache: &Path, relpath: &str) -> PathBuf {
    let name = relpath.rsplit('/').next().unwrap_or(relpath);
    cache.join(name)
}

// ─── gpg-signed metadata ────────────────────────────────────────

/// Generate a throwaway key, sign `repomd.xml`, and return
/// `(public key, detached signature)`. `None` when gpg is unavailable.
fn sign_repomd(repomd: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    if !have_tool("gpg") {
        return None;
    }
    let home = tempfile::tempdir().ok()?;
    let run = |args: &[&str]| {
        Command::new("gpg")
            .arg("--homedir")
            .arg(home.path())
            .args(["--batch", "--no-tty", "--no-options", "--quiet"])
            .args(args)
            .stdin(Stdio::null())
            .output()
            .ok()
    };

    let generated = run(&[
        "--passphrase",
        "",
        "--quick-generate-key",
        "ExtOS RPM Test <rpm-test@extos.invalid>",
        "ed25519",
        "sign",
        "0",
    ])?;
    if !generated.status.success() {
        eprintln!(
            "skipping: gpg cannot generate a test key: {}",
            String::from_utf8_lossy(&generated.stderr)
        );
        return None;
    }

    let doc = home.path().join("repomd.xml");
    let sig = home.path().join("repomd.xml.asc");
    fs::write(&doc, repomd).ok()?;
    let signed = run(&[
        "--detach-sign",
        "--armor",
        "--output",
        &sig.to_string_lossy(),
        &doc.to_string_lossy(),
    ])?;
    if !signed.status.success() {
        eprintln!("skipping: gpg could not sign the fixture");
        return None;
    }
    let exported = run(&["--armor", "--export", "rpm-test@extos.invalid"])?;
    if !exported.status.success() || exported.stdout.is_empty() {
        eprintln!("skipping: gpg could not export the test key");
        return None;
    }
    Some((exported.stdout, fs::read(&sig).ok()?))
}

#[test]
fn sync_db_verifies_a_signed_repomd() {
    let mirror = TestMirror::start();
    let fixture = Fixture::hello();
    let Some((key, signature)) = sign_repomd(fixture.repomd.as_bytes()) else {
        eprintln!("skipping: gpg test key unavailable");
        return;
    };
    mirror.route("/repodata/repomd.xml", fixture.repomd.clone());
    mirror.route("/repodata/repomd.xml.asc", signature);
    mirror.route("/repodata/abc-primary.xml", fixture.primary.clone());
    mirror.route(&format!("/{}", fixture.href), fixture.rpm.clone());
    let cache = tempfile::tempdir().expect("cache");
    let fetcher = fetcher(&mirror, cache.path());

    let index = fetcher.sync_db(Some(&key)).expect("signed sync_db");
    assert!(index.signature_verified());
    assert!(index.repomd_signature().is_some());
    assert_eq!(index.packages.len(), 1);

    // The same key re-verifies the stored document during a Key download; the
    // package itself is unsigned, so the chain stops with a typed integrity
    // error rather than a silent success.
    let err = fetcher
        .download(&index, "hello", "1.0-1", SigCheck::Key(&key))
        .expect_err("unsigned package cannot pass a Key check");
    assert!(
        matches!(
            err,
            ExtosError::CasIntegrity { .. } | ExtosError::ConfigParse { .. }
        ),
        "expected CasIntegrity/ConfigParse, got {err:?}"
    );
}

#[test]
fn sync_db_rejects_a_tampered_signed_repomd() {
    let mirror = TestMirror::start();
    let fixture = Fixture::hello();
    let Some((key, signature)) = sign_repomd(fixture.repomd.as_bytes()) else {
        eprintln!("skipping: gpg test key unavailable");
        return;
    };
    let tampered = fixture.repomd.replace("1700000000", "1700000001");
    mirror.route("/repodata/repomd.xml", tampered);
    mirror.route("/repodata/repomd.xml.asc", signature);
    mirror.route("/repodata/abc-primary.xml", fixture.primary.clone());
    let cache = tempfile::tempdir().expect("cache");

    let err = fetcher(&mirror, cache.path())
        .sync_db(Some(&key))
        .expect_err("tampered repomd must fail");
    assert!(
        matches!(err, ExtosError::CasIntegrity { .. }),
        "expected CasIntegrity, got {err:?}"
    );
}

// ─── librpm bridge (gated on host capabilities) ─────────────────

/// Locate the fork's bridge without hardcoding a host path.
fn bridge_path() -> Option<PathBuf> {
    if let Some(value) = std::env::var_os(libextos::fetcher::rpm::BRIDGE_ENV) {
        let path = PathBuf::from(value);
        if path.is_file() {
            return Some(path);
        }
    }
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let candidate =
        manifest_dir.join("../../inherited/librpm-extos/extos/build/libextos-rpm-bridge.so");
    candidate
        .is_file()
        .then(|| candidate.canonicalize().unwrap_or(candidate))
}

#[test]
fn bridge_reads_a_real_rpm_when_available() {
    let Some(bridge) = bridge_path() else {
        eprintln!(
            "skipping: no libextos-rpm-bridge.so (build it with \
             inherited/librpm-extos/extos/build-bridge.sh)"
        );
        return;
    };
    if !have_tool("rpmbuild") {
        eprintln!("skipping: rpmbuild is not available to build a real RPM fixture");
        return;
    }

    let dir = tempfile::tempdir().expect("tempdir");
    let topdir = dir.path().join("top");
    for sub in ["BUILD", "RPMS", "SOURCES", "SPECS", "SRPMS", "BUILDROOT"] {
        fs::create_dir_all(topdir.join(sub)).expect("rpmbuild tree");
    }
    let spec = dir.path().join("hello.spec");
    fs::write(
        &spec,
        "Name: hello\nVersion: 1.0\nRelease: 3\nSummary: hello\nLicense: MIT\n\
         BuildArch: x86_64\n%description\nhello\n%prep\n%build\n%install\n%files\n",
    )
    .expect("spec");
    let output = Command::new("rpmbuild")
        .arg("--define")
        .arg(format!("_topdir {}", topdir.display()))
        .arg("-bb")
        .arg(&spec)
        .stdin(Stdio::null())
        .output()
        .expect("run rpmbuild");
    assert!(
        output.status.success(),
        "rpmbuild failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let rpm = topdir.join("RPMS/x86_64/hello-1.0-3.x86_64.rpm");
    assert!(
        rpm.is_file(),
        "rpmbuild produced no package at {}",
        rpm.display()
    );

    let report = read_header_with_bridge(&bridge, &rpm, None).expect("bridge header read");
    assert_eq!(report.source, HeaderSource::LibrpmBridge);
    assert_eq!(report.nvra.name, "hello");
    assert_eq!(report.nvra.version, "1.0");
    assert_eq!(report.nvra.release, "3");
    assert_eq!(report.nvra.arch, "x86_64");
    // Unsigned fixture: digests are fine, but there is no signature to trust.
    assert_eq!(report.signature, SignatureStatus::Unsigned);
    assert!(
        report.provides.iter().any(|cap| cap == "hello"),
        "provides should include the package name: {:?}",
        report.provides
    );
}
