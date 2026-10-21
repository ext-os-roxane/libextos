//! Integration tests for the libalpm-backed Arch fetcher (PLAN 3.2.7).
//!
//! Everything here runs against a loopback mirror started by the test itself
//! (the same std-only `TcpListener` pattern as `core/pkt/tests/cli.rs`), so no
//! test touches the public network. The one exception is
//! `real_mirror_when_enabled()`, which is gated behind
//! `EXTOS_TEST_ALPM_NETWORK=1` and prints an explicit skip line otherwise.
//!
//! Fixtures are synthesized at runtime -- a gzip tar archive in pacman db
//! layout (`<name>-<ver>/desc`) plus an opaque package payload -- so no blob is
//! committed. Signatures are produced with a throwaway GnuPG home created per
//! test; `gpg` is an external tool, so signature tests print a skip line when it
//! is missing instead of failing.
//!
//! Which libalpm is exercised: whatever `EXTOS_ALPM_LIB`,
//! `EXTOS_PACMAN_BUILD_DIR` or the system loader resolves (see the
//! `fetcher::alpm` module docs). Every passing test prints the version string
//! and the source path reported by the fetcher, so a run states it honestly.

use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use libextos::fetcher::alpm::{AlpmFetch, AlpmFetchError, SigCheck};

/// Package name used by every fixture.
const PKG_NAME: &str = "hello";
/// Package version used by every fixture.
const PKG_VERSION: &str = "1.0.0-1";
/// Package archive name used by every fixture.
const PKG_FILENAME: &str = "hello-1.0.0-1-x86_64.pkg.tar.zst";

// ---- loopback mirror -------------------------------------------------------

/// A std-only HTTP/1.1 mirror serving a fixed path -> body map.
///
/// Unknown paths answer `404 Not Found`, which is what the fetcher's
/// `SigCheck::Optional` policy and the missing-database test rely on.
struct TestMirror {
    base_url: String,
    requests: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl TestMirror {
    /// Serve `routes` (request path -> body) on an ephemeral loopback port.
    fn start(routes: HashMap<String, Vec<u8>>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback mirror");
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
                        Err(ref error) if error.kind() == std::io::ErrorKind::WouldBlock => {
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
}

impl Drop for TestMirror {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Read one request and write the canned response, then close the connection.
fn serve_one(stream: TcpStream, routes: &HashMap<String, Vec<u8>>, requests: &Mutex<Vec<String>>) {
    let mut writer = stream.try_clone().expect("clone mirror stream");
    let mut reader = BufReader::new(stream);

    let mut request_line = String::new();
    if reader.read_line(&mut request_line).is_err() {
        return;
    }
    // Drain the header block; the request body is irrelevant (GET only).
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

    let response = match routes.get(&path) {
        Some(body) => {
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            writer
                .write_all(header.as_bytes())
                .and_then(|()| writer.write_all(body))
        }
        None => writer
            .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"),
    };
    let _ = response.and_then(|()| writer.flush());
}

// ---- fixtures -------------------------------------------------------------

/// Opaque package payload; the tests only compare bytes.
fn package_payload() -> Vec<u8> {
    let mut payload = Vec::with_capacity(4 * 1024);
    payload.extend_from_slice(b"EXTOS-ALPM-TEST-PAYLOAD\n");
    for index in 0..1024u32 {
        payload.extend_from_slice(&index.to_le_bytes());
    }
    payload
}

/// One `<name>-<version>/desc` entry of a pacman sync database.
struct DbEntry<'a> {
    /// Package name (`%NAME%` and the entry directory prefix).
    name: &'a str,
    /// Full version (`%VERSION%`), `pkgver-pkgrel`.
    version: &'a str,
    /// Archive file name (`%FILENAME%`).
    filename: &'a str,
    /// Compressed size (`%CSIZE%`).
    csize: u64,
}

/// Render the `desc` body libalpm parses for one database entry.
fn desc_text(entry: &DbEntry<'_>) -> String {
    format!(
        "%NAME%\n{}\n\n%VERSION%\n{}\n\n%FILENAME%\n{}\n\n%CSIZE%\n{}\n\n%ISIZE%\n{}\n\n",
        entry.name,
        entry.version,
        entry.filename,
        entry.csize,
        entry.csize * 2,
    )
}

/// Build a one-package (or empty) `.db` archive: a gzip-compressed ustar tar
/// with pacman sync-database layout. Written by hand so the test needs no
/// compression crate and commits no blob.
fn sync_db_archive(entries: &[DbEntry<'_>]) -> Vec<u8> {
    let mut tar = Vec::new();
    for entry in entries {
        let name = format!("{}-{}/desc", entry.name, entry.version);
        let body = desc_text(entry);
        tar.extend_from_slice(&tar_header(&name, body.len() as u64));
        tar.extend_from_slice(body.as_bytes());
        let padding = (512 - body.len() % 512) % 512;
        tar.resize(tar.len() + padding, 0);
    }
    // Two zero blocks terminate a tar archive.
    tar.resize(tar.len() + 1024, 0);
    gzip_stored(&tar)
}

/// Build a `ustar` header for one regular file of `size` bytes.
fn tar_header(name: &str, size: u64) -> [u8; 512] {
    let mut header = [0u8; 512];
    assert!(name.len() < 100, "tar entry name is too long: {name}");
    header[..name.len()].copy_from_slice(name.as_bytes());
    write_octal(&mut header[100..108], 0o644); // mode
    write_octal(&mut header[108..116], 0); // uid
    write_octal(&mut header[116..124], 0); // gid
    write_octal(&mut header[124..136], size); // size
    write_octal(&mut header[136..148], 0); // mtime
    header[156] = b'0'; // regular file
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");

    // Checksum: the sum of every header byte with the checksum field read as
    // spaces, written as six octal digits, NUL, space.
    let checksum: u32 = header
        .iter()
        .enumerate()
        .map(|(index, byte)| {
            if (148..156).contains(&index) {
                u32::from(b' ')
            } else {
                u32::from(*byte)
            }
        })
        .sum();
    let text = format!("{checksum:06o}");
    header[148..154].copy_from_slice(text.as_bytes());
    header[154] = 0;
    header[155] = b' ';
    header
}

/// Write `value` as zero-padded octal into `field`, NUL-terminated.
fn write_octal(field: &mut [u8], value: u64) {
    let width = field.len() - 1;
    let text = format!("{value:0width$o}");
    assert!(text.len() <= width, "octal field overflow in tar header");
    let start = width - text.len();
    field[..start].fill(b'0');
    field[start..width].copy_from_slice(text.as_bytes());
    field[width] = 0;
}

/// Wrap `data` in a gzip container using only stored (uncompressed) deflate
/// blocks, which libarchive reads like any other gzip member.
fn gzip_stored(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x1f, 0x8b, 0x08, 0x00, 0, 0, 0, 0, 0x00, 0xff];
    let mut chunks = data.chunks(65_535).peekable();
    if chunks.peek().is_none() {
        out.extend_from_slice(&[0x01, 0x00, 0x00, 0xff, 0xff]);
    }
    while let Some(chunk) = chunks.next() {
        let last = chunks.peek().is_none();
        out.push(u8::from(last));
        let length = chunk.len() as u16;
        out.extend_from_slice(&length.to_le_bytes());
        out.extend_from_slice(&(!length).to_le_bytes());
        out.extend_from_slice(chunk);
    }
    out.extend_from_slice(&crc32(data).to_le_bytes());
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out
}

/// CRC-32/ISO-HDLC, as required by the gzip trailer.
fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0xedb8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// A throwaway GnuPG home holding one signing key.
///
/// Signature tests need the `gpg` binary; when it is absent they print a skip
/// line instead of failing, so the suite still runs on a minimal host.
struct GpgHome {
    dir: tempfile::TempDir,
}

impl GpgHome {
    /// Create a fresh home and an unprotected ed25519 signing key.
    fn new() -> Option<Self> {
        let probe = Command::new("gpg")
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .ok()?;
        if !probe.success() {
            return None;
        }
        let dir = tempfile::tempdir().ok()?;
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).ok()?;
        let generated = Command::new("gpg")
            .arg("--homedir")
            .arg(dir.path())
            .args([
                "--batch",
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                "",
                "--quick-generate-key",
                "ExtOS ALPM test <alpm-test@extos.invalid>",
                "ed25519",
                "sign",
                "never",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .ok()?;
        generated.success().then_some(Self { dir })
    }

    /// The home directory to hand to the fetcher.
    fn path(&self) -> &Path {
        self.dir.path()
    }

    /// Produce a detached signature over `bytes`.
    fn sign(&self, bytes: &[u8]) -> Vec<u8> {
        let scratch = tempfile::tempdir().expect("signature scratch directory");
        let payload = scratch.path().join("payload");
        let signature = scratch.path().join("payload.sig");
        fs::write(&payload, bytes).expect("write payload to sign");
        let status = Command::new("gpg")
            .arg("--homedir")
            .arg(self.path())
            .args([
                "--batch",
                "--yes",
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                "",
                "--detach-sign",
                "--output",
            ])
            .arg(&signature)
            .arg(&payload)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("run gpg --detach-sign");
        assert!(status.success(), "gpg --detach-sign failed");
        fs::read(&signature).expect("read detached signature")
    }
}

/// Build the path -> body map a [`TestMirror`] serves.
///
/// Paths are taken as `AsRef<str>` so call sites can pass computed routes
/// (`&format!(...)`) without binding a local first.
fn routes<I, P>(entries: I) -> HashMap<String, Vec<u8>>
where
    I: IntoIterator<Item = (P, Vec<u8>)>,
    P: AsRef<str>,
{
    entries
        .into_iter()
        .map(|(path, body)| (path.as_ref().to_string(), body))
        .collect()
}

/// Open a fetcher on `dbpath`, or print a skip line when libalpm is missing.
///
/// The version and source are printed so a run states which library the tests
/// exercised (fork build when `EXTOS_PACMAN_BUILD_DIR` points at one).
fn fetcher(dbpath: &Path) -> Option<AlpmFetch> {
    match AlpmFetch::new(dbpath) {
        Ok(fetcher) => {
            println!(
                "libalpm {} loaded from {}",
                fetcher.library_version(),
                fetcher.library_source()
            );
            Some(fetcher)
        }
        Err(error) => {
            println!("skip: libalpm unavailable ({error})");
            None
        }
    }
}

/// The path a package archive is served from on the mirror.
fn package_route() -> String {
    format!("/{}/{PKG_FILENAME}", "core")
}

// ---- tests ----------------------------------------------------------------

#[test]
fn sync_and_download_chain() {
    let work = tempfile::tempdir().expect("work directory");
    let payload = package_payload();
    let db = sync_db_archive(&[DbEntry {
        name: PKG_NAME,
        version: PKG_VERSION,
        filename: PKG_FILENAME,
        csize: payload.len() as u64,
    }]);
    let mirror = TestMirror::start(routes(vec![
        ("/core.db", db),
        (&package_route(), payload.clone()),
    ]));

    let Some(mut fetch) = fetcher(&work.path().join("alpm")) else {
        return;
    };
    let synced = fetch
        .sync_db(&mirror.base_url, SigCheck::Skip)
        .expect("synchronize the loopback database");
    assert_eq!(synced.repo(), "core");
    assert_eq!(synced.package_count(), 1);
    assert!(synced.db_path().is_file(), "database must be committed");
    assert_eq!(synced.base_url(), mirror.base_url);

    let archive = fetch
        .download(PKG_NAME, Some(PKG_VERSION), SigCheck::Skip)
        .expect("download the package");
    assert!(archive.is_file(), "archive must be committed");
    assert_eq!(fs::read(&archive).expect("read archive"), payload);
    assert!(
        archive.starts_with(fetch.cache_dir()),
        "archive {} is outside {}",
        archive.display(),
        fetch.cache_dir().display()
    );

    let requests = mirror.requests();
    assert_eq!(requests.first().map(String::as_str), Some("/core.db"));
    assert!(
        requests.iter().any(|path| path == &package_route()),
        "package route was not requested: {requests:?}"
    );
}

#[test]
fn required_signatures_are_verified() {
    let Some(home) = GpgHome::new() else {
        println!("skip: gpg is not installed, signature verification not exercised");
        return;
    };
    let work = tempfile::tempdir().expect("work directory");
    let payload = package_payload();
    let db = sync_db_archive(&[DbEntry {
        name: PKG_NAME,
        version: PKG_VERSION,
        filename: PKG_FILENAME,
        csize: payload.len() as u64,
    }]);
    let db_sig = home.sign(&db);
    let package_sig = home.sign(&payload);

    let mut served: Vec<(String, Vec<u8>)> = vec![
        (String::from("/core.db"), db),
        (String::from("/core.db.sig"), db_sig),
        (package_route(), payload.clone()),
    ];
    let package_sig_route = format!("{}.sig", package_route());
    served.push((package_sig_route.clone(), package_sig));
    let mirror = TestMirror::start(routes(served));

    let Some(fetch) = fetcher(&work.path().join("alpm")) else {
        return;
    };
    let mut fetch = fetch.with_gnupg_home(home.path());
    fetch
        .sync_db(&mirror.base_url, SigCheck::Required)
        .expect("signed database must verify");
    let archive = fetch
        .download(PKG_NAME, Some(PKG_VERSION), SigCheck::Required)
        .expect("signed package must verify");
    assert_eq!(fs::read(&archive).expect("read archive"), payload);

    let requests = mirror.requests();
    assert!(requests.iter().any(|path| path == "/core.db.sig"));
    assert!(requests.iter().any(|path| path == &package_sig_route));

    for directory in [fetch.dbpath().join("sync"), fetch.cache_dir().to_path_buf()] {
        for entry in fs::read_dir(&directory).expect("read staging directory") {
            let path = entry.expect("directory entry").path();
            let name = path.file_name().unwrap_or_default().to_string_lossy();
            assert!(
                !name.contains(".part"),
                "staging file left behind: {}",
                path.display()
            );
        }
    }
}

#[test]
fn bad_signature_is_rejected() {
    let Some(home) = GpgHome::new() else {
        println!("skip: gpg is not installed, signature verification not exercised");
        return;
    };
    let work = tempfile::tempdir().expect("work directory");
    let db = sync_db_archive(&[DbEntry {
        name: PKG_NAME,
        version: PKG_VERSION,
        filename: PKG_FILENAME,
        csize: 42,
    }]);
    // A valid signature, but over bytes the mirror never serves.
    let wrong_sig = home.sign(b"a different database\n");
    let mirror = TestMirror::start(routes(vec![("/core.db", db), ("/core.db.sig", wrong_sig)]));

    let Some(fetch) = fetcher(&work.path().join("alpm")) else {
        return;
    };
    let mut fetch = fetch.with_gnupg_home(home.path());
    let error = fetch
        .sync_db(&mirror.base_url, SigCheck::Required)
        .err()
        .expect("a signature over different bytes must be rejected");
    assert!(
        matches!(error, AlpmFetchError::Signature { .. }),
        "unexpected error: {error}"
    );

    let sync_dir = fetch.dbpath().join("sync");
    assert!(
        !sync_dir.join("core.db").exists(),
        "a rejected database must not be committed"
    );
    assert!(
        !sync_dir.join("core.db.part").exists(),
        "staging file must be removed on failure"
    );
    assert!(
        !sync_dir.join("core.db.part.sig").exists(),
        "staging signature must be removed on failure"
    );
}

#[test]
fn missing_repository_database_reports_http_status() {
    let work = tempfile::tempdir().expect("work directory");
    let mirror = TestMirror::start(routes(Vec::<(&str, Vec<u8>)>::new()));

    let Some(mut fetch) = fetcher(&work.path().join("alpm")) else {
        return;
    };
    let error = fetch
        .sync_db(&mirror.base_url, SigCheck::Skip)
        .err()
        .expect("a mirror without core.db must fail");
    match error {
        AlpmFetchError::HttpStatus { status, .. } => assert_eq!(status, 404),
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn unknown_package_reports_package_not_found() {
    let work = tempfile::tempdir().expect("work directory");
    let db = sync_db_archive(&[DbEntry {
        name: PKG_NAME,
        version: PKG_VERSION,
        filename: PKG_FILENAME,
        csize: 1,
    }]);
    let mirror = TestMirror::start(routes(vec![("/core.db", db)]));

    let Some(mut fetch) = fetcher(&work.path().join("alpm")) else {
        return;
    };
    fetch
        .sync_db(&mirror.base_url, SigCheck::Skip)
        .expect("synchronize the loopback database");

    let error = fetch
        .download("absent", None, SigCheck::Skip)
        .err()
        .expect("an unknown package must fail");
    match error {
        AlpmFetchError::PackageNotFound { name, repo } => {
            assert_eq!(name, "absent");
            assert_eq!(repo, "core");
        }
        other => panic!("unexpected error: {other}"),
    }

    let error = fetch
        .download(PKG_NAME, Some("9.9.9-9"), SigCheck::Skip)
        .err()
        .expect("an unknown version must fail");
    assert!(
        matches!(error, AlpmFetchError::VersionNotFound { .. }),
        "unexpected error: {error}"
    );
}

#[test]
fn size_mismatch_is_detected() {
    let work = tempfile::tempdir().expect("work directory");
    let payload = package_payload();
    let declared = payload.len() as u64 + 17;
    let db = sync_db_archive(&[DbEntry {
        name: PKG_NAME,
        version: PKG_VERSION,
        filename: PKG_FILENAME,
        csize: declared,
    }]);
    let mirror = TestMirror::start(routes(vec![
        ("/core.db", db),
        (&package_route(), payload.clone()),
    ]));

    let Some(mut fetch) = fetcher(&work.path().join("alpm")) else {
        return;
    };
    fetch
        .sync_db(&mirror.base_url, SigCheck::Skip)
        .expect("synchronize the loopback database");

    let error = fetch
        .download(PKG_NAME, None, SigCheck::Skip)
        .err()
        .expect("a truncated transfer must fail");
    match error {
        AlpmFetchError::SizeMismatch {
            expected, actual, ..
        } => {
            assert_eq!(expected, declared);
            assert_eq!(actual, payload.len() as u64);
        }
        other => panic!("unexpected error: {other}"),
    }
    assert!(
        !fetch.cache_dir().join(PKG_FILENAME).exists(),
        "a size-mismatched archive must not be committed"
    );
}

#[test]
fn download_before_sync_db_is_rejected() {
    let work = tempfile::tempdir().expect("work directory");
    let Some(fetch) = fetcher(&work.path().join("alpm")) else {
        return;
    };
    let error = fetch
        .download(PKG_NAME, None, SigCheck::Skip)
        .err()
        .expect("download without a database must fail");
    assert!(
        matches!(error, AlpmFetchError::NotSynced),
        "unexpected error: {error}"
    );
}

#[test]
fn optional_signature_tolerates_unsigned_mirror() {
    let work = tempfile::tempdir().expect("work directory");
    let payload = package_payload();
    let db = sync_db_archive(&[DbEntry {
        name: PKG_NAME,
        version: PKG_VERSION,
        filename: PKG_FILENAME,
        csize: payload.len() as u64,
    }]);
    // No `.sig` routes at all: the mirror publishes nothing to verify.
    let mirror = TestMirror::start(routes(vec![
        ("/core.db", db),
        (&package_route(), payload.clone()),
    ]));

    let Some(mut fetch) = fetcher(&work.path().join("alpm")) else {
        return;
    };
    fetch
        .sync_db(&mirror.base_url, SigCheck::Optional)
        .expect("an unsigned database is acceptable under SigCheck::Optional");
    let archive = fetch
        .download(PKG_NAME, Some(PKG_VERSION), SigCheck::Optional)
        .expect("an unsigned package is acceptable under SigCheck::Optional");
    assert_eq!(fs::read(&archive).expect("read archive"), payload);

    let requests = mirror.requests();
    assert!(
        requests.iter().any(|path| path == "/core.db.sig"),
        "SigCheck::Optional must still probe for a signature: {requests:?}"
    );
    // Staging files are consumed by the rename; nothing `.part` may survive.
    for directory in [fetch.dbpath().join("sync"), fetch.cache_dir().to_path_buf()] {
        for entry in fs::read_dir(&directory).expect("read staging directory") {
            let path = entry.expect("directory entry").path();
            let name = path.file_name().unwrap_or_default().to_string_lossy();
            assert!(
                !name.ends_with(".part"),
                "staging file left behind: {}",
                path.display()
            );
        }
    }
}

#[test]
fn real_mirror_when_enabled() {
    if std::env::var("EXTOS_TEST_ALPM_NETWORK").as_deref() != Ok("1") {
        println!("skip: set EXTOS_TEST_ALPM_NETWORK=1 to sync an Arch mirror over the network");
        return;
    }
    let work = tempfile::tempdir().expect("work directory");
    let Some(mut fetch) = fetcher(&work.path().join("alpm")) else {
        return;
    };
    let synced = fetch
        .sync_db(
            "https://geo.mirror.pkgbuild.com/core/os/x86_64",
            SigCheck::Required,
        )
        .expect("sync the real Arch core database");
    assert!(
        synced.package_count() > 100,
        "core should carry hundreds of packages, got {}",
        synced.package_count()
    );
    println!(
        "real mirror: {} packages in core from {}",
        synced.package_count(),
        synced.base_url()
    );
}
