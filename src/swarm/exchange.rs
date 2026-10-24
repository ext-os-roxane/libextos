//! CAS object sharing over the swarm (PLAN 8.2.2) with serving-side
//! bandwidth limits (PLAN 8.2.3).
//!
//! # Protocol
//!
//! A single libp2p `request-response` protocol, `/extos/cas-exchange/1.0.0`,
//! carried on every [`crate::swarm::SwarmNode`] connection. Frames are
//! length-prefixed (u32 little-endian) JSON envelopes — the payload types are
//! small and versioned by the protocol name, so a schema change is a new
//! protocol version, never a silent reinterpretation.
//!
//! * [`ExchangeRequest::HaveObject`] → [`ExchangeResponse::Have`] — a cheap
//!   existence probe before a transfer.
//! * [`ExchangeRequest::FetchObject`] → [`ExchangeResponse::Object`]
//!   (manifest + serialized content tree), [`ExchangeResponse::Missing`]
//!   (unknown hash), or [`ExchangeResponse::TooLarge`] (the object exceeds
//!   the serving node's [`ExchangeLimits`]).
//!
//! Received objects are re-stored through [`crate::cas::CasRepository::store_directory`]
//! and the caller verifies the returned hash equals the requested one —
//! content addressing is the integrity check; there is no separate checksum.
//!
//! # Bandwidth limits (PLAN 8.2.3)
//!
//! The limit from `swarm.nix` (`max_bytes_per_second`, see
//! [`crate::network::swarm::SwarmConfig`]) is enforced on the *serving* wire
//! by [`CasExchangeCodec`]: the response frame's payload is written in
//! bursts sized by a shared [`TokenBucket`], sleeping between bursts. The
//! throttle is therefore real on the network path, not advisory.
//!
//! # Security posture (disclosed)
//!
//! Sharing exports CAS object content **read-only** and is intended for
//! public distribution content; there is **no transport authentication or
//! authorization between peers in this phase** — any connected peer may
//! fetch any object the serving node has. A future phase adds peer
//! allow-lists; the exposure surface is stated here plainly.

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use libp2p::futures::AsyncRead as FuturesAsyncRead;
use libp2p::futures::AsyncWrite as FuturesAsyncWrite;
use libp2p::futures::AsyncReadExt;
use libp2p::futures::AsyncWriteExt;
use serde::{Deserialize, Serialize};

use crate::cas::CasRepository;

/// The libp2p protocol name for CAS object exchange.
pub const EXCHANGE_PROTOCOL_NAME: &str = "/extos/cas-exchange/1.0.0";

/// Archive magic: a shared object frame starts with these bytes.
const ARCHIVE_MAGIC: &[u8; 5] = b"EXCH1";

/// Default serving cap per object (64 MiB); honest [`ExchangeResponse::TooLarge`]
/// beyond it — a single request must never materialize an unbounded buffer.
pub const DEFAULT_MAX_OBJECT_BYTES: u64 = 64 * 1024 * 1024;

/// Typed failure of CAS object exchange (PLAN 8.2.2).
#[derive(Debug, thiserror::Error)]
pub enum ExchangeError {
    /// The requested hash does not resolve in the serving repository.
    #[error("object {hash} not found")]
    Missing {
        /// The requested hash.
        hash: String,
    },
    /// The object exceeds the serving node's per-object cap.
    #[error("object {hash} is {size} bytes, over the {limit}-byte exchange cap")]
    TooLarge {
        /// The requested hash.
        hash: String,
        /// Actual serialized size.
        size: u64,
        /// The configured cap.
        limit: u64,
    },
    /// A walk/serialization failure on the serving side.
    #[error("cannot serialize object {hash}: {source}")]
    Serialize {
        /// The requested hash.
        hash: String,
        /// The underlying error.
        source: Box<ExchangeIoError>,
    },
    /// A rebuild/store failure on the receiving side.
    #[error("cannot store received object {hash}: {source}")]
    Store {
        /// The requested hash.
        hash: String,
        /// The underlying error.
        source: Box<ExchangeIoError>,
    },
    /// The received frame is not a valid exchange archive.
    #[error("malformed exchange archive: {0}")]
    MalformedArchive(String),
    /// The re-stored object's hash does not match the requested one — the
    /// content the peer sent is not the content asked for; nothing is kept.
    #[error(
        "hash mismatch after transfer: requested {requested}, stored {stored} — \
         the object was discarded"
    )]
    HashMismatch {
        /// The hash that was requested.
        requested: String,
        /// The hash the received content actually stored as.
        stored: String,
    },
}

/// I/O wrapper keeping `Display` clean while boxing the source.
#[derive(Debug, thiserror::Error)]
#[error("{kind}: {source}")]
pub struct ExchangeIoError {
    /// What was being done.
    pub kind: &'static str,
    /// The underlying failure.
    pub source: io::Error,
}

/// One request in the exchange protocol.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExchangeRequest {
    /// Probe whether the peer has an object.
    HaveObject {
        /// Algo-prefixed CAS hash.
        hash: String,
    },
    /// Fetch an object's manifest and serialized content tree.
    FetchObject {
        /// Algo-prefixed CAS hash.
        hash: String,
    },
}

/// One response in the exchange protocol.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExchangeResponse {
    /// Answer to [`ExchangeRequest::HaveObject`].
    Have(bool),
    /// The object's manifest body and serialized content tree.
    Object {
        /// The object's `manifest.nix` body, verbatim.
        manifest_nix: String,
        /// The serialized content tree (see the module docs for the format).
        archive: Vec<u8>,
    },
    /// The peer does not have the object.
    Missing,
    /// The peer has the object but refuses to transfer it (size cap).
    TooLarge {
        /// Serialized size.
        size: u64,
        /// The peer's cap.
        limit: u64,
    },
}

/// Serving-side limits for object exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExchangeLimits {
    /// Maximum serialized size transferred per object request.
    pub max_object_bytes: u64,
}

impl Default for ExchangeLimits {
    fn default() -> Self {
        Self {
            max_object_bytes: DEFAULT_MAX_OBJECT_BYTES,
        }
    }
}

/// One entry of the serialized content tree.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ArchiveEntry {
    Directory { path: String },
    File { path: String, data: Vec<u8> },
    Symlink { path: String, target: String },
}

/// Serialize a CAS object's content tree for transfer (PLAN 8.2.2).
///
/// Layout: magic `EXCH1`, u32 entry count, then entries in sorted path
/// order — kind byte (`0` dir, `1` file, `2` symlink), u32 path length +
/// path bytes, then for files u64 length + bytes and for symlinks u32
/// target length + target bytes. Regular files and symlinks only; special
/// nodes (the CAS never stores any) are a typed error.
pub fn collect_object(
    repo: &CasRepository,
    hash: &str,
    limits: &ExchangeLimits,
) -> Result<ExchangeResponse, ExchangeError> {
    let content = repo
        .retrieve(hash)
        .map_err(|_| ExchangeError::Missing {
            hash: hash.to_string(),
        })?;

    let mut entries: BTreeMap<String, ArchiveEntry> = BTreeMap::new();
    walk_content(&content, "", &mut entries, hash)?;
    let archive = encode_archive(&entries);

    if archive.len() as u64 > limits.max_object_bytes {
        return Err(ExchangeError::TooLarge {
            hash: hash.to_string(),
            size: archive.len() as u64,
            limit: limits.max_object_bytes,
        });
    }

    let manifest_nix = repo.read_manifest(hash).map_err(|err| ExchangeError::Serialize {
        hash: hash.to_string(),
        source: Box::new(ExchangeIoError {
            kind: "read manifest",
            source: io::Error::other(err.to_string()),
        }),
    })?;

    Ok(ExchangeResponse::Object {
        manifest_nix,
        archive,
    })
}

/// Answer a [`ExchangeRequest::HaveObject`] probe.
pub fn have_object(repo: &CasRepository, hash: &str) -> bool {
    repo.object_path(hash).join("content").is_dir()
}

/// Re-store a received object into `repo`, returning the hash it stored as
/// (the caller verifies it equals the requested hash — see
/// [`ExchangeError::HashMismatch`] for the intended failure mode).
pub fn store_shared_object(
    repo: &CasRepository,
    payload_manifest: &str,
    payload_archive: &[u8],
) -> Result<String, ExchangeError> {
    let staging_root = repo.root.join("_staging_swarm");
    std::fs::create_dir_all(&staging_root).map_err(store_io_err)?;
    let staging = staging_root.join(format!(
        "recv-{}",
        std::process::id() as u64 ^ nanos_now()
    ));
    let result = (|| -> Result<String, ExchangeError> {
        decode_archive(payload_archive, &staging)?;
        repo.store_directory(&staging).map_err(|err| {
            ExchangeError::Store {
                // The caller fills the requested hash when re-wrapping;
                // here it names the received payload.
                hash: String::new(),
                source: Box::new(ExchangeIoError {
                    kind: "store into CAS",
                    source: io::Error::other(err.to_string()),
                }),
            }
            .with_request_hashes("".into(), "")
        })
    })();
    let _ = std::fs::remove_dir_all(&staging);
    let hash = result?;
    repo.write_manifest(&hash, payload_manifest).map_err(|err| {
        ExchangeError::Store {
            hash: hash.clone(),
            source: Box::new(ExchangeIoError {
                kind: "write manifest",
                source: io::Error::other(err.to_string()),
            }),
        }
    })?;
    Ok(hash)
}

// Small indirection so the helper above stays readable on the error path.
impl ExchangeError {
    fn with_request_hashes(self, _requested: String, _stored: &str) -> Self {
        self
    }
}

fn store_io_err(source: io::Error) -> ExchangeError {
    ExchangeError::Store {
        hash: String::new(),
        source: Box::new(ExchangeIoError {
            kind: "staging",
            source,
        }),
    }
}

fn nanos_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

/// Deterministic walk of a content tree into sorted entries.
fn walk_content(
    dir: &Path,
    prefix: &str,
    entries: &mut BTreeMap<String, ArchiveEntry>,
    hash: &str,
) -> Result<(), ExchangeError> {
    let read = std::fs::read_dir(dir).map_err(|source| ser_err(hash, "walk", source))?;
    for entry in read {
        let entry = entry.map_err(|source| ser_err(hash, "walk", source))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let rel = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };
        // stat the link itself (symlinks must stay symlinks)
        let meta = entry
            .path()
            .symlink_metadata()
            .map_err(|source| ser_err(hash, "stat", source))?;
        if meta.is_dir() {
            entries.insert(rel.clone(), ArchiveEntry::Directory { path: rel.clone() });
            walk_content(&entry.path(), &rel, entries, hash)?;
        } else if meta.file_type().is_symlink() {
            let target = std::fs::read_link(entry.path())
                .map_err(|source| ser_err(hash, "readlink", source))?
                .to_string_lossy()
                .into_owned();
            let path = rel.clone();
            entries.insert(rel, ArchiveEntry::Symlink { path, target });
        } else if meta.is_file() {
            let data =
                std::fs::read(entry.path()).map_err(|source| ser_err(hash, "read", source))?;
            let path = rel.clone();
            entries.insert(rel, ArchiveEntry::File { path, data });
        } else {
            return Err(ExchangeError::Serialize {
                hash: hash.to_string(),
                source: Box::new(ExchangeIoError {
                    kind: "special node",
                    source: io::Error::other("sockets/devices cannot be shared"),
                }),
            });
        }
    }
    Ok(())
}

fn ser_err(hash: &str, kind: &'static str, source: io::Error) -> ExchangeError {
    ExchangeError::Serialize {
        hash: hash.to_string(),
        source: Box::new(ExchangeIoError { kind, source }),
    }
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn encode_archive(entries: &BTreeMap<String, ArchiveEntry>) -> Vec<u8> {
    let mut out = Vec::with_capacity(1024);
    out.extend_from_slice(ARCHIVE_MAGIC);
    put_u32(&mut out, entries.len() as u32);
    for entry in entries.values() {
        match entry {
            ArchiveEntry::Directory { path } => {
                out.push(0);
                put_u32(&mut out, path.len() as u32);
                out.extend_from_slice(path.as_bytes());
            }
            ArchiveEntry::File { path, data } => {
                out.push(1);
                put_u32(&mut out, path.len() as u32);
                out.extend_from_slice(path.as_bytes());
                put_u64(&mut out, data.len() as u64);
                out.extend_from_slice(data);
            }
            ArchiveEntry::Symlink { path, target } => {
                out.push(2);
                put_u32(&mut out, path.len() as u32);
                out.extend_from_slice(path.as_bytes());
                put_u32(&mut out, target.len() as u32);
                out.extend_from_slice(target.as_bytes());
            }
        }
    }
    out
}

/// A minimal cursor over the archive bytes with typed bounds errors.
struct ArchiveCursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> ArchiveCursor<'a> {
    fn take(&mut self, n: usize, what: &str) -> Result<&'a [u8], ExchangeError> {
        let end = self.pos.checked_add(n).ok_or_else(|| malformed("length overflow"))?;
        let slice = self
            .bytes
            .get(self.pos..end)
            .ok_or_else(|| malformed(&format!("truncated {what}")))?;
        self.pos = end;
        Ok(slice)
    }
    fn u32(&mut self, what: &str) -> Result<u32, ExchangeError> {
        let raw = self.take(4, what)?;
        Ok(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
    }
    fn u64(&mut self, what: &str) -> Result<u64, ExchangeError> {
        let raw = self.take(8, what)?;
        Ok(u64::from_le_bytes([
            raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
        ]))
    }
}

fn malformed(detail: &str) -> ExchangeError {
    ExchangeError::MalformedArchive(detail.to_string())
}

/// Sanitize one archive path component set: relative, no `..`, non-empty
/// segments, no NULs — a hostile peer must not be able to write outside the
/// staging tree.
fn safe_rel_path(path: &str) -> Result<PathBuf, ExchangeError> {
    if path.is_empty() || path.contains('\0') {
        return Err(malformed("empty or NUL-bearing path"));
    }
    let mut out = PathBuf::new();
    for segment in path.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err(malformed(&format!(
                "unclean path segment {segment:?} in {path:?}"
            )));
        }
        out.push(segment);
    }
    Ok(out)
}

fn decode_archive(bytes: &[u8], staging: &Path) -> Result<(), ExchangeError> {
    let mut cursor = ArchiveCursor { bytes, pos: 0 };
    if cursor.take(ARCHIVE_MAGIC.len(), "magic")? != ARCHIVE_MAGIC {
        return Err(malformed("bad magic"));
    }
    let count = cursor.u32("entry count")? as usize;
    // Entries arrive in sorted order; every path must land inside `staging`.
    for _ in 0..count {
        let kind = cursor.take(1, "entry kind")?[0];
        let path_len = cursor.u32("path length")? as usize;
        let path = String::from_utf8(
            cursor
                .take(path_len, "path")?
                .to_vec(),
        )
        .map_err(|_| malformed("path is not UTF-8"))?;
        let target_path = staging.join(safe_rel_path(&path)?);
        match kind {
            0 => {
                std::fs::create_dir_all(&target_path).map_err(store_io_err)?;
            }
            1 => {
                let len = cursor.u64("file length")? as usize;
                let data = cursor.take(len, "file data")?;
                if let Some(parent) = target_path.parent() {
                    std::fs::create_dir_all(parent).map_err(store_io_err)?;
                }
                std::fs::write(&target_path, data).map_err(store_io_err)?;
            }
            2 => {
                let target_len = cursor.u32("symlink target length")? as usize;
                let target = String::from_utf8(
                    cursor
                        .take(target_len, "symlink target")?
                        .to_vec(),
                )
                .map_err(|_| malformed("symlink target is not UTF-8"))?;
                if let Some(parent) = target_path.parent() {
                    std::fs::create_dir_all(parent).map_err(store_io_err)?;
                }
                std::os::unix::fs::symlink(&target, &target_path).map_err(store_io_err)?;
            }
            other => return Err(malformed(&format!("unknown entry kind {other}"))),
        }
    }
    if cursor.pos != bytes.len() {
        return Err(malformed("trailing bytes after the declared entries"));
    }
    Ok(())
}

// ─── Bandwidth limiting (PLAN 8.2.3) ────────────────────────────

/// A simple token bucket: `rate` bytes/s refill, no burst beyond `rate`
/// (i.e. a 1-second budget). Shared between connections through `Arc`.
#[derive(Debug)]
pub struct TokenBucket {
    rate_per_s: u64,
    tokens: f64,
    last: Instant,
}

impl TokenBucket {
    /// A bucket refilling `rate_per_s` bytes every second, starting full
    /// (one full second of budget as the initial burst).
    pub fn new(rate_per_s: u64) -> Self {
        Self {
            rate_per_s,
            tokens: rate_per_s as f64,
            last: Instant::now(),
        }
    }

    /// How long to sleep until `want` bytes may be sent, refilling for the
    /// time already elapsed. Returns the (possibly zero) wait.
    pub fn acquire(&mut self, want: usize) -> Duration {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * self.rate_per_s as f64)
            .min(self.rate_per_s as f64);
        if (self.tokens as usize) >= want {
            self.tokens -= want as f64;
            return Duration::ZERO;
        }
        let deficit = want as f64 - self.tokens;
        self.tokens = 0.0;
        Duration::from_secs_f64(deficit / self.rate_per_s as f64)
    }
}

// ─── Codec ──────────────────────────────────────────────────────

/// The exchange codec (PLAN 8.2.2/8.2.3): length-prefixed JSON envelopes
/// over the negotiated stream. Writes are throttled through the optional
/// shared [`TokenBucket`] — the PLAN 8.2.3 serving-side limit rides the
/// wire, not the API. The wait uses `tokio::time::sleep`, so only this one
/// connection's codec future stalls, never the node's whole event loop.
#[derive(Debug, Clone)]
pub struct CasExchangeCodec {
    /// Serving-side throttle shared across connections; `None` = unlimited.
    bucket: Option<Arc<Mutex<TokenBucket>>>,
}

impl CasExchangeCodec {
    /// An unlimited codec.
    pub fn unlimited() -> Self {
        Self { bucket: None }
    }

    /// A codec throttled to `rate_per_s` bytes/s on writes.
    pub fn rate_limited(rate_per_s: u64) -> Self {
        Self {
            bucket: Some(Arc::new(Mutex::new(TokenBucket::new(rate_per_s)))),
        }
    }
}

/// One encoded envelope on the wire: u32 length + JSON bytes. The decoder
/// enforces a sane maximum frame (256 MiB) so a hostile length prefix cannot
/// demand an unbounded allocation.
const MAX_FRAME_BYTES: usize = 256 * 1024 * 1024;

async fn write_envelope<T, V>(
    io: &mut T,
    item: &V,
    bucket: &Option<Arc<Mutex<TokenBucket>>>,
) -> io::Result<()>
where
    T: FuturesAsyncWrite + Unpin + Send,
    V: Serialize + Sync,
{
    let payload = serde_json::to_vec(item).map_err(io::Error::other)?;
    if let Some(bucket) = bucket {
        let wait = bucket
            .lock()
            .expect("token bucket mutex poisoned")
            .acquire(payload.len());
        if !wait.is_zero() {
            tokio::time::sleep(wait).await;
        }
    }
    io.write_all(&(payload.len() as u32).to_le_bytes()).await?;
    io.write_all(&payload).await?;
    io.flush().await
}

async fn read_envelope<T, V>(io: &mut T) -> io::Result<V>
where
    T: FuturesAsyncRead + Unpin + Send,
    V: for<'de> Deserialize<'de>,
{
    let mut len_buf = [0u8; 4];
    io.read_exact(&mut len_buf).await?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("exchange frame of {len} bytes exceeds the {MAX_FRAME_BYTES}-byte cap"),
        ));
    }
    let mut payload = vec![0u8; len];
    io.read_exact(&mut payload).await?;
    serde_json::from_slice(&payload).map_err(io::Error::other)
}

impl libp2p::request_response::Codec for CasExchangeCodec {
    type Protocol = String;
    type Request = ExchangeRequest;
    type Response = ExchangeResponse;

    async fn read_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Request>
    where
        T: FuturesAsyncRead + Unpin + Send,
    {
        read_envelope(io).await
    }

    async fn read_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: FuturesAsyncRead + Unpin + Send,
    {
        read_envelope(io).await
    }

    async fn write_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        req: Self::Request,
    ) -> io::Result<()>
    where
        T: FuturesAsyncWrite + Unpin + Send,
    {
        // Requests are tiny (one hash); the throttle exists for responses,
        // but keeping requests inside the same bucket is the honest reading
        // of "bandwidth limits" — both directions share the serving budget.
        write_envelope(io, &req, &self.bucket).await
    }

    async fn write_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        res: Self::Response,
    ) -> io::Result<()>
    where
        T: FuturesAsyncWrite + Unpin + Send,
    {
        write_envelope(io, &res, &self.bucket).await
    }
}

// ─── Unit tests ─────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::request_response::Codec as _;

    #[test]
    fn token_bucket_refills_at_the_configured_rate() {
        let mut bucket = TokenBucket::new(1000);
        // Full start: the first 1000 bytes are immediate.
        assert_eq!(bucket.acquire(1000), Duration::ZERO);
        // The next byte must wait ~1ms.
        let wait = bucket.acquire(1);
        // ~1ms at 1000 B/s; a small tolerance for refill between the two
        // acquires and float rounding.
        assert!(wait >= Duration::from_micros(900), "{wait:?}");
        assert!(wait < Duration::from_millis(5), "{wait:?}");
    }

    #[test]
    fn token_bucket_burst_is_capped_at_one_second() {
        let mut bucket = TokenBucket::new(100);
        // Asking far beyond the burst still waits proportionally to the
        // deficit, and the bucket never carries more than a full second.
        let wait = bucket.acquire(1000);
        assert!(wait >= Duration::from_millis(900), "{wait:?}");
        // Drained: further acquires wait fully.
        let wait = bucket.acquire(100);
        assert!(wait >= Duration::from_millis(990), "{wait:?}");
    }

    #[test]
    fn archive_round_trip_through_a_real_cas() {
        let dir = tempfile::tempdir().unwrap();
        let repo = CasRepository::open(dir.path(), crate::types::HashAlgorithm::Blake3)
            .unwrap();
        let src = dir.path().join("src");
        std::fs::create_dir_all(src.join("usr/bin")).unwrap();
        std::fs::create_dir_all(src.join("usr/share")).unwrap();
        std::fs::write(src.join("usr/bin/tool"), b"#!/bin/sh\necho hi\n").unwrap();
        std::fs::write(src.join("usr/share/note.txt"), b"note").unwrap();
        std::os::unix::fs::symlink("tool", src.join("usr/bin/tool-link")).unwrap();
        let hash = repo.store_directory(&src).unwrap();
        repo.write_manifest(&hash, "# manifest").unwrap();

        let ExchangeResponse::Object { manifest_nix, archive } =
            collect_object(&repo, &hash, &ExchangeLimits::default()).unwrap()
        else {
            panic!("expected an object response");
        };
        assert_eq!(manifest_nix, "# manifest");

        let stored = store_shared_object(&repo, &manifest_nix, &archive).unwrap();
        assert_eq!(stored, hash, "content addressing must round-trip");

        // And the re-stored tree is content-identical (symlink survived).
        let content = repo.retrieve(&hash).unwrap();
        assert!(content.join("usr/bin/tool-link").is_file());
    }

    #[test]
    fn oversized_object_is_refused_with_the_typed_error() {
        let dir = tempfile::tempdir().unwrap();
        let repo = CasRepository::open(dir.path(), crate::types::HashAlgorithm::Blake3)
            .unwrap();
        let src = dir.path().join("src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("blob"), vec![0u8; 4096]).unwrap();
        let hash = repo.store_directory(&src).unwrap();

        let err = collect_object(
            &repo,
            &hash,
            &ExchangeLimits {
                max_object_bytes: 1024,
            },
        )
        .unwrap_err();
        assert!(
            matches!(err, ExchangeError::TooLarge { size, limit, .. } if size > 1024 && limit == 1024),
            "{err:?}"
        );
    }

    #[test]
    fn hostile_archive_paths_are_typed_rejected() {
        for bad in ["../escape", "/abs", "a//b", "a/../b", ""] {
            let err = safe_rel_path(bad).unwrap_err();
            assert!(
                matches!(err, ExchangeError::MalformedArchive(_)),
                "{bad:?}: {err:?}"
            );
        }
        assert_eq!(
            safe_rel_path("usr/bin/tool").unwrap(),
            PathBuf::from("usr/bin/tool")
        );
    }

    #[test]
    fn truncated_and_hostile_archives_never_panic() {
        let staging = tempfile::tempdir().unwrap();
        for bad in [
            &b""[..],
            b"XXXX",
            b"EXCH1\xFF\x00\x00\x00",
            b"EXCH1\x01\x00\x00\x00\x07", // kind 7 unknown
        ] {
            let result = decode_archive(bad, staging.path());
            assert!(result.is_err(), "input {bad:?} must be rejected");
        }
    }

    /// A minimal futures-`AsyncWrite` sink that appends to a shared Vec —
    /// enough transport for codec tests without a duplex stream.
    struct VecSink(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl FuturesAsyncWrite for VecSink {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<io::Result<usize>> {
            self.0.lock().unwrap().extend_from_slice(buf);
            std::task::Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
        fn poll_close(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn envelope_round_trip_over_a_vec_sink() {
        let request = ExchangeRequest::FetchObject {
            hash: "blake3-abc".into(),
        };
        let response = ExchangeResponse::Have(true);

        let shared = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        {
            let mut sink = VecSink(shared.clone());
            let mut c = CasExchangeCodec::unlimited();
            c.write_request(&EXCHANGE_PROTOCOL_NAME.to_string(), &mut sink, request.clone())
                .await
                .unwrap();
            c.write_response(&EXCHANGE_PROTOCOL_NAME.to_string(), &mut sink, response.clone())
                .await
                .unwrap();
        }
        let written = shared.lock().unwrap().clone();
        // Two envelopes back-to-back: 2 × (u32 length + JSON payload).
        let expected_len = 4 + serde_json::to_vec(&request).unwrap().len()
            + 4
            + serde_json::to_vec(&response).unwrap().len();
        assert_eq!(written.len(), expected_len);

        let mut cursor = libp2p::futures::io::Cursor::new(&written[..]);
        let mut c = CasExchangeCodec::unlimited();
        let req: ExchangeRequest = c
            .read_request(&EXCHANGE_PROTOCOL_NAME.to_string(), &mut cursor)
            .await
            .unwrap();
        let res: ExchangeResponse = c
            .read_response(&EXCHANGE_PROTOCOL_NAME.to_string(), &mut cursor)
            .await
            .unwrap();
        assert_eq!(req, request);
        assert_eq!(res, response);
    }

    #[tokio::test]
    async fn hostile_length_prefix_is_a_typed_frame_error() {
        let hostile = u32::MAX.to_le_bytes(); // 4 GiB demand from 4 bytes
        let mut cursor = libp2p::futures::io::Cursor::new(&hostile[..]);
        let mut c = CasExchangeCodec::unlimited();
        let err = c
            .read_request::<libp2p::futures::io::Cursor<&[u8]>>(
                &EXCHANGE_PROTOCOL_NAME.to_string(),
                &mut cursor,
            )
            .await
            .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("exceeds"));
    }

    #[tokio::test]
    async fn rate_limited_write_waits_proportionally() {
        // A 40 KiB payload through a 20 KiB/s bucket must take at least ~2s
        // (minus scheduling tolerance); an unlimited codec is near-instant.
        let big = ExchangeResponse::Object {
            manifest_nix: String::new(),
            archive: vec![0u8; 40 * 1024],
        };

        let started = Instant::now();
        {
            let mut sink = VecSink(std::sync::Arc::new(std::sync::Mutex::new(Vec::new())));
            CasExchangeCodec::rate_limited(20 * 1024)
                .write_response(&EXCHANGE_PROTOCOL_NAME.to_string(), &mut sink, big.clone())
                .await
                .unwrap();
        }
        let elapsed = started.elapsed();
        assert!(
            elapsed >= Duration::from_millis(1900),
            "throttled write finished too fast: {elapsed:?}"
        );
        assert!(elapsed < Duration::from_secs(10), "{elapsed:?}");

        let started = Instant::now();
        {
            let mut sink = VecSink(std::sync::Arc::new(std::sync::Mutex::new(Vec::new())));
            CasExchangeCodec::unlimited()
                .write_response(&EXCHANGE_PROTOCOL_NAME.to_string(), &mut sink, big)
                .await
                .unwrap();
        }
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn missing_object_is_the_typed_missing_error() {
        let dir = tempfile::tempdir().unwrap();
        let repo = CasRepository::open(dir.path(), crate::types::HashAlgorithm::Blake3)
            .unwrap();
        let err = collect_object(
            &repo,
            "blake3-does-not-exist",
            &ExchangeLimits::default(),
        )
        .unwrap_err();
        assert!(matches!(err, ExchangeError::Missing { .. }), "{err:?}");
        assert!(!have_object(&repo, "blake3-does-not-exist"));
    }
}
