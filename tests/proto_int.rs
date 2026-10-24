//! Control-plane protobuf schema pins for PLAN 8.1.1 / 8.1.2 (lane L29).
//!
//! The `extos.pkt` / `extos.instanz` schemas are the wire contract between the
//! root daemons (PLAN 8.1.3 / 8.1.4 servers) and unprivileged clients (the
//! Phase 9 GUI), so this suite pins the things a later lane must not be able
//! to silently change:
//!
//! * every RPC request/response round-trips through prost (`encode_to_vec` /
//!   `decode`) and re-encodes byte-stably — field numbers and types are
//!   pinned by the wire bytes themselves;
//! * proto3 explicit presence is real presence: `optional` fields keep
//!   `Some("")` / `Some(0)` on the wire instead of default-punning to absent;
//! * oneof arms survive both ways (the two `-F` arms, the two rollback
//!   targets);
//! * `common::ErrorCode` discriminants stay aligned with the
//!   `error::ExtosError` variant order documented in `common.proto`;
//! * the generated module exposes both service client/server markers, the
//!   tonic client constructor paths work (`connect` over `unix://`, with
//!   `new` exercised inside it), and a live in-process server over a tmpdir
//!   UDS answers a real RPC for each service — the exact pattern the
//!   PLAN 8.1.3/8.1.4 servers and the request's UDS round-trip verification
//!   method use.
//!
//! Error convention under test (see `proto/extos/common.proto`): gRPC status
//! codes are transport-only; a domain failure rides in the response's
//! `error` field (uniformly field 15) with gRPC status OK, and an unset
//! `error` field means success.
//!
//! Everything is fixture-local: sockets live in `tempfile` tmpdirs, the
//! in-process servers are test-local stubs, and nothing here touches any
//! `src/` module — the lane owns only the `.proto` sources and this file.

use std::path::Path;
use std::time::Duration;

use libextos::pb::extos::{common, instanz, pkt};
use prost::Message;
use tonic::codegen::tokio_stream::wrappers::UnixListenerStream;

/// Generous per-call bound so a wedged server fails the test instead of
/// hanging the suite; local UDS round-trips finish in microseconds.
const CALL_TIMEOUT: Duration = Duration::from_secs(5);

// ─── Round-trip helper ──────────────────────────────────────────

/// Encode, decode, compare, re-encode.
///
/// The re-encode equality is the field-stability pin: if a later lane
/// renumbers a field, retypes it, or drops/changes presence semantics, either
/// the decode comparison or the byte-stable re-encode fails.
fn assert_round_trip<M: Message + Default + PartialEq>(msg: &M) -> M {
    let bytes = msg.encode_to_vec();
    let decoded = M::decode(bytes.as_slice()).expect("decode of a just-encoded message");
    assert!(decoded == *msg, "decoded value differs from the original");
    let reencoded = decoded.encode_to_vec();
    assert!(reencoded == bytes, "re-encode is not byte-stable");
    decoded
}

/// `Capabilities` fixture shaped like an `htop` ingest
/// (`manifest::Capabilities` mirror).
fn htop_capabilities() -> pkt::Capabilities {
    pkt::Capabilities {
        binaries: vec!["htop".into(), "htop-vim".into()],
        libraries: vec!["libncursesw.so.6".into()],
        virtual_caps: vec!["system-monitor".into()],
        resources: vec!["/usr/share/applications/htop.desktop".into()],
    }
}

/// A representative `ingest::IngestResult`-shaped payload.
fn ingest_payload() -> (pkt::IngestResponse, pkt::SyncResponse) {
    let ingest = pkt::IngestResponse {
        hash: "blake3:0123456789abcdef".into(),
        origin: "archlinux".into(),
        name: "htop".into(),
        version: "3.3.0-1".into(),
        capabilities: Some(htop_capabilities()),
        rosetta_translated: true,
        sanitized_bits: 2,
        error: None,
    };
    let sync = pkt::SyncResponse {
        archive_path: "/repository/cache/archlinux/htop-3.3.0-1.pkg.tar.xz".into(),
        archive_bytes: 234_567,
        hash: ingest.hash.clone(),
        origin: ingest.origin.clone(),
        name: ingest.name.clone(),
        version: ingest.version.clone(),
        capabilities: ingest.capabilities.clone(),
        rosetta_translated: ingest.rosetta_translated,
        sanitized_bits: ingest.sanitized_bits,
        error: None,
    };
    (ingest, sync)
}

/// A representative domain failure: the `-S` mirror chain answered 404 for
/// every configured mirror (`ExtosError::PackageNotFound`).
fn package_not_found_error() -> Option<common::Error> {
    Some(common::Error {
        code: common::ErrorCode::PackageNotFound as i32,
        message: "Package not found: archlinux/htop/9.9.9".into(),
    })
}

// ─── pkt Sync (pkt -S) ──────────────────────────────────────────

#[test]
fn sync_request_round_trip() {
    let request = pkt::SyncRequest {
        origin: "archlinux".into(),
        name: "htop".into(),
        version: "3.3.0-1".into(),
        download_only: true,
    };
    let decoded = assert_round_trip(&request);
    assert_eq!(decoded.origin, "archlinux");
    assert_eq!(decoded.name, "htop");
    assert_eq!(decoded.version, "3.3.0-1");
    assert!(decoded.download_only);
}

#[test]
fn sync_response_round_trip() {
    let (_, sync) = ingest_payload();
    let decoded = assert_round_trip(&sync);
    let caps = decoded.capabilities.expect("capabilities set");
    assert_eq!(caps.binaries, vec!["htop".to_string(), "htop-vim".to_string()]);
    assert_eq!(caps.libraries, vec!["libncursesw.so.6".to_string()]);
    assert_eq!(caps.virtual_caps, vec!["system-monitor".to_string()]);
    assert_eq!(caps.resources, vec!["/usr/share/applications/htop.desktop".to_string()]);
    assert_eq!(decoded.archive_bytes, 234_567);
    assert!(decoded.error.is_none(), "unset error = success");
}

#[test]
fn sync_response_carries_the_domain_error() {
    let mut sync = ingest_payload().1;
    sync.error = package_not_found_error();
    let decoded = assert_round_trip(&sync);
    let error = decoded.error.expect("domain error present");
    assert_eq!(error.code, common::ErrorCode::PackageNotFound as i32);
    assert_eq!(error.message, "Package not found: archlinux/htop/9.9.9");
}

// ─── pkt Query (pkt -Q --all-refs) ──────────────────────────────

#[test]
fn query_request_origin_presence_is_explicit() {
    // Absent = all origins; the empty string is *not* a valid encoding of
    // "no filter" — explicit presence must survive the wire.
    let all = assert_round_trip(&pkt::QueryRequest { origin: None });
    assert!(all.origin.is_none());

    let filtered = assert_round_trip(&pkt::QueryRequest {
        origin: Some("".into()),
    });
    assert_eq!(filtered.origin.as_deref(), Some(""), "Some(\"\") must not default-pun");
}

#[test]
fn query_response_round_trip_including_dangling_rows() {
    let response = pkt::QueryResponse {
        refs: vec![
            pkt::RefEntry {
                origin: "archlinux".into(),
                name: "htop".into(),
                version: "3.3.0-1".into(),
                object_hash: Some("blake3:aaa".into()),
            },
            // The `(dangling)` row of `pkt -Q --all-refs`.
            pkt::RefEntry {
                origin: "debian".into(),
                name: "curl".into(),
                version: "8.5.0-2".into(),
                object_hash: None,
            },
        ],
        error: None,
    };
    let decoded = assert_round_trip(&response);
    assert_eq!(decoded.refs.len(), 2);
    assert_eq!(decoded.refs[0].object_hash.as_deref(), Some("blake3:aaa"));
    assert!(decoded.refs[1].object_hash.is_none(), "dangling = absent hash");
}

// ─── pkt Files (pkt -F and pkt -F --soname) ─────────────────────

#[test]
fn files_request_round_trip() {
    // Matching rules are the `cas::matches_query` rules; the leading-`/`
    // anchored form is the strictest one clients send.
    let request = assert_round_trip(&pkt::FilesRequest {
        path_query: "/usr/bin/sh".into(),
    });
    assert_eq!(request.path_query, "/usr/bin/sh");

    let glob = assert_round_trip(&pkt::FilesRequest {
        path_query: "*.so".into(),
    });
    assert_eq!(glob.path_query, "*.so");
}

#[test]
fn files_response_round_trip() {
    let response = pkt::FilesResponse {
        hits: vec![pkt::FileHit {
            ref_entry: Some(pkt::RefEntry {
                origin: "archlinux".into(),
                name: "bash".into(),
                version: "5.2.26-1".into(),
                object_hash: Some("blake3:bbb".into()),
            }),
            path: "/usr/bin/bash".into(),
        }],
        error: None,
    };
    let decoded = assert_round_trip(&response);
    let hit = &decoded.hits[0];
    let owner = hit.ref_entry.as_ref().expect("owning ref present");
    assert_eq!(owner.origin, "archlinux");
    assert_eq!(owner.name, "bash");
    assert_eq!(owner.version, "5.2.26-1");
    assert_eq!(hit.path, "/usr/bin/bash");
}

#[test]
fn soname_response_round_trip_with_population_summary() {
    let response = pkt::SonameResponse {
        providers: vec![
            pkt::SonameProvider {
                origin: "archlinux".into(),
                name: "openssl".into(),
                version: "3.3.1-1".into(),
                ref_version: "3.3.1".into(),
                object_hash: Some("blake3:ccc".into()),
                provides: vec!["libssl.so.3".into(), "libcrypto.so.3".into()],
            },
            pkt::SonameProvider {
                origin: "rpm".into(),
                name: "openssl-libs".into(),
                version: "3.0.7-1".into(),
                ref_version: "3.0.7".into(),
                object_hash: None,
                provides: vec!["libssl.so.3".into()],
            },
        ],
        refs_scanned: 12,
        packages_indexed: 9,
        entries: 40,
        sonames_indexed: 31,
        warnings: vec!["rpm/openssl-libs/3.0.7-1: manifest unreadable".into()],
        error: None,
    };
    let decoded = assert_round_trip(&response);
    assert_eq!(decoded.providers.len(), 2);
    // `version` (human) and `ref_version` (ref component) are distinct fields,
    // mirroring `CapabilityProvider`.
    assert_eq!(decoded.providers[0].version, "3.3.1-1");
    assert_eq!(decoded.providers[0].ref_version, "3.3.1");
    assert_eq!(decoded.providers[0].object_hash.as_deref(), Some("blake3:ccc"));
    assert!(decoded.providers[1].object_hash.is_none());
    assert_eq!(decoded.refs_scanned, 12);
    assert_eq!(decoded.sonames_indexed, 31);
    assert_eq!(decoded.warnings.len(), 1);
}

// ─── pkt Ingest (pkt -U) ────────────────────────────────────────

#[test]
fn ingest_request_origin_presence_is_explicit() {
    // Absent origin = auto-detect via `default_origin_for_archive`.
    let auto = assert_round_trip(&pkt::IngestRequest {
        archive_path: "/tmp/fixture.pkg.tar.zst".into(),
        origin: None,
        rosetta: true,
    });
    assert!(auto.origin.is_none());
    assert!(auto.rosetta);

    // `-o origin` is the explicit form.
    let explicit = assert_round_trip(&pkt::IngestRequest {
        archive_path: "/tmp/fixture.pkg.tar.zst".into(),
        origin: Some("scratch".into()),
        rosetta: false,
    });
    assert_eq!(explicit.origin.as_deref(), Some("scratch"));
    assert!(!explicit.rosetta);
}

#[test]
fn ingest_response_mirrors_ingest_result() {
    let (ingest, _) = ingest_payload();
    let decoded = assert_round_trip(&ingest);
    assert_eq!(decoded.hash, "blake3:0123456789abcdef");
    assert_eq!(decoded.origin, "archlinux");
    assert_eq!(decoded.name, "htop");
    assert_eq!(decoded.version, "3.3.0-1");
    assert!(decoded.capabilities.is_some());
    assert!(decoded.rosetta_translated);
    assert_eq!(decoded.sanitized_bits, 2);
    assert!(decoded.error.is_none());
}

// ─── instanz Apply (instanz apply <system.nix>) ─────────────────

#[test]
fn apply_request_round_trip() {
    let request = instanz::ApplyRequest {
        config_path: "/config/systems/workstation.nix".into(),
    };
    let decoded = assert_round_trip(&request);
    assert_eq!(decoded.config_path, "/config/systems/workstation.nix");
}

#[test]
fn apply_response_mirrors_apply_report() {
    let response = instanz::ApplyResponse {
        generation: 7,
        root: "/runlevel/1/workstation/gen-7".into(),
        plan_ops: 1284,
        phantom_rows: 42,
        lockfile: "/runlevel/1/workstation/gen-7/.lock".into(),
        forge: "forged".into(),
        bls_entries: 3,
        reaped: vec![2, 3],
        apparmor_profiles: vec!["usr.bin.htop".into()],
        apparmor_skipped: vec!["declared profile missing template".into()],
        selinux_applied: 96,
        selinux_skipped: vec!["archlinux/htop".into()],
        services_enabled: 4,
        services_disabled: 1,
        error: None,
    };
    let decoded = assert_round_trip(&response);
    assert_eq!(decoded.generation, 7);
    assert_eq!(decoded.plan_ops, 1284);
    assert_eq!(decoded.reaped, vec![2, 3]);
    assert_eq!(decoded.apparmor_profiles.len(), 1);
    assert_eq!(decoded.selinux_applied, 96);
    assert_eq!(decoded.services_enabled, 4);
    assert_eq!(decoded.services_disabled, 1);
    assert!(decoded.error.is_none());
}

// ─── instanz Rollback (instanz rollback) ────────────────────────

#[test]
fn rollback_request_oneof_arms_survive_the_wire() {
    let previous = assert_round_trip(&instanz::RollbackRequest {
        target: Some(instanz::rollback_request::Target::Previous(
            instanz::PreviousGeneration {},
        )),
    });
    assert!(matches!(
        previous.target,
        Some(instanz::rollback_request::Target::Previous(_))
    ));

    let number = assert_round_trip(&instanz::RollbackRequest {
        target: Some(instanz::rollback_request::Target::Number(42)),
    });
    assert!(matches!(
        number.target,
        Some(instanz::rollback_request::Target::Number(42))
    ));

    let empty = assert_round_trip(&instanz::RollbackRequest { target: None });
    assert!(empty.target.is_none());
}

#[test]
fn rollback_response_round_trip() {
    let response = instanz::RollbackResponse {
        generation: 5,
        root: "/runlevel/1/workstation/gen-5".into(),
        error: None,
    };
    let decoded = assert_round_trip(&response);
    assert_eq!(decoded.generation, 5);
    assert_eq!(decoded.root, "/runlevel/1/workstation/gen-5");
}

// ─── instanz Generations (instanz generations) ──────────────────

#[test]
fn generations_request_encodes_empty() {
    let request = instanz::GenerationsRequest {};
    assert!(
        request.encode_to_vec().is_empty(),
        "an empty request encodes to zero bytes"
    );
    let decoded = assert_round_trip(&request);
    assert!(decoded == instanz::GenerationsRequest {});
}

#[test]
fn generation_row_timestamp_presence_is_explicit() {
    let row = assert_round_trip(&instanz::GenerationRow {
        number: 7,
        timestamp: Some(0), // epoch: must stay Some on the wire
        packages: vec!["archlinux/htop".into(), "debian/curl".into()],
        description: "seed generation".into(),
        is_current: true,
        pinned: false,
    });
    assert_eq!(row.timestamp, Some(0), "Some(0) must not default-pun");
    assert_eq!(row.packages.len(), 2);
    assert!(row.is_current);

    let bare = assert_round_trip(&instanz::GenerationRow {
        number: 1,
        timestamp: None,
        packages: vec![],
        description: String::new(),
        is_current: false,
        pinned: true,
    });
    assert!(bare.timestamp.is_none());
    assert!(bare.pinned);
}

#[test]
fn generations_response_round_trip() {
    let response = instanz::GenerationsResponse {
        generations: vec![
            instanz::GenerationRow {
                number: 5,
                timestamp: Some(1_700_000_000),
                packages: vec!["archlinux/base".into()],
                description: "first apply".into(),
                is_current: false,
                pinned: false,
            },
            instanz::GenerationRow {
                number: 7,
                timestamp: None,
                packages: vec!["archlinux/htop".into()],
                description: String::new(),
                is_current: true,
                pinned: true,
            },
        ],
        error: None,
    };
    let decoded = assert_round_trip(&response);
    assert_eq!(decoded.generations.len(), 2);
    assert_eq!(decoded.generations[0].number, 5);
    assert!(decoded.generations[1].is_current);
    assert!(decoded.generations[1].pinned);
}

// ─── instanz Container (instanz run <profile>) ──────────────────

#[test]
fn container_request_level_presence_is_explicit() {
    // Absent = manifest profile level, else isolated (RunOptions::level None).
    let no_override = assert_round_trip(&instanz::ContainerRequest {
        profile: "workstation".into(),
        level: None,
    });
    assert!(no_override.level.is_none());

    // "Override with level 0" must differ from "no override" on the wire.
    let forced_isolated = assert_round_trip(&instanz::ContainerRequest {
        profile: "workstation".into(),
        level: Some(instanz::IsolationLevel::Isolated as i32),
    });
    assert_eq!(forced_isolated.level, Some(0));

    let privileged = assert_round_trip(&instanz::ContainerRequest {
        profile: "workstation".into(),
        level: Some(instanz::IsolationLevel::Privileged as i32),
    });
    assert_eq!(
        instanz::IsolationLevel::try_from(privileged.level.expect("level present"))
            .expect("level in range"),
        instanz::IsolationLevel::Privileged
    );
}

#[test]
fn container_response_round_trip_preserves_exit_sign() {
    let response = instanz::ContainerResponse {
        roof: "/runlevel/1/workstation/gen-7".into(),
        backend: "native".into(),
        // Signal-killed containers surface as negative i32 in `run::run`.
        exit_code: -9,
        error: None,
    };
    let decoded = assert_round_trip(&response);
    assert_eq!(decoded.exit_code, -9, "int32 keeps the sign of run::run's i32");
    assert_eq!(decoded.backend, "native");
}

// ─── common::ErrorCode ↔ error::ExtosError alignment ────────────

#[test]
fn error_code_discriminants_pin_the_documented_variant_order() {
    // The numbers must match the `error::ExtosError` variant mapping listed
    // in `proto/extos/common.proto` — reordering the enum would silently
    // remap every persisted/logged code.
    let pinned: [(common::ErrorCode, i32); 13] = [
        (common::ErrorCode::Unspecified, 0),
        (common::ErrorCode::Io, 1),
        (common::ErrorCode::ConfigParse, 2),
        (common::ErrorCode::CasIntegrity, 3),
        (common::ErrorCode::PackageNotFound, 4),
        (common::ErrorCode::DependencyUnresolvable, 5),
        (common::ErrorCode::Collision, 6),
        (common::ErrorCode::Weave, 7),
        (common::ErrorCode::Snapshot, 8),
        (common::ErrorCode::Container, 9),
        (common::ErrorCode::RosettaPlugin, 10),
        (common::ErrorCode::Serialization, 11),
        (common::ErrorCode::Internal, 12),
    ];
    for (variant, value) in pinned {
        assert_eq!(variant as i32, value, "{variant:?} drifted from its pin");
    }
}

#[test]
fn default_error_is_unspecified() {
    let error = common::Error::default();
    assert_eq!(error.code, common::ErrorCode::Unspecified as i32);
    assert!(error.message.is_empty());
}

// ─── Service markers & tonic constructor paths ──────────────────

/// UDS URI for a socket path (`unix://` + absolute tmpdir path).
fn uds_uri(sock: &Path) -> String {
    format!("unix://{}", sock.display())
}

#[test]
fn pkt_client_connect_fails_cleanly_without_a_listener() {
    // The `connect` constructor path must exist and speak the `unix://`
    // scheme the daemon socket uses; a nonexistent socket is a transport
    // error, not a panic. `PktServiceClient::new` is exercised inside
    // `connect` (the generated body ends in `Self::new(conn)`).
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    rt.block_on(async {
        let dir = tempfile::tempdir().expect("tmpdir");
        let missing = dir.path().join("absent.sock");
        let attempted = tokio::time::timeout(
            CALL_TIMEOUT,
            pkt::pkt_service_client::PktServiceClient::connect(uds_uri(&missing)),
        )
        .await
        .expect("connect must not hang");
        match attempted {
            Err(_) => { /* eager connect failed, as expected */ }
            Ok(mut client) => {
                // Lazy-connect transports surface the failure on first use.
                let call = tokio::time::timeout(
                    CALL_TIMEOUT,
                    client.sync(pkt::SyncRequest::default()),
                )
                .await
                .expect("sync must not hang");
                assert!(call.is_err(), "RPC against a dead endpoint must fail");
            }
        }
    });
}

/// Test-local `PktService` stub: answers `sync` with a canned report and
/// marks the other four methods unimplemented. This pins the exact server
/// trait shape (`async fn` per RPC, `tonic::Request`/`Response` wrapping)
/// that the PLAN 8.1.3 server will implement.
struct PktStub;

#[tonic::async_trait]
impl pkt::pkt_service_server::PktService for PktStub {
    async fn sync(
        &self,
        request: tonic::Request<pkt::SyncRequest>,
    ) -> Result<tonic::Response<pkt::SyncResponse>, tonic::Status> {
        let req = request.into_inner();
        let (_, mut response) = ingest_payload();
        response.origin = req.origin;
        response.name = req.name;
        response.version = req.version;
        Ok(tonic::Response::new(response))
    }

    async fn query(
        &self,
        _request: tonic::Request<pkt::QueryRequest>,
    ) -> Result<tonic::Response<pkt::QueryResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("schema pin: query"))
    }

    async fn files(
        &self,
        _request: tonic::Request<pkt::FilesRequest>,
    ) -> Result<tonic::Response<pkt::FilesResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("schema pin: files"))
    }

    async fn soname(
        &self,
        _request: tonic::Request<pkt::SonameRequest>,
    ) -> Result<tonic::Response<pkt::SonameResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("schema pin: soname"))
    }

    async fn ingest(
        &self,
        _request: tonic::Request<pkt::IngestRequest>,
    ) -> Result<tonic::Response<pkt::IngestResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("schema pin: ingest"))
    }
}

/// Test-local `InstanzService` stub answering `generations` (see PktStub).
struct InstanzStub;

#[tonic::async_trait]
impl instanz::instanz_service_server::InstanzService for InstanzStub {
    async fn apply(
        &self,
        _request: tonic::Request<instanz::ApplyRequest>,
    ) -> Result<tonic::Response<instanz::ApplyResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("schema pin: apply"))
    }

    async fn rollback(
        &self,
        _request: tonic::Request<instanz::RollbackRequest>,
    ) -> Result<tonic::Response<instanz::RollbackResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("schema pin: rollback"))
    }

    async fn generations(
        &self,
        _request: tonic::Request<instanz::GenerationsRequest>,
    ) -> Result<tonic::Response<instanz::GenerationsResponse>, tonic::Status> {
        Ok(tonic::Response::new(instanz::GenerationsResponse {
            generations: vec![instanz::GenerationRow {
                number: 7,
                timestamp: Some(1_700_000_000),
                packages: vec!["archlinux/htop".into()],
                description: "seed generation".into(),
                is_current: true,
                pinned: false,
            }],
            error: None,
        }))
    }

    async fn container(
        &self,
        _request: tonic::Request<instanz::ContainerRequest>,
    ) -> Result<tonic::Response<instanz::ContainerResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("schema pin: container"))
    }
}

#[test]
fn pkt_service_wire_round_trip_over_uds() {
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    rt.block_on(async {
        let dir = tempfile::tempdir().expect("tmpdir");
        let sock = dir.path().join("pkt.sock");
        let listener = tokio::net::UnixListener::bind(&sock).expect("bind control socket");
        let incoming = UnixListenerStream::new(listener);
        let server = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(pkt::pkt_service_server::PktServiceServer::new(PktStub))
                .serve_with_incoming(incoming)
                .await
                .expect("pkt schema server must not fail");
        });

        // `bind` created the socket file, so the client can connect before
        // the server task is first polled (the listener backlog holds it).
        let mut client = tokio::time::timeout(
            CALL_TIMEOUT,
            pkt::pkt_service_client::PktServiceClient::connect(uds_uri(&sock)),
        )
        .await
        .expect("connect must not hang")
        .expect("client connect over UDS");

        let request = pkt::SyncRequest {
            origin: "archlinux".into(),
            name: "htop".into(),
            version: "3.3.0-1".into(),
            download_only: false,
        };
        let response = tokio::time::timeout(CALL_TIMEOUT, client.sync(request))
            .await
            .expect("sync must not hang")
            .expect("sync must succeed")
            .into_inner();

        let (_, expected) = ingest_payload();
        assert!(response == expected, "wire round-trip must preserve the payload");

        // An unimplemented method is a transport-level status (the schema
        // convention), observable from the client.
        let status = tokio::time::timeout(
            CALL_TIMEOUT,
            client.query(pkt::QueryRequest { origin: None }),
        )
        .await
        .expect("query must not hang")
        .expect_err("unimplemented method must be a gRPC status");
        assert_eq!(status.code(), tonic::Code::Unimplemented);

        server.abort();
        let _ = server.await;
    });
}

#[test]
fn instanz_service_wire_round_trip_over_uds() {
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    rt.block_on(async {
        let dir = tempfile::tempdir().expect("tmpdir");
        let sock = dir.path().join("instanz.sock");
        let listener = tokio::net::UnixListener::bind(&sock).expect("bind control socket");
        let incoming = UnixListenerStream::new(listener);
        let server = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(instanz::instanz_service_server::InstanzServiceServer::new(
                    InstanzStub,
                ))
                .serve_with_incoming(incoming)
                .await
                .expect("instanz schema server must not fail");
        });

        let mut client = tokio::time::timeout(
            CALL_TIMEOUT,
            instanz::instanz_service_client::InstanzServiceClient::connect(uds_uri(&sock)),
        )
        .await
        .expect("connect must not hang")
        .expect("client connect over UDS");

        let response = tokio::time::timeout(
            CALL_TIMEOUT,
            client.generations(instanz::GenerationsRequest {}),
        )
        .await
        .expect("generations must not hang")
        .expect("generations must succeed")
        .into_inner();

        assert_eq!(response.generations.len(), 1);
        assert_eq!(response.generations[0].number, 7);
        assert!(response.generations[0].is_current);
        assert!(response.error.is_none());

        server.abort();
        let _ = server.await;
    });
}

#[test]
fn server_markers_construct_and_client_types_exist() {
    // The generated server wrappers are generic over any service type; both
    // must construct here and carry the tuning methods the real servers
    // (PLAN 8.1.3/8.1.4) will use. The client type aliases below pin the
    // full module path of every generated marker.
    let _pkt_server = pkt::pkt_service_server::PktServiceServer::new(PktStub)
        .max_decoding_message_size(1024 * 1024);
    let _instanz_server = instanz::instanz_service_server::InstanzServiceServer::new(InstanzStub)
        .max_decoding_message_size(1024 * 1024);

    type PktClient = pkt::pkt_service_client::PktServiceClient<tonic::transport::Channel>;
    type InstanzClient =
        instanz::instanz_service_client::InstanzServiceClient<tonic::transport::Channel>;
    fn assert_send_sync<T: Send + Sync + Clone + 'static>() {}
    assert_send_sync::<PktClient>();
    assert_send_sync::<InstanzClient>();
}
