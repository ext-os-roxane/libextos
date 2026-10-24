//! Integration tests for the libp2p swarm node (PLAN 8.2.1, lane L32).
//!
//! Every test drives the REAL libp2p stack on loopback with ephemeral
//! ports (no fixed ports, no mocks): the two-node dial test connects a
//! genuine TCP+noise+yamux transport between two in-process nodes, and the
//! mDNS probe exercises true multicast discovery on the host.
//!
//! Honest-skip contract (mirrors `users_int.rs`): only an *environmental*
//! impossibility (no multicast socket on the host) prints a typed
//! `SKIP mDNS multicast unavailable …` — never a fake pass. Everything the
//! host can provide must be proven, within bounded timeouts.

use std::time::Duration;

use libextos::network::swarm::SwarmConfig;
use libextos::swarm::{DiscoverySource, SwarmError, SwarmNode, SwarmNodeEvent};

/// How long a test drives the event loops before declaring failure.
const DRIVE_TIMEOUT: Duration = Duration::from_secs(30);

/// An enabled node config listening on an ephemeral loopback port.
fn loopback_config(bootstrap: Vec<String>) -> SwarmConfig {
    SwarmConfig {
        enabled: true,
        listen: "/ip4/127.0.0.1/tcp/0".to_string(),
        bootstrap,
        max_bytes_per_second: None,
    }
}

/// Collect events from both nodes until `done` says stop (or the bounded
/// timeout hits — the select carries the deadline itself so a total event
/// drought cannot hang the loop). Returns the collected events.
async fn drive_both(
    a: &mut SwarmNode,
    b: &mut SwarmNode,
    done: impl Fn(&[SwarmNodeEvent], &[SwarmNodeEvent]) -> bool,
) -> (Vec<SwarmNodeEvent>, Vec<SwarmNodeEvent>) {
    let mut a_events = Vec::new();
    let mut b_events = Vec::new();
    let deadline = tokio::time::Instant::now() + DRIVE_TIMEOUT;
    while !done(&a_events, &b_events) {
        let sleep = tokio::time::sleep_until(deadline);
        tokio::pin!(sleep);
        tokio::select! {
            event = a.next_event() => a_events.push(event),
            event = b.next_event() => b_events.push(event),
            _ = &mut sleep => panic!(
                "swarm drive timed out after {DRIVE_TIMEOUT:?}: a={a_events:?} b={b_events:?}"
            ),
        }
    }
    (a_events, b_events)
}

/// Deterministic two-node dial (the plan's named probe): node A listens on
/// an ephemeral loopback port, node B's config carries A's address + peer
/// id as a bootstrap peer. Both must report `PeerDiscovered{Bootstrap}`,
/// and the Identify exchange must fire in both directions through the REAL
/// libp2p stack.
#[tokio::test(flavor = "multi_thread")]
async fn two_node_bootstrap_dial_exchanges_identify() {
    let mut a = SwarmNode::new(&loopback_config(vec![]))
        .await
        .expect("node A");
    let a_listen = a.listen_addresses()[0].clone();

    // Bootstrap entry: A's dialable address with its peer id attached.
    let a_multiaddr = a.dialable_addresses()[0].clone();
    let mut b = SwarmNode::new(&loopback_config(vec![a_multiaddr.to_string()]))
        .await
        .expect("node B");

    let a_peer = a.local_peer_id();
    let b_peer = b.local_peer_id();
    assert_ne!(a_peer, b_peer);

    let (a_events, b_events) = drive_both(&mut a, &mut b, |a_events, b_events| {
        let both_discovered = a_events.iter().any(|e| {
            matches!(e, SwarmNodeEvent::PeerDiscovered { peer_id, source: DiscoverySource::Bootstrap }
                if *peer_id == b_peer)
        }) && b_events.iter().any(|e| {
            matches!(e, SwarmNodeEvent::PeerDiscovered { peer_id, source: DiscoverySource::Bootstrap }
                if *peer_id == a_peer)
        });
        let identify_both_ways = a_events.iter().any(|e| {
            matches!(e, SwarmNodeEvent::Identified { peer_id, agent_version, listen_addrs }
                if *peer_id == b_peer && agent_version.contains("extos") && !listen_addrs.is_empty())
        }) && b_events.iter().any(|e| {
            matches!(e, SwarmNodeEvent::Identified { peer_id, agent_version, listen_addrs }
                if *peer_id == a_peer && agent_version.contains("extos") && !listen_addrs.is_empty())
        });
        both_discovered && identify_both_ways
    })
    .await;

    // Pin each half explicitly (the drive condition stops early).
    assert!(
        b_events.iter().any(|e| matches!(e,
            SwarmNodeEvent::PeerDiscovered { peer_id, source: DiscoverySource::Bootstrap }
                if *peer_id == a_peer)),
        "B must discover A via the bootstrap dial: {b_events:?}"
    );
    assert!(
        a_events.iter().any(|e| matches!(e,
            SwarmNodeEvent::PeerDiscovered { peer_id, source: DiscoverySource::Bootstrap }
                if *peer_id == b_peer)),
        "A must see the inbound bootstrap connection: {a_events:?}"
    );
    for (events, remote, label) in [
        (&b_events, a_peer, "B→A"),
        (&a_events, b_peer, "A→B"),
    ] {
        assert!(
            events.iter().any(|e| matches!(e,
                SwarmNodeEvent::Identified { peer_id, agent_version, listen_addrs }
                    if *peer_id == remote
                        && agent_version.contains("extos")
                        && !listen_addrs.is_empty())),
            "Identify exchange {label} must carry agent version + listen addrs: {events:?}"
        );
    }
    // A reported its real (ephemeral) listener.
    assert!(
        a_events
            .iter()
            .any(|e| matches!(e, SwarmNodeEvent::ListeningOn(addr) if *addr == a_listen)),
        "ListeningOn must carry the resolved ephemeral address: {a_events:?}"
    );
    println!(
        "PROVEN two-node bootstrap dial over the real libp2p stack: a={{peer {a_peer}, {} event(s)}}, \
         b={{peer {b_peer}, {} event(s)}} — PeerDiscovered{{Bootstrap}} both ways, Identify \
         exchanged both ways",
        a_events.len(),
        b_events.len()
    );
}

/// Kademlia: after the bootstrap connect, B's DHT routing table contains A
/// — asserted both through the event surface (`PeerDiscovered{Kademlia}`
/// from `kad::Event::RoutingUpdated`) and through a live k-bucket walk.
#[tokio::test(flavor = "multi_thread")]
async fn kademlia_routing_table_contains_the_bootstrap_peer() {
    let mut a = SwarmNode::new(&loopback_config(vec![]))
        .await
        .expect("node A");
    let a_multiaddr = a.dialable_addresses()[0].clone();
    let mut b = SwarmNode::new(&loopback_config(vec![a_multiaddr.to_string()]))
        .await
        .expect("node B");
    let a_peer = a.local_peer_id();

    // Drive until B's routing table accepted A (the server-mode kad adds
    // every established connection's address; RoutingUpdated is the event).
    let mut b_events = Vec::new();
    let deadline = tokio::time::Instant::now() + DRIVE_TIMEOUT;
    loop {
        let in_table = b.kad_kbucket_contains(&a_peer);
        let kad_event = b_events.iter().any(|e| {
            matches!(e, SwarmNodeEvent::PeerDiscovered { peer_id, source: DiscoverySource::Kademlia }
                if *peer_id == a_peer)
        });
        if in_table && kad_event {
            break;
        }
        let sleep = tokio::time::sleep_until(deadline);
        tokio::pin!(sleep);
        tokio::select! {
            _ = a.next_event() => {} // A must be driven too (identify push, kad peer feed)
            event = b.next_event() => b_events.push(event),
            _ = &mut sleep => panic!(
                "kad routing table never accepted the bootstrap peer within {DRIVE_TIMEOUT:?} \
                 (in_table={in_table}, kad_event={kad_event}): {b_events:?}"
            ),
        }
    }

    // The live k-buckets and the event-tracked view agree.
    assert!(
        b.kad_kbucket_contains(&a_peer),
        "B's Kademlia routing table must contain the bootstrap peer A"
    );
    assert!(
        b.kad_peers().any(|peer| *peer == a_peer),
        "the event-tracked kad view must contain A"
    );
    assert!(
        b_events.iter().any(|e| matches!(e,
            SwarmNodeEvent::PeerDiscovered { peer_id, source: DiscoverySource::Kademlia }
                if *peer_id == a_peer)),
        "kad acceptance must surface as PeerDiscovered{{Kademlia}}: {b_events:?}"
    );
    println!(
        "PROVEN Kademlia bootstrap seeding: B's live k-buckets contain A (peer {a_peer}) after \
         the bootstrap connect, with PeerDiscovered{{Kademlia}} on the event surface"
    );
}

/// mDNS probe: two nodes on the same host, no bootstrap config, mdns
/// enabled (part of the node build) — genuine multicast discovery.
///
/// Honesty contract: an *environmental* impossibility must be proven, not
/// assumed. If the libp2p node cannot even construct mDNS
/// ([`SwarmError::Mdns`]) that is one typed proof; otherwise a raw UDP
/// multicast probe (join the group, send, expect local delivery — the same
/// egress path the mdns behaviour's queries take) establishes whether this
/// host delivers multicast at all. Raw probe failing → honest
/// `SKIP mDNS multicast unavailable …` with the evidence; raw probe
/// succeeding while the swarm never reports a peer → genuine FAIL (a real
/// stack bug may not hide behind a skip).
#[tokio::test(flavor = "multi_thread")]
async fn mdns_discovers_peers_on_the_same_host() {
    let mut a = match SwarmNode::new(&loopback_config(vec![])).await {
        Ok(node) => node,
        Err(SwarmError::Mdns { source }) => {
            println!("SKIP mDNS multicast unavailable on this host: {source}");
            return;
        }
        Err(err) => panic!("node A: {err}"),
    };
    let mut b = match SwarmNode::new(&loopback_config(vec![])).await {
        Ok(node) => node,
        Err(SwarmError::Mdns { source }) => {
            println!("SKIP mDNS multicast unavailable on this host: {source}");
            return;
        }
        Err(err) => panic!("node B: {err}"),
    };

    // Independent host-capability probe: a raw UDP socket joins the mDNS
    // group the way libp2p-mdns does (unspecified interface = kernel
    // default egress) and sends; local loop-back delivery is the kernel
    // capability same-host mDNS discovery needs.
    if !raw_multicast_probe().expect("raw multicast probe ran") {
        println!(
            "SKIP mDNS multicast unavailable on this host: a raw UDP multicast probe \
             (group join + send + local receive, unspecified egress interface) received \
             nothing back — the kernel never delivered the datagram to a local group \
             member, so the mdns behaviour's queries cannot reach a same-host peer either"
        );
        return;
    }

    let a_peer = a.local_peer_id();
    let b_peer = b.local_peer_id();

    // No dials are configured: the only way these two learn of each other
    // is the multicast link-local layer.
    let (a_events, b_events) = drive_both(&mut a, &mut b, |a_events, b_events| {
        a_events.iter().any(|e| {
            matches!(e, SwarmNodeEvent::PeerDiscovered { peer_id, source: DiscoverySource::Mdns }
                if *peer_id == b_peer)
        }) || b_events.iter().any(|e| {
            matches!(e, SwarmNodeEvent::PeerDiscovered { peer_id, source: DiscoverySource::Mdns }
                if *peer_id == a_peer)
        })
    })
    .await;

    let found = a_events
        .iter()
        .chain(b_events.iter())
        .find(|e| matches!(e, SwarmNodeEvent::PeerDiscovered { source: DiscoverySource::Mdns, .. }))
        .expect("mDNS discovery must fire within the bounded timeout once the raw probe proved delivery");
    println!(
        "PROVEN mDNS discovery: {found:?} (a saw {} event(s), b saw {} event(s))",
        a_events.len(),
        b_events.len()
    );
    assert!(
        matches!(found, SwarmNodeEvent::PeerDiscovered { source: DiscoverySource::Mdns, .. }),
        "{found:?}"
    );
}

/// Raw UDP multicast capability probe: `true` when a datagram sent to the
/// mDNS group is delivered back to a local group member. Mirrors the
/// socket discipline of `libp2p-mdns`'s iface setup (multicast loop on,
/// group joined with the *unspecified* interface → kernel default egress),
/// using only `std::net` (no new dev-dependency).
fn raw_multicast_probe() -> std::io::Result<bool> {
    use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};

    const GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251); // the mDNS group

    let receiver = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))?;
    receiver.set_read_timeout(Some(Duration::from_secs(2)))?;
    receiver.set_multicast_loop_v4(true)?;
    receiver.join_multicast_v4(&GROUP, &Ipv4Addr::UNSPECIFIED)?;
    let recv_port = receiver.local_addr()?.port();

    // The sender is a second group member, exactly like the mdns recv
    // socket of a second node: its datagram must loop back to the receiver.
    let sender = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))?;
    sender.set_multicast_loop_v4(true)?;
    sender.join_multicast_v4(&GROUP, &Ipv4Addr::UNSPECIFIED)?;

    for attempt in 0..3 {
        let payload = format!("extos-mdns-probe-{attempt}");
        sender.send_to(payload.as_bytes(), SocketAddrV4::new(GROUP, recv_port))?;
        let mut buf = [0u8; 128];
        match receiver.recv(&mut buf) {
            Ok(n) if buf[..n] == *payload.as_bytes() => return Ok(true),
            Ok(_) => continue,
            Err(err)
                if err.kind() == std::io::ErrorKind::WouldBlock
                    || err.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue
            }
            Err(err) => return Err(err),
        }
    }
    Ok(false)
}

/// Config validation: a hostile multiaddr (whitespace, control characters,
/// or a charset-clean but unparseable placeholder) is a typed error before
/// any network touch.
#[tokio::test]
async fn hostile_multiaddr_is_typed_rejected_before_any_network_touch() {
    // Whitespace in the listen address.
    let err = match SwarmNode::new(&SwarmConfig {
        enabled: true,
        listen: "bad addr with space".to_string(),
        bootstrap: vec![],
        max_bytes_per_second: None,
    })
    .await
    {
        Err(err) => err,
        Ok(_) => panic!("hostile listen addr must be rejected"),
    };
    assert!(matches!(err, SwarmError::InvalidMultiaddr { .. }), "{err}");
    assert!(err.to_string().contains("bad addr with space"), "{err}");

    // Control character in a bootstrap entry.
    let err = match SwarmNode::new(&SwarmConfig {
        enabled: true,
        listen: "/ip4/127.0.0.1/tcp/0".to_string(),
        bootstrap: vec!["/ip4/127.0.0.1/tcp/4001\nInjected".to_string()],
        max_bytes_per_second: None,
    })
    .await
    {
        Err(err) => err,
        Ok(_) => panic!("hostile bootstrap entry must be rejected"),
    };
    assert!(matches!(err, SwarmError::InvalidMultiaddr { .. }), "{err}");

    // Charset-clean but unparseable (the shipped grammar template's
    // placeholder is not a multiaddr — the runtime constrains it).
    let err = match SwarmNode::new(&SwarmConfig {
        enabled: true,
        listen: "/ip4/127.0.0.1/tcp/0".to_string(),
        bootstrap: vec!["p2p://swarm.extos.org".to_string()],
        max_bytes_per_second: None,
    })
    .await
    {
        Err(err) => err,
        Ok(_) => panic!("unparseable bootstrap entry must be rejected"),
    };
    assert!(matches!(err, SwarmError::InvalidMultiaddr { .. }), "{err}");
    assert!(err.to_string().contains("p2p://swarm.extos.org"), "{err}");
}

/// A disabled config builds an inert node: no listener, no dials, and the
/// node stays constructible on any host (nothing touches the network).
#[tokio::test]
async fn disabled_config_builds_an_inert_node() {
    let node = SwarmNode::new(&SwarmConfig {
        enabled: false,
        listen: "/ip4/127.0.0.1/tcp/0".to_string(),
        bootstrap: vec!["/ip4/127.0.0.1/tcp/9".to_string()],
        max_bytes_per_second: None,
    })
    .await
    .expect("inert node");
    assert!(node.listen_addresses().is_empty());
    assert!(node.dialable_addresses().is_empty());
    // Inert but real: the DHT view is empty and the identity exists.
    assert_eq!(node.kad_peers().count(), 0);
    let peer = node.local_peer_id();
    assert!(!peer.to_string().is_empty());
}

// ─── PLAN 8.2.2 / 8.2.4: CAS object sharing between two nodes ──

mod share_fixtures {
    use libextos::cas::CasRepository;
    use libextos::types::HashAlgorithm;

    /// A tmpdir CAS carrying one small object (content + manifest).
    pub fn cas_with_object(tag: &str, scratch: &std::path::Path) -> (CasRepository, String) {
        let repo = CasRepository::open(scratch.join(tag), HashAlgorithm::Blake3).unwrap();
        let src = scratch.join(format!("{tag}-src"));
        std::fs::create_dir_all(src.join("usr/bin")).unwrap();
        std::fs::create_dir_all(src.join("usr/share")).unwrap();
        std::fs::write(src.join("usr/bin/tool"), b"#!/bin/sh\necho from-the-swarm\n").unwrap();
        std::fs::write(src.join("usr/share/README"), b"shared over the extos swarm").unwrap();
        std::os::unix::fs::symlink("tool", src.join("usr/bin/tool-link")).unwrap();
        let hash = repo.store_directory(&src).unwrap();
        repo.write_manifest(&hash, "# manifest from the serving node").unwrap();
        (repo, hash)
    }
}

/// Move a node onto a background task that drives its event loop forever
/// (a server must be polled for its inbound requests to be answered).
async fn spawn_drain(mut node: SwarmNode) {
    tokio::spawn(async move {
        loop {
            node.next_event().await;
        }
    });
}

/// The PLAN's named e2e (8.2.4): two nodes over the REAL libp2p stack on
/// loopback; the serving node shares a CAS object; the fetching node
/// re-stores it and content addressing proves the bytes survived intact.
#[tokio::test]
async fn two_nodes_share_a_cas_object_over_libp2p() {
    use libextos::swarm::exchange::{store_shared_object, ExchangeLimits, ExchangeResponse};

    let scratch = tempfile::tempdir().unwrap();
    let (serving_repo, hash) = share_fixtures::cas_with_object("a", scratch.path());
    let receiving_repo =
        libextos::cas::CasRepository::open(scratch.path().join("b"), libextos::types::HashAlgorithm::Blake3)
            .unwrap();

    // Node A listens; node B bootstraps against it.
    let mut a = SwarmNode::new(&loopback_config(vec![])).await.unwrap();
    let addr = a
        .dialable_addresses()
        .into_iter()
        .next()
        .expect("node A has a dialable address");
    let mut b = SwarmNode::new(&loopback_config(vec![format!(
        "{}/p2p/{}",
        addr,
        a.local_peer_id()
    )]))
    .await
    .unwrap();
    // Drive both until B discovered A (the connection exists).
    drive_both(&mut a, &mut b, |_, b_events| {
        b_events
            .iter()
            .any(|e| matches!(e, SwarmNodeEvent::PeerDiscovered { .. }))
    })
    .await;
    a.serve_repository(serving_repo, ExchangeLimits::default());
    let a_peer = a.local_peer_id();
    spawn_drain(a).await;

    // Probe then fetch — the real request-response protocol on the wire.
    let present = b
        .probe_object(&a_peer, &hash, Duration::from_secs(20))
        .await
        .unwrap();
    assert!(present, "the serving node must report the object");

    let response = b
        .fetch_object(&a_peer, &hash, Duration::from_secs(20))
        .await
        .unwrap();
    let ExchangeResponse::Object {
        manifest_nix,
        archive,
    } = response
    else {
        panic!("expected an object response, got {response:?}");
    };
    assert_eq!(manifest_nix, "# manifest from the serving node");

    let stored = store_shared_object(&receiving_repo, &manifest_nix, &archive).unwrap();
    assert_eq!(stored, hash, "content addressing must survive the swarm");
    // The symlink rode along.
    assert!(receiving_repo
        .retrieve(&hash)
        .unwrap()
        .join("usr/bin/tool-link")
        .is_file());
}

/// A discovery-only peer (never called `serve_repository`) answers Missing.
#[tokio::test]
async fn discovery_only_nodes_answer_missing() {
    let scratch = tempfile::tempdir().unwrap();
    let (_idle_repo, hash) = share_fixtures::cas_with_object("idle", scratch.path());

    let mut a = SwarmNode::new(&loopback_config(vec![])).await.unwrap();
    let addr = a.dialable_addresses().remove(0);
    let mut b = SwarmNode::new(&loopback_config(vec![format!(
        "{}/p2p/{}",
        addr,
        a.local_peer_id()
    )]))
    .await
    .unwrap();
    drive_both(&mut a, &mut b, |_, b_events| {
        b_events
            .iter()
            .any(|e| matches!(e, SwarmNodeEvent::PeerDiscovered { .. }))
    })
    .await;
    let a_peer = a.local_peer_id();
    spawn_drain(a).await;

    // The probe is honest: node A has the object in its repo but serves
    // nothing, so both probe and fetch report absence.
    let present = b
        .probe_object(&a_peer, &hash, Duration::from_secs(20))
        .await
        .unwrap();
    assert!(!present);
    let response = b
        .fetch_object(&a_peer, &hash, Duration::from_secs(20))
        .await
        .unwrap();
    assert!(
        matches!(response, libextos::swarm::exchange::ExchangeResponse::Missing),
        "{response:?}"
    );
}

/// The per-object cap refuses transfers with the typed wire response.
#[tokio::test]
async fn too_large_objects_are_refused_over_the_wire() {
    use libextos::swarm::exchange::{ExchangeLimits, ExchangeResponse};

    let scratch = tempfile::tempdir().unwrap();
    let (serving_repo, hash) = share_fixtures::cas_with_object("cap", scratch.path());

    let mut a = SwarmNode::new(&loopback_config(vec![])).await.unwrap();
    let addr = a.dialable_addresses().remove(0);
    let mut b = SwarmNode::new(&loopback_config(vec![format!(
        "{}/p2p/{}",
        addr,
        a.local_peer_id()
    )]))
    .await
    .unwrap();
    // A cap of 1 byte: every real object is over it.
    a.serve_repository(
        serving_repo,
        ExchangeLimits {
            max_object_bytes: 1,
        },
    );
    drive_both(&mut a, &mut b, |_, b_events| {
        b_events
            .iter()
            .any(|e| matches!(e, SwarmNodeEvent::PeerDiscovered { .. }))
    })
    .await;
    let a_peer = a.local_peer_id();
    spawn_drain(a).await;

    let response = b
        .fetch_object(&a_peer, &hash, Duration::from_secs(20))
        .await
        .unwrap();
    match response {
        ExchangeResponse::TooLarge { size, limit } => {
            assert!(size > 1);
            assert_eq!(limit, 1);
        }
        other => panic!("expected TooLarge, got {other:?}"),
    }
}
