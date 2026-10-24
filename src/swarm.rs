//! P2P swarm node (PLAN 8.2.1): libp2p peer discovery over mDNS and
//! Kademlia, driven by the Phase-7 declarative surface
//! [`crate::network::swarm::SwarmConfig`].
//!
//! # Scope (PLAN 8.2.1, lane L32)
//!
//! This module ships the swarm *foundation*: a [`SwarmNode`] that builds a
//! real libp2p stack (tokio + TCP + noise + yamux), discovers peers over
//! mDNS ([`SwarmNodeEvent::PeerDiscovered`] with
//! [`DiscoverySource::Mdns`]), seeds and maintains a Kademlia DHT in server
//! mode from the config's bootstrap multiaddrs
//! ([`DiscoverySource::Kademlia`]), exchanges Identify metadata
//! ([`SwarmNodeEvent::Identified`]) and reports its listeners
//! ([`SwarmNodeEvent::ListeningOn`]).
//!
//! **Not in this phase** (next lane, PLAN 8.2.2/8.2.3): CAS object sharing
//! and bandwidth limits. The extension point is [`ExtosBehaviour`] — the
//! composed behaviour struct the next lane extends with a
//! `request-response` behaviour and a rate-limited transport; every event
//! surfaces through the single [`SwarmNode::next_event`] translation, so
//! new behaviour arms slot in without changing the node API.
//!
//! # Security disclosure (Phase 8 scope, per the approved artifact)
//!
//! **Transport authentication between peers is out of scope this phase.**
//! Any peer that can reach the listen address can connect, be discovered,
//! and enter the DHT; noise encrypts the transport but there is no peer
//! identity allow-list. This is acceptable for Phase 8 because the swarm
//! distributes *public package content* (the CAS objects the design exports
//! read-only); the exposure surface is: peer connectivity, discovery
//! metadata (agent version, listen addresses) and DHT participation — no
//! private data crosses the wire at this layer. The declarative surface
//! (`swarm.nix`, PLAN 7.3.2) is the future home of an auth policy.
//!
//! # Config surface
//!
//! [`SwarmNode::new`] consumes the Phase-7
//! [`crate::network::swarm::SwarmConfig`] (`enabled` / `listen` /
//! `bootstrap`):
//!
//! * every `listen` and `bootstrap` string is first re-checked against the
//!   7.3.2 charset contract (no whitespace, quotes, backslashes or control
//!   characters — [`validate_peer_string`] reuses
//!   `network::hostile_str_reason`), then parsed as a libp2p
//!   [`Multiaddr`]. Both checks run **before any network touch**, so a
//!   hostile config fails with a typed [`SwarmError::InvalidMultiaddr`]
//!   and never opens a socket;
//! * the grammar's bootstrap entries are *strings* — the runtime constrains
//!   them to parseable multiaddrs. A bootstrap entry may carry a
//!   `/p2p/<peer-id>` suffix: the peer id is then known before dialing and
//!   seeds the DHT eagerly; entries without one are dialed and their peer
//!   id is learned at connect time;
//! * `enabled = false` builds an inert node: no listener, no dials
//!   (discovery behaviours exist but the node never opens a connection);
//! * `enabled = true` listens on `listen` **and awaits the bind result**
//!   inside [`SwarmNode::new`] (bounded), so a port clash surfaces as a
//!   typed [`SwarmError::Listen`] instead of an async surprise; then the
//!   bootstrap multiaddrs are dialed.
//!
//! # Event surface
//!
//! The node is *poll-able*: [`SwarmNode::next_event`] awaits the next
//! translated event. Translation never discards libp2p events — anything
//! that carries no node-level meaning updates internal state only. Events
//! produced while [`SwarmNode::new`] awaited the listener are buffered and
//! delivered by [`SwarmNode::next_event`] first (lossless). Two nodes are
//! driven concurrently by selecting over their `next_event` futures — the
//! swarm poll is atomic per event, so the futures are cancellation-safe.
//!
//! [`SwarmNodeEvent::PeerDiscovered`] sources, precisely:
//!
//! * [`DiscoverySource::Mdns`] — the mDNS behaviour reported the peer
//!   (local-link discovery); mDNS never triggers dials;
//! * [`DiscoverySource::Bootstrap`] — a connection was *established* on the
//!   bootstrap dial path: either we dialed a configured bootstrap address,
//!   or a peer connected to us (the inbound leg of its bootstrap dial —
//!   indistinguishable at this layer, same source). In a discovery-only
//!   node every established connection originates from this path, which is
//!   what makes the two-node bootstrap probe deterministic;
//! * [`DiscoverySource::Kademlia`] — the DHT's routing table accepted the
//!   peer (`kad::Event::RoutingUpdated`; the node adds every established
//!   connection's remote address to the routing table, server mode).
//!
//! # Examples
//!
//! ```
//! use libextos::network::swarm::SwarmConfig;
//! use libextos::swarm::{SwarmError, SwarmNode, validate_peer_string};
//!
//! # async fn demo() -> Result<(), SwarmError> {
//! // The 7.3.2 charset contract, re-exported for callers that build
//! // configs programmatically.
//! validate_peer_string("/ip4/127.0.0.1/tcp/0").unwrap();
//!
//! let mut node = SwarmNode::new(&SwarmConfig {
//!     enabled: true,
//!     listen: "/ip4/127.0.0.1/tcp/0".to_string(), // ephemeral
//!     bootstrap: vec![],
//!     max_bytes_per_second: None, // PLAN 8.2.3: unlimited serving
//! })
//! .await?;
//! // The bind result was awaited inside `new`, so the real address is known.
//! assert!(node.listen_addresses()[0]
//!     .to_string()
//!     .starts_with("/ip4/127.0.0.1/tcp/"));
//!
//! let event = node.next_event().await; // PeerDiscovered / Identified / ...
//! # let _ = event;
//! # Ok(())
//! # }
//! ```

pub mod exchange;

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::future::poll_fn;
use std::task::Poll;
use std::time::Duration;

use libp2p::futures::StreamExt;
use libp2p::identity::Keypair;
use libp2p::kad::store::MemoryStore;
use libp2p::multiaddr::{Error as MultiaddrError, Multiaddr, Protocol};
use libp2p::swarm::{NetworkBehaviour, Swarm, SwarmEvent};
use libp2p::{identify, kad, mdns, noise, tcp, yamux, StreamProtocol};

use crate::cas::CasRepository;
use crate::network::hostile_str_reason;
use crate::network::swarm::SwarmConfig;

use exchange::{
    CasExchangeCodec, ExchangeLimits, ExchangeRequest, ExchangeResponse, EXCHANGE_PROTOCOL_NAME,
};

/// The identify protocol version this node advertises (PLAN 8.2.1).
pub const IDENTIFY_PROTOCOL_VERSION: &str = "extos/swarm/1";

/// The identify agent version this node advertises; peers see it in
/// [`SwarmNodeEvent::Identified`].
pub const IDENTIFY_AGENT_VERSION: &str = "extos/swarm/8.2.1";

/// The Kademlia protocol name (namespaced to ExtOS, not the IPFS default).
pub const KAD_PROTOCOL_NAME: &str = "/extos/kad/1.0.0";

/// How long [`SwarmNode::new`] waits for the listener to report its bind
/// result before failing with [`SwarmError::Listen`].
const LISTEN_TIMEOUT: Duration = Duration::from_secs(5);

/// Typed failure of the swarm node (PLAN 8.2.1).
#[derive(Debug, thiserror::Error)]
pub enum SwarmError {
    /// A config multiaddr failed the 7.3.2 charset contract or the libp2p
    /// parser. Raised before any network touch.
    #[error("invalid multiaddr {addr:?}: {reason}")]
    InvalidMultiaddr {
        /// The offending config string.
        addr: String,
        /// Why it is invalid (charset contract or parse error).
        reason: String,
    },
    /// The node could not bind its listener (`enabled = true`).
    #[error("cannot listen on {addr}: {detail}")]
    Listen {
        /// The configured listen multiaddr.
        addr: String,
        /// The libp2p listen failure (`listen_on` rejection, the async bind
        /// error, or a listen-result timeout).
        detail: String,
    },
    /// A configured bootstrap multiaddr could not be dialed.
    #[error("cannot dial bootstrap peer {addr}: {source}")]
    Dial {
        /// The bootstrap multiaddr that failed.
        addr: String,
        /// The libp2p dial error.
        source: libp2p::swarm::DialError,
    },
    /// The mDNS behaviour could not be created (no multicast-capable
    /// socket on this host — containers often lack it). Honest and typed:
    /// the node is not built half-wired, callers see exactly why.
    #[error("mDNS unavailable: {source}")]
    Mdns {
        /// The underlying socket error.
        source: std::io::Error,
    },
    /// An object-exchange request failed (PLAN 8.2.2): the peer answered
    /// unexpectedly, the outbound request failed, or the timeout elapsed.
    #[error("object exchange failed: {detail}")]
    Exchange {
        /// What failed (peer answer shape, transport error, or timeout).
        detail: String,
    },
    /// Anything else the transport builder refuses.
    #[error("swarm config error: {0}")]
    Config(String),
}

/// Why a peer entered (or left) the node's view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoverySource {
    /// Local-link discovery via mDNS (never dials).
    Mdns,
    /// The bootstrap/static dial path (outgoing dial of a configured
    /// bootstrap address, or the inbound leg of one — see the module docs).
    Bootstrap,
    /// The Kademlia DHT routing table accepted the peer.
    Kademlia,
}

impl std::fmt::Display for DiscoverySource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DiscoverySource::Mdns => f.write_str("mdns"),
            DiscoverySource::Bootstrap => f.write_str("bootstrap"),
            DiscoverySource::Kademlia => f.write_str("kademlia"),
        }
    }
}

/// A node-level swarm event (PLAN 8.2.1 event surface).
///
/// This is the *minimum* surface of the plan; the next lane (8.2.2) adds
/// transfer events at the same place without changing the existing arms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SwarmNodeEvent {
    /// A peer became visible from `source`. A peer may be reported more
    /// than once with different sources (mDNS and a bootstrap dial
    /// legitimately coexist).
    PeerDiscovered {
        /// The discovered peer.
        peer_id: libp2p::PeerId,
        /// How the peer was learned.
        source: DiscoverySource,
    },
    /// A previously discovered peer expired (mDNS TTL lapse without
    /// refresh). Kademlia has no expiry events in this libp2p release, and
    /// a connection loss is not an "expiry" — this arm is mDNS-sourced.
    PeerExpired {
        /// The expired peer.
        peer_id: libp2p::PeerId,
        /// The discovery layer that dropped it.
        source: DiscoverySource,
    },
    /// The Identify exchange completed for a connected peer.
    Identified {
        /// The identified peer.
        peer_id: libp2p::PeerId,
        /// The peer's advertised agent version.
        agent_version: String,
        /// The listen addresses the peer advertises.
        listen_addrs: Vec<Multiaddr>,
    },
    /// The node's listener bound an address (the resolved address of an
    /// ephemeral port included).
    ListeningOn(Multiaddr),
}

/// The composed libp2p behaviour of a [`SwarmNode`] (PLAN 8.2.1).
///
/// **Extension point (PLAN 8.2.2/8.2.3, next lane):** the CAS
/// `request-response` behaviour and the bandwidth-limited transport land
/// here as additional fields. The derive regenerates
/// `ExtosBehaviourEvent`, and `SwarmNode::translate` is the single match
/// to extend — the node API, event enum and tests stay stable.
#[derive(NetworkBehaviour)]
#[behaviour(event_process = false)]
pub struct ExtosBehaviour {
    /// Local-link discovery (mDNS).
    pub mdns: mdns::tokio::Behaviour,
    /// Kademlia DHT, server mode, [`MemoryStore`]-backed.
    pub kad: kad::Behaviour<MemoryStore>,
    /// Protocol/agent version exchange.
    pub identify: identify::Behaviour,
    /// CAS object exchange over request-response (PLAN 8.2.2), writes
    /// throttled per PLAN 8.2.3 by the codec's shared token bucket.
    pub rr: libp2p::request_response::Behaviour<CasExchangeCodec>,
}

/// A libp2p swarm node (PLAN 8.2.1): peer discovery over mDNS + Kademlia +
/// Identify, driven by the Phase-7 `swarm.nix` surface.
///
/// Construct with [`SwarmNode::new`]; drive with [`SwarmNode::next_event`].
/// Everything loopback/ephemeral in tests; no fixed ports.
pub struct SwarmNode {
    swarm: Swarm<ExtosBehaviour>,
    local_peer_id: libp2p::PeerId,
    listen_addrs: Vec<Multiaddr>,
    /// Event-buffer for events translated while `new` awaited the listener.
    pending: VecDeque<SwarmNodeEvent>,
    /// Peers learned through mDNS (for `PeerExpired` dedup).
    mdns_seen: BTreeSet<libp2p::PeerId>,
    /// Peers the DHT routing table accepted (`kad::Event::RoutingUpdated`),
    /// the event-tracked view beside the live [`SwarmNode::kad_kbucket_contains`].
    kad_peers: BTreeSet<libp2p::PeerId>,
    /// Serving state when [`SwarmNode::serve_repository`] was called;
    /// `None` means the node answers every exchange request with
    /// [`ExchangeResponse::Missing`] (discovery-only node, PLAN 8.2.2).
    serve: Option<ServeState>,
    /// Completed (or failed) outbound exchange requests awaiting their
    /// [`SwarmNode::fetch_object`] / `probe_object` caller.
    inflight: BTreeMap<libp2p::request_response::OutboundRequestId, Result<ExchangeResponse, String>>,
}

/// What a node serves over the exchange protocol (PLAN 8.2.2).
struct ServeState {
    /// The read-only repository whose objects are shared.
    repo: CasRepository,
    /// Per-object serving caps.
    limits: ExchangeLimits,
}

impl SwarmNode {
    /// Build a node from the Phase-7 declarative surface (PLAN 8.2.1).
    ///
    /// Order of operations, each typed on failure:
    ///
    /// 1. charset-validate every config string (7.3.2 contract) — **before
    ///    any network touch**;
    /// 2. parse each string as a libp2p [`Multiaddr`], splitting the
    ///    optional `/p2p/<peer-id>` suffix off bootstrap entries;
    /// 3. build the transport (tokio TCP + noise + yamux) and the
    ///    [`ExtosBehaviour`] (mDNS + server-mode Kademlia + Identify);
    /// 4. `enabled = true`: listen on `config.listen` and await the bind
    ///    result (bounded) so a port clash is a typed [`SwarmError::Listen`];
    /// 5. `enabled = true`: dial the bootstrap multiaddrs (connection
    ///    establishment is asynchronous — discovery proceeds through
    ///    [`SwarmNode::next_event`]).
    ///
    /// # Errors
    ///
    /// [`SwarmError`] per step above.
    pub async fn new(config: &SwarmConfig) -> Result<SwarmNode, SwarmError> {
        // 1. The 7.3.2 charset contract, re-checked for programmatically
        //    built configs. Nothing has touched the network yet.
        let strings =
            std::iter::once(("listen", config.listen.as_str()))
                .chain(config.bootstrap.iter().map(|a| ("bootstrap", a.as_str())));
        for (field, addr) in strings {
            if let Some(reason) = hostile_str_reason(addr) {
                return Err(SwarmError::InvalidMultiaddr {
                    addr: format!("{field}={addr}"),
                    reason,
                });
            }
        }

        // 2. Parse into libp2p multiaddrs.
        let listen: Multiaddr = config
            .listen
            .parse()
            .map_err(|err: MultiaddrError| SwarmError::InvalidMultiaddr {
                addr: config.listen.clone(),
                reason: err.to_string(),
            })?;
        let mut bootstraps: Vec<(Option<libp2p::PeerId>, Multiaddr)> =
            Vec::with_capacity(config.bootstrap.len());
        for entry in &config.bootstrap {
            bootstraps.push(split_p2p_entry(entry)?);
        }

        // 3. Transport + behaviour.
        let keypair = Keypair::generate_ed25519();
        let local_peer_id = libp2p::PeerId::from(keypair.public());
        let mdns = mdns::tokio::Behaviour::new(mdns::Config::default(), local_peer_id)
            .map_err(|source| SwarmError::Mdns { source })?;
        let mut kad = kad::Behaviour::with_config(
            local_peer_id,
            MemoryStore::new(local_peer_id),
            kad::Config::new(StreamProtocol::new(KAD_PROTOCOL_NAME)),
        );
        // Server mode: the node participates in the DHT (routing-table
        // acceptance + record storage), which the bootstrap seeding and the
        // next lane's object sharing both rely on. Without this, kad falls
        // back to auto-mode and behaves as a client until an external
        // address is confirmed — never the case on a loopback-only test.
        kad.set_mode(Some(kad::Mode::Server));
        let identify = identify::Behaviour::new(
            identify::Config::new(
                IDENTIFY_PROTOCOL_VERSION.to_string(),
                keypair.public(),
            )
            .with_agent_version(IDENTIFY_AGENT_VERSION.to_string()),
        );
        // PLAN 8.2.2/8.2.3: the exchange protocol rides every node; the
        // codec's write throttle comes straight from the declarative limit.
        let codec = match config.max_bytes_per_second {
            Some(rate) => CasExchangeCodec::rate_limited(rate),
            None => CasExchangeCodec::unlimited(),
        };
        let rr = libp2p::request_response::Behaviour::with_codec(
            codec,
            std::iter::once((
                EXCHANGE_PROTOCOL_NAME.to_string(),
                libp2p::request_response::ProtocolSupport::Full,
            )),
            libp2p::request_response::Config::default(),
        );
        let behaviour = ExtosBehaviour { mdns, kad, identify, rr };

        let swarm = libp2p::SwarmBuilder::with_existing_identity(keypair)
            .with_tokio()
            .with_tcp(
                tcp::Config::default().nodelay(true),
                noise::Config::new,
                yamux::Config::default,
            )
            .map_err(|err| SwarmError::Config(format!("transport: {err}")))?
            .with_behaviour(|_| behaviour)
            .map_err(|err: std::convert::Infallible| match err {})?
            .with_swarm_config(|cfg| {
                cfg.with_idle_connection_timeout(Duration::from_secs(60))
            })
            .build();

        let mut node = SwarmNode {
            swarm,
            local_peer_id,
            listen_addrs: Vec::new(),
            pending: VecDeque::new(),
            mdns_seen: BTreeSet::new(),
            kad_peers: BTreeSet::new(),
            serve: None,
            inflight: BTreeMap::new(),
        };

        // 4. Listen (awaited) when enabled: drive the swarm until the
        //    listener reports its bind, so a port clash is a typed
        //    [`SwarmError::Listen`], not an async surprise. Events with no
        //    listener meaning that arrive meanwhile are translated and
        //    buffered (lossless — [`SwarmNode::next_event`] drains them).
        if config.enabled {
            let listen_addr = config.listen.clone();
            node.swarm
                .listen_on(listen)
                .map_err(|err| SwarmError::Listen {
                    addr: listen_addr.clone(),
                    detail: err.to_string(),
                })?;
            let deadline = tokio::time::Instant::now() + LISTEN_TIMEOUT;
            loop {
                let event = tokio::time::timeout_at(
                    deadline,
                    poll_fn(|cx| match node.swarm.poll_next_unpin(cx) {
                        Poll::Ready(Some(event)) => Poll::Ready(Some(event)),
                        // `Swarm`'s stream never ends; treat the
                        // unreachable `None` as Pending.
                        Poll::Ready(None) | Poll::Pending => Poll::Pending,
                    }),
                )
                .await
                .map_err(|_| SwarmError::Listen {
                    addr: listen_addr.clone(),
                    detail: format!("no listener result within {LISTEN_TIMEOUT:?}"),
                })?;
                match event {
                    Some(SwarmEvent::NewListenAddr { address, .. }) => {
                        node.listen_addrs.push(address.clone());
                        node.pending
                            .push_back(SwarmNodeEvent::ListeningOn(address));
                        break;
                    }
                    Some(SwarmEvent::ListenerError { error, .. }) => {
                        return Err(SwarmError::Listen {
                            addr: listen_addr,
                            detail: error.to_string(),
                        });
                    }
                    Some(other) => {
                        if let Some(translated) = node.translate(other) {
                            node.pending.push_back(translated);
                        }
                    }
                    None => {
                        return Err(SwarmError::Listen {
                            addr: listen_addr,
                            detail: "listener ended without a result".to_string(),
                        });
                    }
                }
            }

            // 5. Dial the bootstrap peers. Connection failures surface as
            //    events, not construction errors (a down bootstrap peer
            //    must not prevent the node from serving).
            for (peer, addr) in bootstraps {
                node.dial_bootstrap(peer, &addr)?;
            }
        }

        Ok(node)
    }

    /// Serve this node's CAS objects to peers (PLAN 8.2.2).
    ///
    /// The repository is shared **read-only** (the exchange path never
    /// mutates it); `limits` bound each transfer. Until this is called the
    /// node answers every exchange request with [`ExchangeResponse::Missing`].
    pub fn serve_repository(&mut self, repo: CasRepository, limits: ExchangeLimits) {
        self.serve = Some(ServeState { repo, limits });
    }

    /// Fetch an object from `peer` by CAS hash (PLAN 8.2.2).
    ///
    /// Returns the peer's raw response; storing and hash-verifying the
    /// payload is the caller's step ([`exchange::store_shared_object`] +
    /// the requested-hash equality check — content addressing is the
    /// integrity contract).
    pub async fn fetch_object(
        &mut self,
        peer: &libp2p::PeerId,
        hash: &str,
        timeout: Duration,
    ) -> Result<ExchangeResponse, SwarmError> {
        self.exchange_roundtrip(
            peer,
            ExchangeRequest::FetchObject {
                hash: hash.to_string(),
            },
            timeout,
        )
        .await
    }

    /// Probe whether `peer` has an object (PLAN 8.2.2).
    pub async fn probe_object(
        &mut self,
        peer: &libp2p::PeerId,
        hash: &str,
        timeout: Duration,
    ) -> Result<bool, SwarmError> {
        match self
            .exchange_roundtrip(
                peer,
                ExchangeRequest::HaveObject {
                    hash: hash.to_string(),
                },
                timeout,
            )
            .await?
        {
            ExchangeResponse::Have(present) => Ok(present),
            other => Err(SwarmError::Exchange {
                detail: format!("peer answered a HaveObject probe with {other:?}"),
            }),
        }
    }

    /// Drive one outbound exchange request to completion (or timeout).
    ///
    /// While waiting, the swarm keeps being polled: node-level events are
    /// translated and buffered (never lost), and *other* completed exchange
    /// requests stay parked in `inflight` for their own callers.
    async fn exchange_roundtrip(
        &mut self,
        peer: &libp2p::PeerId,
        request: ExchangeRequest,
        timeout: Duration,
    ) -> Result<ExchangeResponse, SwarmError> {
        let request_id = self.swarm.behaviour_mut().rr.send_request(peer, request);
        let fut = poll_fn(|cx| {
            if let Some(done) = self.inflight.remove(&request_id) {
                return Poll::Ready(done);
            }
            loop {
                match self.swarm.poll_next_unpin(cx) {
                    Poll::Ready(Some(event)) => {
                        if let Some(node_event) = self.translate(event) {
                            self.pending.push_back(node_event);
                        }
                        // The translate above may have completed our request.
                        if let Some(done) = self.inflight.remove(&request_id) {
                            return Poll::Ready(done);
                        }
                        // An event was consumed but ours is not done: keep
                        // polling *within this poll call* — returning
                        // Pending here would drop the wake (the Ready branch
                        // registered no waker) and stall until the timeout.
                        continue;
                    }
                    // No more progress now: Pending registers the waker.
                    Poll::Ready(None) | Poll::Pending => return Poll::Pending,
                }
            }
        });
        match tokio::time::timeout(timeout, fut).await {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(detail)) => Err(SwarmError::Exchange { detail }),
            Err(_) => {
                // Leave nothing half-tracked for a later caller to trip on.
                self.inflight.remove(&request_id);
                Err(SwarmError::Exchange {
                    detail: format!(
                        "no answer from {peer} within {timeout:?} (request {request_id})"
                    ),
                })
            }
        }
    }

    /// One inbound exchange event: answer requests, park responses.
    fn handle_exchange_event(
        &mut self,
        event: libp2p::request_response::Event<ExchangeRequest, ExchangeResponse>,
    ) {
        use libp2p::request_response as rr;
        match event {
            rr::Event::Message {
                peer,
                message: rr::Message::Request { request, channel, .. },
                ..
            } => {
                let response = self.answer_exchange(&peer, request);
                if self
                    .swarm
                    .behaviour_mut()
                    .rr
                    .send_response(channel, response)
                    .is_err()
                {
                    tracing::warn!("exchange answer for {peer} could not be sent");
                }
            }
            rr::Event::Message {
                message: rr::Message::Response { request_id, response },
                ..
            } => {
                self.inflight.insert(request_id, Ok(response));
            }
            rr::Event::OutboundFailure {
                request_id, error, ..
            } => {
                self.inflight.insert(request_id, Err(error.to_string()));
            }
            rr::Event::InboundFailure { peer, error, .. } => {
                tracing::warn!("inbound exchange from {peer} failed: {error}");
            }
            _ => {}
        }
    }

    /// Answer one exchange request against the serving state.
    fn answer_exchange(
        &self,
        _peer: &libp2p::PeerId,
        request: ExchangeRequest,
    ) -> ExchangeResponse {
        let Some(state) = &self.serve else {
            // Discovery-only node: nothing is shared — a probe says "no"
            // (not an error), a fetch says the object is absent.
            return match request {
                ExchangeRequest::HaveObject { .. } => ExchangeResponse::Have(false),
                ExchangeRequest::FetchObject { .. } => ExchangeResponse::Missing,
            };
        };
        match request {
            ExchangeRequest::HaveObject { hash } => {
                ExchangeResponse::Have(exchange::have_object(&state.repo, &hash))
            }
            ExchangeRequest::FetchObject { hash } => {
                match exchange::collect_object(&state.repo, &hash, &state.limits) {
                    Ok(response) => response,
                    Err(exchange::ExchangeError::TooLarge { size, limit, .. }) => {
                        ExchangeResponse::TooLarge { size, limit }
                    }
                    Err(err) => {
                        // Unknown hashes and serialization failures are both
                        // "the peer cannot have what you asked for" — but a
                        // serialization failure is worth surfacing locally.
                        tracing::warn!("cannot serve object: {err}");
                        ExchangeResponse::Missing
                    }
                }
            }
        }
    }

    /// Dial one bootstrap target.
    ///
    /// With a peer id (from a `/p2p/` suffix) the dial is addressed; the
    /// address is also seeded into the Kademlia routing table so the DHT
    /// knows the hop even before the connection completes. Without one the
    /// dial is by address and the peer id is learned at connect.
    fn dial_bootstrap(
        &mut self,
        peer: Option<libp2p::PeerId>,
        addr: &Multiaddr,
    ) -> Result<(), SwarmError> {
        let opts = match peer {
            Some(peer) => libp2p::swarm::dial_opts::DialOpts::peer_id(peer)
                .addresses(vec![addr.clone()])
                .build(),
            None => libp2p::swarm::dial_opts::DialOpts::unknown_peer_id()
                .address(addr.clone())
                .build(),
        };
        self.swarm.dial(opts).map_err(|source| SwarmError::Dial {
            addr: addr.to_string(),
            source,
        })
    }

    /// The node's own peer id.
    pub fn local_peer_id(&self) -> libp2p::PeerId {
        self.local_peer_id
    }

    /// The addresses the listener has bound so far (the ephemeral port
    /// resolved by the first [`SwarmNodeEvent::ListeningOn`] included).
    pub fn listen_addresses(&self) -> &[Multiaddr] {
        &self.listen_addrs
    }

    /// The node's dialable identity multiaddrs: every bound listen address
    /// with the `/p2p/<local peer id>` suffix appended — exactly the shape
    /// a peer's `bootstrap` list consumes.
    pub fn dialable_addresses(&self) -> Vec<Multiaddr> {
        self.listen_addrs
            .iter()
            .map(|addr| {
                let mut full = addr.clone();
                full.push(Protocol::P2p(self.local_peer_id));
                full
            })
            .collect()
    }

    /// The peers the DHT routing table has accepted so far (the
    /// event-tracked view of [`kad::Event::RoutingUpdated`]; see also
    /// [`SwarmNode::kad_kbucket_contains`] for the live kbuckets walk).
    pub fn kad_peers(&self) -> impl Iterator<Item = &libp2p::PeerId> {
        self.kad_peers.iter()
    }

    /// Walk the *live* Kademlia k-buckets for `peer` (the honest routing
    /// table membership check; needs `&mut` because libp2p's kbuckets
    /// iterator takes one).
    pub fn kad_kbucket_contains(&mut self, peer: &libp2p::PeerId) -> bool {
        self.swarm
            .behaviour_mut()
            .kad
            .kbuckets()
            .any(|bucket| bucket.iter().any(|entry| entry.node.key.preimage() == peer))
    }

    /// Await the next node-level event (the poll-able surface, PLAN 8.2.1).
    ///
    /// Events translated while [`SwarmNode::new`] awaited its listener are
    /// delivered first (lossless buffering). Cancellation-safe: the swarm
    /// poll is atomic per event, so dropping this future loses nothing.
    pub async fn next_event(&mut self) -> SwarmNodeEvent {
        poll_fn(|cx| {
            if let Some(event) = self.pending.pop_front() {
                return Poll::Ready(event);
            }
            loop {
                match self.swarm.poll_next_unpin(cx) {
                    Poll::Ready(Some(event)) => {
                        if let Some(translated) = self.translate(event) {
                            return Poll::Ready(translated);
                        }
                        // Not node-level: state was updated, keep polling.
                    }
                    // `Swarm`'s stream never ends; treat the unreachable
                    // `None` as Pending (the last poll registered the waker).
                    Poll::Ready(None) | Poll::Pending => return Poll::Pending,
                }
            }
        })
        .await
    }

    /// Translate one libp2p event into the node surface (or none), updating
    /// internal state along the way. The single seam the next lane extends
    /// for 8.2.2/8.2.3 behaviour events.
    fn translate(
        &mut self,
        event: SwarmEvent<ExtosBehaviourEvent>,
    ) -> Option<SwarmNodeEvent> {
        match event {
            SwarmEvent::NewListenAddr { address, .. } => {
                self.listen_addrs.push(address.clone());
                Some(SwarmNodeEvent::ListeningOn(address))
            }
            SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                // Every established connection feeds the DHT routing table
                // (server mode); kad reports acceptance via RoutingUpdated.
                self.swarm
                    .behaviour_mut()
                    .kad
                    .add_address(&peer_id, endpoint.get_remote_address().clone());
                // See the module docs: in a discovery-only node every
                // established connection originates from the bootstrap
                // dial path (outgoing or inbound leg).
                Some(SwarmNodeEvent::PeerDiscovered {
                    peer_id,
                    source: DiscoverySource::Bootstrap,
                })
            }
            SwarmEvent::Behaviour(ExtosBehaviourEvent::Mdns(mdns::Event::Discovered(
                peers,
            ))) => {
                // One Discovered event may carry several peers: the first
                // new one returns, the rest buffer (lossless ordering).
                let mut first = None;
                for (peer_id, _addr) in peers {
                    if self.mdns_seen.insert(peer_id) {
                        let event = SwarmNodeEvent::PeerDiscovered {
                            peer_id,
                            source: DiscoverySource::Mdns,
                        };
                        if first.is_none() {
                            first = Some(event);
                        } else {
                            self.pending.push_back(event);
                        }
                    }
                }
                first
            }
            SwarmEvent::Behaviour(ExtosBehaviourEvent::Mdns(mdns::Event::Expired(
                peers,
            ))) => {
                let mut first = None;
                for (peer_id, _addr) in peers {
                    if self.mdns_seen.remove(&peer_id) {
                        let event = SwarmNodeEvent::PeerExpired {
                            peer_id,
                            source: DiscoverySource::Mdns,
                        };
                        if first.is_none() {
                            first = Some(event);
                        } else {
                            self.pending.push_back(event);
                        }
                    }
                }
                first
            }
            SwarmEvent::Behaviour(ExtosBehaviourEvent::Kad(kad::Event::RoutingUpdated {
                peer,
                ..
            })) => {
                self.kad_peers.insert(peer);
                Some(SwarmNodeEvent::PeerDiscovered {
                    peer_id: peer,
                    source: DiscoverySource::Kademlia,
                })
            }
            SwarmEvent::Behaviour(ExtosBehaviourEvent::Rr(event)) => {
                self.handle_exchange_event(event);
                None
            }
            SwarmEvent::Behaviour(ExtosBehaviourEvent::Identify(
                identify::Event::Received { peer_id, info, .. },
            )) => Some(SwarmNodeEvent::Identified {
                peer_id,
                agent_version: info.agent_version,
                listen_addrs: info.listen_addrs,
            }),
            // Everything else updates nothing node-level (transport churn,
            // kad queries, identify pushes, external-address bookkeeping).
            _ => None,
        }
    }
}

/// Split one bootstrap config entry into `(optional peer id, dialable
/// multiaddr)`: the `/p2p/<peer-id>` suffix (if any) is removed from the
/// dial address and returned as the peer id.
fn split_p2p_entry(entry: &str) -> Result<(Option<libp2p::PeerId>, Multiaddr), SwarmError> {
    let parsed: Multiaddr = entry
        .parse()
        .map_err(|err: MultiaddrError| SwarmError::InvalidMultiaddr {
            addr: entry.to_string(),
            reason: err.to_string(),
        })?;
    let mut peer = None;
    let mut addr = Multiaddr::empty();
    for proto in parsed.iter() {
        match proto {
            Protocol::P2p(peer_id) => peer = Some(peer_id),
            other => addr.push(other),
        }
    }
    Ok((peer, addr))
}

/// Re-check one config string against the 7.3.2 charset contract (no
/// whitespace, quotes, backslashes or control characters) — the same
/// charset contract the `swarm.nix` parser enforces (via its private
/// `hostile_str_reason` helper),
/// exposed for configs built programmatically (tests, embedded hosts).
///
/// # Errors
///
/// [`SwarmError::InvalidMultiaddr`] naming the reason, when hostile.
pub fn validate_peer_string(addr: &str) -> Result<(), SwarmError> {
    match hostile_str_reason(addr) {
        Some(reason) => Err(SwarmError::InvalidMultiaddr {
            addr: addr.to_string(),
            reason,
        }),
        None => Ok(()),
    }
}

// ─── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::swarm::DEFAULT_LISTEN_MULTIADDR;

    fn config(listen: &str, bootstrap: &[&str]) -> SwarmConfig {
        SwarmConfig {
            enabled: false,
            listen: listen.to_string(),
            bootstrap: bootstrap.iter().map(|s| s.to_string()).collect(),
            max_bytes_per_second: None,
        }
    }

    #[test]
    fn hostile_config_strings_are_typed_rejected() {
        // Whitespace (the 7.3.2 charset contract, reused).
        let err = validate_peer_string("has space").unwrap_err();
        assert!(
            err.to_string()
                .contains("must not contain whitespace, quotes, backslashes, or control characters"),
            "{err}"
        );
        // Control characters.
        assert!(validate_peer_string("nl\nhere").is_err());
        // Empty.
        assert!(validate_peer_string("").is_err());
    }

    #[test]
    fn charset_clean_but_unparseable_entries_are_typed_rejected() {
        // The shipped grammar template's placeholder is NOT a multiaddr —
        // the runtime constrains bootstrap entries to parseable addrs.
        let err = split_p2p_entry("p2p://swarm.extos.org").unwrap_err();
        assert!(matches!(err, SwarmError::InvalidMultiaddr { .. }), "{err}");
        assert!(err.to_string().contains("p2p://swarm.extos.org"));
    }

    #[test]
    fn p2p_suffix_is_split_off_the_dial_address() {
        let peer = libp2p::PeerId::random();
        let entry = format!("/ip4/127.0.0.1/tcp/4001/p2p/{peer}");
        let (split_peer, addr) = split_p2p_entry(&entry).expect("split");
        assert_eq!(split_peer, Some(peer));
        assert_eq!(addr, "/ip4/127.0.0.1/tcp/4001".parse::<Multiaddr>().unwrap());

        // Without the suffix: no peer, full address.
        let (no_peer, plain) =
            split_p2p_entry("/ip4/127.0.0.1/tcp/4001").expect("split");
        assert_eq!(no_peer, None);
        assert_eq!(plain, "/ip4/127.0.0.1/tcp/4001".parse::<Multiaddr>().unwrap());
    }

    #[tokio::test]
    async fn disabled_config_builds_an_inert_node_without_listening() {
        let node = SwarmNode::new(&config("/ip4/127.0.0.1/tcp/0", &[]))
            .await
            .expect("inert node");
        assert!(node.listen_addresses().is_empty());
        // The peer id exists and the stack is built (mDNS included).
        assert_ne!(node.local_peer_id(), libp2p::PeerId::random());

        // The grammar default would bind 0.0.0.0:4001 — validation accepts
        // it even when disabled (no network touch either way).
        let defaulted = SwarmNode::new(&config(DEFAULT_LISTEN_MULTIADDR, &[]))
            .await
            .expect("defaulted inert node");
        assert!(defaulted.listen_addresses().is_empty());
    }

    #[tokio::test]
    async fn listen_failure_is_typed() {
        // Occupy a loopback port, then ask the node for it: the bind
        // (awaited in `new`) must surface as a typed Listen error.
        let holder = std::net::TcpListener::bind("127.0.0.1:0").expect("holder");
        let port = holder.local_addr().expect("addr").port();
        let cfg = config(&format!("/ip4/127.0.0.1/tcp/{port}"), &[]);
        let cfg = SwarmConfig { enabled: true, ..cfg };
        let err = match SwarmNode::new(&cfg).await {
            Err(err) => err,
            Ok(_) => panic!("bind on an occupied port must fail"),
        };
        assert!(matches!(err, SwarmError::Listen { .. }), "{err}");
        assert!(err.to_string().contains(&format!("tcp/{port}")), "{err}");
    }
}
