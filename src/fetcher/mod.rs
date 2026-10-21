//! Phase 3 fetcher stack (PLAN sub-phases 3.2/3.3/3.4).
//!
//! One child module per transport: alpm (libalpm FFI, Arch), debian
//! (APT infrastructure), rpm (librpm FFI). Each fetcher exposes the same
//! minimal surface -- sync_db() and download() -- so the shared ingestion
//! pipeline can slot any of them into the mirror chain without
//! per-origin divergence. Wiring into ingest.rs is a single later task
//! (PLAN 3.2.6/3.3.4/3.4.5, one writer); these ship API-complete,
//! unwired. Every fetcher degrades honestly: absence of a transport
//! library or tool is a typed error, never a silent fallback.

pub mod alpm;
pub mod debian;
pub mod rpm;
