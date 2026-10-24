//! # libextos
//!
//! Shared library for the ExtOS operating system.
//! Provides core types, configuration parsing, Content-Addressable Storage,
//! package extraction, ELF scanning, ingestion pipeline,
//! Rosetta plugin engine, and the Symlink/Reflink Weaver engine.

pub mod anchor;
pub mod anchors_map;
pub mod appdir;
pub mod cas;
pub mod caps;
pub mod config;
pub mod container;
pub mod daemons;
pub mod dependency;
pub mod elf_scan;
pub mod error;
pub mod extract;
pub mod fetcher;
pub mod forge;
pub mod ingest;
pub mod manifest;
pub mod nix_eval;
pub mod network;
pub mod phantom;
pub mod rosetta;
pub mod security;
pub mod snapshot;
pub mod types;
pub mod users;
pub mod vlock;
pub mod weaver;
