//! # libextos
//!
//! Shared library for the ExtOS operating system.
//! Provides core types, configuration parsing, Content-Addressable Storage,
//! package extraction, ELF scanning, ingestion pipeline,
//! Rosetta plugin engine, and the Symlink/Reflink Weaver engine.

pub mod cas;
pub mod config;
pub mod dependency;
pub mod elf_scan;
pub mod error;
pub mod extract;
pub mod ingest;
pub mod manifest;
pub mod rosetta;
pub mod types;
pub mod weaver;
