//! # libextos
//!
//! Shared library for the ExtOS operating system.
//! Provides core types, configuration parsing, Content-Addressable Storage,
//! and the Symlink/Reflink Weaver engine.

pub mod cas;
pub mod config;
pub mod dependency;
pub mod error;
pub mod manifest;
pub mod types;
pub mod weaver;
