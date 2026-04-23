//! Unified error types for ExtOS.

use thiserror::Error;

/// Top-level error type for the ExtOS ecosystem.
#[derive(Debug, Error)]
pub enum ExtosError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Configuration parse error at {path}:{line}: {message}")]
    ConfigParse {
        path: String,
        line: usize,
        message: String,
    },

    #[error("CAS integrity failure: expected {expected}, got {actual}")]
    CasIntegrity { expected: String, actual: String },

    #[error("Package not found: {origin}/{name}/{version}")]
    PackageNotFound {
        origin: String,
        name: String,
        version: String,
    },

    #[error("Dependency unresolvable: {0}")]
    DependencyUnresolvable(String),

    #[error("Collision: {path} claimed by {claimant_a} and {claimant_b}")]
    Collision {
        path: String,
        claimant_a: String,
        claimant_b: String,
    },

    #[error("Weave error: {0}")]
    Weave(String),

    #[error("Snapshot error: {0}")]
    Snapshot(String),

    #[error("Container error: {0}")]
    Container(String),

    #[error("Rosetta plugin error ({plugin}): {message}")]
    RosettaPlugin { plugin: String, message: String },

    #[error("Serialization error: {0}")]
    Serialization(String),
}
