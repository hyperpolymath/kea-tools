// SPDX-License-Identifier: AGPL-3.0-or-later
//! Error types for Kea-Bivouac

use thiserror::Error;

/// Result type alias for Kea-Bivouac operations
pub type Result<T> = std::result::Result<T, BivouacError>;

/// Errors that can occur during Bivouac operations
#[derive(Error, Debug)]
pub enum BivouacError {
    /// Configuration file not found
    #[error("Configuration file not found: {path}")]
    ConfigNotFound { path: String },

    /// Invalid configuration format
    #[error("Invalid configuration: {message}")]
    InvalidConfig { message: String },

    /// Playbook parsing error
    #[error("Failed to parse playbook '{path}': {message}")]
    PlaybookParseError { path: String, message: String },

    /// Playbook not found
    #[error("Playbook not found: {name}")]
    PlaybookNotFound { name: String },

    /// Action execution failed
    #[error("Action '{action}' failed: {message}")]
    ActionFailed { action: String, message: String },

    /// mTLS configuration error
    #[error("mTLS configuration error: {message}")]
    MtlsError { message: String },

    /// Certificate error
    #[error("Certificate error: {message}")]
    CertificateError { message: String },

    /// IO error wrapper
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    /// TOML parsing error
    #[error("TOML parse error: {0}")]
    TomlError(#[from] toml::de::Error),

    /// JSON parsing error
    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),

    /// Command not found
    #[error("Command not found: {command}")]
    CommandNotFound { command: String },

    /// Invalid trigger name
    #[error("Invalid trigger: {name}")]
    InvalidTrigger { name: String },
}
