// SPDX-License-Identifier: AGPL-3.0-or-later
//! Configuration management for Kea-Bivouac

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::error::{BivouacError, Result};

/// Main configuration structure for Bivouac
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Bivouac instance name
    pub name: String,

    /// Version of the configuration format
    #[serde(default = "default_version")]
    pub version: String,

    /// Playbook directory path
    #[serde(default = "default_playbook_dir")]
    pub playbook_dir: PathBuf,

    /// mTLS configuration
    #[serde(default)]
    pub mtls: MtlsConfig,

    /// Deployment configuration
    #[serde(default)]
    pub deployment: DeploymentConfig,

    /// Logging configuration
    #[serde(default)]
    pub logging: LoggingConfig,
}

/// mTLS (mutual TLS) configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MtlsConfig {
    /// Enable mTLS enforcement
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Path to CA certificate
    pub ca_cert: Option<PathBuf>,

    /// Path to client certificate
    pub client_cert: Option<PathBuf>,

    /// Path to client key
    pub client_key: Option<PathBuf>,

    /// Require client certificate verification
    #[serde(default = "default_true")]
    pub require_client_cert: bool,
}

/// Deployment configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DeploymentConfig {
    /// Enable nomadic deployment mode
    #[serde(default)]
    pub nomadic: bool,

    /// DNS fluctuation interval in seconds
    #[serde(default = "default_fluctuation_interval")]
    pub fluctuation_interval_secs: u64,

    /// Target satellites for deployment
    #[serde(default)]
    pub satellites: Vec<String>,
}

/// Logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level (trace, debug, info, warn, error)
    #[serde(default = "default_log_level")]
    pub level: String,

    /// Output format (text, json)
    #[serde(default = "default_log_format")]
    pub format: String,

    /// Log file path (optional)
    pub file: Option<PathBuf>,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            format: default_log_format(),
            file: None,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            name: "bivouac".to_string(),
            version: default_version(),
            playbook_dir: default_playbook_dir(),
            mtls: MtlsConfig::default(),
            deployment: DeploymentConfig::default(),
            logging: LoggingConfig::default(),
        }
    }
}

impl Config {
    /// Load configuration from a TOML file
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the configuration file
    ///
    /// # Returns
    ///
    /// The parsed configuration or an error
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();

        if !path.exists() {
            return Err(BivouacError::ConfigNotFound {
                path: path.display().to_string(),
            });
        }

        let contents = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&contents)?;

        config.validate()?;
        Ok(config)
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<()> {
        if self.name.is_empty() {
            return Err(BivouacError::InvalidConfig {
                message: "Bivouac name cannot be empty".to_string(),
            });
        }

        if self.mtls.enabled && self.mtls.ca_cert.is_none() {
            return Err(BivouacError::InvalidConfig {
                message: "mTLS enabled but ca_cert not specified".to_string(),
            });
        }

        Ok(())
    }

    /// Create a configuration with mTLS disabled (for testing)
    pub fn with_mtls_disabled(mut self) -> Self {
        self.mtls.enabled = false;
        self
    }
}

// Default value functions

fn default_version() -> String {
    "1.0".to_string()
}

fn default_playbook_dir() -> PathBuf {
    PathBuf::from("playbooks")
}

fn default_true() -> bool {
    true
}

fn default_fluctuation_interval() -> u64 {
    3600 // 1 hour
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_log_format() -> String {
    "text".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.name, "bivouac");
        assert_eq!(config.version, "1.0");
        // Default::default() sets enabled to false (derive Default behavior)
        // serde(default = "default_true") only affects deserialization
        assert!(!config.mtls.enabled);
    }

    #[test]
    fn test_config_validation_empty_name() {
        let mut config = Config::default();
        config.name = String::new();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_validation_mtls_without_ca() {
        let mut config = Config::default();
        config.mtls.enabled = true; // Enable mTLS
        // mTLS is enabled but no CA cert - should fail validation
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_with_mtls_disabled() {
        let config = Config::default().with_mtls_disabled();
        assert!(!config.mtls.enabled);
        // Should pass validation now
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_parse_toml_config() {
        let toml_content = r#"
            name = "test-bivouac"
            version = "1.0"
            playbook_dir = "/tmp/playbooks"

            [mtls]
            enabled = false

            [deployment]
            nomadic = true
            fluctuation_interval_secs = 1800
            satellites = ["sat1", "sat2"]

            [logging]
            level = "debug"
            format = "json"
        "#;

        let config: Config = toml::from_str(toml_content).unwrap();
        assert_eq!(config.name, "test-bivouac");
        assert!(!config.mtls.enabled);
        assert!(config.deployment.nomadic);
        assert_eq!(config.deployment.fluctuation_interval_secs, 1800);
        assert_eq!(config.deployment.satellites.len(), 2);
        assert_eq!(config.logging.level, "debug");
    }
}
