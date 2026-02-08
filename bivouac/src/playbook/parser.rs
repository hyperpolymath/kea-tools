// SPDX-License-Identifier: AGPL-3.0-or-later
//! Playbook file parser
//!
//! Supports both TOML and a simplified S-expression format for playbooks.

use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::error::{BivouacError, Result};

/// A playbook definition containing triggers and actions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Playbook {
    /// Unique identifier for the playbook
    pub name: String,

    /// Human-readable description
    #[serde(default)]
    pub description: String,

    /// Version of the playbook
    #[serde(default = "default_version")]
    pub version: String,

    /// Trigger that activates this playbook
    pub trigger: PlaybookTrigger,

    /// Actions to execute when triggered
    pub actions: Vec<PlaybookAction>,

    /// Whether to continue executing actions if one fails
    #[serde(default)]
    pub continue_on_error: bool,

    /// Maximum execution time in seconds
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

/// Trigger types that can activate a playbook
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum PlaybookTrigger {
    /// Manual trigger via CLI
    Manual,

    /// Scheduled execution (cron-like)
    Schedule {
        /// Cron expression for scheduling
        cron: String,
    },

    /// Integrity violation detected
    IntegrityViolation {
        /// Severity level (low, medium, high, critical)
        #[serde(default = "default_severity")]
        severity: String,
    },

    /// Deployment event
    Deployment {
        /// Event type (pre-deploy, post-deploy, rollback)
        event: String,
    },

    /// Health check failure
    HealthCheckFailure {
        /// Service name that failed
        service: String,
    },

    /// Custom webhook trigger
    Webhook {
        /// Webhook path
        path: String,
        /// Expected secret (for validation)
        #[serde(default)]
        secret: Option<String>,
    },
}

/// Actions that can be executed as part of a playbook
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum PlaybookAction {
    /// Execute a shell command
    Command {
        /// Command to execute
        cmd: String,
        /// Working directory
        #[serde(default)]
        cwd: Option<String>,
        /// Environment variables
        #[serde(default)]
        env: std::collections::HashMap<String, String>,
        /// Timeout in seconds
        #[serde(default = "default_action_timeout")]
        timeout_secs: u64,
    },

    /// Send a notification
    Notify {
        /// Notification channel (slack, email, webhook)
        channel: String,
        /// Message to send
        message: String,
        /// Additional metadata
        #[serde(default)]
        metadata: std::collections::HashMap<String, String>,
    },

    /// Rotate DNS/IP records
    RotateDns {
        /// Zone to update
        zone: String,
        /// Record name
        record: String,
        /// TTL in seconds
        #[serde(default = "default_ttl")]
        ttl: u32,
    },

    /// Restart a service
    RestartService {
        /// Service name
        name: String,
        /// Delay before restart in seconds
        #[serde(default)]
        delay_secs: u64,
    },

    /// Log an event
    Log {
        /// Log level
        level: String,
        /// Message to log
        message: String,
    },

    /// Wait for a specified duration
    Wait {
        /// Duration in seconds
        seconds: u64,
    },

    /// Execute another playbook
    ExecutePlaybook {
        /// Name of the playbook to execute
        name: String,
    },
}

impl Playbook {
    /// Parse a playbook from a TOML file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();

        if !path.exists() {
            return Err(BivouacError::PlaybookNotFound {
                name: path.display().to_string(),
            });
        }

        let contents = std::fs::read_to_string(path)?;

        let extension = path.extension().and_then(|e| e.to_str()).unwrap_or("");

        match extension {
            "toml" => Self::from_toml(&contents, path),
            "scm" => Self::from_scm(&contents, path),
            _ => Err(BivouacError::PlaybookParseError {
                path: path.display().to_string(),
                message: format!("Unsupported file extension: {}", extension),
            }),
        }
    }

    /// Parse a playbook from TOML content
    fn from_toml(contents: &str, path: &Path) -> Result<Self> {
        toml::from_str(contents).map_err(|e| BivouacError::PlaybookParseError {
            path: path.display().to_string(),
            message: e.to_string(),
        })
    }

    /// Parse a playbook from S-expression content
    /// This is a simplified parser for basic PLAYBOOK.scm files
    fn from_scm(contents: &str, path: &Path) -> Result<Self> {
        // For now, we implement a minimal SCM parser
        // A full implementation would use a proper S-expression parser
        let name = extract_scm_value(contents, "name").ok_or_else(|| {
            BivouacError::PlaybookParseError {
                path: path.display().to_string(),
                message: "Missing 'name' field in SCM playbook".to_string(),
            }
        })?;

        let description =
            extract_scm_value(contents, "description").unwrap_or_default();

        // Default trigger for SCM files
        let trigger = if contents.contains("(trigger integrity-violation") {
            PlaybookTrigger::IntegrityViolation {
                severity: "high".to_string(),
            }
        } else {
            // Default to manual trigger for all other cases
            PlaybookTrigger::Manual
        };

        // Extract basic command actions
        let mut actions = Vec::new();
        for line in contents.lines() {
            let line = line.trim();
            if line.starts_with("(action command") || line.starts_with("(command ") {
                if let Some(cmd) = extract_quoted_string(line) {
                    actions.push(PlaybookAction::Command {
                        cmd,
                        cwd: None,
                        env: std::collections::HashMap::new(),
                        timeout_secs: default_action_timeout(),
                    });
                }
            } else if line.starts_with("(action log") || line.starts_with("(log ") {
                if let Some(msg) = extract_quoted_string(line) {
                    actions.push(PlaybookAction::Log {
                        level: "info".to_string(),
                        message: msg,
                    });
                }
            }
        }

        Ok(Playbook {
            name,
            description,
            version: default_version(),
            trigger,
            actions,
            continue_on_error: false,
            timeout_secs: default_timeout(),
        })
    }

    /// Validate the playbook configuration
    pub fn validate(&self) -> Result<()> {
        if self.name.is_empty() {
            return Err(BivouacError::InvalidConfig {
                message: "Playbook name cannot be empty".to_string(),
            });
        }

        if self.actions.is_empty() {
            return Err(BivouacError::InvalidConfig {
                message: format!("Playbook '{}' has no actions defined", self.name),
            });
        }

        Ok(())
    }
}

// Helper functions for SCM parsing

fn extract_scm_value(content: &str, key: &str) -> Option<String> {
    let pattern = format!("({} ", key);
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with(&pattern) {
            return extract_quoted_string(line);
        }
    }
    None
}

fn extract_quoted_string(line: &str) -> Option<String> {
    let start = line.find('"')?;
    let end = line.rfind('"')?;
    if start < end {
        Some(line[start + 1..end].to_string())
    } else {
        None
    }
}

// Default value functions

fn default_version() -> String {
    "1.0".to_string()
}

fn default_timeout() -> u64 {
    300 // 5 minutes
}

fn default_action_timeout() -> u64 {
    60 // 1 minute
}

fn default_severity() -> String {
    "high".to_string()
}

fn default_ttl() -> u32 {
    300 // 5 minutes
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_parse_toml_playbook() {
        let toml_content = r#"
            name = "test-playbook"
            description = "A test playbook"
            version = "1.0"
            continue_on_error = true
            timeout_secs = 600

            [trigger]
            type = "integrity-violation"
            severity = "critical"

            [[actions]]
            type = "log"
            level = "warn"
            message = "Integrity violation detected!"

            [[actions]]
            type = "command"
            cmd = "echo 'Taking action'"
            timeout_secs = 30

            [[actions]]
            type = "notify"
            channel = "slack"
            message = "Alert: Integrity violation handled"
        "#;

        let temp_dir = tempdir().unwrap();
        let file_path = temp_dir.path().join("test.toml");
        fs::write(&file_path, toml_content).unwrap();

        let playbook = Playbook::from_file(&file_path).unwrap();
        assert_eq!(playbook.name, "test-playbook");
        assert_eq!(playbook.description, "A test playbook");
        assert!(playbook.continue_on_error);
        assert_eq!(playbook.actions.len(), 3);

        match &playbook.trigger {
            PlaybookTrigger::IntegrityViolation { severity } => {
                assert_eq!(severity, "critical");
            }
            _ => panic!("Expected IntegrityViolation trigger"),
        }
    }

    #[test]
    fn test_parse_scm_playbook() {
        let scm_content = r#"
            ; SPDX-License-Identifier: AGPL-3.0-or-later
            ; Test playbook in SCM format

            (playbook
              (name "integrity-violation")
              (description "Handle integrity violations")
              (trigger integrity-violation)
              (actions
                (log "Starting integrity check")
                (command "echo 'Checking integrity'")
                (log "Integrity check complete")))
        "#;

        let temp_dir = tempdir().unwrap();
        let file_path = temp_dir.path().join("test.scm");
        fs::write(&file_path, scm_content).unwrap();

        let playbook = Playbook::from_file(&file_path).unwrap();
        assert_eq!(playbook.name, "integrity-violation");
        assert!(!playbook.description.is_empty());
        assert!(!playbook.actions.is_empty());
    }

    #[test]
    fn test_playbook_validation_empty_name() {
        let playbook = Playbook {
            name: String::new(),
            description: String::new(),
            version: "1.0".to_string(),
            trigger: PlaybookTrigger::Manual,
            actions: vec![PlaybookAction::Log {
                level: "info".to_string(),
                message: "test".to_string(),
            }],
            continue_on_error: false,
            timeout_secs: 300,
        };

        assert!(playbook.validate().is_err());
    }

    #[test]
    fn test_playbook_validation_no_actions() {
        let playbook = Playbook {
            name: "test".to_string(),
            description: String::new(),
            version: "1.0".to_string(),
            trigger: PlaybookTrigger::Manual,
            actions: vec![],
            continue_on_error: false,
            timeout_secs: 300,
        };

        assert!(playbook.validate().is_err());
    }

    #[test]
    fn test_extract_quoted_string() {
        assert_eq!(
            extract_quoted_string(r#"(name "hello world")"#),
            Some("hello world".to_string())
        );
        assert_eq!(extract_quoted_string(r#"(name "test")"#), Some("test".to_string()));
        assert_eq!(extract_quoted_string("(name unquoted)"), None);
    }

    #[test]
    fn test_trigger_types() {
        let manual: PlaybookTrigger = serde_json::from_str(r#"{"type":"manual"}"#).unwrap();
        assert_eq!(manual, PlaybookTrigger::Manual);

        let schedule: PlaybookTrigger =
            serde_json::from_str(r#"{"type":"schedule","cron":"0 * * * *"}"#).unwrap();
        match schedule {
            PlaybookTrigger::Schedule { cron } => assert_eq!(cron, "0 * * * *"),
            _ => panic!("Expected Schedule trigger"),
        }
    }
}
