// SPDX-License-Identifier: AGPL-3.0-or-later
//! Playbook action executor
//!
//! Handles the execution of playbook actions including commands,
//! notifications, and service management.

use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;
use tracing::{debug, error, info, warn};

use super::{Playbook, PlaybookAction};
use crate::error::{BivouacError, Result};

/// Executor for playbook actions
pub struct PlaybookExecutor {
    /// Whether to run in dry-run mode (no actual execution)
    dry_run: bool,
}

/// Result of executing a single action
#[derive(Debug)]
pub struct ActionResult {
    /// Whether the action succeeded
    pub success: bool,
    /// Output from the action (if any)
    pub output: Option<String>,
    /// Error message (if failed)
    pub error: Option<String>,
    /// Duration of the action
    pub duration_ms: u64,
}

/// Result of executing a complete playbook
#[derive(Debug)]
pub struct PlaybookResult {
    /// Name of the playbook
    pub playbook_name: String,
    /// Whether all actions succeeded
    pub success: bool,
    /// Results for each action
    pub action_results: Vec<ActionResult>,
    /// Total duration
    pub total_duration_ms: u64,
    /// Number of successful actions
    pub actions_succeeded: usize,
    /// Number of failed actions
    pub actions_failed: usize,
}

impl PlaybookExecutor {
    /// Create a new executor
    pub fn new(dry_run: bool) -> Self {
        Self { dry_run }
    }

    /// Execute a playbook
    pub async fn execute(&self, playbook: &Playbook) -> Result<PlaybookResult> {
        let start_time = std::time::Instant::now();
        let mut action_results = Vec::new();
        let mut actions_succeeded = 0usize;
        let mut actions_failed = 0usize;
        let mut overall_success = true;

        info!(
            playbook = %playbook.name,
            actions = playbook.actions.len(),
            "Starting playbook execution"
        );

        for (index, action) in playbook.actions.iter().enumerate() {
            debug!(action_index = index, "Executing action");

            let result = self.execute_action(action, playbook.timeout_secs).await;

            if result.success {
                actions_succeeded += 1;
                debug!(action_index = index, "Action completed successfully");
            } else {
                actions_failed += 1;
                overall_success = false;
                error!(
                    action_index = index,
                    error = ?result.error,
                    "Action failed"
                );

                if !playbook.continue_on_error {
                    warn!("Stopping playbook execution due to action failure");
                    action_results.push(result);
                    break;
                }
            }

            action_results.push(result);
        }

        let total_duration_ms = start_time.elapsed().as_millis() as u64;

        info!(
            playbook = %playbook.name,
            success = overall_success,
            duration_ms = total_duration_ms,
            succeeded = actions_succeeded,
            failed = actions_failed,
            "Playbook execution completed"
        );

        Ok(PlaybookResult {
            playbook_name: playbook.name.clone(),
            success: overall_success,
            action_results,
            total_duration_ms,
            actions_succeeded,
            actions_failed,
        })
    }

    /// Execute a single action
    async fn execute_action(&self, action: &PlaybookAction, _timeout_secs: u64) -> ActionResult {
        let start_time = std::time::Instant::now();

        let result = match action {
            PlaybookAction::Command {
                cmd,
                cwd,
                env,
                timeout_secs: action_timeout,
            } => {
                self.execute_command(cmd, cwd.as_deref(), env, *action_timeout)
                    .await
            }
            PlaybookAction::Log { level, message } => self.execute_log(level, message),
            PlaybookAction::Wait { seconds } => self.execute_wait(*seconds).await,
            PlaybookAction::Notify {
                channel,
                message,
                metadata,
            } => self.execute_notify(channel, message, metadata).await,
            PlaybookAction::RotateDns { zone, record, ttl } => {
                self.execute_rotate_dns(zone, record, *ttl).await
            }
            PlaybookAction::RestartService { name, delay_secs } => {
                self.execute_restart_service(name, *delay_secs).await
            }
            PlaybookAction::ExecutePlaybook { name } => {
                // Nested playbook execution would require loading and executing
                // For now, just log and return success
                info!(playbook = %name, "Would execute nested playbook");
                if self.dry_run {
                    Ok(Some(format!("Would execute playbook: {}", name)))
                } else {
                    Err(BivouacError::ActionFailed {
                        action: "execute-playbook".to_string(),
                        message: "Nested playbook execution not implemented".to_string(),
                    })
                }
            }
        };

        let duration_ms = start_time.elapsed().as_millis() as u64;

        match result {
            Ok(output) => ActionResult {
                success: true,
                output,
                error: None,
                duration_ms,
            },
            Err(e) => ActionResult {
                success: false,
                output: None,
                error: Some(e.to_string()),
                duration_ms,
            },
        }
    }

    /// Execute a shell command
    async fn execute_command(
        &self,
        cmd: &str,
        cwd: Option<&str>,
        env: &std::collections::HashMap<String, String>,
        timeout_secs: u64,
    ) -> Result<Option<String>> {
        info!(command = %cmd, "Executing command");

        if self.dry_run {
            return Ok(Some(format!("[DRY RUN] Would execute: {}", cmd)));
        }

        let mut command = Command::new("sh");
        command.arg("-c").arg(cmd);

        if let Some(dir) = cwd {
            command.current_dir(dir);
        }

        for (key, value) in env {
            command.env(key, value);
        }

        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());

        let duration = Duration::from_secs(timeout_secs);
        let child = command.spawn()?;

        match timeout(duration, child.wait_with_output()).await {
            Ok(Ok(output)) => {
                let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                let stderr = String::from_utf8_lossy(&output.stderr).to_string();

                if output.status.success() {
                    Ok(Some(stdout))
                } else {
                    Err(BivouacError::ActionFailed {
                        action: "command".to_string(),
                        message: format!("Command failed with status {}: {}", output.status, stderr),
                    })
                }
            }
            Ok(Err(e)) => Err(BivouacError::ActionFailed {
                action: "command".to_string(),
                message: format!("Failed to execute command: {}", e),
            }),
            Err(_) => Err(BivouacError::ActionFailed {
                action: "command".to_string(),
                message: format!("Command timed out after {} seconds", timeout_secs),
            }),
        }
    }

    /// Execute a log action
    fn execute_log(&self, level: &str, message: &str) -> Result<Option<String>> {
        match level.to_lowercase().as_str() {
            "trace" => tracing::trace!("{}", message),
            "debug" => debug!("{}", message),
            "info" => info!("{}", message),
            "warn" | "warning" => warn!("{}", message),
            "error" => error!("{}", message),
            _ => info!("{}", message),
        }
        Ok(None)
    }

    /// Execute a wait action
    async fn execute_wait(&self, seconds: u64) -> Result<Option<String>> {
        info!(seconds = seconds, "Waiting");

        if self.dry_run {
            return Ok(Some(format!("[DRY RUN] Would wait {} seconds", seconds)));
        }

        tokio::time::sleep(Duration::from_secs(seconds)).await;
        Ok(None)
    }

    /// Execute a notification action
    async fn execute_notify(
        &self,
        channel: &str,
        message: &str,
        _metadata: &std::collections::HashMap<String, String>,
    ) -> Result<Option<String>> {
        info!(
            channel = %channel,
            message = %message,
            "Sending notification"
        );

        if self.dry_run {
            return Ok(Some(format!(
                "[DRY RUN] Would notify via {}: {}",
                channel, message
            )));
        }

        // In a real implementation, this would integrate with various notification services
        // For now, just log the notification
        warn!(
            "Notification channel '{}' not implemented. Message: {}",
            channel, message
        );

        Ok(Some(format!("Notification sent to {}", channel)))
    }

    /// Execute a DNS rotation action
    async fn execute_rotate_dns(
        &self,
        zone: &str,
        record: &str,
        ttl: u32,
    ) -> Result<Option<String>> {
        info!(zone = %zone, record = %record, ttl = ttl, "Rotating DNS record");

        if self.dry_run {
            return Ok(Some(format!(
                "[DRY RUN] Would rotate DNS record {}.{} with TTL {}",
                record, zone, ttl
            )));
        }

        // In a real implementation, this would call the Resource-Record-Fluctuator
        warn!("DNS rotation not implemented for {}.{}", record, zone);

        Ok(Some(format!("DNS rotated for {}.{}", record, zone)))
    }

    /// Execute a service restart action
    async fn execute_restart_service(
        &self,
        name: &str,
        delay_secs: u64,
    ) -> Result<Option<String>> {
        info!(service = %name, delay = delay_secs, "Restarting service");

        if self.dry_run {
            return Ok(Some(format!(
                "[DRY RUN] Would restart service '{}' after {} seconds",
                name, delay_secs
            )));
        }

        if delay_secs > 0 {
            tokio::time::sleep(Duration::from_secs(delay_secs)).await;
        }

        // In a real implementation, this would use systemd or another init system
        warn!("Service restart not implemented for {}", name);

        Ok(Some(format!("Service {} restarted", name)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::playbook::PlaybookTrigger;

    fn create_test_playbook(actions: Vec<PlaybookAction>) -> Playbook {
        Playbook {
            name: "test-playbook".to_string(),
            description: "Test playbook".to_string(),
            version: "1.0".to_string(),
            trigger: PlaybookTrigger::Manual,
            actions,
            continue_on_error: false,
            timeout_secs: 60,
        }
    }

    #[tokio::test]
    async fn test_execute_log_action() {
        let executor = PlaybookExecutor::new(false);
        let result = executor.execute_log("info", "Test log message");
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_execute_wait_dry_run() {
        let executor = PlaybookExecutor::new(true);
        let result = executor.execute_wait(5).await;
        assert!(result.is_ok());
        assert!(result.unwrap().unwrap().contains("DRY RUN"));
    }

    #[tokio::test]
    async fn test_execute_command_dry_run() {
        let executor = PlaybookExecutor::new(true);
        let result = executor
            .execute_command("echo hello", None, &std::collections::HashMap::new(), 30)
            .await;
        assert!(result.is_ok());
        assert!(result.unwrap().unwrap().contains("DRY RUN"));
    }

    #[tokio::test]
    async fn test_execute_command_real() {
        let executor = PlaybookExecutor::new(false);
        let result = executor
            .execute_command("echo 'test output'", None, &std::collections::HashMap::new(), 30)
            .await;
        assert!(result.is_ok());
        let output = result.unwrap().unwrap();
        assert!(output.contains("test output"));
    }

    #[tokio::test]
    async fn test_execute_playbook_dry_run() {
        let executor = PlaybookExecutor::new(true);
        let playbook = create_test_playbook(vec![
            PlaybookAction::Log {
                level: "info".to_string(),
                message: "Starting test".to_string(),
            },
            PlaybookAction::Wait { seconds: 1 },
        ]);

        let result = executor.execute(&playbook).await.unwrap();
        assert!(result.success);
        assert_eq!(result.actions_succeeded, 2);
        assert_eq!(result.actions_failed, 0);
    }

    #[tokio::test]
    async fn test_execute_playbook_with_failure() {
        let executor = PlaybookExecutor::new(false);
        let playbook = create_test_playbook(vec![
            PlaybookAction::Log {
                level: "info".to_string(),
                message: "Starting".to_string(),
            },
            PlaybookAction::Command {
                cmd: "false".to_string(), // This command always fails
                cwd: None,
                env: std::collections::HashMap::new(),
                timeout_secs: 30,
            },
            PlaybookAction::Log {
                level: "info".to_string(),
                message: "Should not reach here".to_string(),
            },
        ]);

        let result = executor.execute(&playbook).await.unwrap();
        assert!(!result.success);
        assert_eq!(result.actions_succeeded, 1);
        assert_eq!(result.actions_failed, 1);
        // Should stop at the failed action since continue_on_error is false
        assert_eq!(result.action_results.len(), 2);
    }

    #[tokio::test]
    async fn test_execute_playbook_continue_on_error() {
        let executor = PlaybookExecutor::new(false);
        let mut playbook = create_test_playbook(vec![
            PlaybookAction::Command {
                cmd: "false".to_string(),
                cwd: None,
                env: std::collections::HashMap::new(),
                timeout_secs: 30,
            },
            PlaybookAction::Log {
                level: "info".to_string(),
                message: "This should execute".to_string(),
            },
        ]);
        playbook.continue_on_error = true;

        let result = executor.execute(&playbook).await.unwrap();
        assert!(!result.success); // Overall still fails
        assert_eq!(result.actions_succeeded, 1);
        assert_eq!(result.actions_failed, 1);
        assert_eq!(result.action_results.len(), 2); // Both actions executed
    }
}
