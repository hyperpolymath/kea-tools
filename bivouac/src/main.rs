// SPDX-License-Identifier: AGPL-3.0-or-later
//! Kea-Bivouac: Orchestration and deployment controller for the Kea ecosystem
//!
//! The Bivouac is the strategic "Roost" where the Flock's actions are coordinated.

use std::path::PathBuf;

use anyhow::Context;
use clap::{Parser, Subcommand};
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use kea_bivouac::{
    playbook::{self, PlaybookExecutor},
    Config,
};

/// Kea-Bivouac: The Command Authority
///
/// Orchestration and deployment controller for the Kea ecosystem.
/// Manages playbook execution, mTLS communication, and nomadic deployments.
#[derive(Parser, Debug)]
#[command(name = "bivouac")]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Configuration file path
    #[arg(short, long, default_value = "bivouac.toml")]
    config: PathBuf,

    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,

    /// Enable debug logging
    #[arg(long)]
    debug: bool,

    /// Dry run mode (no actual execution)
    #[arg(long)]
    dry_run: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Execute a playbook
    #[command(alias = "exec")]
    Execute {
        /// Name or path of the playbook to execute
        playbook: String,
    },

    /// Trigger a playbook by trigger type
    #[command(alias = "trigger-playbook")]
    Trigger {
        /// Trigger type (e.g., integrity-violation, deployment)
        trigger_type: String,
    },

    /// List available playbooks
    #[command(alias = "ls")]
    List,

    /// Validate a playbook file
    Validate {
        /// Path to the playbook file
        playbook: PathBuf,
    },

    /// Show configuration
    Config,

    /// Initialize a new bivouac configuration
    Init {
        /// Force overwrite existing configuration
        #[arg(short, long)]
        force: bool,
    },

    /// Show version information
    Version,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    let filter = if cli.debug {
        EnvFilter::new("debug")
    } else if cli.verbose {
        EnvFilter::new("info")
    } else {
        EnvFilter::new("warn")
    };

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(cli.debug)
        .init();

    match cli.command {
        Commands::Version => {
            println!("Kea-Bivouac v{}", env!("CARGO_PKG_VERSION"));
            println!("The Command Authority for the Kea Ecosystem");
            Ok(())
        }

        Commands::Init { force } => {
            init_config(&cli.config, force).await
        }

        Commands::Config => {
            show_config(&cli.config).await
        }

        Commands::List => {
            list_playbooks(&cli.config).await
        }

        Commands::Validate { playbook } => {
            validate_playbook(&playbook).await
        }

        Commands::Execute { playbook } => {
            execute_playbook(&cli.config, &playbook, cli.dry_run).await
        }

        Commands::Trigger { trigger_type } => {
            trigger_playbook(&cli.config, &trigger_type, cli.dry_run).await
        }
    }
}

/// Initialize a new configuration file
async fn init_config(config_path: &PathBuf, force: bool) -> anyhow::Result<()> {
    if config_path.exists() && !force {
        anyhow::bail!(
            "Configuration file already exists: {}. Use --force to overwrite.",
            config_path.display()
        );
    }

    let default_config = r#"# SPDX-License-Identifier: AGPL-3.0-or-later
# Kea-Bivouac Configuration

name = "bivouac"
version = "1.0"
playbook_dir = "playbooks"

[mtls]
enabled = false
# ca_cert = "/path/to/ca.crt"
# client_cert = "/path/to/client.crt"
# client_key = "/path/to/client.key"
# require_client_cert = true

[deployment]
nomadic = false
fluctuation_interval_secs = 3600
satellites = []

[logging]
level = "info"
format = "text"
# file = "/var/log/bivouac.log"
"#;

    std::fs::write(config_path, default_config)?;
    info!("Created configuration file: {}", config_path.display());
    println!("Created configuration file: {}", config_path.display());
    Ok(())
}

/// Show the current configuration
async fn show_config(config_path: &PathBuf) -> anyhow::Result<()> {
    if !config_path.exists() {
        // Use default config for display
        let config = Config::default().with_mtls_disabled();
        println!("No configuration file found. Using defaults:");
        println!();
        println!("{}", toml::to_string_pretty(&config)?);
        return Ok(());
    }

    let config = Config::from_file(config_path)
        .with_context(|| format!("Failed to load config from {}", config_path.display()))?;

    println!("{}", toml::to_string_pretty(&config)?);
    Ok(())
}

/// List available playbooks
async fn list_playbooks(config_path: &PathBuf) -> anyhow::Result<()> {
    let playbook_dir = if config_path.exists() {
        let config = Config::from_file(config_path)?;
        config.playbook_dir
    } else {
        PathBuf::from("playbooks")
    };

    let playbooks = playbook::list_playbooks(&playbook_dir)?;

    if playbooks.is_empty() {
        println!("No playbooks found in {}", playbook_dir.display());
        println!();
        println!("Create a playbook file (*.toml or *.scm) in the playbook directory.");
    } else {
        println!("Available playbooks in {}:", playbook_dir.display());
        println!();
        for name in playbooks {
            println!("  - {}", name);
        }
    }

    Ok(())
}

/// Validate a playbook file
async fn validate_playbook(playbook_path: &PathBuf) -> anyhow::Result<()> {
    info!("Validating playbook: {}", playbook_path.display());

    let playbook = playbook::load_playbook(playbook_path)
        .with_context(|| format!("Failed to parse playbook: {}", playbook_path.display()))?;

    playbook.validate()
        .with_context(|| "Playbook validation failed")?;

    println!("Playbook '{}' is valid", playbook.name);
    println!();
    println!("  Description: {}", playbook.description);
    println!("  Version: {}", playbook.version);
    println!("  Actions: {}", playbook.actions.len());
    println!("  Timeout: {} seconds", playbook.timeout_secs);
    println!("  Continue on error: {}", playbook.continue_on_error);

    Ok(())
}

/// Execute a playbook by name or path
async fn execute_playbook(
    config_path: &PathBuf,
    playbook_name: &str,
    dry_run: bool,
) -> anyhow::Result<()> {
    let playbook_path = if PathBuf::from(playbook_name).exists() {
        PathBuf::from(playbook_name)
    } else {
        let playbook_dir = if config_path.exists() {
            let config = Config::from_file(config_path)?;
            config.playbook_dir
        } else {
            PathBuf::from("playbooks")
        };

        // Try different extensions
        let toml_path = playbook_dir.join(format!("{}.toml", playbook_name));
        let scm_path = playbook_dir.join(format!("{}.scm", playbook_name));

        if toml_path.exists() {
            toml_path
        } else if scm_path.exists() {
            scm_path
        } else {
            anyhow::bail!(
                "Playbook '{}' not found. Tried:\n  - {}\n  - {}",
                playbook_name,
                toml_path.display(),
                scm_path.display()
            );
        }
    };

    info!("Loading playbook: {}", playbook_path.display());
    let playbook = playbook::load_playbook(&playbook_path)?;

    playbook.validate()?;

    if dry_run {
        println!("[DRY RUN] Would execute playbook: {}", playbook.name);
    } else {
        println!("Executing playbook: {}", playbook.name);
    }

    let executor = PlaybookExecutor::new(dry_run);
    let result = executor.execute(&playbook).await?;

    println!();
    if result.success {
        println!("Playbook completed successfully");
    } else {
        println!("Playbook completed with errors");
    }

    println!();
    println!("Results:");
    println!("  Duration: {} ms", result.total_duration_ms);
    println!("  Actions succeeded: {}", result.actions_succeeded);
    println!("  Actions failed: {}", result.actions_failed);

    if !result.success {
        std::process::exit(1);
    }

    Ok(())
}

/// Trigger a playbook by trigger type
async fn trigger_playbook(
    config_path: &PathBuf,
    trigger_type: &str,
    dry_run: bool,
) -> anyhow::Result<()> {
    let playbook_dir = if config_path.exists() {
        let config = Config::from_file(config_path)?;
        config.playbook_dir
    } else {
        PathBuf::from("playbooks")
    };

    // Map common trigger types to playbook names
    let playbook_name = match trigger_type {
        "integrity-violation" | "integrity" => "integrity-violation",
        "failover" | "fail-over" => "failover",
        "deployment" | "deploy" => "deployment",
        "health-check" | "health" => "health-check",
        "rotate-dns" | "dns" => "rotate-dns",
        _ => trigger_type,
    };

    // Look for the playbook
    let toml_path = playbook_dir.join(format!("{}.toml", playbook_name));
    let scm_path = playbook_dir.join(format!("{}.scm", playbook_name));

    let playbook_path = if toml_path.exists() {
        toml_path
    } else if scm_path.exists() {
        scm_path
    } else {
        error!(
            trigger = %trigger_type,
            "No playbook found for trigger"
        );
        anyhow::bail!(
            "No playbook found for trigger '{}'. Expected:\n  - {}\n  - {}",
            trigger_type,
            toml_path.display(),
            scm_path.display()
        );
    };

    execute_playbook(config_path, playbook_path.to_str().unwrap(), dry_run).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_parsing() {
        let cli = Cli::try_parse_from(["bivouac", "version"]).unwrap();
        match cli.command {
            Commands::Version => {}
            _ => panic!("Expected Version command"),
        }
    }

    #[test]
    fn test_cli_execute_command() {
        let cli = Cli::try_parse_from(["bivouac", "execute", "test-playbook"]).unwrap();
        match cli.command {
            Commands::Execute { playbook } => {
                assert_eq!(playbook, "test-playbook");
            }
            _ => panic!("Expected Execute command"),
        }
    }

    #[test]
    fn test_cli_dry_run_flag() {
        let cli = Cli::try_parse_from(["bivouac", "--dry-run", "list"]).unwrap();
        assert!(cli.dry_run);
    }

    #[test]
    fn test_cli_verbose_flag() {
        let cli = Cli::try_parse_from(["bivouac", "-v", "list"]).unwrap();
        assert!(cli.verbose);
    }
}
