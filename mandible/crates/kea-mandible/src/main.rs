// SPDX-License-Identifier: AGPL-3.0-or-later
//! Kea-Mandible: High-dexterity investigative sensors for Kea
//!
//! Main CLI entry point for the Kea-Mandible ecosystem.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tracing::{error, info};
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::EnvFilter;

use kea_beak::{AuditConfiguration, BeakEngine, HashAlgorithm, SecurityAuditor};
use slop_gate::{SlopGateAuditor, SlopGateConfiguration};
use wp_praxis::{WpAuditor, WpConfigAuditor, WordPressInfo};

/// Kea-Mandible: High-dexterity investigative sensors for Kea
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    /// Enable verbose output
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Output format (json, text)
    #[arg(short, long, default_value = "text", global = true)]
    format: OutputFormat,

    /// Log level (error, warn, info, debug, trace)
    #[arg(long, default_value = "info", global = true)]
    log_level: String,

    #[command(subcommand)]
    command: Commands,
}

/// Output format for reports
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum OutputFormat {
    /// Human-readable text format
    Text,
    /// JSON format
    Json,
}

/// Available commands
#[derive(Subcommand, Debug)]
enum Commands {
    /// Deep audit of a target path (general filesystem audit)
    Pry {
        /// Target path to audit
        #[arg(short, long)]
        target: PathBuf,

        /// Maximum depth to traverse
        #[arg(short, long)]
        depth: Option<usize>,

        /// Follow symbolic links
        #[arg(long)]
        follow_symlinks: bool,

        /// Include hidden files and directories
        #[arg(long)]
        include_hidden: bool,

        /// Calculate file hashes
        #[arg(long)]
        hashes: bool,

        /// Hash algorithm (sha256, blake3)
        #[arg(long, default_value = "blake3")]
        hash_algorithm: String,
    },

    /// WordPress-specific audit
    WordPress {
        /// Path to WordPress installation
        #[arg(short, long)]
        path: PathBuf,

        /// Also audit wp-config.php settings
        #[arg(long)]
        audit_config: bool,
    },

    /// Detect and report bloat
    Slop {
        /// Target path to analyze
        #[arg(short, long)]
        target: PathBuf,

        /// Detect duplicate files (requires hashing)
        #[arg(long)]
        duplicates: bool,

        /// Threshold for large binary detection in MB
        #[arg(long, default_value = "10")]
        large_binary_mb: u64,
    },

    /// Show version information
    Version,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    // Initialize tracing
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&cli.log_level));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_span_events(FmtSpan::CLOSE)
        .with_target(false)
        .init();

    // Run the async runtime
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Failed to create runtime");

    match runtime.block_on(run(cli)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            error!("Error: {:#}", error);
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Commands::Pry {
            target,
            depth,
            follow_symlinks,
            include_hidden,
            hashes,
            hash_algorithm,
        } => {
            run_pry(
                &target,
                depth,
                follow_symlinks,
                include_hidden,
                hashes,
                &hash_algorithm,
                cli.format,
            )
            .await
        }
        Commands::WordPress { path, audit_config } => {
            run_wordpress(&path, audit_config, cli.format).await
        }
        Commands::Slop {
            target,
            duplicates,
            large_binary_mb,
        } => run_slop(&target, duplicates, large_binary_mb, cli.format).await,
        Commands::Version => {
            println!("kea-mandible {}", env!("CARGO_PKG_VERSION"));
            println!("Components:");
            println!("  - kea-beak: General-purpose filesystem auditor");
            println!("  - wp-praxis: WordPress environment auditor");
            println!("  - slop-gate: Runtime bloat rejection filter");
            Ok(())
        }
    }
}

/// Run the general filesystem audit (pry command)
async fn run_pry(
    target: &Path,
    max_depth: Option<usize>,
    follow_symlinks: bool,
    include_hidden: bool,
    calculate_hashes: bool,
    hash_algorithm: &str,
    format: OutputFormat,
) -> Result<()> {
    info!("Starting deep audit of {}", target.display());

    let hash_algo = match hash_algorithm.to_lowercase().as_str() {
        "sha256" => HashAlgorithm::Sha256,
        "blake3" => HashAlgorithm::Blake3,
        other => {
            return Err(anyhow::anyhow!(
                "Unknown hash algorithm: {}. Use 'sha256' or 'blake3'",
                other
            ))
        }
    };

    let configuration = AuditConfiguration {
        target_path: target.to_path_buf(),
        max_depth,
        follow_symlinks,
        include_hidden,
        calculate_hashes,
        hash_algorithm: hash_algo,
        ..Default::default()
    };

    let mut engine = BeakEngine::new(configuration);

    // Add security auditor
    engine.add_auditor(Box::new(SecurityAuditor));

    // Add slop-gate auditor
    engine.add_auditor(Box::new(SlopGateAuditor::default()));

    let report = engine
        .run_audit()
        .await
        .context("Failed to run audit")?;

    // Output report
    match format {
        OutputFormat::Json => {
            let json = serde_json::to_string_pretty(&report)?;
            println!("{}", json);
        }
        OutputFormat::Text => {
            println!("\n=== Kea-Mandible Audit Report ===\n");
            println!("Target: {}", report.configuration.target_path.display());
            println!("Started: {}", report.started_at);
            println!("Completed: {}", report.completed_at);
            println!();
            println!("=== Statistics ===");
            println!("Files scanned: {}", report.statistics.files_scanned);
            println!(
                "Directories scanned: {}",
                report.statistics.directories_scanned
            );
            println!("Bytes processed: {}", report.statistics.bytes_processed);
            println!("Files skipped: {}", report.statistics.files_skipped);
            println!("Errors: {}", report.statistics.errors_encountered);
            println!(
                "Duration: {:.2}s",
                report.statistics.duration.as_secs_f64()
            );
            println!(
                "Throughput: {:.0} files/sec",
                report.statistics.files_per_second
            );
            println!();

            if report.findings.is_empty() {
                println!("=== No findings ===");
            } else {
                println!("=== Findings ({}) ===\n", report.findings.len());
                for finding in &report.findings {
                    println!(
                        "[{}] {} - {}",
                        finding.severity, finding.finding_id, finding.description
                    );
                    println!("  Path: {}", finding.path.display());
                    if let Some(ref context) = finding.context {
                        println!("  Context: {}", context);
                    }
                    if let Some(ref recommendation) = finding.recommendation {
                        println!("  Recommendation: {}", recommendation);
                    }
                    println!();
                }
            }
        }
    }

    Ok(())
}

/// Run WordPress-specific audit
async fn run_wordpress(path: &Path, audit_config: bool, format: OutputFormat) -> Result<()> {
    info!("Starting WordPress audit of {}", path.display());

    // Detect WordPress installation
    let wp_info = WordPressInfo::detect(path)
        .await
        .context("Failed to detect WordPress installation")?;

    // Create audit configuration
    let configuration = AuditConfiguration {
        target_path: path.to_path_buf(),
        include_hidden: true,
        ..Default::default()
    };

    let mut engine = BeakEngine::new(configuration);

    // Add WordPress auditor
    engine.add_auditor(Box::new(WpAuditor::new()));

    let report = engine
        .run_audit()
        .await
        .context("Failed to run WordPress audit")?;

    // Optionally audit wp-config.php
    let config_findings = if audit_config {
        WpConfigAuditor::audit_config(path).await.unwrap_or_default()
    } else {
        vec![]
    };

    // Output report
    match format {
        OutputFormat::Json => {
            let combined = serde_json::json!({
                "wordpress_info": wp_info,
                "audit_report": report,
                "config_findings": config_findings,
            });
            println!("{}", serde_json::to_string_pretty(&combined)?);
        }
        OutputFormat::Text => {
            println!("\n=== WordPress Audit Report ===\n");
            println!("WordPress Root: {}", wp_info.root_path.display());
            println!(
                "Version: {}",
                wp_info.version.as_deref().unwrap_or("Unknown")
            );
            println!("Multisite: {}", wp_info.is_multisite);
            println!();
            println!("=== Installed Plugins ({}) ===", wp_info.plugins.len());
            for plugin in &wp_info.plugins {
                println!(
                    "  - {} ({})",
                    plugin.name.as_deref().unwrap_or(&plugin.slug),
                    plugin.version.as_deref().unwrap_or("unknown")
                );
            }
            println!();
            println!("=== Installed Themes ({}) ===", wp_info.themes.len());
            for theme in &wp_info.themes {
                println!(
                    "  - {} ({})",
                    theme.name.as_deref().unwrap_or(&theme.slug),
                    theme.version.as_deref().unwrap_or("unknown")
                );
            }
            println!();

            let all_findings: Vec<_> = report
                .findings
                .iter()
                .chain(config_findings.iter())
                .collect();

            if all_findings.is_empty() {
                println!("=== No security findings ===");
            } else {
                println!("=== Security Findings ({}) ===\n", all_findings.len());
                for finding in all_findings {
                    println!(
                        "[{}] {} - {}",
                        finding.severity, finding.finding_id, finding.description
                    );
                    println!("  Path: {}", finding.path.display());
                    if let Some(ref context) = finding.context {
                        println!("  Context: {}", context);
                    }
                    if let Some(ref recommendation) = finding.recommendation {
                        println!("  Recommendation: {}", recommendation);
                    }
                    println!();
                }
            }
        }
    }

    Ok(())
}

/// Run bloat detection (slop command)
async fn run_slop(
    target: &Path,
    detect_duplicates: bool,
    large_binary_mb: u64,
    format: OutputFormat,
) -> Result<()> {
    info!("Starting bloat analysis of {}", target.display());

    let slop_config = SlopGateConfiguration {
        detect_duplicates,
        large_binary_threshold: large_binary_mb * 1024 * 1024,
        ..Default::default()
    };

    let configuration = AuditConfiguration {
        target_path: target.to_path_buf(),
        calculate_hashes: detect_duplicates,
        ..Default::default()
    };

    let mut engine = BeakEngine::new(configuration);
    engine.add_auditor(Box::new(SlopGateAuditor::new(slop_config)));

    let report = engine
        .run_audit()
        .await
        .context("Failed to run bloat analysis")?;

    // Output report
    match format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        OutputFormat::Text => {
            println!("\n=== Slop-Gate Bloat Analysis ===\n");
            println!("Target: {}", target.display());
            println!("Files analyzed: {}", report.statistics.files_scanned);
            println!();

            if report.findings.is_empty() {
                println!("=== No bloat detected ===");
            } else {
                // Group by category
                let mut by_category: std::collections::HashMap<String, Vec<_>> =
                    std::collections::HashMap::new();

                for finding in &report.findings {
                    let category = if finding.finding_id.starts_with("SLOP") {
                        finding
                            .context
                            .as_ref()
                            .and_then(|c| c.split(',').next())
                            .unwrap_or("Other")
                            .to_string()
                    } else {
                        "Other".to_string()
                    };
                    by_category.entry(category).or_default().push(finding);
                }

                println!("=== Bloat Findings ({}) ===\n", report.findings.len());

                for (category, findings) in &by_category {
                    println!("--- {} ({}) ---", category, findings.len());
                    for finding in findings {
                        println!("  {} - {}", finding.path.display(), finding.description);
                    }
                    println!();
                }
            }
        }
    }

    Ok(())
}
