// SPDX-License-Identifier: AGPL-3.0-or-later
//! Playbook parsing and execution module
//!
//! Playbooks define automated responses to various triggers such as
//! integrity violations, deployment events, and scheduled maintenance.

mod parser;
mod executor;

pub use parser::{Playbook, PlaybookAction, PlaybookTrigger};
pub use executor::PlaybookExecutor;

use std::path::Path;
use crate::error::Result;

/// Load a playbook from a file
///
/// # Arguments
///
/// * `path` - Path to the playbook file
///
/// # Returns
///
/// The parsed playbook or an error
pub fn load_playbook<P: AsRef<Path>>(path: P) -> Result<Playbook> {
    parser::Playbook::from_file(path)
}

/// List all available playbooks in a directory
///
/// # Arguments
///
/// * `dir` - Directory containing playbook files
///
/// # Returns
///
/// A vector of playbook names
pub fn list_playbooks<P: AsRef<Path>>(dir: P) -> Result<Vec<String>> {
    let dir = dir.as_ref();
    let mut playbooks = Vec::new();

    if !dir.exists() {
        return Ok(playbooks);
    }

    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();

        if path.is_file() {
            if let Some(ext) = path.extension() {
                if ext == "toml" || ext == "scm" {
                    if let Some(stem) = path.file_stem() {
                        playbooks.push(stem.to_string_lossy().to_string());
                    }
                }
            }
        }
    }

    playbooks.sort();
    Ok(playbooks)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_list_playbooks_empty_dir() {
        let temp_dir = tempdir().unwrap();
        let playbooks = list_playbooks(temp_dir.path()).unwrap();
        assert!(playbooks.is_empty());
    }

    #[test]
    fn test_list_playbooks_with_files() {
        let temp_dir = tempdir().unwrap();

        // Create some playbook files
        fs::write(temp_dir.path().join("integrity.toml"), "").unwrap();
        fs::write(temp_dir.path().join("failover.toml"), "").unwrap();
        fs::write(temp_dir.path().join("backup.scm"), "").unwrap();
        fs::write(temp_dir.path().join("readme.txt"), "").unwrap(); // Should be ignored

        let playbooks = list_playbooks(temp_dir.path()).unwrap();
        assert_eq!(playbooks.len(), 3);
        assert!(playbooks.contains(&"backup".to_string()));
        assert!(playbooks.contains(&"failover".to_string()));
        assert!(playbooks.contains(&"integrity".to_string()));
    }

    #[test]
    fn test_list_playbooks_nonexistent_dir() {
        let playbooks = list_playbooks("/nonexistent/path").unwrap();
        assert!(playbooks.is_empty());
    }
}
