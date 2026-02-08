// SPDX-License-Identifier: AGPL-3.0-or-later
//! Kea-Bivouac: Orchestration and deployment controller for the Kea ecosystem
//!
//! The Bivouac is the strategic "Roost" where the Flock's actions are coordinated.
//! It manages the Separation of Administration from Runtime, ensuring the "Wharf"
//! remains invisible to the "Range."
//!
//! # Features
//!
//! * **Nomadic Deployment:** Uses Resource-Record-Fluctuator to rotate IP/DNS locations
//! * **Playbook Execution:** Directly interprets PLAYBOOK.scm files to resolve incidents
//! * **mTLS Integrity:** Enforces zero-trust communication between all satellites and Refugia

pub mod config;
pub mod error;
pub mod playbook;

pub use config::Config;
pub use error::{BivouacError, Result};
