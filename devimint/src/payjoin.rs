//! Payjoin testing infrastructure for devimint.
//!
//! This module provides the `PayjoinMailroom` component which runs a local
//! Payjoin Directory and OHTTP Relay server for testing Payjoin V2 (BIP-77)
//! functionality.

use std::ops::ControlFlow;
use std::time::Duration;

use anyhow::{Context, Result};
use fedimint_core::util::{FmtCompact, write_overwrite_async};
use fedimint_logging::LOG_DEVIMINT;
use tracing::{debug, info};

use crate::cmd;
use crate::util::{ProcessHandle, ProcessManager, poll};
use crate::vars::utf8;

/// A running instance of payjoin-mailroom (combined Payjoin Directory + OHTTP
/// Relay)
#[derive(Clone)]
pub struct PayjoinMailroom {
    pub(crate) _process: ProcessHandle,
    /// The URL of the payjoin directory
    pub directory_url: String,
    /// The URL of the OHTTP relay
    pub ohttp_relay_url: String,
}

impl PayjoinMailroom {
    /// Starts a new payjoin-mailroom instance.
    ///
    /// The server provides both the Payjoin Directory (where senders and
    /// receivers exchange encrypted PSBTs) and the OHTTP Relay (which
    /// provides privacy by hiding client IPs from the directory).
    pub async fn new(process_mgr: &ProcessManager) -> Result<Self> {
        let port = process_mgr.globals.FM_PORT_PAYJOIN_MAILROOM;

        // Create the configuration file for payjoin-mailroom
        let config = format!(
            r#"# Payjoin Mailroom configuration for devimint testing

[server]
# Listen on localhost only for testing
bind = "127.0.0.1:{port}"

[directory]
# Store sessions in /tmp for testing (auto-cleaned on reboot)
db_path = "/tmp/payjoin-mailroom-{port}/sessions"
# Short timeout for testing (5 minutes)
timeout_secs = 300
"#,
            port = port,
        );

        write_overwrite_async(
            process_mgr.globals.FM_PAYJOIN_DIR.join("config.toml"),
            config,
        )
        .await?;

        let config_path = process_mgr.globals.FM_PAYJOIN_DIR.join("config.toml");
        let cmd =
            cmd!(crate::util::PayjoinMailroom, "--config", utf8(&config_path)).current_dir("/tmp");

        let process = process_mgr
            .spawn_daemon("payjoin-mailroom", cmd)
            .await
            .context("Failed to spawn payjoin-mailroom")?;

        let directory_url = format!("http://127.0.0.1:{}", port);
        let ohttp_relay_url = directory_url.clone();

        let mailroom = Self {
            _process: process,
            directory_url: directory_url.clone(),
            ohttp_relay_url,
        };

        // Wait for the server to be ready
        mailroom.poll_ready(&directory_url).await?;

        info!(
            target: LOG_DEVIMINT,
            directory_url = %directory_url,
            "Payjoin mailroom started"
        );

        Ok(mailroom)
    }

    /// Poll until the payjoin-mailroom server is ready to accept connections
    async fn poll_ready(&self, url: &str) -> Result<()> {
        poll("payjoin-mailroom ready", || async {
            // Try to connect to the health endpoint or just check if the port is open
            let client = reqwest::Client::builder()
                .timeout(Duration::from_secs(2))
                .build()
                .map_err(|e| ControlFlow::Break(e.into()))?;

            // payjoin-mailroom should respond to a basic request
            // The server returns 404 for unknown paths but that means it's up
            match client.get(url).send().await {
                Ok(_) => {
                    debug!(target: LOG_DEVIMINT, "Payjoin mailroom is ready");
                    Ok(())
                }
                Err(err) => {
                    debug!(
                        target: LOG_DEVIMINT,
                        err = %err.fmt_compact(),
                        "Payjoin mailroom not ready yet"
                    );
                    Err(ControlFlow::Continue(err.into()))
                }
            }
        })
        .await
    }

    /// Returns the URL for the Payjoin Directory
    pub fn directory_url(&self) -> &str {
        &self.directory_url
    }

    /// Returns the URL for the OHTTP Relay
    pub fn ohttp_relay_url(&self) -> &str {
        &self.ohttp_relay_url
    }
}
