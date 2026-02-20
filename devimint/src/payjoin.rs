//! Payjoin testing infrastructure for devimint.
//!
//! This module provides the `PayjoinMailroom` component which runs a local
//! Payjoin Directory or OHTTP Relay server for testing Payjoin V2 (BIP-77)
//! functionality.
//!
//! Note: For payjoin to work, we need separate directory and relay instances
//! because payjoin-mailroom rejects OHTTP requests from the same-instance relay
//! (for privacy/security reasons).

use std::ops::ControlFlow;
use std::time::Duration;

use anyhow::{Context, Result};
use fedimint_core::util::{FmtCompact, write_overwrite_async};
use fedimint_logging::LOG_DEVIMINT;
use tracing::{debug, info};

use crate::cmd;
use crate::util::{ProcessHandle, ProcessManager, poll};
use crate::vars::utf8;

/// A running instance of payjoin-mailroom
#[derive(Clone)]
pub struct PayjoinMailroom {
    pub(crate) _process: ProcessHandle,
    /// The URL of this payjoin-mailroom instance
    pub url: String,
    /// The name/role of this instance (e.g., "directory" or "relay")
    pub name: String,
}

impl PayjoinMailroom {
    /// Starts the payjoin directory instance.
    pub async fn new_directory(process_mgr: &ProcessManager) -> Result<Self> {
        let port = process_mgr.globals.FM_PORT_PAYJOIN_DIRECTORY;
        Self::new_with_port(process_mgr, port, "directory").await
    }

    /// Starts the payjoin OHTTP relay instance.
    pub async fn new_relay(process_mgr: &ProcessManager) -> Result<Self> {
        let port = process_mgr.globals.FM_PORT_PAYJOIN_RELAY;
        Self::new_with_port(process_mgr, port, "relay").await
    }

    /// Starts a new payjoin-mailroom instance with the given port and name.
    async fn new_with_port(process_mgr: &ProcessManager, port: u16, name: &str) -> Result<Self> {
        let payjoin_dir = utf8(&process_mgr.globals.FM_PAYJOIN_DIR);

        info!(target: LOG_DEVIMINT, %payjoin_dir, %port, %name, "Starting payjoin-mailroom");

        // Create the configuration file for payjoin-mailroom
        let config = format!(
            r#"# Payjoin Mailroom configuration for devimint testing ({name})
# Listen on localhost only for testing
listener = "127.0.0.1:{port}"

# Store sessions in /tmp for testing (auto-cleaned on reboot)
storage_dir = "/tmp/payjoin-{name}-{port}/sessions"
# Short timeout for testing (5 minutes)
timeout = 300
"#,
            name = name,
            port = port,
        );

        let config_path = process_mgr
            .globals
            .FM_PAYJOIN_DIR
            .join(format!("{}-config.toml", name));
        write_overwrite_async(config_path.clone(), config).await?;

        info!(target: LOG_DEVIMINT, config_path = ?config_path, %name, "Config written");

        let cmd = cmd!(crate::util::PayjoinMailroom, "--config", utf8(&config_path));

        info!(target: LOG_DEVIMINT, %name, "Spawning payjoin-mailroom process");

        let daemon_name = format!("payjoin-{}", name);
        let process = process_mgr
            .spawn_daemon(&daemon_name, cmd)
            .await
            .context(format!("Failed to spawn payjoin-mailroom {}", name))?;

        let url = format!("http://127.0.0.1:{}", port);

        info!(target: LOG_DEVIMINT, %url, %name, "Waiting for payjoin-mailroom to be ready");

        let mailroom = Self {
            _process: process,
            url: url.clone(),
            name: name.to_string(),
        };

        // Wait for the server to be ready
        mailroom.poll_ready().await?;

        info!(
            target: LOG_DEVIMINT,
            url = %url,
            name = %name,
            "Payjoin mailroom started"
        );

        Ok(mailroom)
    }

    /// Poll until the payjoin-mailroom server is ready to accept connections
    async fn poll_ready(&self) -> Result<()> {
        let poll_name = format!("payjoin-{} ready", self.name);
        let url = self.url.clone();
        let name = self.name.clone();
        poll(&poll_name, || async {
            let client = reqwest::Client::builder()
                .timeout(Duration::from_secs(2))
                .build()
                .map_err(|e| ControlFlow::Break(e.into()))?;

            // payjoin-mailroom should respond to a basic request
            // The server returns 404 for unknown paths but that means it's up
            match client.get(&url).send().await {
                Ok(_) => {
                    debug!(target: LOG_DEVIMINT, %name, "Payjoin mailroom is ready");
                    Ok(())
                }
                Err(err) => {
                    debug!(
                        target: LOG_DEVIMINT,
                        %url,
                        %name,
                        err = %err.fmt_compact(),
                        "Payjoin mailroom not ready yet"
                    );
                    Err(ControlFlow::Continue(err.into()))
                }
            }
        })
        .await
    }

    /// Returns the URL of this payjoin-mailroom instance
    pub fn url(&self) -> &str {
        &self.url
    }
}
