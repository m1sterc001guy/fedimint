use std::collections::HashMap;

use anyhow::Result;

use crate::util::{ProcessHandle, ProcessManager};
use crate::{cmd, envs};

#[derive(Clone)]
pub struct Recurringd {
    pub(crate) _process: ProcessHandle,
}

impl Recurringd {
    pub async fn new(process_mgr: &ProcessManager) -> Result<Self> {
        let port = process_mgr.globals.FM_PORT_RECURRINGD;
        let listen = format!("127.0.0.1:{port}");
        let recurringd_env: HashMap<String, String> =
            HashMap::from_iter([(envs::FM_RECURRING_LISTEN_ADDR_ENV.to_owned(), listen)]);
        let process = process_mgr
            .spawn_daemon(
                "recurringd",
                cmd!(crate::util::Recurringd).envs(recurringd_env),
            )
            .await?;
        Ok(Recurringd { _process: process })
    }
}
