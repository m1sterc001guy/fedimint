use std::collections::HashMap;

use anyhow::Result;

use crate::util::{ProcessHandle, ProcessManager};
use crate::vars::utf8;
use crate::{cmd, envs};

#[derive(Clone)]
pub struct Recurringd {
    pub(crate) _process: ProcessHandle,
}

impl Recurringd {
    pub async fn new(process_mgr: &ProcessManager) -> Result<Self> {
        let port = process_mgr.globals.FM_PORT_RECURRINGD;
        let listen = format!("0.0.0.0:{port}");
        let api_addr = format!("http://127.0.0.1:{port}");
        let data_dir = format!("{}/recurringd", utf8(&process_mgr.globals.FM_TEST_DIR));
        let recurringd_env: HashMap<String, String> = HashMap::from_iter([
            (envs::FM_RECURRING_LISTEN_ADDR_ENV.to_owned(), listen),
            (envs::FM_RECURRING_API_ADDR_ENV.to_owned(), api_addr),
            (envs::FM_RECURRINGD_DATA_DIR_ENV.to_owned(), data_dir),
        ]);
        let process = process_mgr
            .spawn_daemon(
                "recurringd",
                cmd!(crate::util::Recurringd).envs(recurringd_env),
            )
            .await?;
        Ok(Recurringd { _process: process })
    }
}
