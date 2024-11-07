use fedimint_client::db::event_log::{Event, EventKind};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct OutgoingLightningPayment;

impl Event for OutgoingLightningPayment {
    //const MODULE: Option<fedimint_core::core::ModuleKind> =
    // Some(fedimint_lnv2_common::KIND);
    const MODULE: Option<fedimint_core::core::ModuleKind> = None;

    const KIND: EventKind = EventKind::from_static("outgoing-lightning-payment");
}
