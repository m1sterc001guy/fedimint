use bitcoin_hashes::{sha256, Hash};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::Amount;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::error;

use crate::gatewaylnrpc::SubscribeInterceptHtlcsResponse;

#[derive(Error, Debug, Serialize, Deserialize, Encodable, Decodable, Clone, Eq, PartialEq)]
pub enum ReceiveError {
    #[error("Route htlc error")]
    RouteHtlcError,
}
#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct Htlc {
    /// The HTLC payment hash.
    pub payment_hash: sha256::Hash,
    /// The incoming HTLC amount in millisatoshi.
    pub incoming_amount_msat: Amount,
    /// The outgoing HTLC amount in millisatoshi
    pub outgoing_amount_msat: Amount,
    /// The incoming HTLC expiry
    pub incoming_expiry: u32,
    /// The short channel id of the HTLC.
    pub short_channel_id: u64,
    /// The id of the incoming channel
    pub incoming_chan_id: u64,
    /// The index of the incoming htlc in the incoming channel
    pub htlc_id: u64,
}

impl TryFrom<SubscribeInterceptHtlcsResponse> for Htlc {
    type Error = anyhow::Error;

    fn try_from(s: SubscribeInterceptHtlcsResponse) -> Result<Self, Self::Error> {
        Ok(Self {
            payment_hash: sha256::Hash::from_slice(&s.payment_hash)?,
            incoming_amount_msat: Amount::from_msats(s.incoming_amount_msat),
            outgoing_amount_msat: Amount::from_msats(s.outgoing_amount_msat),
            incoming_expiry: s.incoming_expiry,
            short_channel_id: s.short_channel_id,
            incoming_chan_id: s.incoming_chan_id,
            htlc_id: s.htlc_id,
        })
    }
}
