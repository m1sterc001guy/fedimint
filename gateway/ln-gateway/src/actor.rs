use std::sync::Arc;
use std::time::Duration;

use bitcoin::{Address, Transaction};
use bitcoin_hashes::{sha256, Hash};
use fedimint_core::task::TaskGroup;
use fedimint_core::{Amount, OutPoint, TransactionId};
use futures::stream::StreamExt;
use mint_client::modules::ln::contracts::{ContractId, Preimage};
use mint_client::modules::ln::route_hints::RouteHint;
use mint_client::modules::wallet::txoproof::TxOutProof;
use mint_client::{GatewayClient, PaymentParameters};
use rand::{CryptoRng, RngCore};
use tracing::{debug, error, info, instrument, warn};

use crate::gatewaylnrpc::complete_htlcs_request::{Action, Cancel, Settle};
use crate::gatewaylnrpc::{
    CompleteHtlcsRequest, PayInvoiceRequest, PayInvoiceResponse, SubscribeInterceptHtlcsRequest,
    SubscribeInterceptHtlcsResponse,
};
use crate::lnrpc_client::{ILnRpcClient, NetworkLnRpcClient};
use crate::rpc::{FederationInfo, GatewayRpcSender};
use crate::utils::retry;
use crate::{GatewayError, Result};

/// How long a gateway announcement stays valid
const GW_ANNOUNCEMENT_TTL: Duration = Duration::from_secs(600);

#[derive(Clone)]
pub struct GatewayActor {
    client: Arc<GatewayClient>,
    task_group: TaskGroup,
    gateway_rpc: GatewayRpcSender,
}

#[derive(Debug, Clone)]
pub enum BuyPreimage {
    Internal((OutPoint, ContractId)),
    External(Preimage),
}

impl GatewayActor {
    pub async fn new(
        client: Arc<GatewayClient>,
        lnrpc: &mut NetworkLnRpcClient,
        route_hints: Vec<RouteHint>,
        task_group: TaskGroup,
        gateway_rpc: GatewayRpcSender,
    ) -> Result<Self> {
        let register_client = client.clone();
        tokio::spawn(async move {
            loop {
                // Retry gateway registration
                match retry(
                    String::from("Register With Federation"),
                    #[allow(clippy::unit_arg)]
                    || async {
                        let gateway_registration = register_client
                            .config()
                            .to_gateway_registration_info(route_hints.clone(), GW_ANNOUNCEMENT_TTL);
                        Ok(register_client
                            .register_with_federation(gateway_registration.clone())
                            .await?)
                    },
                    Duration::from_secs(1),
                    5,
                )
                .await
                {
                    Ok(_) => {
                        info!("Connected with federation");
                        tokio::time::sleep(GW_ANNOUNCEMENT_TTL / 2).await;
                    }
                    Err(e) => {
                        warn!("Failed to connect with federation: {}", e);
                        tokio::time::sleep(GW_ANNOUNCEMENT_TTL / 4).await;
                    }
                }
            }
        });

        let actor = Self {
            client,
            task_group,
            gateway_rpc,
        };

        actor.subscribe_htlcs(lnrpc).await?;

        Ok(actor)
    }

    async fn subscribe_htlcs(&self, lnrpc: &mut NetworkLnRpcClient) -> Result<()> {
        let short_channel_id = self.client.config().mint_channel_id;
        let mut tg = self.task_group.clone();

        let mut stream = lnrpc
            .subscribe_htlcs(SubscribeInterceptHtlcsRequest { short_channel_id })
            .await?;
        info!("Subscribed to HTLCs with {:?}", short_channel_id);

        let actor = self.to_owned();
        //let lnrpc_copy = self.lnrpc.to_owned();
        /*
        tg.spawn(
            "Subscribe to intercepted HTLCs in stream",
            move |subscription| async move {
                while let Some(SubscribeInterceptHtlcsResponse {
                    payment_hash,
                    outgoing_amount_msat,
                    intercepted_htlc_id,
                    ..
                }) = match stream.next().await {
                    Some(msg) => match msg {
                        Ok(msg) => Some(msg),
                        Err(e) => {
                            warn!("Error sent over HTLC subscription: {}. Need to send RPC to gateway to reconnect.", e);
                            None
                        }
                    },
                    None => {
                        warn!("HTLC stream closed by service");
                        None
                    }
                } {
                    if subscription.is_shutting_down() {
                        info!("Shutting down HTLC subscription");
                        break;
                    }

                    // TODO: Assert short channel id matches the one we subscribed to, or cancel
                    // processing of intercepted HTLC TODO: Assert the offered
                    // fee derived from invoice amount and outgoing amount is acceptable or cancel
                    // processing of intercepted HTLC TODO: Assert the HTLC
                    // expiry or cancel processing of intercepted HTLC

                    let hash = match sha256::Hash::from_slice(&payment_hash) {
                        Ok(hash) => hash,
                        Err(e) => {
                            let fail = "Failed to parse payment hash";

                            error!("{}: {:?}", fail, e);
                            let _ = lnrpc
                                .complete_htlc(CompleteHtlcsRequest {
                                    intercepted_htlc_id,
                                    action: Some(Action::Cancel(Cancel {
                                        reason: fail.to_string(),
                                    })),
                                })
                                .await;
                            continue;
                        }
                    };

                    let amount_msat = Amount::from_msats(outgoing_amount_msat);

                    let (outpoint, contract_id) = match actor
                        .buy_preimage_from_federation(&hash, &amount_msat)
                        .await
                    {
                        Ok((outpoint, contract_id)) => (outpoint, contract_id),
                        Err(e) => {
                            error!("Failed to buy preimage: {:?}", e);
                            // Note: this specific complete htlc requires no further action.
                            // If we fail to send the complete htlc message, or get an error
                            // result, lightning node will still
                            // cancel HTCL after expiry period lapses.
                            // Result can be safely ignored.
                            // TODO: make sure this succeeded?
                            let _ = lnrpc
                                .complete_htlc(CompleteHtlcsRequest {
                                    intercepted_htlc_id,
                                    action: Some(Action::Cancel(Cancel {
                                        reason: e.to_string(),
                                    })),
                                })
                                .await;
                            continue;
                        }
                    };

                    match actor
                        .pay_invoice_buy_preimage_finalize(BuyPreimage::Internal((
                            outpoint,
                            contract_id,
                        )))
                        .await
                    {
                        Ok(preimage) => {
                            info!("Successfully processed intercepted HTLC");
                            if let Err(e) = lnrpc
                                .complete_htlc(CompleteHtlcsRequest {
                                    intercepted_htlc_id,
                                    action: Some(Action::Settle(Settle {
                                        preimage: preimage.0.to_vec(),
                                    })),
                                })
                                .await
                            {
                                error!("Failed to complete HTLC: {:?}", e);
                                // Note: To prevent loss of funds for the
                                // gateway,
                                // we should either retry completing the htlc or
                                // reclaim funds from the federation
                            };
                        }
                        Err(e) => {
                            error!("Failed to process intercepted HTLC: {:?}", e);
                            // Note: this specific complete htlc requires no further action.
                            // If we fail to send the complete htlc message, or get an error result,
                            // lightning node will still cancel HTCL after expiry period lapses.
                            // Result can be safely ignored.
                            let _ = lnrpc
                                .complete_htlc(CompleteHtlcsRequest {
                                    intercepted_htlc_id,
                                    action: Some(Action::Cancel(Cancel {
                                        reason: e.to_string(),
                                    })),
                                })
                                .await;
                        }
                    };
                }
            },
        )
        .await;
        */

        Ok(())
    }

    async fn fetch_all_notes(&self) {
        if let Err(e) = self.client.fetch_all_notes().await {
            debug!(error = %e, "Fetching notes failed");
        }
    }

    pub async fn buy_preimage_offer(
        &self,
        payment_hash: &sha256::Hash,
        amount: &Amount,
        rng: impl RngCore + CryptoRng,
    ) -> Result<(OutPoint, ContractId)> {
        let (outpoint, contract_id) = self
            .client
            .buy_preimage_offer(payment_hash, amount, rng)
            .await?;
        Ok((outpoint, contract_id))
    }

    // TODO: Move this API to messaging
    pub async fn await_preimage_decryption(&self, outpoint: OutPoint) -> Result<Preimage> {
        let preimage = self.client.await_preimage_decryption(outpoint).await?;
        Ok(preimage)
    }

    #[instrument(skip_all, fields(%contract_id))]
    pub async fn pay_invoice(
        &self,
        contract_id: ContractId,
        lnrpc: &mut NetworkLnRpcClient,
    ) -> Result<OutPoint> {
        self.pay_invoice_buy_preimage_finalize_and_claim(
            contract_id,
            self.pay_invoice_buy_preimage(contract_id, lnrpc).await?,
        )
        .await
    }

    #[instrument(skip_all, fields(%contract_id), err)]
    pub async fn pay_invoice_buy_preimage(
        &self,
        contract_id: ContractId,
        lnrpc: &mut NetworkLnRpcClient,
    ) -> Result<BuyPreimage> {
        debug!("Fetching contract");
        let contract_account = self.client.fetch_outgoing_contract(contract_id).await?;

        let payment_params = match self
            .client
            .validate_outgoing_account(&contract_account)
            .await
        {
            Ok(payment_params) => payment_params,
            Err(e) => {
                self.client
                    .cancel_outgoing_contract(contract_account)
                    .await?;
                return Err(e.into());
            }
        };

        debug!(
            account = ?contract_account,
            "Fetched and validated contract account"
        );

        self.client
            .save_outgoing_payment(contract_account.clone())
            .await;

        let is_internal_payment = payment_params.maybe_internal
            && self
                .client
                .ln_client()
                .offer_exists(payment_params.payment_hash)
                .await
                .unwrap_or(false);

        Ok(if is_internal_payment {
            BuyPreimage::Internal(
                self.buy_preimage_from_federation(
                    &payment_params.payment_hash,
                    &payment_params.invoice_amount,
                )
                .await?,
            )
        } else {
            BuyPreimage::External(
                self.buy_preimage_over_lightning(
                    contract_account.contract.invoice,
                    &payment_params,
                    lnrpc,
                )
                .await?,
            )
        })
    }

    pub async fn pay_invoice_buy_preimage_finalize(
        &self,
        buy_preimage: BuyPreimage,
    ) -> Result<Preimage> {
        match buy_preimage {
            BuyPreimage::Internal((out_point, contract_id)) => {
                self.buy_preimage_from_federation_await_decryption(out_point, contract_id)
                    .await
            }
            BuyPreimage::External(preimage) => Ok(preimage),
        }
    }

    #[instrument(skip_all, fields(?buy_preimage), err)]
    pub async fn pay_invoice_buy_preimage_finalize_and_claim(
        &self,
        contract_id: ContractId,
        buy_preimage: BuyPreimage,
    ) -> Result<OutPoint> {
        let rng = rand::rngs::OsRng;

        match self.pay_invoice_buy_preimage_finalize(buy_preimage).await {
            Ok(preimage) => {
                let outpoint = self
                    .client
                    .claim_outgoing_contract(contract_id, preimage, rng)
                    .await?;
                Ok(outpoint)
            }
            Err(e) => {
                warn!("Invoice payment failed. Aborting");
                // FIXME: combine both errors?
                self.client.abort_outgoing_payment(contract_id).await?;
                Err(e)
            }
        }
    }

    #[instrument(skip(self), ret, err)]
    pub async fn buy_preimage_from_federation(
        &self,
        payment_hash: &sha256::Hash,
        invoice_amount: &Amount,
    ) -> Result<(OutPoint, ContractId)> {
        let mut rng = rand::rngs::OsRng;

        self.fetch_all_notes().await;

        Ok(self
            .client
            .buy_preimage_offer(payment_hash, invoice_amount, &mut rng)
            .await?)
    }

    #[instrument(skip(self), ret, err)]
    pub async fn buy_preimage_from_federation_await_decryption(
        &self,
        out_point: OutPoint,
        contract_id: ContractId,
    ) -> Result<Preimage> {
        let rng = rand::rngs::OsRng;

        match self.client.await_preimage_decryption(out_point).await {
            Ok(preimage) => Ok(preimage),
            Err(error) => {
                warn!(%error, "Failed to decrypt preimage. Now requesting a refund");
                self.client
                    .refund_incoming_contract(contract_id, rng)
                    .await?;
                Err(GatewayError::ClientError(error))
            }
        }
    }

    pub async fn buy_preimage_over_lightning(
        &self,
        invoice: lightning_invoice::Invoice,
        payment_params: &PaymentParameters,
        lnrpc: &mut NetworkLnRpcClient,
    ) -> Result<Preimage> {
        match lnrpc
            .pay(PayInvoiceRequest {
                invoice: invoice.to_string(),
                max_delay: payment_params.max_delay,
                max_fee_percent: payment_params.max_fee_percent(),
            })
            .await
        {
            Ok(PayInvoiceResponse { preimage, .. }) => {
                let slice: [u8; 32] = preimage.try_into().expect("Failed to parse preimage");
                Ok(Preimage(slice))
            }
            Err(e) => Err(e),
        }
    }

    pub async fn await_outgoing_contract_claimed(
        &self,
        contract_id: ContractId,
        outpoint: OutPoint,
    ) -> Result<()> {
        Ok(self
            .client
            .await_outgoing_contract_claimed(contract_id, outpoint)
            .await?)
    }

    pub async fn get_deposit_address(&self) -> Result<Address> {
        let rng = rand::rngs::OsRng;
        Ok(self.client.get_new_pegin_address(rng).await)
    }

    pub async fn deposit(
        &self,
        txout_proof: TxOutProof,
        transaction: Transaction,
    ) -> Result<TransactionId> {
        let rng = rand::rngs::OsRng;

        self.client
            .peg_in(txout_proof, transaction, rng)
            .await
            .map_err(GatewayError::ClientError)
    }

    pub async fn withdraw(
        &self,
        amount: bitcoin::Amount,
        address: Address,
    ) -> Result<TransactionId> {
        self.fetch_all_notes().await;

        let rng = rand::rngs::OsRng;

        let peg_out = self
            .client
            .new_peg_out_with_fees(amount, address)
            .await
            .expect("Failed to create pegout with fees");
        self.client
            .peg_out(peg_out, rng)
            .await
            .map_err(GatewayError::ClientError)
            .map(|out_point| out_point.txid)
    }

    pub async fn backup(&self) -> Result<()> {
        self.client
            .mint_client()
            .back_up_ecash_to_federation()
            .await
            .map_err(GatewayError::Other)?;

        Ok(())
    }

    pub async fn restore(&self) -> Result<()> {
        // TODO: get the task group from `self`
        let mut task_group = TaskGroup::new();

        self.client
            .mint_client()
            .restore_ecash_from_federation(10, &mut task_group)
            .await
            .map_err(GatewayError::Other)?
            .map_err(|e| GatewayError::Other(e.into()))?;

        task_group
            .join_all(None)
            .await
            .map_err(GatewayError::Other)?;

        Ok(())
    }

    pub async fn get_balance(&self) -> Result<Amount> {
        self.fetch_all_notes().await;

        Ok(self.client.notes().await.total_amount())
    }

    pub fn get_info(&self) -> Result<FederationInfo> {
        let cfg = self.client.config();
        Ok(FederationInfo {
            federation_id: cfg.client_config.federation_id.clone(),
            mint_pubkey: cfg.redeem_key.x_only_public_key().0,
        })
    }
}
