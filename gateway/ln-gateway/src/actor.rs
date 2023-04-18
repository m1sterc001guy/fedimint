use std::sync::Arc;
use std::time::Duration;

use bitcoin::{Address, Transaction};
use bitcoin_hashes::{sha256, Hash};
use fedimint_client_legacy::mint::backup::Metadata;
use fedimint_client_legacy::modules::ln::contracts::{ContractId, Preimage};
use fedimint_client_legacy::modules::ln::route_hints::RouteHint;
use fedimint_client_legacy::modules::wallet::txoproof::TxOutProof;
use fedimint_client_legacy::{GatewayClient, PaymentParameters};
use fedimint_core::task::{RwLock, TaskGroup};
use fedimint_core::{Amount, OutPoint, TransactionId};
use rand::{CryptoRng, RngCore};
use tracing::{debug, info, instrument, warn};

use crate::gatewaylnrpc::{PayInvoiceRequest, PayInvoiceResponse, SubscribeInterceptHtlcsResponse};
use crate::lnrpc_client::ILnRpcClient;
use crate::rpc::FederationInfo;
use crate::utils::retry;
use crate::{GatewayError, LightningSenderStream, Result};

/// How long a gateway announcement stays valid
const GW_ANNOUNCEMENT_TTL: Duration = Duration::from_secs(600);

#[derive(Clone)]
pub struct GatewayActor {
    client: Arc<GatewayClient>,
    pub lnrpc: Arc<RwLock<dyn ILnRpcClient>>,
    pub short_channel_id: u64,
}

#[derive(Debug, Clone)]
pub enum BuyPreimage {
    Internal((OutPoint, ContractId)),
    External(Preimage),
}

impl GatewayActor {
    pub async fn new(
        client: Arc<GatewayClient>,
        lnrpc: Arc<RwLock<dyn ILnRpcClient>>,
        route_hints: Vec<RouteHint>,
        mut task_group: TaskGroup,
        short_channel_id: u64,
    ) -> Result<Self> {
        let register_client = client.clone();
        task_group
            .spawn("Register with federation", |_| async move {
                loop {
                    // Retry gateway registration
                    match retry(
                        String::from("Register With Federation"),
                        #[allow(clippy::unit_arg)]
                        || async {
                            let gateway_registration =
                                register_client.config().to_gateway_registration_info(
                                    route_hints.clone(),
                                    GW_ANNOUNCEMENT_TTL,
                                );
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
            })
            .await;

        let actor = Self {
            client,
            lnrpc,
            short_channel_id,
        };

        Ok(actor)
    }

    pub async fn handle_intercepted_htlc(
        &self,
        htlc: SubscribeInterceptHtlcsResponse,
        ln_sender: LightningSenderStream,
    ) -> Result<()> {
        let SubscribeInterceptHtlcsResponse {
            payment_hash,
            outgoing_amount_msat,
            incoming_chan_id,
            htlc_id,
            ..
        } = htlc;

        // TODO: Assert short channel id matches the one we subscribed to, or cancel
        // processing of intercepted HTLC TODO: Assert the offered
        // fee derived from invoice amount and outgoing amount is acceptable or
        // cancel processing of intercepted HTLC TODO:
        // Assert the HTLC expiry or cancel processing of
        // intercepted HTLC

        let hash = match sha256::Hash::from_slice(&payment_hash) {
            Ok(hash) => hash,
            Err(_) => {
                return ln_sender
                    .cancel_htlc("Failed to parse payment hash", incoming_chan_id, htlc_id)
                    .await;
            }
        };

        let amount_msat = Amount::from_msats(outgoing_amount_msat);

        let (outpoint, contract_id) =
            match self.buy_preimage_from_federation(&hash, &amount_msat).await {
                Ok((outpoint, contract_id)) => (outpoint, contract_id),
                Err(_) => {
                    return ln_sender
                        .cancel_htlc("Failed to buy preimage", incoming_chan_id, htlc_id)
                        .await;
                }
            };

        match self
            .pay_invoice_buy_preimage_finalize(BuyPreimage::Internal((outpoint, contract_id)))
            .await
        {
            Ok(preimage) => {
                return ln_sender
                    .settle_htlc(preimage, incoming_chan_id, htlc_id)
                    .await;
            }
            Err(_) => {
                return ln_sender
                    .cancel_htlc(
                        "Failed to process intercepted HTLC",
                        incoming_chan_id,
                        htlc_id,
                    )
                    .await;
            }
        }
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
    pub async fn pay_invoice(&self, contract_id: ContractId) -> Result<OutPoint> {
        self.pay_invoice_buy_preimage_finalize_and_claim(
            contract_id,
            self.pay_invoice_buy_preimage(contract_id).await?,
        )
        .await
    }

    #[instrument(skip_all, fields(%contract_id), err)]
    pub async fn pay_invoice_buy_preimage(&self, contract_id: ContractId) -> Result<BuyPreimage> {
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
    ) -> Result<Preimage> {
        match self
            .lnrpc
            .read()
            .await
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
            .back_up_ecash_to_federation(Metadata::empty())
            .await
            .map_err(GatewayError::Other)?;

        Ok(())
    }

    pub async fn restore(&self, mut task_group: TaskGroup) -> Result<()> {
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

        Ok(self.client.summary().await.total_amount())
    }

    pub fn get_info(&self) -> Result<FederationInfo> {
        let cfg = self.client.config();
        Ok(FederationInfo {
            federation_id: cfg.client_config.federation_id.clone(),
            mint_pubkey: cfg.redeem_key.x_only_public_key().0,
        })
    }
}
