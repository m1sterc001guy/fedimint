use std::sync::Arc;

use bitcoin_hashes::{sha256, Hash};
use fedimint_client::sm::{State, StateTransition};
use fedimint_client::DynGlobalClientContext;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::task::RwLock;
use fedimint_core::Amount;
use fedimint_ln_common::api::LnFederationApi;
use fedimint_ln_common::contracts::outgoing::OutgoingContractAccount;
use fedimint_ln_common::contracts::{ContractId, FundedContract, Preimage};
use fedimint_ln_common::ContractAccount;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::GatewayClientContext;

// TODO: Add diagram
#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub enum GatewayPayStates {
    FetchContract(GatewayPayFetchContract),
    BuyPreimage(GatewayPayBuyPreimage),
    InternalPayment,
    ExternalPayment,
    Cancel,
    Canceled,
    Funded,
    Preimage,
    Refund,
    Claimed,
    Failure,
    Refunded,
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct GatewayPayCommon {
    // TODO: Revisit if this should be here
    redeem_key: bitcoin::KeyPair,
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct GatewayPayStateMachine {
    pub common: GatewayPayCommon,
    pub state: GatewayPayStates,
}

impl State for GatewayPayStateMachine {
    type ModuleContext = GatewayClientContext;

    type GlobalContext = DynGlobalClientContext;

    fn transitions(
        &self,
        context: &Self::ModuleContext,
        global_context: &Self::GlobalContext,
    ) -> Vec<fedimint_client::sm::StateTransition<Self>> {
        match &self.state {
            GatewayPayStates::FetchContract(gateway_pay_fetch_contract) => {
                gateway_pay_fetch_contract.transitions(global_context.clone(), self.common.clone())
            }
            GatewayPayStates::BuyPreimage(gateway_pay_buy_preimage) => {
                gateway_pay_buy_preimage.transitions()
            }
            _ => {
                vec![]
            }
        }
    }

    fn operation_id(&self) -> fedimint_client::sm::OperationId {
        todo!()
    }
}

#[derive(Error, Debug, Serialize, Deserialize, Encodable, Decodable, Clone, Eq, PartialEq)]
pub enum GatewayPayError {
    #[error("OutgoingContract does not exist {contract_id}")]
    OutgoingContractDoesNotExist { contract_id: ContractId },
    #[error("Invalid OutgoingContract {contract_id}")]
    InvalidOutgoingContract { contract_id: ContractId },
    #[error("The contract is already cancelled and can't be processed by the gateway")]
    CancelledContract,
    #[error("The Account or offer is keyed to another gateway")]
    NotOurKey,
    #[error("Invoice is missing amount")]
    InvoiceMissingAmount,
    #[error("Outgoing contract is underfunded, wants us to pay {0}, but only contains {1}")]
    Underfunded(Amount, Amount),
    #[error("The contract's timeout is in the past or does not allow for a safety margin")]
    TimeoutTooClose,
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct GatewayPayFetchContract {
    contract_id: ContractId,
    timelock_delta: u64,
    node_pub_key: bitcoin::secp256k1::PublicKey,
}

impl GatewayPayFetchContract {
    fn transitions(
        &self,
        global_context: DynGlobalClientContext,
        common: GatewayPayCommon,
    ) -> Vec<StateTransition<GatewayPayStateMachine>> {
        let timelock_delta = self.timelock_delta;
        let node_pub_key = self.node_pub_key;
        vec![StateTransition::new(
            Self::await_fetch_contract(global_context.clone(), self.contract_id),
            move |_dbtx, result, _old_state| {
                Box::pin(Self::transition_fetch_contract(
                    global_context.clone(),
                    result,
                    common.clone(),
                    timelock_delta,
                    node_pub_key,
                ))
            },
        )]
    }

    async fn await_fetch_contract(
        global_context: DynGlobalClientContext,
        contract_id: ContractId,
    ) -> Result<OutgoingContractAccount, GatewayPayError> {
        let account = global_context
            .module_api()
            .fetch_contract(contract_id)
            .await
            .map_err(|_| GatewayPayError::OutgoingContractDoesNotExist { contract_id })?;
        if let FundedContract::Outgoing(contract) = account.contract {
            return Ok(OutgoingContractAccount {
                amount: account.amount,
                contract,
            });
        }

        Err(GatewayPayError::OutgoingContractDoesNotExist { contract_id })
    }

    async fn transition_fetch_contract(
        global_context: DynGlobalClientContext,
        result: Result<OutgoingContractAccount, GatewayPayError>,
        common: GatewayPayCommon,
        timelock_delta: u64,
        node_pub_key: bitcoin::secp256k1::PublicKey,
    ) -> GatewayPayStateMachine {
        match result {
            Ok(contract) => {
                if let Ok(buy_preimage) = Self::validate_outgoing_account(
                    global_context,
                    &contract,
                    common.redeem_key,
                    timelock_delta,
                    node_pub_key,
                )
                .await
                {
                    return GatewayPayStateMachine {
                        common,
                        state: GatewayPayStates::BuyPreimage(buy_preimage),
                    };
                }

                GatewayPayStateMachine {
                    common,
                    state: GatewayPayStates::Cancel,
                }
            }
            Err(_) => GatewayPayStateMachine {
                common,
                state: GatewayPayStates::Canceled,
            },
        }
    }

    async fn validate_outgoing_account(
        global_context: DynGlobalClientContext,
        account: &OutgoingContractAccount,
        redeem_key: bitcoin::KeyPair,
        timelock_delta: u64,
        node_pub_key: bitcoin::secp256k1::PublicKey,
    ) -> Result<GatewayPayBuyPreimage, GatewayPayError> {
        let our_pub_key = secp256k1_zkp::XOnlyPublicKey::from_keypair(&redeem_key).0;

        if account.contract.cancelled {
            return Err(GatewayPayError::CancelledContract);
        }

        if account.contract.gateway_key != our_pub_key {
            return Err(GatewayPayError::NotOurKey);
        }

        let invoice = account.contract.invoice.clone();
        let invoice_amount = Amount::from_msats(
            invoice
                .amount_milli_satoshis()
                .ok_or(GatewayPayError::InvoiceMissingAmount)?,
        );

        if account.amount < invoice_amount {
            return Err(GatewayPayError::Underfunded(invoice_amount, account.amount));
        }

        let consensus_block_height = global_context
            .module_api()
            .fetch_consensus_block_height()
            .await
            .map_err(|_| GatewayPayError::TimeoutTooClose)?;

        if consensus_block_height.is_none() {
            return Err(GatewayPayError::TimeoutTooClose);
        }

        let max_delay = (account.contract.timelock as u64)
            .checked_sub(consensus_block_height.unwrap())
            .and_then(|delta| delta.checked_sub(timelock_delta));
        if max_delay.is_none() {
            return Err(GatewayPayError::TimeoutTooClose);
        }

        let route_hint_first_id = invoice
            .route_hints()
            .first()
            .and_then(|rh| rh.0.last())
            .map(|hop| hop.src_node_id);
        let is_internal = Some(node_pub_key) == route_hint_first_id;

        Ok(GatewayPayBuyPreimage {
            max_delay: max_delay.unwrap(),
            invoice_amount,
            max_send_amount: account.amount,
            payment_hash: *invoice.payment_hash(),
            is_internal,
        })
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct GatewayPayBuyPreimage {
    max_delay: u64,
    invoice_amount: Amount,
    max_send_amount: Amount,
    payment_hash: sha256::Hash,
    is_internal: bool,
}

impl GatewayPayBuyPreimage {
    fn transitions(&self) -> Vec<StateTransition<GatewayPayStateMachine>> {
        vec![]
    }

    async fn await_buy_preimage_over_lightning(
        invoice: lightning_invoice::Invoice,
    ) -> Result<Preimage, GatewayPayError> {
        todo!()
    }
}
