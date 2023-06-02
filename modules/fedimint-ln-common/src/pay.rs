//! # Internal Pay Module
//!
//! This shared pay state machine is used by clients
//! that want to pay other clients within the federation
//!
//! It's applied in two places:
//!   - `fedimint-ln-client` for internal payments without involving the gateway
//!   - `gateway` for receiving payments into the federation

use std::time::Duration;

use fedimint_client::sm::{ClientSMDatabaseTransaction, OperationId, State, StateTransition};
use fedimint_client::DynGlobalClientContext;
use fedimint_core::api::GlobalFederationApi;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::task::sleep;
use fedimint_core::{OutPoint, TransactionId};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::error;

use crate::api::LnFederationApi;
use crate::contracts::incoming::IncomingContractAccount;
use crate::contracts::{ContractId, DecryptedPreimage, Preimage};
use crate::{LightningClientContext, LightningOutputOutcome};

#[cfg_attr(doc, aquamarine::aquamarine)]
/// State machine that executes internal payment between two users
/// within a federation.
///
/// ```mermaid
/// graph LR
/// classDef virtual fill:#fff,stroke-dasharray: 5 5
///
///    FundingOffer -- funded incoming contract --> DecryptingPreimage
///    FundingOffer -- funding incoming contract failed --> FundingFailed
///    DecryptingPreimage -- successfully decrypted preimage --> Preimage
///    DecryptingPreimage -- invalid preimage --> RefundSubmitted
///    DecryptingPreimage -- error decrypting preimage --> Failure
/// ```
#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub enum InternalPayStates {
    FundingOffer(FundingOfferState),
    DecryptingPreimage(DecryptingPreimageState),
    Preimage(Preimage),
    RefundSubmitted(TransactionId),
    FundingFailed(String),
    Failure(String),
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct InternalPayCommon {
    pub operation_id: OperationId,
    pub contract_id: ContractId,
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct InternalPayStateMachine {
    pub common: InternalPayCommon,
    pub state: InternalPayStates,
}

impl State for InternalPayStateMachine {
    type ModuleContext = LightningClientContext;
    type GlobalContext = DynGlobalClientContext;

    fn transitions(
        &self,
        context: &Self::ModuleContext,
        global_context: &Self::GlobalContext,
    ) -> Vec<fedimint_client::sm::StateTransition<Self>> {
        match &self.state {
            InternalPayStates::FundingOffer(state) => state.transitions(global_context, context),
            InternalPayStates::DecryptingPreimage(state) => {
                state.transitions(&self.common, global_context, context)
            }
            _ => {
                vec![]
            }
        }
    }

    fn operation_id(&self) -> fedimint_client::sm::OperationId {
        self.common.operation_id
    }
}

#[derive(Error, Debug, Serialize, Deserialize, Encodable, Decodable, Clone, Eq, PartialEq)]
pub enum InternalPayError {
    #[error("Violated fee policy")]
    ViolatedFeePolicy,
    #[error("Invalid offer")]
    InvalidOffer,
    #[error("Timeout")]
    Timeout,
    #[error("Fetch contract error")]
    FetchContractError,
    #[error("Incoming contract error")]
    IncomingContractError,
    #[error("Invalid preimage")]
    InvalidPreimage(Box<IncomingContractAccount>),
    #[error("Output outcome error")]
    OutputOutcomeError,
    #[error("Incoming contract not found")]
    IncomingContractNotFound,
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct FundingOfferState {
    pub txid: TransactionId,
}

impl FundingOfferState {
    fn transitions(
        &self,
        global_context: &DynGlobalClientContext,
        context: &LightningClientContext,
    ) -> Vec<StateTransition<InternalPayStateMachine>> {
        let txid = self.txid;
        vec![StateTransition::new(
            Self::await_funding_success(
                global_context.clone(),
                OutPoint { txid, out_idx: 0 },
                context.clone(),
            ),
            move |_dbtx, result, old_state| {
                Box::pin(Self::transition_funding_success(result, old_state))
            },
        )]
    }

    async fn await_funding_success(
        global_context: DynGlobalClientContext,
        out_point: OutPoint,
        context: LightningClientContext,
    ) -> Result<(), InternalPayError> {
        global_context
            .api()
            .await_output_outcome::<LightningOutputOutcome>(
                out_point,
                Duration::from_millis(i32::MAX as u64),
                &context.ln_decoder,
            )
            .await
            .map_err(|_| InternalPayError::OutputOutcomeError)?;
        Ok(())
    }

    async fn transition_funding_success(
        result: Result<(), InternalPayError>,
        old_state: InternalPayStateMachine,
    ) -> InternalPayStateMachine {
        let txid = match old_state.state {
            InternalPayStates::FundingOffer(refund) => refund.txid,
            _ => panic!("Invalid state transition"),
        };

        match result {
            Ok(_) => InternalPayStateMachine {
                common: old_state.common,
                state: InternalPayStates::DecryptingPreimage(DecryptingPreimageState { txid }),
            },
            Err(e) => InternalPayStateMachine {
                common: old_state.common,
                state: InternalPayStates::FundingFailed(e.to_string()),
            },
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct DecryptingPreimageState {
    txid: TransactionId,
}

impl DecryptingPreimageState {
    fn transitions(
        &self,
        common: &InternalPayCommon,
        global_context: &DynGlobalClientContext,
        context: &LightningClientContext,
    ) -> Vec<StateTransition<InternalPayStateMachine>> {
        let success_context = global_context.clone();
        let gateway_context = context.clone();

        vec![StateTransition::new(
            Self::await_preimage_decryption(success_context.clone(), common.contract_id),
            move |dbtx, result, old_state| {
                let gateway_context = gateway_context.clone();
                let success_context = success_context.clone();
                Box::pin(Self::transition_incoming_contract_funded(
                    result,
                    old_state,
                    dbtx,
                    success_context,
                    gateway_context,
                ))
            },
        )]
    }

    async fn await_preimage_decryption(
        global_context: DynGlobalClientContext,
        contract_id: ContractId,
    ) -> Result<Preimage, InternalPayError> {
        // TODO: Get rid of polling
        let preimage = loop {
            let contract = global_context
                .module_api()
                .get_incoming_contract(contract_id)
                .await;

            match contract {
                Ok(contract) => match contract.contract.decrypted_preimage {
                    DecryptedPreimage::Pending => {}
                    DecryptedPreimage::Some(preimage) => break preimage,
                    DecryptedPreimage::Invalid => {
                        return Err(InternalPayError::InvalidPreimage(Box::new(contract)));
                    }
                },
                Err(e) => {
                    error!("Failed to fetch contract {e:?}");
                }
            }

            sleep(Duration::from_secs(1)).await;
        };

        Ok(preimage)
    }

    async fn transition_incoming_contract_funded(
        result: Result<Preimage, InternalPayError>,
        old_state: InternalPayStateMachine,
        dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        global_context: DynGlobalClientContext,
        context: LightningClientContext,
    ) -> InternalPayStateMachine {
        assert!(matches!(
            old_state.state,
            InternalPayStates::DecryptingPreimage(_)
        ));

        match result {
            Ok(preimage) => InternalPayStateMachine {
                common: old_state.common,
                state: InternalPayStates::Preimage(preimage),
            },
            Err(InternalPayError::InvalidPreimage(contract)) => {
                Self::refund_incoming_contract(dbtx, global_context, context, old_state, contract)
                    .await
            }
            Err(e) => InternalPayStateMachine {
                common: old_state.common,
                state: InternalPayStates::Failure(format!(
                    "Unexpected internal error occured while decrypting the preimage: {e:?}"
                )),
            },
        }
    }

    async fn refund_incoming_contract(
        _dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        _global_context: DynGlobalClientContext,
        _context: LightningClientContext,
        _old_state: InternalPayStateMachine,
        _contract: Box<IncomingContractAccount>,
    ) -> InternalPayStateMachine {
        // TODO: Create a generic client input based on context of sm application
        unimplemented!()

        // let claim_input = contract.claim();
        // let client_input = ClientInput::<LightningInput,
        // GatewayClientStateMachines> {     input: claim_input,
        //     state_machines: Arc::new(|_, _| vec![]),
        //     keys: vec![context.redeem_key],
        // };

        // let (refund_txid, _) = global_context.claim_input(dbtx,
        // client_input).await;

        // InternalPayStateMachine {
        //     common: old_state.common,
        //     state: InternalPayStates::RefundSubmitted(refund_txid),
        // }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct AwaitingPreimageDecryption {
    txid: TransactionId,
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct PreimageState {
    preimage: Preimage,
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct RefundSuccessState {
    refund_txid: TransactionId,
}
