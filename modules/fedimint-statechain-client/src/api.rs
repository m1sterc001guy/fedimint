use std::collections::BTreeMap;

use fedimint_api_client::api::{DynModuleApi, FederationApiExt, FederationResult, ServerResult};
use fedimint_core::module::ApiRequestErased;
use fedimint_core::{PeerId, apply, async_trait_maybe_send};
use fedimint_statechain_common::endpoint_constants::{
    BLOCK_COUNT_ENDPOINT, COIN_ENDPOINT, EPHEMERAL_KEYS_ENDPOINT, INCOMING_ENDPOINT,
    NONCE_ENDPOINT, SIGN_ENDPOINT,
};
use fedimint_statechain_common::{
    CoinId, CoinRecord, NonceRequest, PublicNonce, ScalarBytes, SignRequest,
};
use secp256k1::PublicKey;

#[apply(async_trait_maybe_send!)]
pub trait StatechainFederationApi {
    async fn block_count(&self) -> FederationResult<u64>;

    async fn coin(&self, coin: CoinId) -> FederationResult<Option<CoinRecord>>;

    async fn ephemeral_keys(&self, coin: CoinId) -> FederationResult<BTreeMap<PeerId, PublicKey>>;

    async fn incoming(&self, receiver: PublicKey) -> FederationResult<Vec<CoinId>>;

    async fn nonce(&self, peer: PeerId, request: NonceRequest) -> ServerResult<PublicNonce>;

    async fn sign(&self, peer: PeerId, request: SignRequest) -> ServerResult<ScalarBytes>;
}

#[apply(async_trait_maybe_send!)]
impl StatechainFederationApi for DynModuleApi {
    async fn block_count(&self) -> FederationResult<u64> {
        self.request_current_consensus(BLOCK_COUNT_ENDPOINT.to_string(), ApiRequestErased::new(()))
            .await
    }

    async fn coin(&self, coin: CoinId) -> FederationResult<Option<CoinRecord>> {
        self.request_current_consensus(COIN_ENDPOINT.to_string(), ApiRequestErased::new(coin))
            .await
    }

    async fn ephemeral_keys(&self, coin: CoinId) -> FederationResult<BTreeMap<PeerId, PublicKey>> {
        self.request_current_consensus(
            EPHEMERAL_KEYS_ENDPOINT.to_string(),
            ApiRequestErased::new(coin),
        )
        .await
    }

    async fn incoming(&self, receiver: PublicKey) -> FederationResult<Vec<CoinId>> {
        self.request_current_consensus(
            INCOMING_ENDPOINT.to_string(),
            ApiRequestErased::new(receiver),
        )
        .await
    }

    async fn nonce(&self, peer: PeerId, request: NonceRequest) -> ServerResult<PublicNonce> {
        self.request_single_peer(
            NONCE_ENDPOINT.to_string(),
            ApiRequestErased::new(request),
            peer,
        )
        .await
    }

    async fn sign(&self, peer: PeerId, request: SignRequest) -> ServerResult<ScalarBytes> {
        self.request_single_peer(
            SIGN_ENDPOINT.to_string(),
            ApiRequestErased::new(request),
            peer,
        )
        .await
    }
}
