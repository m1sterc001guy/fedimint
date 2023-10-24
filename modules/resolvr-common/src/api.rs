use fedimint_core::api::{FederationApiExt, FederationResult, IModuleFederationApi};
use fedimint_core::module::{ApiAuth, ApiRequestErased};
use fedimint_core::task::{MaybeSend, MaybeSync};
use fedimint_core::{apply, async_trait_maybe_send};

use crate::UnsignedEvent;

#[apply(async_trait_maybe_send!)]
pub trait ResolvrFederationApi {
    async fn request_sign_event(
        &self,
        unsigned_event: UnsignedEvent,
        auth: ApiAuth,
    ) -> FederationResult<()>;
    async fn get_npub(&self) -> FederationResult<nostr_sdk::key::XOnlyPublicKey>;
}

#[apply(async_trait_maybe_send!)]
impl<T: ?Sized> ResolvrFederationApi for T
where
    T: IModuleFederationApi + MaybeSend + MaybeSync + 'static,
{
    async fn request_sign_event(
        &self,
        unsigned_event: UnsignedEvent,
        auth: ApiAuth,
    ) -> FederationResult<()> {
        self.request_current_consensus(
            "sign_event".to_string(),
            ApiRequestErased::new(unsigned_event).with_auth(auth),
        )
        .await
    }

    async fn get_npub(&self) -> FederationResult<nostr_sdk::key::XOnlyPublicKey> {
        self.request_current_consensus("npub".to_string(), ApiRequestErased::default())
            .await
    }
}
