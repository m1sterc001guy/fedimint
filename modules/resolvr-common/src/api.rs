use fedimint_core::api::{FederationApiExt, FederationResult, IModuleFederationApi};
use fedimint_core::module::ApiRequestErased;
use fedimint_core::task::{MaybeSend, MaybeSync};
use fedimint_core::{apply, async_trait_maybe_send};

#[apply(async_trait_maybe_send!)]
pub trait ResolvrFederationApi {
    async fn request_sign_message(&self, msg: String) -> FederationResult<()>;
}

#[apply(async_trait_maybe_send!)]
impl<T: ?Sized> ResolvrFederationApi for T
where
    T: IModuleFederationApi + MaybeSend + MaybeSync + 'static,
{
    async fn request_sign_message(&self, msg: String) -> FederationResult<()> {
        self.request_current_consensus("sign_message".to_string(), ApiRequestErased::new(msg))
            .await
    }
}
