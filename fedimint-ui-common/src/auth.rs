use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::response::Redirect;
use axum_extra::extract::CookieJar;
use fedimint_core::net::auth::GuardianAuthToken;

use crate::{LOGIN_ROUTE, UiRole, UiState};

/// Extractor that validates user authentication and provides role information
pub struct UserAuth {
    /// UserAuth is an axum extractor guaranteeing when the admin password was
    /// verified. This implies we can grant logic holding it access to
    /// fedimint-core internals that require `GuardianAuthToken`, which is a
    /// very similar mechanism.
    pub guardian_auth_token: GuardianAuthToken,
    /// The authenticated user's role (Admin or User)
    pub role: UiRole,
}

impl UserAuth {
    fn authenticated(role: UiRole) -> Self {
        Self {
            guardian_auth_token: GuardianAuthToken::new_unchecked(),
            role,
        }
    }

    /// Returns true if the user has Admin role
    pub fn is_admin(&self) -> bool {
        self.role == UiRole::Admin
    }
}

impl<Api> FromRequestParts<UiState<Api>> for UserAuth
where
    Api: Send + Sync + 'static,
{
    type Rejection = Redirect;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &UiState<Api>,
    ) -> Result<Self, Self::Rejection> {
        let jar = CookieJar::from_request_parts(parts, state)
            .await
            .map_err(|_| Redirect::to(LOGIN_ROUTE))?;

        // Check admin cookie first
        if let Some(cookie) = jar.get(&state.admin_cookie_name) {
            if cookie.value() == state.admin_cookie_value {
                return Ok(UserAuth::authenticated(UiRole::Admin));
            }
        }

        // Check user cookie if user role is enabled
        if let (Some(user_cookie_name), Some(user_cookie_value)) =
            (&state.user_cookie_name, &state.user_cookie_value)
        {
            if let Some(cookie) = jar.get(user_cookie_name) {
                if cookie.value() == user_cookie_value {
                    return Ok(UserAuth::authenticated(UiRole::User));
                }
            }
        }

        Err(Redirect::to(LOGIN_ROUTE))
    }
}
