use super::internal_server::*;
use crate::authorization_code_flow;
use crate::credentials::cache::TokenCache;
use crate::TokenCredentialOptions;
use azure_core::{
    credentials::{AccessToken, TokenCredential},
    error::ErrorKind,
    http::{new_http_client, Url},
    Error,
};
use oauth2::{
    basic::BasicTokenType, AuthorizationCode, ClientId, EmptyExtraTokenFields,
    StandardTokenResponse, TokenResponse,
};
use std::time::Duration;
use std::{str::FromStr, sync::Arc};
use time::OffsetDateTime;


/// Default OAuth scopes used when none are provided.
#[allow(dead_code)]
const DEFAULT_SCOPE_ARR: [&str; 3] = ["openid", "offline_access", "profile"];
/// Default client ID for interactive browser authentication.
#[allow(dead_code)]
const DEFAULT_DEVELOPER_SIGNON_CLIENT_ID: &str = "04b07795-8ddb-461a-bbee-02f9e1bf7b46";
/// Default tenant ID used when none is specified.
#[allow(dead_code)]
const DEFAULT_ORGANIZATIONS_TENANT_ID: &str = "organizations";


/// Options for constructing a new [`InteractiveBrowserCredential`].
#[derive(Debug)]
pub struct InteractiveBrowserCredentialOptions {
    /// The client ID to use for authentication.
    /// Defaults to Microsoft's public developer sign-on if not specified.
    pub client_id: Option<ClientId>,
    /// The tenant ID to use for authentication.
    /// Defaults to "organizations" if not specified.
    pub tenant_id: Option<String>,
    /// The redirect URL to use for authentication.
    /// Defaults to http://localhost:<LOCAL_SERVER_PORT> if not specified.
    pub redirect_url: Option<Url>,
    /// Prompt behavior for the authentication request.
    /// Possible values include "login", "none", "consent", and "select_account".
    /// Defaults to "select_account" if not specified.
    pub prompt: Option<String>,
    /// Additional tenants for which the credential may acquire tokens.
    /// Add the wildcard value "*" to allow the credential to acquire tokens for any tenant.
    pub additionally_allowed_tenants: Vec<String>,
    /// Options for the token credential.
    pub credential_options: TokenCredentialOptions,
}

impl Default for InteractiveBrowserCredentialOptions {
    fn default() -> Self {
        Self {
            client_id: None,
            tenant_id: None,
            redirect_url: None,
            prompt: Some("select_account".to_string()),
            additionally_allowed_tenants: Vec::new(),
            credential_options: TokenCredentialOptions::default(),
        }
    }
}
/// Provides interactive browser-based authentication.
#[derive(Debug)]
pub struct InteractiveBrowserCredential {
    /// Client ID of the application.
    client_id: ClientId,
    /// Tenant ID for the authentication request.
    tenant_id: String,
    /// Redirect URI where the authentication response is sent.
    redirect_url: Url,
    /// Prompt behavior for the authentication request.
    prompt: Option<String>,
    cache: TokenCache,
    /// Additional options for the credential.
    options: InteractiveBrowserCredentialOptions,
}

impl InteractiveBrowserCredential {
    /// Creates a new `InteractiveBrowserCredential` instance with optional parameters.
    pub fn new(
        options: Option<InteractiveBrowserCredentialOptions>,
    ) -> azure_core::Result<Arc<Self>> {
        let options = options.unwrap_or_default();
        let client_id = options
            .client_id
            .clone()
            .unwrap_or_else(|| ClientId::new(DEFAULT_DEVELOPER_SIGNON_CLIENT_ID.to_owned()));
        let tenant_id = options
            .tenant_id
            .clone()
            .unwrap_or_else(|| DEFAULT_ORGANIZATIONS_TENANT_ID.to_owned());
        let redirect_url = options.redirect_url.clone().unwrap_or_else(|| {
            Url::from_str(&format!("http://localhost:{}", LOCAL_SERVER_PORT))
                .expect("Failed to parse redirect URL")
        });
        Ok(Arc::new(Self {
            client_id,
            tenant_id,
            redirect_url,
            prompt: options.prompt.clone(),
            cache: TokenCache::new(),
            options,
        }))
    }
    // For backward compatibility
    pub fn new_with_params(
        client_id: Option<ClientId>,
        tenant_id: Option<String>,
        redirect_url: Option<Url>,
    ) -> azure_core::Result<Arc<Self>> {
        let options = InteractiveBrowserCredentialOptions {
            client_id,
            tenant_id,
            redirect_url,
            ..Default::default()
        };
        Self::new(Some(options))
    }
    /// Implement the token acquisition logic as a private method
    async fn get_token(&self, scopes: &[&str]) -> azure_core::Result<AccessToken> {
        let mut combined_scopes = DEFAULT_SCOPE_ARR.to_vec();
        if let Some(user_scopes) = Some(scopes) {
            for &scope in user_scopes {
                if !combined_scopes.contains(&scope) {
                    combined_scopes.push(scope);
                }
            }
        }
        println!("Initiating device login...");
        println!("A web browser will open for you to authenticate.");
        let authorization_code_flow = authorization_code_flow::authorize(
            self.client_id.clone(),
            None,
            &self.tenant_id,
            self.redirect_url.clone(),
            &combined_scopes,
            self.prompt.as_deref(),
        );
        println!(
            "Waiting for authentication in browser. If the browser doesn't open automatically, please go to: {}", 
            authorization_code_flow.authorize_url.as_ref()
        );
        let auth_code = open_url(authorization_code_flow.authorize_url.as_ref()).await;
        match auth_code {
            Some(code) => {
                let token_response = authorization_code_flow
                    .exchange(new_http_client(), AuthorizationCode::new(code))
                    .await?;
                // Convert the token response to an AccessToken
                let std_duration = Duration::from_secs(token_response.expires_in().map(|d| d.as_secs()).unwrap_or(3600));
                let time_duration = time::Duration::seconds(std_duration.as_secs() as i64);
                let access_token = AccessToken::new(
                    azure_core::credentials::Secret::new(
                        token_response.access_token().secret().to_string(),
                    ),
                    OffsetDateTime::now_utc() + time_duration,
                );
                Ok(access_token)
            }
            None => Err(Error::message(
                ErrorKind::Other,
                "Failed to retrieve authorization code.",
            )),
        }
    }
}

// Implement the TokenCredential trait to support the common pattern
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl TokenCredential for InteractiveBrowserCredential {
    async fn get_token(&self, scopes: &[&str]) -> azure_core::Result<AccessToken> {
        self.cache
            .get_token(scopes, Box::pin(async move { self.get_token(scopes).await }))
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing::debug;
    use tracing::Level;
    use tracing_subscriber;
    static INIT: std::sync::Once = std::sync::Once::new();
    fn init_tracing() {
        INIT.call_once(|| {
            tracing_subscriber::fmt()
                .with_max_level(Level::DEBUG)
                .init();
        });
    }
    #[tokio::test]
    async fn interactive_auth_flow_should_return_token() {
        init_tracing();
        debug!("Starting interactive authentication test");
        let credential =
            InteractiveBrowserCredential::new(None).expect("Failed to create credential");
        let token_response = credential.get_token(&[]).await;
        debug!("Authentication result: {:#?}", token_response);
        assert!(token_response.is_ok());
    }
}
