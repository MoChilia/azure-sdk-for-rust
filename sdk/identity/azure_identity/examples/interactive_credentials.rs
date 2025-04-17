use azure_core::{
    credentials::{Secret, TokenCredential},
    http::new_http_client,
};
use azure_identity::{
    interactive_credential::interactive_browser_credential::{
        InteractiveBrowserCredential, InteractiveBrowserCredentialOptions,
    },
    refresh_token,
};
use oauth2::{ClientId, TokenResponse};
use reqwest::Client;
use std::{error::Error, str::FromStr};
use url::Url;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let test_subscription_id = "6b085460-5f21-477e-ba44-1035046e9101".to_string();
    let test_tenant_id = "72f988bf-86f1-41af-91ab-2d7cd011db47".to_string();

    let _ = run_app_inter(test_subscription_id, test_tenant_id).await?;
    Ok(())
}

async fn run_app_inter(subscription_id: String, tenant_id: String) -> Result<(), Box<dyn Error>> {
    // Create InteractiveBrowserCredential with the new constructor
    let options = InteractiveBrowserCredentialOptions {
        tenant_id: Some(tenant_id.clone()),
        ..Default::default()
    };

    let interactive_credentials = InteractiveBrowserCredential::new(Some(options))?;

    // Correct the token request to use a slice of string slices
    let token_response = interactive_credentials
        .get_token(&["https://management.core.windows.net/.default"])
        .await?;

    let access_token_secret = token_response.access_token().secret();
    println!("Original access_token: {}", access_token_secret);

    // Store the refresh token if available
    if let Some(refresh_token) = token_response.refresh_token() {
        println!("Got refresh_token: {}", refresh_token.secret());

        // Save refresh token for later use
        let refresh_token_secret = Secret::new(refresh_token.secret().to_string());

        println!("\n--- Refreshing the token using refresh_token ---\n");

        // Use the refresh token to get a new access token silently (without browser prompt)
        let new_token_response = refresh_token::exchange(
            new_http_client(),
            &tenant_id,
            // Use the same client_id as in InteractiveBrowserCredential
            "04b07795-8ddb-461a-bbee-02f9e1bf7b46",
            None, // No client secret for public client
            &refresh_token_secret,
        )
        .await?;

        println!(
            "Refreshed access_token: {}",
            new_token_response.access_token().secret()
        );
        println!(
            "New refresh_token: {}",
            new_token_response.refresh_token().secret()
        );

        // Use the new access token
        let access_token_secret = new_token_response.access_token().secret();

        // Make API call with the refreshed token
        let url = Url::parse(&format!(
            "https://management.azure.com/subscriptions/{}/providers/Microsoft.Storage/storageAccounts?api-version=2019-06-01",
            subscription_id
        ))?;

        let resp = Client::new()
            .get(url)
            .header("Authorization", format!("Bearer {}", access_token_secret))
            .send()
            .await?
            .text()
            .await?;

        // Optionally print the response
        // println!("API response with refreshed token: {resp}");
    } else {
        println!("No refresh token was provided, cannot refresh access token");

        // Use original access token
        let url = Url::parse(&format!(
            "https://management.azure.com/subscriptions/{}/providers/Microsoft.Storage/storageAccounts?api-version=2019-06-01",
            subscription_id
        ))?;

        let resp = Client::new()
            .get(url)
            .header("Authorization", format!("Bearer {}", access_token_secret))
            .send()
            .await?
            .text()
            .await?;
    }

    Ok(())
}
