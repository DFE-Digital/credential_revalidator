use anyhow::Result;
use serde::{Deserialize, Serialize};
use tracing::trace;

use crate::{AzureCredentialArgs, found_secrets::SecretCheck};

#[derive(Debug, Deserialize, Clone)]
pub struct AzureCreds {
    #[serde(alias = "clientId")]
    client_id: String,
    #[serde(alias = "clientSecret")]
    client_secret: String,
    #[serde(alias = "tenantId")]
    tenant_id: String,
}

impl From<AzureCredentialArgs> for AzureCreds {
    fn from(value: AzureCredentialArgs) -> Self {
        Self {
            client_id: value.client_id,
            client_secret: value.client_secret,
            tenant_id: value.tenant_id,
        }
    }
}

impl SecretCheck for AzureCreds {
    async fn check_secret(&self) -> Result<()> {
        let url = format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
            self.tenant_id
        );

        let client = reqwest::Client::new();
        let form = AzureOauthForm::from(self);
        let response = client
            .post(url)
            .form(&form)
            .header("accept", "application/json")
            .header("content-type", "application/x-www-form-urlencoded")
            .header("user-agent", "Something")
            .send()
            .await?;
        trace!("response: {:#?}", &response);
        trace!("response HTTP status code: {}", &response.status());
        let body = response.text().await.unwrap();
        trace!("response body: {:#?}", &body);
        match serde_json::from_str::<AzureOauthResponse>(&body) {
            Ok(AzureOauthResponse::AccessToken(_token)) => Ok(()),
            Ok(AzureOauthResponse::Error(error)) => anyhow::bail!("{:?}", error),
            _ => anyhow::bail!("unable to parse oauth response"),
        }
    }
}

#[derive(Serialize)]
struct AzureOauthForm {
    client_id: String,
    client_secret: String,
    grant_type: String,
    scope: String,
    tenant: String,
}

impl From<&AzureCreds> for AzureOauthForm {
    fn from(value: &AzureCreds) -> Self {
        Self {
            grant_type: "client_credentials".to_string(),
            tenant: value.tenant_id.to_string(),
            client_id: value.client_id.to_string(),
            client_secret: value.client_secret.to_string(),
            scope: "https://graph.microsoft.com/.default".to_string(),
        }
    }
}

#[derive(Deserialize, Debug)]
#[serde(untagged)]
enum AzureOauthResponse {
    AccessToken(AzureOauthResponseAccessToken),
    Error(AzureOauthError),
}

#[derive(Deserialize, Debug)]
struct AzureOauthResponseAccessToken {
    token_type: String,
    expires_in: u32,
    access_token: String,
}

#[derive(Deserialize, Debug)]
struct AzureOauthError {
    error: String,
    error_description: String,
    error_codes: Vec<usize>,
    timestamp: String,
    trace_id: String,
    correlation_id: String,
    error_uri: String,
}

#[tokio::test]
async fn test_check_azure_creds() {
    let expired_creds = AzureCreds {
        client_id: "foo".into(),
        client_secret: "bar".into(),
        tenant_id: "baz".into(),
    };

    assert!(expired_creds.check_secret().await.is_err());

    let creds = AzureCreds {
        client_id: "foo".into(),
        client_secret: "bar".into(),
        tenant_id: "baz".into(),
    };

    assert!(creds.check_secret().await.is_ok());
}
