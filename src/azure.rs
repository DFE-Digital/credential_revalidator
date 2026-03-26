use anyhow::Result;
use serde::{Deserialize, Serialize};

pub struct AzureCreds {
    client_id: String,
    client_secret: String,
    tenant: String,
}

#[derive(Serialize)]
struct AzureOauthForm {
    client_id: String,
    client_secret: String,
    grant_type: String,
    scope: String,
    tenant: String,
}

impl From<AzureCreds> for AzureOauthForm {
    fn from(value: AzureCreds) -> Self {
        Self {
            grant_type: "client_credentials".into(),
            tenant: value.tenant,
            client_id: value.client_id,
            client_secret: value.client_secret,
            scope: "https://graph.microsoft.com/.default".into(),
        }
    }
}

async fn check_azure_creds(azure_creds: AzureCreds) -> Result<()> {
    let url = format!(
        "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
        azure_creds.tenant
    );

    let client = reqwest::Client::new();
    let form = AzureOauthForm::from(azure_creds);
    let response = client
        .post(url)
        .form(&form)
        .header("accept", "application/json")
        .header("content-type", "application/x-www-form-urlencoded")
        .header("user-agent", "Something")
        .send()
        .await?;
    dbg!(&response);
    dbg!(&response.status());
    let body = response.text().await.unwrap();
    dbg!(&body);
    match serde_json::from_str::<AzureOauthResponse>(&body) {
        Ok(AzureOauthResponse::AccessToken(_token)) => Ok(()),
        Ok(AzureOauthResponse::Error(error)) => anyhow::bail!("{:?}", error),
        _ => anyhow::bail!("unable to parse oauth response"),
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
        tenant: "baz".into(),
    };

    assert!(check_azure_creds(expired_creds).await.is_err());

    let creds = AzureCreds {
        client_id: "foo".into(),
        client_secret: "bar".into(),
        tenant: "baz".into(),
    };

    assert!(check_azure_creds(creds).await.is_ok());
}
