use anyhow::Result;
use serde::Deserialize;

use crate::{
    azure::AzureCreds,
    azure_storage::AzureStorageSecret,
    ms_sql_server::MsSqlServerSecret,
    slack_webhooks::SlackWebhook,
    truffle_hog::{TruffleHog, TruffleHogReports},
    uri::Uri,
};

#[derive(Debug, Clone, Deserialize)]
pub enum SecretCreds {
    Azure(AzureCreds),
    AzureStorage(AzureStorageSecret),
    MsSqlServer(MsSqlServerSecret),
    SlackWebhook(SlackWebhook),
    Uri(Uri),
}

impl SecretCreds {
    pub async fn check_secret(&self) -> Result<()> {
        match self {
            SecretCreds::Azure(foundsecret) => foundsecret.check_secret().await,
            SecretCreds::AzureStorage(foundsecret) => foundsecret.check_secret().await,
            SecretCreds::MsSqlServer(foundsecret) => foundsecret.check_secret().await,
            SecretCreds::SlackWebhook(foundsecret) => foundsecret.check_secret().await,
            SecretCreds::Uri(foundsecret) => foundsecret.check_secret().await,
        }
    }
    pub fn false_positive(&self) -> isize {
        match self {
            SecretCreds::Azure(foundsecret) => foundsecret.false_positive(),
            SecretCreds::AzureStorage(foundsecret) => foundsecret.false_positive(),
            SecretCreds::MsSqlServer(foundsecret) => foundsecret.false_positive(),
            SecretCreds::SlackWebhook(foundsecret) => foundsecret.false_positive(),
            SecretCreds::Uri(foundsecret) => foundsecret.false_positive(),
        }
    }
}

//pub trait SecretCheck: TryFrom<TruffleHog> {
pub trait SecretCheck {
    async fn check_secret(&self) -> Result<()>;
    /// Return a value representing how likely this secret is to be a false positive
    /// 0 is likely to be a valid secret
    /// 100 is very likely to be a false positive
    /// This should not go over the network and should be based on static analysis of the secret data
    fn false_positive(&self) -> isize {
        0
    }
}
