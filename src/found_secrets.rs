use anyhow::Result;
use serde::Deserialize;

use crate::{
    azure_storage::AzureStorageSecret, ms_sql_server::MsSqlServerSecret,
    slack_webhooks::SlackWebhook,
};

// #[derive(Debug, Clone, Deserialize)]
// #[serde(transparent)]
// pub(crate) struct FoundSecrets {
//     inner: Vec<FoundSecret>,
// }

// impl FoundSecrets {
//     pub fn confirmed(self) -> FoundSecretsConfirmed {
//         self.inner
//             .into_iter()
//             .filter_map(|fs| fs.into_confirmed())
//             .collect()
//     }
// }

// #[derive(Debug, Clone, Deserialize)]
// struct FoundSecret {
//     pub detector_name: String,
//     link: String,
//     file: String,
//     commit: String,
//     secret: Option<String>,
// }

// impl FoundSecret {
//     fn into_confirmed(self) -> Option<FoundSecretConfirmed> {
//         if let Some(secret) = self.secret {
//             let secret = match self.detector_name.as_str() {
//                 "AzureStorage" => {
//                     let secret = AzureStorageSecret::try_from(secret.as_str()).ok()?;
//                     SecretCreds::AzureStorage(secret)
//                 }
//                 "SQLServer" => {
//                     let secret = MsSqlServerSecret::try_from(secret.as_str()).ok()?;
//                     SecretCreds::MsSqlServer(secret)
//                 }
//                 "SlackWebhook" => {
//                     let secret = SlackWebhook::try_from(secret.as_str()).ok()?;
//                     SecretCreds::SlackWebhook(secret)
//                 }
//                 _ => todo!("Unsupported secret type"),
//             };
//             Some(FoundSecretConfirmed {
//                 detector_name: self.detector_name,
//                 link: self.link,
//                 file: self.file,
//                 commit: self.commit,
//                 secret,
//             })
//         } else {
//             None
//         }
//     }
// }

// #[derive(Debug, Clone, Deserialize)]
// #[serde(transparent)]
// pub struct FoundSecretsConfirmed {
//     pub inner: Vec<FoundSecretConfirmed>,
// }

// impl FromIterator<FoundSecretConfirmed> for FoundSecretsConfirmed {
//     fn from_iter<I: IntoIterator<Item = FoundSecretConfirmed>>(iter: I) -> Self {
//         let mut inner = Vec::new();

//         for i in iter {
//             inner.push(i);
//         }

//         FoundSecretsConfirmed { inner }
//     }
// }

// impl FromIterator<Option<FoundSecretConfirmed>> for FoundSecretsConfirmed {
//     fn from_iter<I: IntoIterator<Item = Option<FoundSecretConfirmed>>>(iter: I) -> Self {
//         let mut inner = Vec::new();

//         for i in iter.into_iter().flatten() {
//             inner.push(i);
//         }

//         FoundSecretsConfirmed { inner }
//     }
// }

// #[derive(Debug, Clone, Deserialize)]
// pub struct FoundSecretConfirmed {
//     pub detector_name: String,
//     link: String,
//     file: String,
//     commit: String,
//     secret: SecretCreds,
// }

// impl FoundSecretConfirmed {
//     pub async fn check_secret(&self) -> SecretReportSplunk {
//         let result = self.secret.check_secret().await;
//         SecretReportSplunk {
//             datetime: chrono::Utc::now().to_rfc3339(),
//             detector_name: self.detector_name.to_string(),
//             link: self.link.to_string(),
//             file: Some(self.file.to_string()),
//             commit: self.commit.to_string(),
//             valid: result.is_ok(),
//             valid_from_trufflehog: todo!(),
//             valid_now: todo!(),
//             repo_public: todo!(),
//             repo_archived: todo!(),
//             repo_owner: todo!(),
//             repo_name: todo!(),
//         }
//     }
// }

#[derive(Debug, Clone, Deserialize)]
pub enum SecretCreds {
    AzureStorage(AzureStorageSecret),
    MsSqlServer(MsSqlServerSecret),
    SlackWebhook(SlackWebhook),
}

impl SecretCreds {
    pub async fn check_secret(&self) -> Result<()> {
        match self {
            SecretCreds::AzureStorage(foundsecret) => foundsecret.check_secret().await,
            SecretCreds::MsSqlServer(foundsecret) => foundsecret.check_secret().await,
            SecretCreds::SlackWebhook(foundsecret) => foundsecret.check_secret().await,
        }
    }
}

pub trait SecretCheck {
    async fn check_secret(&self) -> Result<()>;
}
