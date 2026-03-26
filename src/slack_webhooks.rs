use anyhow::Result;

use serde::Deserialize;
use thiserror::Error;

use crate::found_secrets::SecretCheck;

#[derive(Debug, PartialEq, Eq, Clone, Deserialize)]
pub struct SlackWebhook {
    url: String,
}

impl SecretCheck for SlackWebhook {
    async fn check_secret(&self) -> Result<()> {
        let client = reqwest::Client::new();
        let result = client
            .post(&self.url)
            .header("content-type", "application/json")
            .body("{}")
            .send()
            .await?;
        let status = result.status().as_u16();
        dbg!(status);
        match status {
            404 => anyhow::bail!(
                "channel_not_found - the channel associated with your request does not exist."
            ),
            _ => Ok(()),
        }
    }
}

#[derive(Error, Debug)]
#[error("{msg}")]
pub struct ParseError {
    msg: String,
}

impl TryFrom<&str> for SlackWebhook {
    type Error = ParseError;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        Ok(SlackWebhook { url: value.into() })
    }
}
