use std::{borrow::Cow, collections::HashMap, sync::Arc};

use crate::{found_secrets::SecretCheck, truffle_hog::TrufflehogRawV2AzureStorage};
use anyhow::Result;
use async_trait::async_trait;
use azure_core::{
    credentials::Secret, error::ErrorKind, http::{
        ClientOptions, Method, RetryOptions,
        headers::{CONTENT_LENGTH, HeaderName, Headers},
        policies::{Policy, PolicyResult},
    }
};
use azure_storage_blob::{BlobServiceClient, BlobServiceClientOptions};
use base64::{Engine, prelude::BASE64_STANDARD};
use futures::StreamExt;
use hmac::{Hmac, Mac};
use reqwest::Url;
use serde::Deserialize;
use serde_json::Value;
use sha2::Sha256;
use thiserror::Error;
use tracing::{debug, trace};
use typespec_client_core::http::{Context, Request};

#[derive(Debug, PartialEq, Eq, Clone, Deserialize)]
pub struct AzureStorageSecret {
    default_endpoints_protocol: Option<String>,
    account_name: String,
    account_key: String,
    endpoint_suffix: Option<String>,
}

impl SecretCheck for AzureStorageSecret {
    async fn check_secret(&self) -> Result<()> {
        let client =
            blob_client(self.account_name.to_string(), self.account_key.to_string()).await?;
        let mut containers = client.list_containers(None)?;
        let mut count = 0;
        while let Some(Ok(container)) = containers.next().await {
            dbg!(container);
            count += 1;
        }

        debug!("countainer count: {}", &count);
        //assert!(count > 0);
        if count > 0 {
            Ok(())
        } else {
            anyhow::bail!("No containers listed,");
        }
    }
}

#[derive(Error, Debug)]
#[error("{msg}")]
pub struct ParseError {
    msg: String,
}

impl From<TrufflehogRawV2AzureStorage> for AzureStorageSecret {
    fn from(value: TrufflehogRawV2AzureStorage) -> Self {
        AzureStorageSecret {
            default_endpoints_protocol: None,
            account_name: value.account_name,
            account_key: value.account_key,
            endpoint_suffix: None,
        }
    }
}

impl TryFrom<Value> for AzureStorageSecret {
    type Error = serde_json::Error;

    fn try_from(value: Value) -> std::result::Result<Self, Self::Error> {
        serde_json::from_value(value)
    }
}

impl TryFrom<&str> for AzureStorageSecret {
    type Error = ParseError;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        let mut map = HashMap::new();
        let parts = value.split(";");
        for p in parts {
            let k_v = p.split_once("=");
            if let Some((k, v)) = k_v {
                map.insert(k, v);
            }
        }
        let default_endpoints_protocol = map.get("DefaultEndpointsProtocol").map(|s| s.to_string());
        let account_name = map
            .get("AccountName")
            .map(|s| s.to_string())
            .ok_or(ParseError {
                msg: "No Storage Account Name".into(),
            })?;
        let account_key = map
            .get("AccountKey")
            .map(|s| s.to_string())
            .ok_or(ParseError {
                msg: "No Storage account key".into(),
            })?;
        let endpoint_suffix = map.get("EndpointSuffix").map(|s| s.to_string());
        Ok(AzureStorageSecret {
            default_endpoints_protocol,
            account_name,
            account_key,
            endpoint_suffix,
        })
    }
}

#[test]
fn test_azure_storage_secret_try_from_string() {
    let test_s = "DefaultEndpointsProtocol=https;AccountName=foo;AccountKey=fookey==;EndpointSuffix=core.windows.net";
    let result = AzureStorageSecret::try_from(test_s).unwrap();
    let expected = AzureStorageSecret {
        default_endpoints_protocol: Some("https".into()),
        account_name: "foo".into(),
        account_key: "fookey==".into(),
        endpoint_suffix: Some("core.windows.net".into()),
    };
    assert_eq!(result, expected);
}

fn lexy_sort<'a>(
    vec: impl Iterator<Item = (Cow<'a, str>, Cow<'a, str>)> + 'a,
    query_param: &str,
) -> Vec<Cow<'a, str>> {
    let mut values = vec
        .filter(|(k, _)| *k == query_param)
        .map(|(_, v)| v)
        .collect::<Vec<_>>();
    values.sort_unstable();
    values
}

fn canonicalized_resource(account: &str, uri: &Url) -> String {
    let mut can_res: String = String::new();
    can_res += "/";
    can_res += account;

    for p in uri.path_segments().into_iter().flatten() {
        can_res.push('/');
        can_res.push_str(p);
    }
    can_res += "\n";

    // query parameters
    let query_pairs = uri.query_pairs();
    {
        let mut qps: Vec<String> = Vec::new();
        for (q, _) in query_pairs {
            if !(qps.iter().any(|x| x == &*q)) {
                qps.push(q.into_owned());
            }
        }

        qps.sort();

        for qparam in qps {
            // find correct parameter
            let ret = lexy_sort(query_pairs, &qparam);

            can_res = can_res + &qparam.to_lowercase() + ":";

            for (i, item) in ret.iter().enumerate() {
                if i > 0 {
                    can_res += ",";
                }
                can_res += item;
            }

            can_res += "\n";
        }
    };

    can_res[0..can_res.len() - 1].to_owned()
}
#[inline]
fn add_if_exists<'a>(h: &'a Headers, key: &HeaderName) -> &'a str {
    h.get_optional_str(key).unwrap_or("")
}

fn canonicalize_header(headers: &Headers) -> String {
    let mut names = headers
        .iter()
        .filter_map(|(k, _)| (k.as_str().starts_with("x-ms")).then_some(k))
        .collect::<Vec<_>>();
    names.sort_unstable();

    let mut result = String::new();

    for header_name in names {
        let value = headers.get_optional_str(header_name).unwrap();
        let name = header_name.as_str();
        result = format!("{result}{name}:{value}\n");
    }
    result
}

#[allow(unknown_lints)]
fn string_to_sign(account: &str, h: &Headers, u: &Url, method: &Method) -> String {
    // content lenght must only be specified if != 0
    // this is valid from 2015-02-21
    let content_length = h
        .get_optional_str(&CONTENT_LENGTH)
        .filter(|&v| v != "0")
        .unwrap_or_default();
    format!(
        "{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}{}",
        method.as_ref(),
        add_if_exists(h, &HeaderName::from_static("content-encoding")),
        add_if_exists(h, &HeaderName::from_static("content-language")),
        content_length,
        add_if_exists(h, &HeaderName::from_static("content-md5")),
        add_if_exists(h, &HeaderName::from_static("content-type")),
        add_if_exists(h, &HeaderName::from_static("date")),
        add_if_exists(h, &HeaderName::from_static("if-modified-since")),
        add_if_exists(h, &HeaderName::from_static("if-match")),
        add_if_exists(h, &HeaderName::from_static("if-none-match")),
        add_if_exists(h, &HeaderName::from_static("if-unmodified-since")),
        add_if_exists(h, &HeaderName::from_static("byte_range")),
        canonicalize_header(h),
        canonicalized_resource(account, u)
    )
}

pub fn hmac_sha256(data: &str, key: &Secret) -> Result<String> {
    let key = BASE64_STANDARD.decode(key.secret())?;
    let mut hmac = Hmac::<Sha256>::new_from_slice(&key)?;
    hmac.update(data.as_bytes());
    Ok(BASE64_STANDARD.encode(hmac.finalize().into_bytes()))
}

fn generate_authorization(
    h: &Headers,
    u: &Url,
    method: Method,
    account: &str,
    key: &Secret,
) -> Result<String> {
    let str_to_sign = string_to_sign(account, h, u, &method);
    trace!("azure storage string to sign: {:?}", &str_to_sign);
    let auth = hmac_sha256(&str_to_sign, key)?;
    Ok(format!("SharedKey {account}:{auth}"))
}

#[derive(Debug)]
struct SharedKeyAuthorizationPolicy {
    account: String,
    shared_key: String,
}

#[async_trait]
impl Policy for SharedKeyAuthorizationPolicy {
    async fn send(
        &self,
        ctx: &Context,
        request: &mut Request,
        next: &[Arc<dyn Policy>],
    ) -> PolicyResult {
        request.insert_header(
            "x-ms-date",
            chrono::Utc::now().to_rfc2822().replace("+0000", "GMT"),
        );
        trace!("azure storage headers: {:?}", &request.headers());
        let auth_header = generate_authorization(
            request.headers(),
            request.url(),
            request.method(),
            &self.account,
            &Secret::new(self.shared_key.to_string()),
        )
            .map_err(|err| azure_core::Error::with_message(ErrorKind::Credential, format!("{:?}", err)))?;
        trace!("azure storage auth header: {:?}", &auth_header);
        request.insert_header("authorization", auth_header);
        next[0].send(ctx, request, &next[1..]).await
    }
}

async fn blob_client(account: String, shared_key: String) -> Result<BlobServiceClient> {
    Ok(BlobServiceClient::new(
        &format!("https://{}.blob.core.windows.net", account),
        None,
        Some(BlobServiceClientOptions {
            client_options: ClientOptions {
                per_try_policies: vec![Arc::new(SharedKeyAuthorizationPolicy {
                    account,
                    shared_key,
                })],
                retry: RetryOptions::none(),
                ..Default::default()
            },
            ..Default::default()
        }),
    )?)
}
