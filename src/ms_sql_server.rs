use anyhow::Result;
use futures::TryStreamExt;
use serde::Deserialize;
use std::collections::HashMap;
use thiserror::Error;
use tiberius::{AuthMethod, Client, Config, Query, QueryItem};
use tokio::net::TcpStream;
use tokio_util::compat::TokioAsyncWriteCompatExt;
use url::Url;

use crate::{SqlServerArgs, found_secrets::SecretCheck, truffle_hog::RawV2};

#[derive(Debug, PartialEq, Eq, Clone, Deserialize)]
pub struct MsSqlServerSecret {
    //server: String,
    host: String,
    port: Option<u16>,
    initial_catalog: Option<String>,
    //persist_security_info: Option<bool>,
    user_id: String,
    password: String,
    //multiple_active_result_sets: bool,
    //encrypt: bool,
    //trust_server_certificate: bool,
    //connection_timeout: Option<u16>,
}

#[derive(Error, Debug)]
pub enum ParseError {
    #[error("Error parsing Trufflehog rawv2 url")]
    UrlParseError(#[from] url::ParseError),
    #[error("Missing component from Trufflehog rawv2 url: {0}")]
    MissingComponent(String),
    #[error("Unable to urldecode String")]
    Urlencoding(#[from] std::string::FromUtf8Error),
}

impl From<SqlServerArgs> for MsSqlServerSecret {
    fn from(value: SqlServerArgs) -> Self {
        Self {
            host: value.host,
            port: value.port,
            initial_catalog: value.initial_catalog,
            user_id: value.user_id,
            password: value.password,
        }
    }
}

impl TryFrom<String> for MsSqlServerSecret {
    type Error = ParseError;

    fn try_from(value: String) -> std::result::Result<Self, Self::Error> {
        MsSqlServerSecret::try_from(value.as_str())
    }
}

impl TryFrom<&RawV2<'_>> for MsSqlServerSecret {
    type Error = ParseError;

    fn try_from(value: &RawV2) -> std::result::Result<Self, Self::Error> {
        let url = Url::parse(value.0)?;
        let host = url
            .host()
            .map(|h| h.to_string())
            .ok_or(ParseError::MissingComponent("host".to_string()))?;
        let port = url.port();
        let user_id = {
            let decoded = urlencoding::decode(url.username())?;

            // Trufflehog doesn't parse urlencoded '@'s in urls properly. They can be hidden in the username
            // e.g "foo%40host:password@host" usernames should be "foo" but trufflehog logs it as "foo%40host"
            // decoded.split('@').next().map(|s| s.to_string()).ok_or(ParseError::MissingComponent("username".to_string()))?
            decoded.into_owned()
        };

        let initial_catalog = find_query_pair_value(&url, "database");
        let password = {
            let password = url
                .password()
                .ok_or(ParseError::MissingComponent("password".to_string()))?;
            let decoded = urlencoding::decode(password)?;
            decoded.into_owned()
        };
        Ok(Self {
            host,
            port,
            initial_catalog,
            user_id,
            password,
        })
    }
}

fn find_query_pair_value(url: &Url, key: &str) -> Option<String> {
    url.query_pairs()
        .find(|pair| pair.0 == key)
        .map(|pair| pair.1.into_owned())
}

impl TryFrom<&str> for MsSqlServerSecret {
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
        let server =
            map.get("Server")
                .map(|s| s.to_string())
                .ok_or(ParseError::MissingComponent(
                    "No Storage account key".into(),
                ))?;

        let host = server
            .split(":")
            .nth(1)
            .iter()
            .flat_map(|s| s.split(','))
            .nth(0)
            .map(|s| s.to_string())
            .ok_or(ParseError::MissingComponent("host".into()))?;
        let port: u16 = server
            .split(",")
            .nth(1)
            .ok_or(ParseError::MissingComponent("port".into()))?
            .parse()
            .map_err(|_err| ParseError::MissingComponent("port".into()))?;
        let initial_catalog = map.get("Initial Catalog").map(|s| s.to_string()).ok_or(
            ParseError::MissingComponent("initial catalog/database".into()),
        )?;

        let user_id = map
            .get("User ID")
            .map(|s| s.to_string())
            .ok_or(ParseError::MissingComponent("User Id".into()))?;
        let password = map
            .get("Password")
            .map(|s| s.to_string())
            .ok_or(ParseError::MissingComponent("password".into()))?;

        Ok(MsSqlServerSecret {
            //server,
            host,
            port: Some(port),
            initial_catalog: Some(initial_catalog),
            //persist_security_info: true,
            user_id,
            password,
            //multiple_active_result_sets: true,
            //encrypt: true,
            //trust_server_certificate: true,
            //connection_timeout: 0,
        })
    }
}

#[test]
fn test_ms_sql_server_secret_try_from_string() {
    let test_s = "Server=tcp:foo.database.windows.net,1433;Initial Catalog=foo-dev;Persist Security Info=False;User ID=foo_user;Password=foopass;MultipleActiveResultSets=False;Encrypt=True;TrustServerCertificate=False;Connection Timeout=30;";
    let result = MsSqlServerSecret::try_from(test_s).unwrap();
    let expected = MsSqlServerSecret {
        server: "tcp:foo.database.windows.net,1433".into(),
        host: "foo.database.windows.net".into(),
        port: 1433,
        initial_catalog: "foo-dev".into(),
        persist_security_info: true,
        user_id: "foo_user".into(),
        password: "foopass".into(),
        multiple_active_result_sets: true,
        encrypt: true,
        trust_server_certificate: true,
        connection_timeout: 0,
    };
    assert_eq!(result, expected);
}

impl SecretCheck for MsSqlServerSecret {
    async fn check_secret(&self) -> Result<()> {
        if self.host == "localhost" {
            anyhow::bail!("host is localhost".to_string());
        }
        let mut config = Config::new();
        config.host(&self.host);
        config.port(self.port.unwrap_or(1433));
        config.authentication(AuthMethod::sql_server(&self.user_id, &self.password));
        if let Some(initial_catalog) = &self.initial_catalog {
            config.database(initial_catalog);
        }

        config.encryption(tiberius::EncryptionLevel::Required);

        let tcp = TcpStream::connect(config.get_addr()).await?;
        tcp.set_nodelay(true)?;

        let mut client = match Client::connect(config, tcp.compat_write()).await {
            // Connection successful.
            Ok(client) => client,
            // The server wants us to redirect to a different address
            Err(tiberius::error::Error::Routing { host, port }) => {
                let mut config = Config::new();

                config.host(host);
                config.port(port);
                config.authentication(AuthMethod::sql_server(&self.user_id, &self.password));

                if let Some(initial_catalog) = &self.initial_catalog {
                    config.database(initial_catalog);
                }

                config.encryption(tiberius::EncryptionLevel::Required);

                let tcp = TcpStream::connect(config.get_addr()).await?;
                tcp.set_nodelay(true)?;

                // we should not have more than one redirect, so we'll short-circuit here.
                Client::connect(config, tcp.compat_write()).await?
            }
            Err(e) => Err(e)?,
        };

        let mut stream =
            Query::new("SELECT * FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE='BASE TABLE'")
                .query(&mut client)
                .await?;

        while let Some(item) = stream.try_next().await? {
            if let QueryItem::Row(_row) = item {}
        }

        Ok(())
    }
}
