use anyhow::Context;
use anyhow::Result;
use azure::AzureCreds;
use clap::Args;
use clap::Parser;
use clap::Subcommand;
use data_ingester_splunk::splunk::HecEvent;
use data_ingester_splunk::splunk::Splunk;
use data_ingester_splunk::splunk::SplunkTrait;
use found_secrets::SecretCheck;
use ms_sql_server::MsSqlServerSecret;
use std::collections::HashMap;
use std::future::Future;
use std::path::PathBuf;
use std::time::Duration;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use truffle_hog::THData;
use truffle_hog::THFilters;
use truffle_hog::TruffleHogReports;
pub mod azure;
mod azure_storage;
mod csv_parser;
mod found_secrets;
mod github;
mod ms_sql_server;
mod report;
mod slack_webhooks;
mod truffle_hog;
use tracing::{debug, info, trace};

#[derive(Parser, Debug)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    CsvParser(CsvParserArgs),
    TrufflehogParser(TrufflehogParserArgs),
    TrufflehogParserListDetectors(TrufflehogParserArgs),
    Validator(ValidatorArgs),
    SqlServer(SqlServerArgs),
    AzureCredentials(AzureCredentialArgs),
}

#[derive(Args, Debug)]
struct TrufflehogParserArgs {
    #[clap(short, default_value = ".", help = "Directory for trufflehog JSON")]
    path: PathBuf,
    #[clap(short, help = "Path to repo_details.csv")]
    repo_details_path: PathBuf,
}

#[derive(Args, Debug)]
struct CsvParserArgs {
    #[clap(long, env, help = "http-inputs-foobar.splunkcloud.com")]
    splunk_hec_host: String,
    #[clap(long, env)]
    splunk_hec_token: String,
    csv_path: PathBuf,
}

#[derive(Args, Debug)]
struct ValidatorArgs {
    #[clap(long, env, help = "http-inputs-foobar.splunkcloud.com")]
    splunk_hec_host: Option<String>,
    #[clap(long, env)]
    splunk_hec_token: Option<String>,
    #[clap(
        default_value = r#"/Users/a/repos/access_monitor/trufflehog/"#,
        help = "The path to the directory containing all Trufflehog logs"
    )]
    #[clap(short)]
    trufflhog_json_path: PathBuf,
    #[clap(short, long, help = "Path to repo_details.csv")]
    repo_details_path: PathBuf,

    #[clap(short, help = "filter only matching detector name")]
    detector_name: Option<String>,
    #[clap(short, help = "filter only matching repository name")]
    repo_name: Option<String>,
    #[clap(short, help = "filter only matching owner name")]
    owner_name: Option<String>,

    #[clap(
        short,
        default_value = "false",
        help = "Send validation reports to Splunk",
        requires = "splunk_hec_token",
        requires = "splunk_hec_host"
    )]
    send_to_splunk: bool,
    #[clap(
        short,
        help = "run rerun validation continuiously after this delay in seconds"
    )]
    rerun_interval: Option<u64>,
    #[clap(short, default_value = "false", help = "Skip validation of secrets")]
    no_validate: bool,
}

#[derive(Args, Debug)]
struct SqlServerArgs {
    #[clap(short)]
    host: String,
    #[clap(long)]
    port: Option<u16>,
    #[clap(short)]
    initial_catalog: Option<String>,
    #[clap(short)]
    user_id: String,
    #[clap(short)]
    password: String,
}

#[derive(Args, Debug)]
struct AzureCredentialArgs {
    #[clap(short)]
    client_id: String,
    #[clap(long)]
    client_secret: String,
    #[clap(short)]
    tenant_id: String,
}

fn main() -> Result<()> {
    let fmt_layer = fmt::layer().with_file(true).with_line_number(true);

    let filter_layer = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new("info"))
        .unwrap();

    tracing_subscriber::registry()
        .with(filter_layer)
        .with(fmt_layer)
        .init();

    let cli = Cli::parse();
    info!("Starting {:?}", cli.command);
    debug!("cli arguments: {:#?}", cli);
    match cli.command {
        Commands::TrufflehogParser(trufflehog_parser_args) => {
            let reports = TruffleHogReports::from_path(
                &trufflehog_parser_args.path,
                &trufflehog_parser_args.repo_details_path,
            );
            let stats = reports.stats();
            dbg!(stats);
        }
        Commands::Validator(validator_args) => run_with_tokio(run_validator(validator_args)),
        Commands::CsvParser(csv_parser_args) => {
            run_with_tokio(csv_parser::csv_parser(csv_parser_args))
        }
        Commands::TrufflehogParserListDetectors(trufflehog_parser_args) => {
            let reports = TruffleHogReports::from_path(
                &trufflehog_parser_args.path,
                &trufflehog_parser_args.repo_details_path,
            );
            let stats = reports.stats();
            dbg!(stats.detector_stats);
        }
        Commands::SqlServer(sql_server_args) => {
            let secret = MsSqlServerSecret::from(sql_server_args);
            debug!("secret: {:#?}", secret);
            let block = async move || {
                let result = secret.check_secret().await;
                info!("Sql server access: {:#?}", result);
            };
            run_with_tokio(block())
        }
        Commands::AzureCredentials(azure_credential_args) => {
            let secret = AzureCreds::from(azure_credential_args);
            debug!("secret: {:#?}", secret);
            let block = async move || {
                let result = secret.check_secret().await;
                info!("Sql server access: {:#?}", result);
            };
            run_with_tokio(block())
        }
    };
    Ok(())
}

fn run_with_tokio<Fut, Out>(f: Fut)
where
    Fut: Future<Output = Out>,
{
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let _ = f.await;
        })
}

async fn run_validator(validator_args: ValidatorArgs) -> Result<()> {
    let reports = TruffleHogReports::from_path(
        &validator_args.trufflhog_json_path,
        &validator_args.repo_details_path,
    );

    let splunk = if validator_args.send_to_splunk
        && let Some(host) = &validator_args.splunk_hec_host
        && let Some(token) = &validator_args.splunk_hec_token
    {
        let splunk = Splunk::new(host, token, false).context("Failed to build Splunk client")?;
        Some(splunk)
    } else {
        None
    };

    let iter = reports
        .iter()
        .by_detector_name_option(validator_args.detector_name)
        .by_repo_name_option(validator_args.repo_name)
        .by_owner_option(validator_args.owner_name);

    let mut validator_cache = ValidatorCache::new();

    loop {
        for report in iter.clone() {
            debug!("report: {:#?}", report);

            let validation_report = if !validator_args.no_validate {
                let valid_now = validator_cache.check(report).await;

                let validation_report = report.validation_report(valid_now);

                debug!("Validation report: {:#?}", &validation_report);
                Some(validation_report)
            } else {
                None
            };

            if let Some(ref splunk) = splunk
                && let Some(validation_report) = validation_report
            {
                let mut events = Vec::new();
                let hec_event =
                    HecEvent::new(&validation_report, "access_monitor", "access_monitor").unwrap();
                events.push(hec_event);
                trace!("{:?}", &events);
                let _ = splunk.send_batch(events).await;
            }

            //tokio::time::sleep(Duration::from_secs(5)).await;
        }

        if let Some(loop_interval) = validator_args.rerun_interval {
            tokio::time::sleep(Duration::from_secs(loop_interval)).await;
        } else {
            break;
        }
    }

    Ok(())
}

struct ValidatorCache {
    inner: HashMap<String, bool>,
}

impl ValidatorCache {
    fn new() -> Self {
        Self {
            inner: HashMap::new(),
        }
    }

    async fn check(&mut self, report: &THData) -> bool {
        let Some(cache_key) = report.secret_cache_key() else {
            return false;
        };
        let cached_valid_now = self.inner.get(&cache_key);

        if let Some(valid_now) = cached_valid_now {
            trace!("Credential result in cache");
            *valid_now
        } else {
            trace!("Credential result NOT in cache - Running .check_secret()");
            let valid_now = report.check_secret().await;
            self.inner.insert(cache_key, valid_now);
            valid_now
        }
    }
}
