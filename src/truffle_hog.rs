use std::{
    collections::{HashMap, HashSet},
    fs::File,
    io::{BufRead, BufReader},
    path::Path,
};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use walkdir::WalkDir;

pub struct TruffleHogReports {
    reports: Vec<THData>,
}

#[cfg(test)]
use std::path::PathBuf;

use crate::{
    azure_storage::AzureStorageSecret, found_secrets::SecretCreds,
    ms_sql_server::MsSqlServerSecret, report::SecretReportSplunk, slack_webhooks::SlackWebhook,
};

impl TruffleHogReports {
    pub fn from_path(path: &Path) -> Self {
        let repo_details = RepoDetails::from_file();
        let mut reports = Vec::new();
        let walker = WalkDir::new(path).into_iter();
        for entry in walker {
            let entry_path = entry.as_ref().unwrap().path();

            if Self::is_trufflehog_report(entry_path) {
                let f = File::open(entry_path).unwrap();
                let reader = BufReader::new(f).lines();

                for line in reader.map_while(Result::ok) {
                    let report = TruffleHog::from_str(&line).unwrap();
                    let secret = report.secret_creds();

                    let repo_detail = repo_details.by_clone_url(report.repo()).unwrap().clone();
                    reports.push(THData {
                        report,
                        repo_detail,
                        secret,
                    });
                }
            }
        }
        Self { reports }
    }

    fn is_trufflehog_report(entry: &Path) -> bool {
        let Some(filename) = entry.file_name().map(|p| p.display().to_string()) else {
            return false;
        };

        filename.starts_with("trufflehog") && filename.ends_with(".json")
    }

    pub fn iter(&self) -> impl Iterator<Item = &THData> + Clone {
        self.reports.iter()
    }

    fn owners(&self) -> Vec<String> {
        self.reports
            .iter()
            .map(|report| report.repo_detail.owner.to_string())
            .collect::<HashSet<String>>()
            .into_iter()
            .collect()
    }

    fn detector_names(&self) -> Vec<String> {
        self.reports
            .iter()
            .map(|report| report.report.detector_name.to_string())
            .collect::<HashSet<String>>()
            .into_iter()
            .collect()
    }

    fn detector_counts<'a>(
        &self,
        iter: impl Iterator<Item = &'a THData> + Clone,
    ) -> Vec<(String, usize)> {
        let mut detector_counts = HashMap::new();
        for detector_name in self.detector_names() {
            let entry = detector_counts
                .entry(detector_name.to_string())
                .or_insert(0);
            *entry = iter.clone().by_detector_name(&detector_name).count();
        }
        detector_counts.retain(|_k, v| *v > 0);
        let mut detector_counts = detector_counts
            .into_iter()
            .collect::<Vec<(String, usize)>>();
        detector_counts.sort_by(|a, b| a.1.cmp(&b.1).reverse());
        detector_counts
    }

    fn detector_stats<'a>(&self, iter: impl Iterator<Item = &'a THData> + Clone) -> DetectorStats {
        let detector_counts = self.detector_counts(iter.clone());
        let detector_counts_verified = self.detector_counts(iter.clone().filter_verified());
        let detector_counts_verified_public =
            self.detector_counts(iter.clone().filter_verified().filter_public());
        DetectorStats {
            detector_counts,
            detector_counts_verified,
            detector_counts_verified_public,
        }
    }

    pub fn stats(&self) -> TruffleHogReportStats {
        let mut by_owner = HashMap::new();
        for owner in self.owners() {
            let detector_stats = self.detector_stats(self.iter().by_owner(&owner));

            let owner_stats = OwnerStats {
                total: self.iter().by_owner(&owner).count(),
                public: self.iter().by_owner(&owner).filter_public().count(),
                private: self.iter().by_owner(&owner).filter_private().count(),
                verified: self.iter().by_owner(&owner).filter_verified().count(),
                verified_public: self
                    .iter()
                    .by_owner(&owner)
                    .filter_public()
                    .filter_verified()
                    .count(),
                verified_private: self
                    .iter()
                    .by_owner(&owner)
                    .filter_private()
                    .filter_verified()
                    .count(),
                detector_stats,
            };
            by_owner.insert(owner, owner_stats);
        }

        let detector_stats = self.detector_stats(self.iter());

        TruffleHogReportStats {
            total: self.reports.len(),
            public: self.iter().filter_public().count(),
            private: self.iter().filter_private().count(),
            verified: self.iter().filter_verified().count(),
            verified_public: self.iter().filter_public().filter_verified().count(),
            verified_private: self.iter().filter_private().filter_verified().count(),
            by_owner,
            detector_stats,
        }
    }
}

pub trait THFilters<'a, T>: Iterator + Sized + Iterator<Item = &'a THData> + Clone {
    fn by_detector_name(self, detector_name: &str) -> impl Iterator<Item = &'a THData> + Clone {
        self.filter(move |report| {
                report.report.detector_name == *detector_name
        }
        )
    }
    
    fn by_detector_name_option(self, detector_name: Option<String>) -> impl Iterator<Item = &'a THData> + Clone {
        self.filter(move |report| {
            if let Some(detector_name) = detector_name.as_ref() {
                report.report.detector_name == *detector_name
            } else {
                true
            }
        }
        )
    }

    fn by_owner(self, owner: &str) -> impl Iterator<Item = &'a THData> + Clone {
        self.filter(move |report| {
                report.repo_detail.name == *owner
        })
    }    

    fn by_owner_option(self, owner: Option<String>) -> impl Iterator<Item = &'a THData> + Clone {
        self.filter(move |report| {
            if let Some(owner) = owner.as_ref() {
                report.repo_detail.name == *owner
            } else {
                true
            }
        })
    }

    fn by_repo_name_option(self, repo_name: Option<String>) -> impl Iterator<Item = &'a THData> + Clone {
        self.filter(move |report| {
            if let Some(repo_name) = repo_name.as_ref() {
                report.repo_detail.name == *repo_name
            } else {
                true
            }
        })
    }

    fn by_repo_name(self, repo_name: &str) -> impl Iterator<Item = &'a THData> + Clone {
        self.filter(move |report| {
            report.repo_detail.name == *repo_name
        }
        )
    }    
    

    fn filter_private(self) -> impl Iterator<Item = &'a THData> + Clone {
        self.filter(|report| !report.is_public())
    }

    fn filter_public(self) -> impl Iterator<Item = &'a THData> + Clone {
        self.filter(|report| report.is_public())
    }

    #[allow(dead_code)]
    fn filter_unverified(self) -> impl Iterator<Item = &'a THData> + Clone {
        self.filter(|report| !report.is_verified())
    }

    fn filter_verified(self) -> impl Iterator<Item = &'a THData> + Clone {
        self.filter(|report| report.is_verified())
    }
}

impl<'a, T> THFilters<'a, T> for T where T: Iterator<Item = &'a THData> + Sized + Clone {}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TruffleHogReportStats {
    total: usize,
    public: usize,
    private: usize,
    verified: usize,
    verified_public: usize,
    verified_private: usize,
    pub detector_stats: DetectorStats,
    by_owner: HashMap<String, OwnerStats>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct OwnerStats {
    total: usize,
    public: usize,
    private: usize,
    verified: usize,
    verified_public: usize,
    verified_private: usize,
    detector_stats: DetectorStats,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DetectorStats {
    detector_counts: Vec<(String, usize)>,
    detector_counts_verified: Vec<(String, usize)>,
    detector_counts_verified_public: Vec<(String, usize)>,
}

#[test]
fn test_truffle_hog_reports_from_path() {
    let path = PathBuf::from(".");
    let reports = TruffleHogReports::from_path(&path);
    // dbg!(reports.reports.len());
    let _stats = reports.stats();
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct THData {
    report: TruffleHog,
    repo_detail: RepoDetail,
    #[serde(skip)]
    secret: Option<SecretCreds>,
}

impl THData {
    pub fn owner(&self) -> &str {
        self.repo_detail.owner.as_str()
    }

    pub fn repo_name(&self) -> &str {
        self.repo_detail.name.as_str()
    }

    pub fn detector_name(&self) -> &str {
        self.report.detector_name.as_str()
    }
    
    fn is_public(&self) -> bool {
        self.repo_detail.visibility == "public"
    }

    fn is_verified(&self) -> bool {
        self.report.verified
    }

    pub fn secret(&self) -> Option<&SecretCreds> {
        self.secret.as_ref()
    }

    pub fn secret_cache_key(&self) -> Option<String> {
        self.secret().map(|secret| 
            format!("{:?}", secret)
        )
    }

    pub fn report_raw_v2(&self) -> &str {
        self.report.raw_v2.as_str()
    }
        

    pub fn validation_report(&self, valid_now: bool) -> SecretReportSplunk {
        SecretReportSplunk {
            datetime: chrono::Utc::now().to_rfc3339(),
            detector_name: self.report.detector_name.to_string(),
            link: self.report.source_metadata.data.github.link.to_string(),
            file: self
                .report
                .source_metadata
                .data
                .github
                .file
                .as_ref()
                .map(|f| f.to_string()),
            commit: self.report.source_metadata.data.github.commit.to_string(),
            valid_from_trufflehog: self.is_verified(),
            valid_now,
            repo_public: self.is_public(),
            repo_archived: self.repo_detail.archived,
            repo_owner: self.repo_detail.owner.to_string(),
            repo_name: self.repo_detail.name.to_string(),
        }
    }

    pub async fn check_secret(&self) -> bool {
        if let Some(secret) = self.secret() {
            secret.check_secret().await.is_ok()
        } else {
            false
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
struct TruffleHog {
    decoder_name: String,
    detector_description: String,
    detector_name: String,
    detector_type: usize,
    extra_data: Option<Value>,
    raw: String,
    pub raw_v2: String,
    redacted: String,
    #[serde(rename = "SourceID")]
    source_id: usize,
    source_metadata: SourceMetadata,
    source_name: String,
    source_type: usize,
    structured_data: Option<String>,
    verification_error: Option<String>,
    verification_from_cache: bool,
    verified: bool,
}

impl TruffleHog {
    /// Load a single Trufflehog report
    fn from_str(line: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(line)
    }

    /// The repo that the 
    fn repo(&self) -> &str {
        &self.source_metadata.data.github.repository
    }

    fn secret_creds(&self) -> Option<SecretCreds> {
        let secret = match self.detector_name.as_str() {
            "AzureStorage" => {
                let raw_v2 = self
                    .raw_v2_deserialize::<TrufflehogRawV2AzureStorage>()
                    .ok()?;
                let secret = AzureStorageSecret::from(raw_v2);
                SecretCreds::AzureStorage(secret)
            }
            "SQLServer" => {
                let secret = MsSqlServerSecret::try_from(dbg!(&RawV2(self.raw_v2.as_str()))).ok()?;
                dbg!(&secret);
                SecretCreds::MsSqlServer(secret)
            }
            "SlackWebhook" => {
                let secret = SlackWebhook::try_from(self.raw.as_str()).ok()?;
                SecretCreds::SlackWebhook(secret)
            }
            _ => return None,
        };
        Some(secret)
    }

    fn raw_v2_deserialize<T: DeserializeOwned>(&self) -> Result<T, serde_json::Error> {
        serde_json::from_str(&self.raw_v2)
    }
}

/// NewType to work with TryFrom trait for Secret Parsers
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RawV2<'a>(pub &'a str);

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged)]
enum ExtraData {
    AzureStorage(EDAzureStorage),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct EDAzureStorage {
    #[serde(rename = "Account_name")]
    account_name: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
struct SourceMetadata {
    data: Github,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
struct Github {
    github: GithubDetails,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
//#[serde(rename_all = "PascalCase")]
struct GithubDetails {
    commit: String,
    email: String,
    file: Option<String>,
    line: usize,
    link: String,
    repository: String,
    repository_local_path: Option<String>,
    timestamp: String,
}

#[test]
fn load_truffle_hog_json() {
    let json = [
        r#"
{
  "DecoderName": "PLAIN",
  "DetectorDescription": "SQL Server is a relational database management system developed by Microsoft. SQL Server credentials can be used to access and manage databases.",
  "DetectorName": "SQLServer",
  "DetectorType": 898,
  "ExtraData": null,
  "Raw": "foo",
  "RawV2": "sqlserver://foo:foo@foo.database.windows.net:1433?database=foo&dial+timeout=15&disableretry=false&encrypt=true&protocol=tcp",
  "Redacted": "",
  "SourceID": 1,
  "SourceMetadata": {
    "Data": {
      "Github": {
        "commit": "1",
        "email": "email@foo.com",
        "file": "foo",
        "line": 1,
        "link": "http://",
        "repository": "http://",
        "repository_local_path": "/tmp/trufflehog-34-1342395770",
        "timestamp": "2018-10-05 09:36:11 +0000"
      }
    }
  },
  "SourceName": "trufflehog - github",
  "SourceType": 7,
  "StructuredData": null,
  "VerificationError": "SOME ERRROR.",
  "VerificationFromCache": false,
  "Verified": false
}"#,
        r#"
{
  "DecoderName": "PLAIN",
  "DetectorDescription": "Azure Storage is a Microsoft-managed cloud service that provides storage that is highly available, secure, durable, scalable, and redundant. Azure Storage Account keys can be used to access and manage data within storage accounts.",
  "DetectorName": "AzureStorage",
  "DetectorType": 931,
  "ExtraData": {
    "Account_name": "foo"
  },
  "Raw": "foo==",
  "RawV2": "{\"accountName\":\"foo\",\"accountKey\":\"foo==\"}",
  "Redacted": "",
  "SourceID": 1,
  "SourceMetadata": {
    "Data": {
      "Github": {
        "commit": "1",
        "email": "foo@foo.com",
        "file": "readme.txt",
        "line": 1,
        "link": "https://github.com",
        "repository": "https://github.com/",
        "repository_local_path": "/tmp/trufflehog-33-3858606608",
        "timestamp": "2020-01-07 14:41:29 +0000"
      }
    }
  },
  "SourceName": "trufflehog - github",
  "SourceType": 7,
  "StructuredData": null,
  "VerificationFromCache": false,
  "Verified": false
}
"#,
    ];
    for j in json {
        println!("{}", j);
        let _obj: TruffleHog = serde_json::from_str(&j).unwrap();
    }
}

impl RepoDetails {
    fn from_file() -> Self {
        let mut rdr = csv::Reader::from_path("repo_details.csv").unwrap();
        let mut inner = Vec::new();
        let mut clone_url_map = HashMap::new();
        for result in rdr.deserialize() {
            let record: RepoDetail = result.unwrap();
            clone_url_map.insert(record.clone_url.to_string(), inner.len());
            inner.push(record);
        }

        Self {
            inner,
            clone_url_map,
        }
    }

    fn by_clone_url(&self, clone_url: &str) -> Option<&RepoDetail> {
        self.clone_url_map
            .get(clone_url)
            .and_then(|index| self.inner.get(*index))
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct RepoDetails {
    inner: Vec<RepoDetail>,
    clone_url_map: HashMap<String, usize>,
}

// index=ssphp*data* sourcetype=github source="github:*"
// | table owner.login full_name name visibility archived fork forks_count id created_at updated_at clone_url
// | rename owner.login as owner
#[derive(Serialize, Deserialize, Debug, Clone)]
struct RepoDetail {
    owner: String,
    full_name: String,
    name: String,
    visibility: String,
    archived: bool,
    fork: bool,
    forks_count: u16,
    id: usize,
    // TODO Chrono time
    created_at: String,
    updated_at: String,
    clone_url: String,
}

#[test]
fn test_repo_details() {
    let rd = RepoDetails::from_file();
    assert!(rd.inner.len() > 0);
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrufflehogRawV2AzureStorage {
    pub(crate) account_name: String,
    pub(crate) account_key: String,
}
