use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct SecretReportSplunk {
    pub datetime: String,
    pub detector_name: String,
    pub link: String,
    pub file: Option<String>,
    pub commit: String,
    pub valid_from_trufflehog: bool,
    pub valid_now: bool,
    pub repo_public: bool,
    pub repo_archived: bool,
    pub repo_owner: String,
    pub repo_name: String,
}
