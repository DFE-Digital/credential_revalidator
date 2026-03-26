use std::time::Duration;

use anyhow::Result;
use data_ingester_splunk::splunk::HecEvent;
use data_ingester_splunk::splunk::SplunkTrait;
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::CsvParserArgs;

pub async fn csv_parser(csv_parser_args: CsvParserArgs) -> Result<()> {
    let mut out = Vec::new();

    let splunk = data_ingester_splunk::splunk::Splunk::new(
        &csv_parser_args.splunk_hec_host,
        &csv_parser_args.splunk_hec_token,
        
        false,
    )    .unwrap();


    let path = csv_parser_args.csv_path;
    
    let mut rdr = csv::Reader::from_path(path).unwrap();

    for result in rdr.deserialize() {
        let record: GitHubSecretCsv = result?;
        if record.found_by != "Trufflehog Scan" {
            continue;
        }

        let record = record.parse_description();

        let hec_event = HecEvent::new(&record, "github_findings_csv", "path").unwrap();

        out.push(hec_event);
    }
    let _ = splunk.send_batch(out).await;
    tokio::time::sleep(Duration::from_mins(2)).await;

    Ok(())
}

#[derive(Deserialize, Clone, Debug)]
struct GitHubSecretCsv {
    cvssv3_score: String,
    cwe: String,
    description: String,
    file_path: String,
    line: String,
    service: String,
    severity: String,
    #[serde(alias = "login.dfe.invitations")]
    login_dfe_invitations: String,
    test_id: String,
    title: String,
    found_by: String,
    product_id: String,
    product: String,
}

#[derive(Debug)]
struct Description {
    repo: String,
    link: String,
    commit_hash: String,
    commit_date: String,
    committer: String,
    path: String,
    file_path: String,
    contents: String,
    extra_data: String,
    reason: String,
}

impl GitHubSecretCsv {
    fn parse_description(self) -> GitHubSecretDescription {
        let desc = &self.description;
        dbg!(desc);
        let repo = Regex::new(r"\*\*Repository:\*\*(?<repo>[^\*]+)\*\*").unwrap();
        let link = Regex::new(r"\*\*Link:\*\*(?<link>[^\*]+)\*\*").unwrap();
        let commit_hash = Regex::new(r"\*\*Commit Hash:\*\*(?<commit_hash>[^\*]+)\*\*").unwrap();
        let commit_date = Regex::new(r"\*\*Commit Date:\*\*(?<commit_date>[^\*]+)\*\*").unwrap();
        let committer = Regex::new(r"\*\*Committer:\*\*(?<committer>[^\*]+)\*\*").unwrap();
        let reason = Regex::new(r"\*\*Reason:\*\*(?<reason>[^\*]+)\*\*").unwrap();
        let path = Regex::new(r"\*\*Path:\*\*(?<path>[^\*]+)\*\*").unwrap();
        let file_path = Regex::new(r"\*\*Filepath:\*\*(?<file_path>[^\*]+)\*\*").unwrap();
        let contents = Regex::new(r"\*\*Contents:\*\*(?<contents>[^\*]+)\*\*").unwrap();
        let extra_data = Regex::new(r"\*\*Extra Data:\*\*(?<extra_data>[^\*]+)$").unwrap();

        let description = Description {
            repo: repo
                .captures(desc)
                .map(|cap| cap["repo"].replace("NEWLINE", "\n").trim().to_string())
                .unwrap_or_default(),
            link: link
                .captures(desc)
                .map(|cap| cap["link"].replace("NEWLINE", "\n").trim().to_string())
                .unwrap_or_default(),
            reason: reason
                .captures(desc)
                .map(|cap| cap["reason"].replace("NEWLINE", "\n").trim().to_string())
                .unwrap_or_default(),
            commit_hash: commit_hash
                .captures(desc)
                .map(|cap| {
                    cap["commit_hash"]
                        .replace("NEWLINE", "\n")
                        .trim()
                        .to_string()
                })
                .unwrap_or_default(),
            commit_date: commit_date
                .captures(desc)
                .map(|cap| {
                    cap["commit_date"]
                        .replace("NEWLINE", "\n")
                        .trim()
                        .to_string()
                })
                .unwrap_or_default(),
            committer: committer
                .captures(desc)
                .map(|cap| cap["committer"].replace("NEWLINE", "\n").trim().to_string())
                .unwrap_or_default(),
            path: path
                .captures(desc)
                .map(|cap| cap["path"].replace("NEWLINE", "\n").trim().to_string())
                .unwrap_or_default(),
            file_path: file_path
                .captures(desc)
                .map(|cap| cap["file_path"].replace("NEWLINE", "\n").trim().to_string())
                .unwrap_or_default(),
            contents: contents
                .captures(desc)
                .map(|cap| cap["contents"].replace("NEWLINE", "\n").trim().to_string())
                .unwrap_or_default(),
            extra_data: extra_data
                .captures(desc)
                .map(|cap| cap["extra_data"].replace("NEWLINE", "").trim().to_string())
                .unwrap_or_default(),
        };
        //dbg!(description);
        GitHubSecretDescription {
            cvssv3_score: self.cvssv3_score,
            cwe: self.cwe,
            description: self.description,
            file_path: self.file_path,
            line: self.line,
            service: self.service,
            severity: self.severity,
            login_dfe_invitations: self.login_dfe_invitations,
            test_id: self.test_id,
            title: self.title,
            found_by: self.found_by,
            product_id: self.product_id,
            product: self.product,
            repo: description.repo,
            link: description.link,
            commit_hash: description.commit_hash,
            commit_date: description.commit_date,
            committer: description.committer,
            path: description.path,
            contents: description.contents,
            extra_data: description.extra_data,
            reason: description.reason,
            secret: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct GitHubSecretDescription {
    secret: String,
    found_by: String,
    reason: String,
    link: String,
    repo: String,
    product: String,
    cvssv3_score: String,
    cwe: String,
    file_path: String,
    line: String,
    service: String,
    severity: String,
    login_dfe_invitations: String,
    test_id: String,
    title: String,

    product_id: String,
    commit_hash: String,
    commit_date: String,
    committer: String,
    path: String,
    contents: String,
    extra_data: String,
    description: String,
}
