use anyhow::Result;
use serde::Serialize;

#[derive(Serialize, Debug)]
struct GitHubCheck {
    time: String,
    still_exists: bool,
    status: u16,
    body: String,
}

async fn check_github() -> Result<GitHubCheck> {
    let cookie = "";

    let client = reqwest::Client::new();

    let response = client
        .get("someurl")
        .header("Cookie", cookie)
        .send()
        .await?;

    let status = response.status().as_u16();
    let body = response.text().await?;
    let still_exists = body.contains("foo") && body.contains("bar");

    let now = chrono::Utc::now().to_rfc3339();

    Ok(GitHubCheck {
        time: now,
        still_exists,
        status,
        body,
    })
}
