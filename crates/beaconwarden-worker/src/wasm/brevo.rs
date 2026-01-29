use serde::Serialize;
use worker::{Env, Headers, Method, Request, RequestInit, Result};

use crate::worker_wasm::env::env_string;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct BrevoEmailAddress {
    email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct BrevoSendEmailBody {
    sender: BrevoEmailAddress,
    to: Vec<BrevoEmailAddress>,
    subject: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    html_content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    text_content: Option<String>,
}

fn require_env(env: &Env, key: &str) -> std::result::Result<String, worker::Error> {
    let Some(v) = env_string(env, key) else {
        return Err(worker::Error::RustError(format!("{key} is required")));
    };
    let v = v.trim().to_string();
    if v.is_empty() {
        return Err(worker::Error::RustError(format!("{key} is required")));
    }
    Ok(v)
}

fn is_success_status(status: u16) -> bool {
    (200..=299).contains(&status)
}

pub fn brevo_is_configured(env: &Env) -> bool {
    env_string(env, "BREVO_API_KEY").is_some_and(|v| !v.trim().is_empty())
        && env_string(env, "BREVO_SENDER_EMAIL").is_some_and(|v| !v.trim().is_empty())
}

pub async fn send_email(
    env: &Env,
    to_email: &str,
    to_name: Option<&str>,
    subject: &str,
    html: Option<String>,
    text: Option<String>,
) -> Result<()> {
    let api_key = require_env(env, "BREVO_API_KEY")?;
    let from_email = require_env(env, "BREVO_SENDER_EMAIL")?;
    let from_name = env_string(env, "BREVO_SENDER_NAME");

    let body = BrevoSendEmailBody {
        sender: BrevoEmailAddress {
            email: from_email,
            name: from_name,
        },
        to: vec![BrevoEmailAddress {
            email: to_email.to_string(),
            name: to_name.map(|s| s.to_string()),
        }],
        subject: subject.to_string(),
        html_content: html,
        text_content: text,
    };

    let json = serde_json::to_string(&body)
        .map_err(|e| worker::Error::RustError(format!("Failed to serialize Brevo payload: {e}")))?;

    let headers = Headers::new();
    headers.set("api-key", &api_key)?;
    headers.set("Content-Type", "application/json")?;
    headers.set("Accept", "application/json")?;
    headers.set("User-Agent", "BeaconWarden/0.1 (Cloudflare Worker)")?;

    let mut init = RequestInit::new();
    init.with_method(Method::Post);
    init.with_headers(headers);
    init.with_body(Some(json.into()));

    let req = Request::new_with_init("https://api.brevo.com/v3/smtp/email", &init)?;

    let mut resp = worker::Fetch::Request(req).send().await?;
    let status = resp.status_code();
    if is_success_status(status) {
        return Ok(());
    }

    let body = resp.text().await.unwrap_or_default();
    Err(worker::Error::RustError(format!(
        "Brevo send failed (status={status}): {body}"
    )))
}
