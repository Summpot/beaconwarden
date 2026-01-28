use serde::Deserialize;
use worker::{Env, Request, Result};

use crate::worker_wasm::env::env_string;
use crate::worker_wasm::http::error_response;

#[derive(Debug, Deserialize)]
struct CloudflareApiMessage {
    #[allow(dead_code)]
    code: Option<i64>,
    #[allow(dead_code)]
    message: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CloudflareVerifyResult {
    #[allow(dead_code)]
    id: String,
    #[allow(dead_code)]
    status: String,
    #[allow(dead_code)]
    expires_on: Option<String>,
    #[allow(dead_code)]
    not_before: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CloudflareEnvelope<T> {
    success: bool,
    #[allow(dead_code)]
    errors: Vec<CloudflareApiMessage>,
    #[allow(dead_code)]
    messages: Vec<CloudflareApiMessage>,
    result: Option<T>,
}

pub fn extract_bearer_token(req: &Request) -> Result<Option<String>> {
    let Some(raw) = req.headers().get("Authorization")? else {
        return Ok(None);
    };

    let raw = raw.trim();
    let Some((scheme, rest)) = raw.split_once(' ') else {
        return Ok(None);
    };
    if !scheme.eq_ignore_ascii_case("bearer") {
        return Ok(None);
    }

    let token = rest.trim();
    if token.is_empty() {
        return Ok(None);
    }

    Ok(Some(token.to_string()))
}

async fn verify_cloudflare_api_token_against_url(token: &str, url: &str) -> Result<CloudflareVerifyResult> {
    let headers = worker::Headers::new();
    headers.set("Authorization", &format!("Bearer {token}"))?;
    headers.set("Accept", "application/json")?;
    headers.set("User-Agent", "BeaconWarden/0.1 (Cloudflare Worker)")?;

    let mut init = worker::RequestInit::new();
    init.with_method(worker::Method::Get);
    init.with_headers(headers);

    let cf_req = worker::Request::new_with_init(url, &init)?;

    let mut resp = worker::Fetch::Request(cf_req).send().await?;
    let status = resp.status_code();
    let body = resp.text().await.unwrap_or_default();

    let parsed: CloudflareEnvelope<CloudflareVerifyResult> = serde_json::from_str(&body).map_err(|e| {
        worker::Error::RustError(format!(
            "Cloudflare verify returned non-JSON (status={status}): {e}"
        ))
    })?;

    if !parsed.success {
        return Err(worker::Error::RustError(format!(
            "Cloudflare token verification failed (status={status}, url={url})"
        )));
    }

    parsed.result.ok_or_else(|| {
        worker::Error::RustError(format!(
            "Cloudflare verify response missing result (status={status}, url={url})"
        ))
    })
}

async fn verify_cloudflare_api_token(env: &Env, token: &str) -> Result<CloudflareVerifyResult> {
    // Support both user and account token families.
    let user_url = "https://api.cloudflare.com/client/v4/user/tokens/verify";
    match verify_cloudflare_api_token_against_url(token, user_url).await {
        Ok(v) => Ok(v),
        Err(user_err) => {
            if let Some(account_id) = env_string(env, "CLOUDFLARE_ACCOUNT_ID") {
                let account_url = format!(
                    "https://api.cloudflare.com/client/v4/accounts/{account_id}/tokens/verify"
                );
                verify_cloudflare_api_token_against_url(token, &account_url)
                    .await
                    .map_err(|account_err| {
                        worker::Error::RustError(format!(
                            "Cloudflare token verification failed. user_verify={user_err}; account_verify={account_err}"
                        ))
                    })
            } else {
                Err(worker::Error::RustError(format!(
                    "Cloudflare token verification failed and CLOUDFLARE_ACCOUNT_ID not configured: {user_err}"
                )))
            }
        }
    }
}

/// Shared authorization logic for admin endpoints.
///
/// - If `MIGRATIONS_TOKEN` is configured, require it as a bearer token.
/// - Otherwise, verify the presented bearer token against the Cloudflare API.
///
/// Returns `Ok(None)` when authorized; otherwise returns an error response.
pub async fn ensure_admin_authorized(req: &Request, env: &Env) -> Result<Option<worker::Response>> {
    let Some(token) = extract_bearer_token(req)? else {
        return Ok(Some(error_response(
            req,
            401,
            "missing_token",
            "Missing Authorization Bearer token",
        )?));
    };

    if let Some(required) = env_string(env, "MIGRATIONS_TOKEN") {
        if token != required {
            return Ok(Some(error_response(
                req,
                401,
                "unauthorized",
                "Invalid migrations token",
            )?));
        }
        return Ok(None);
    }

    if let Err(e) = verify_cloudflare_api_token(env, &token).await {
        worker::console_log!("Admin token verification failed: {e}");
        return Ok(Some(error_response(
            req,
            401,
            "unauthorized",
            "Invalid Cloudflare API token",
        )?));
    }

    Ok(None)
}
