use serde_json::Value;
use worker::{Env, Request, Response, Result};

use crate::worker_wasm::env::env_string;
use crate::worker_wasm::http::json_with_cors;

fn parse_bool_env(env: &Env, key: &str) -> bool {
    match env_string(env, key)
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "1" | "true" | "yes" | "on" => true,
        _ => false,
    }
}

fn request_origin(req: &Request) -> Result<String> {
    let url = req.url()?;

    let scheme = url.scheme();
    let host = url.host_str().unwrap_or_default();
    let port = url.port();

    if host.is_empty() {
        return Ok(String::new());
    }

    let origin = match port {
        Some(p) => format!("{scheme}://{host}:{p}"),
        None => format!("{scheme}://{host}"),
    };

    Ok(origin)
}

fn base_url(req: &Request, env: &Env) -> Result<String> {
    if let Some(v) = env_string(env, "BASE_URL") {
        return Ok(v.trim_end_matches('/').to_string());
    }

    Ok(request_origin(req)?.trim_end_matches('/').to_string())
}

pub async fn handle_config(req: Request, env: &Env) -> Result<Response> {
    let domain = base_url(&req, env)?;

    // Keep compatibility with Bitwarden clients: the server version is used for feature gates.
    // Keep this in sync with the upstream-ish Vaultwarden config response.
    let mut feature_states = serde_json::Map::new();
    feature_states.insert("duo-redirect".to_string(), Value::Bool(true));
    feature_states.insert("email-verification".to_string(), Value::Bool(true));
    feature_states.insert("unauth-ui-refresh".to_string(), Value::Bool(true));
    feature_states.insert("enable-pm-flight-recorder".to_string(), Value::Bool(true));
    feature_states.insert("mobile-error-reporting".to_string(), Value::Bool(true));

    let disable_registration = parse_bool_env(env, "DISABLE_USER_REGISTRATION");

    let body = serde_json::json!({
        "version": "2025.12.0",
        "gitHash": option_env!("GIT_REV"),
        "server": {
            "name": "Vaultwarden",
            "url": "https://github.com/dani-garcia/vaultwarden"
        },
        "settings": {
            "disableUserRegistration": disable_registration
        },
        "environment": {
            "vault": domain,
            "api": format!("{domain}/api"),
            "identity": format!("{domain}/identity"),
            "notifications": format!("{domain}/notifications"),
            "sso": "",
            "cloudRegion": null
        },
        "push": {
            "pushTechnology": 0,
            "vapidPublicKey": null
        },
        "featureStates": Value::Object(feature_states),
        "object": "config"
    });

    let resp = Response::from_json(&body)?;
    json_with_cors(&req, resp)
}
