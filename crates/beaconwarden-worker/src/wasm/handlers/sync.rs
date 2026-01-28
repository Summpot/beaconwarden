use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use serde_json::Value;
use worker::{Env, Request, Response, Result, Url};

use crate::worker_wasm::db::db_connect;
use crate::worker_wasm::handlers::admin_auth::extract_bearer_token;
use crate::worker_wasm::http::{error_response, internal_error_response, json_with_cors};
use crate::worker_wasm::util::now_ts;

use entity::{device, user};

fn profile_json(u: &user::Model) -> Value {
    let status = if u.password_hash.as_ref().is_some_and(|v| !v.is_empty()) { 0 } else { 1 };
    serde_json::json!({
        "_status": status,
        "id": u.id,
        "name": u.name.clone().unwrap_or_else(|| u.email.clone()),
        "email": u.email,
        "emailVerified": true,
        "premium": true,
        "premiumFromOrganization": false,
        "culture": "en-US",
        "twoFactorEnabled": false,
        "key": u.akey,
        "privateKey": u.private_key,
        "securityStamp": u.security_stamp,
        "organizations": [],
        "providers": [],
        "providerOrganizations": [],
        "forcePasswordReset": false,
        "avatarColor": Value::Null,
        "usesKeyConnector": false,
        "creationDate": Value::Null,
        "object": "profile",
    })
}

fn master_password_unlock_json(u: &user::Model) -> Value {
    let has_master_password = u.password_hash.as_ref().is_some_and(|v| !v.is_empty());
    if !has_master_password {
        return Value::Null;
    }

    serde_json::json!({
        "kdf": {
            "kdfType": u.client_kdf_type,
            "iterations": u.client_kdf_iter,
            "memory": u.client_kdf_memory,
            "parallelism": u.client_kdf_parallelism,
        },
        "masterKeyEncryptedUserKey": u.akey,
        "masterKeyWrappedUserKey": u.akey,
        "salt": u.email,
    })
}

fn parse_exclude_domains(url: &Url) -> bool {
    url.query_pairs()
        .find(|(k, _)| k == "excludeDomains")
        .map(|(_, v)| v == "true" || v == "1")
        .unwrap_or(false)
}

pub async fn handle_sync(req: Request, env: &Env) -> Result<Response> {
    let db = match db_connect(env).await {
        Ok(db) => db,
        Err(e) => return internal_error_response(&req, "Failed to open libSQL connection", &e),
    };

    let Some(token) = extract_bearer_token(&req)? else {
        return error_response(&req, 401, "unauthorized", "Missing bearer token");
    };

    let now = now_ts();
    let Some(dev) = device::Entity::find()
        .filter(device::Column::AccessToken.eq(&token))
        .one(&db)
        .await
        .map_err(|e| worker::Error::RustError(e.to_string()))?
    else {
        return error_response(&req, 401, "unauthorized", "Invalid token");
    };

    if let Some(exp) = dev.access_token_expires_at {
        if exp <= now {
            return error_response(&req, 401, "unauthorized", "Token expired");
        }
    }

    let Some(u) = user::Entity::find_by_id(dev.user_id.clone())
        .one(&db)
        .await
        .map_err(|e| worker::Error::RustError(e.to_string()))?
    else {
        return error_response(&req, 401, "unauthorized", "Invalid token");
    };

    if !u.enabled {
        return error_response(&req, 403, "forbidden", "User disabled");
    }

    let url = req.url()?;
    let exclude_domains = parse_exclude_domains(&url);

    let domains_json = if exclude_domains { Value::Null } else { Value::Null };

    let resp = Response::from_json(&serde_json::json!({
        "profile": profile_json(&u),
        "folders": [],
        "collections": [],
        "policies": [],
        "ciphers": [],
        "domains": domains_json,
        "sends": [],
        "userDecryption": {
            "masterPasswordUnlock": master_password_unlock_json(&u),
        },
        "object": "sync",
    }))?;

    json_with_cors(&req, resp)
}
