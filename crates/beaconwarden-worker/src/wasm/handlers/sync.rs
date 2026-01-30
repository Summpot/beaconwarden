use std::collections::{HashMap, HashSet};

use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use serde_json::Value;
use worker::{Env, Request, Response, Result, Url};

use crate::worker_wasm::db::db_connect;
use crate::worker_wasm::domains::domains_json_for_user;
use crate::worker_wasm::handlers::auth::{authenticate, AuthResult};
use crate::worker_wasm::http::{internal_error_response, json_with_cors};
use crate::worker_wasm::util::{normalize_user_id_for_client, ts_to_rfc3339};

use entity::{cipher, favorite, folder, folder_cipher, user};

fn folder_json(f: &folder::Model) -> Value {
    serde_json::json!({
        "id": f.id,
        "name": f.name,
        "revisionDate": ts_to_rfc3339(f.updated_at),
        "object": "folder",
    })
}

fn cipher_json(c: &cipher::Model, folder_id: Option<String>, favorite: bool) -> Value {
    let mut obj: Value = serde_json::from_str(&c.data).unwrap_or_else(|_| serde_json::json!({}));

    obj["id"] = Value::String(c.id.clone());
    obj["revisionDate"] = Value::String(ts_to_rfc3339(c.updated_at));
    obj["creationDate"] = Value::String(ts_to_rfc3339(c.created_at));
    obj["deletedDate"] = match c.deleted_at {
        Some(ts) => Value::String(ts_to_rfc3339(ts)),
        None => Value::Null,
    };
    obj["folderId"] = folder_id.map(Value::String).unwrap_or(Value::Null);
    obj["favorite"] = Value::Bool(favorite);

    if obj.get("object").and_then(|v| v.as_str()).is_none() {
        obj["object"] = Value::String("cipher".to_string());
    }

    obj
}

fn profile_json(u: &user::Model) -> Value {
    let status = if u.password_hash.as_ref().is_some_and(|v| !v.is_empty()) { 0 } else { 1 };
    serde_json::json!({
        "_status": status,
        "id": normalize_user_id_for_client(&u.id),
        "name": u.name.clone().unwrap_or_else(|| u.email.clone()),
        "email": u.email,
        "emailVerified": true,
        "premium": true,
        "premiumFromOrganization": false,
        "culture": "en-US",
        "twoFactorEnabled": false,
        "key": u.akey,
        "privateKey": u.private_key.clone().unwrap_or_default(),
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

    let auth = match authenticate(&req, &db).await? {
        AuthResult::Authorized(a) => a,
        AuthResult::Unauthorized(resp) => return Ok(resp),
    };
    let u = auth.user;

    let url = req.url()?;
    let exclude_domains = parse_exclude_domains(&url);

    let domains_json = if exclude_domains {
        Value::Null
    } else {
        domains_json_for_user(&u, true)
    };

    let folders = folder::Entity::find()
        .filter(folder::Column::UserId.eq(u.id.clone()))
        .all(&db)
        .await
        .map_err(|e| worker::Error::RustError(e.to_string()))?;

    let ciphers = cipher::Entity::find()
        .filter(cipher::Column::UserId.eq(u.id.clone()))
        .all(&db)
        .await
        .map_err(|e| worker::Error::RustError(e.to_string()))?;

    let favorite_ids: HashSet<String> = favorite::Entity::find()
        .filter(favorite::Column::UserId.eq(u.id.clone()))
        .all(&db)
        .await
        .map_err(|e| worker::Error::RustError(e.to_string()))?
        .into_iter()
        .map(|f| f.cipher_id)
        .collect();

    let cipher_ids: Vec<String> = ciphers.iter().map(|c| c.id.clone()).collect();
    let folder_map: HashMap<String, String> = if cipher_ids.is_empty() {
        HashMap::new()
    } else {
        let mappings = folder_cipher::Entity::find()
            .filter(folder_cipher::Column::CipherId.is_in(cipher_ids))
            .all(&db)
            .await
            .map_err(|e| worker::Error::RustError(e.to_string()))?;

        let mut map = HashMap::new();
        for m in mappings {
            map.entry(m.cipher_id).or_insert(m.folder_id);
        }
        map
    };

    let resp = Response::from_json(&serde_json::json!({
        "profile": profile_json(&u),
        "folders": folders.iter().map(folder_json).collect::<Vec<_>>(),
        "collections": [],
        "policies": [],
        "ciphers": ciphers
            .iter()
            .map(|c| cipher_json(c, folder_map.get(&c.id).cloned(), favorite_ids.contains(&c.id)))
            .collect::<Vec<_>>(),
        "domains": domains_json,
        "sends": [],
        "userDecryption": {
            "masterPasswordUnlock": master_password_unlock_json(&u),
        },
        "object": "sync",
    }))?;

    json_with_cors(&req, resp)
}
