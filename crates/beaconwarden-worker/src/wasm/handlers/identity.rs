use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use serde_json::Value;
use worker::{Env, FormData, Method, Request, Response, Result};

use crate::worker_wasm::crypto;
use crate::worker_wasm::db::db_connect;
use crate::worker_wasm::http::{error_response, internal_error_response, json_with_cors};
use crate::worker_wasm::util::{generate_access_token, generate_refresh_token, now_ts, random_bytes};

use entity::{device, user};

fn form_get_string(form: &FormData, key: &str) -> Option<String> {
    form.get(key).and_then(|v| match v {
        worker::FormEntry::Field(s) => Some(s),
        worker::FormEntry::File(_) => None,
    })
}

fn oauth_error(req: &Request, status: u16, err: &str, desc: &str) -> Result<Response> {
    let resp = Response::from_json(&serde_json::json!({
        "error": err,
        "error_description": desc,
    }))?
    .with_status(status);

    json_with_cors(req, resp)
}

fn master_password_unlock_json(u: &user::Model, has_master_password: bool) -> Value {
    if !has_master_password {
        return Value::Null;
    }

    serde_json::json!({
        "Kdf": {
            "KdfType": u.client_kdf_type,
            "Iterations": u.client_kdf_iter,
            "Memory": u.client_kdf_memory,
            "Parallelism": u.client_kdf_parallelism,
        },
        "MasterKeyEncryptedUserKey": u.akey,
        "MasterKeyWrappedUserKey": u.akey,
        "Salt": u.email,
    })
}

fn account_keys_json(u: &user::Model) -> Value {
    serde_json::json!({
        "publicKeyEncryptionKeyPair": {
            "wrappedPrivateKey": u.private_key,
            "publicKey": u.public_key,
            "Object": "publicKeyEncryptionKeyPair"
        },
        "Object": "privateKeys"
    })
}

fn token_response_json(u: &user::Model, access_token: &str, refresh_token: &str, scope: &str, expires_in: i64) -> Value {
    let has_master_password = u.password_hash.as_ref().is_some_and(|v| !v.is_empty());

    let mut result = serde_json::json!({
        "access_token": access_token,
        "expires_in": expires_in,
        "token_type": "Bearer",
        "refresh_token": refresh_token,
        "PrivateKey": u.private_key,

        "Kdf": u.client_kdf_type,
        "KdfIterations": u.client_kdf_iter,
        "KdfMemory": u.client_kdf_memory,
        "KdfParallelism": u.client_kdf_parallelism,

        "ResetMasterPassword": false,
        "ForcePasswordReset": false,

        // Minimal stub; official server returns an object.
        "MasterPasswordPolicy": { "Object": "masterPasswordPolicy" },

        "scope": scope,

        "AccountKeys": account_keys_json(u),

        "UserDecryptionOptions": {
            "HasMasterPassword": has_master_password,
            "MasterPasswordUnlock": master_password_unlock_json(u, has_master_password),
            "Object": "userDecryptionOptions",
        },
    });

    if !u.akey.is_empty() {
        result["Key"] = Value::String(u.akey.clone());
    }

    result
}

pub async fn handle_connect_token(mut req: Request, env: &Env) -> Result<Response> {
    if req.method() != Method::Post {
        return error_response(&req, 405, "method_not_allowed", "Method not allowed");
    }

    let db = match db_connect(env).await {
        Ok(db) => db,
        Err(e) => return internal_error_response(&req, "Failed to open libSQL connection", &e),
    };

    let form = match req.form_data().await {
        Ok(f) => f,
        Err(e) => {
            worker::console_log!("Invalid form data: {e}");
            return oauth_error(&req, 400, "invalid_request", "Invalid form body");
        }
    };

    let grant_type = form_get_string(&form, "grant_type")
        .or_else(|| form_get_string(&form, "granttype"))
        .unwrap_or_default();

    match grant_type.as_str() {
        "password" => password_grant(&req, env, &db, &form).await,
        "refresh_token" => refresh_grant(&req, env, &db, &form).await,
        _ => oauth_error(&req, 400, "invalid_request", "Invalid grant_type"),
    }
}

async fn password_grant(
    req: &Request,
    _env: &Env,
    db: &sea_orm::DatabaseConnection,
    form: &FormData,
) -> Result<Response> {
    let username = form_get_string(form, "username").unwrap_or_default().trim().to_lowercase();
    let password = form_get_string(form, "password").unwrap_or_default();

    let client_id = form_get_string(form, "client_id").unwrap_or_default();
    let scope = form_get_string(form, "scope").unwrap_or_else(|| "api offline_access".to_string());

    let device_identifier = form_get_string(form, "device_identifier")
        .or_else(|| form_get_string(form, "deviceidentifier"))
        .unwrap_or_default();
    let device_name = form_get_string(form, "device_name")
        .or_else(|| form_get_string(form, "devicename"))
        .unwrap_or_else(|| "Unknown".to_string());
    let device_type_str = form_get_string(form, "device_type")
        .or_else(|| form_get_string(form, "devicetype"))
        .unwrap_or_default();

    if username.is_empty() || password.is_empty() || client_id.is_empty() || device_identifier.is_empty() {
        return oauth_error(req, 400, "invalid_request", "Missing required fields");
    }

    let Some(u) = user::Entity::find()
        .filter(user::Column::Email.eq(&username))
        .one(db)
        .await
        .map_err(|e| worker::Error::RustError(e.to_string()))?
    else {
        return oauth_error(req, 400, "invalid_grant", "Username or password is incorrect. Try again");
    };

    if !u.enabled {
        return oauth_error(req, 400, "invalid_grant", "This user has been disabled");
    }

    let Some(ref stored_hash) = u.password_hash else {
        return oauth_error(req, 400, "invalid_grant", "Username or password is incorrect. Try again");
    };
    let Some(ref salt) = u.salt else {
        return oauth_error(req, 400, "invalid_grant", "Username or password is incorrect. Try again");
    };

    if !crypto::verify_password_hash(password.as_bytes(), salt, stored_hash, u.password_iterations as u32) {
        return oauth_error(req, 400, "invalid_grant", "Username or password is incorrect. Try again");
    }

    let device_type = device_type_str.parse::<i32>().unwrap_or(14);
    let now = now_ts();

    // Find or create device.
    let existing_device = device::Entity::find_by_id(device_identifier.clone())
        .one(db)
        .await
        .map_err(|e| worker::Error::RustError(e.to_string()))?;

    let mut dev_active: device::ActiveModel = match existing_device {
        Some(d) => {
            if d.user_id != u.id {
                return oauth_error(req, 400, "invalid_grant", "Device identifier is already registered");
            }
            let mut active: device::ActiveModel = d.into();
            active.name = Set(device_name.clone());
            active.device_type = Set(device_type);
            active
        }
        None => device::ActiveModel {
            id: Set(device_identifier.clone()),
            user_id: Set(u.id.clone()),
            name: Set(device_name.clone()),
            device_type: Set(device_type),
            push_uuid: Set(Some(crate::worker_wasm::util::hex_encode(&random_bytes(16)))),
            push_token: Set(None),
            refresh_token: Set(String::new()),
            twofactor_remember: Set(None),
            access_token: Set(None),
            access_token_expires_at: Set(None),
            created_at: Set(now),
            updated_at: Set(now),
        },
    };

    // Rotate refresh token on successful login.
    let refresh_token = generate_refresh_token();
    dev_active.refresh_token = Set(refresh_token.clone());

    let access_token = generate_access_token();
    let expires_in: i64 = 3600;
    dev_active.access_token = Set(Some(access_token.clone()));
    dev_active.access_token_expires_at = Set(Some(now + expires_in));
    dev_active.updated_at = Set(now);

    if let Err(e) = dev_active.save(db).await {
        return internal_error_response(req, "Failed to save device", &e);
    }

    let json = token_response_json(&u, &access_token, &refresh_token, &scope, expires_in);
    let resp = Response::from_json(&json)?;
    json_with_cors(req, resp)
}

async fn refresh_grant(
    req: &Request,
    _env: &Env,
    db: &sea_orm::DatabaseConnection,
    form: &FormData,
) -> Result<Response> {
    let refresh_token = form_get_string(form, "refresh_token")
        .or_else(|| form_get_string(form, "refreshtoken"))
        .unwrap_or_default();

    if refresh_token.is_empty() {
        return oauth_error(req, 401, "invalid_grant", "Missing refresh_token");
    }

    let Some(dev) = device::Entity::find()
        .filter(device::Column::RefreshToken.eq(&refresh_token))
        .one(db)
        .await
        .map_err(|e| worker::Error::RustError(e.to_string()))?
    else {
        return oauth_error(req, 401, "invalid_grant", "Unable to refresh login credentials");
    };

    let Some(u) = user::Entity::find_by_id(dev.user_id.clone())
        .one(db)
        .await
        .map_err(|e| worker::Error::RustError(e.to_string()))?
    else {
        return oauth_error(req, 401, "invalid_grant", "Unable to refresh login credentials");
    };

    if !u.enabled {
        return oauth_error(req, 401, "invalid_grant", "Unable to refresh login credentials");
    }

    let now = now_ts();
    let expires_in: i64 = 3600;

    let new_refresh_token = generate_refresh_token();
    let access_token = generate_access_token();

    let mut active: device::ActiveModel = dev.into();
    active.refresh_token = Set(new_refresh_token.clone());
    active.access_token = Set(Some(access_token.clone()));
    active.access_token_expires_at = Set(Some(now + expires_in));
    active.updated_at = Set(now);

    if let Err(e) = active.save(db).await {
        return internal_error_response(req, "Failed to save device", &e);
    }

    // Scope is not included in refresh requests by some clients. Keep the canonical one.
    let scope = form_get_string(form, "scope").unwrap_or_else(|| "api offline_access".to_string());

    let json = token_response_json(&u, &access_token, &new_refresh_token, &scope, expires_in);
    let resp = Response::from_json(&json)?;
    json_with_cors(req, resp)
}
