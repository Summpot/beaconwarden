use std::time::Duration;

use serde::Deserialize;
use serde_json::Value;
use worker::{Env, Method, Request, Response, Result};

use sea_orm::{ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set};

use crate::worker_wasm::crypto;
use crate::worker_wasm::db::db_connect;
use crate::worker_wasm::env::env_string;
use crate::worker_wasm::handlers::auth::{authenticate, AuthResult};
use crate::worker_wasm::http::{error_response, internal_error_response, json_with_cors};
use crate::worker_wasm::util::{
    generate_access_token, generate_security_stamp, normalize_user_id_for_client, now_ts, random_bytes,
    ts_to_rfc3339, uuid_v4,
};
use crate::worker_wasm::{brevo};

use entity::{device, user, user::Entity as UserEntity};

fn profile_json(u: &user::Model) -> Value {
    let status = if u.password_hash.as_ref().is_some_and(|v| !v.is_empty()) {
        0
    } else {
        1
    };

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
        "avatarColor": u
            .avatar_color
            .as_ref()
            .filter(|s| !s.trim().is_empty())
            .map(|s| Value::String(s.clone()))
            .unwrap_or(Value::Null),
        "usesKeyConnector": false,
        "creationDate": Value::Null,
        "object": "profile",
    })
}

fn master_password_policy_json() -> Value {
    // Keep a stable shape and match Vaultwarden's PascalCase `Object`.
    serde_json::json!({
        "Object": "masterPasswordPolicy",
    })
}

fn clean_password_hint(password_hint: &Option<String>) -> Option<String> {
    match password_hint.as_ref().map(|s| s.trim()).filter(|s| !s.is_empty()) {
        Some(v) => Some(v.to_string()),
        None => None,
    }
}

fn verify_master_password_hash(u: &user::Model, master_password_hash: &str) -> bool {
    let Some(ref stored_hash) = u.password_hash else {
        return false;
    };
    let Some(ref salt) = u.salt else {
        return false;
    };

    crypto::verify_password_hash(
        master_password_hash.as_bytes(),
        salt,
        stored_hash,
        u.password_iterations as u32,
    )
}

async fn delete_other_devices(
    db: &DatabaseConnection,
    user_id: &str,
    keep_device_id: &str,
) -> Result<()> {
    device::Entity::delete_many()
        .filter(device::Column::UserId.eq(user_id))
        .filter(device::Column::Id.ne(keep_device_id))
        .exec(db)
        .await
        .map_err(|e| worker::Error::RustError(e.to_string()))?;
    Ok(())
}

async fn delete_all_devices(db: &DatabaseConnection, user_id: &str) -> Result<()> {
    device::Entity::delete_many()
        .filter(device::Column::UserId.eq(user_id))
        .exec(db)
        .await
        .map_err(|e| worker::Error::RustError(e.to_string()))?;
    Ok(())
}

pub async fn handle_profile(req: Request, env: &Env) -> Result<Response> {
    let db = match db_connect(env).await {
        Ok(db) => db,
        Err(e) => return internal_error_response(&req, "Failed to open libSQL connection", &e),
    };

    let auth = match authenticate(&req, &db).await? {
        AuthResult::Authorized(a) => a,
        AuthResult::Unauthorized(resp) => return Ok(resp),
    };

    let resp = Response::from_json(&profile_json(&auth.user))?;
    json_with_cors(&req, resp)
}

pub async fn handle_revision_date(req: Request, env: &Env) -> Result<Response> {
    let db = match db_connect(env).await {
        Ok(db) => db,
        Err(e) => return internal_error_response(&req, "Failed to open libSQL connection", &e),
    };

    let auth = match authenticate(&req, &db).await? {
        AuthResult::Authorized(a) => a,
        AuthResult::Unauthorized(resp) => return Ok(resp),
    };

    // Vaultwarden returns a timestamp in milliseconds.
    let revision_ms: i64 = auth.user.updated_at.saturating_mul(1000);
    let resp = Response::from_json(&revision_ms)?;
    json_with_cors(&req, resp)
}

pub async fn handle_tasks(req: Request, _env: &Env) -> Result<Response> {
    let resp = Response::from_json(&serde_json::json!({
        "data": [],
        "object": "list",
    }))?;
    json_with_cors(&req, resp)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProfileData {
    name: String,
}

/// POST/PUT /api/accounts/profile
pub async fn handle_profile_update(mut req: Request, env: &Env) -> Result<Response> {
    if req.method() != Method::Post && req.method() != Method::Put {
        return error_response(&req, 405, "method_not_allowed", "Method not allowed");
    }

    let payload: ProfileData = match req.json().await {
        Ok(p) => p,
        Err(e) => {
            worker::console_log!("Invalid JSON in accounts/profile: {e}");
            return error_response(&req, 400, "invalid_json", "Invalid JSON body");
        }
    };

    if payload.name.len() > 50 {
        return error_response(
            &req,
            400,
            "invalid_name",
            "The field Name must be a string with a maximum length of 50.",
        );
    }

    let db = match db_connect(env).await {
        Ok(db) => db,
        Err(e) => return internal_error_response(&req, "Failed to open libSQL connection", &e),
    };

    let auth = match authenticate(&req, &db).await? {
        AuthResult::Authorized(a) => a,
        AuthResult::Unauthorized(resp) => return Ok(resp),
    };

    let now = now_ts();
    let mut active: user::ActiveModel = auth.user.into();
    active.name = Set(Some(payload.name));
    active.updated_at = Set(now);

    let saved = match active.update(&db).await {
        Ok(u) => u,
        Err(e) => return internal_error_response(&req, "Failed to save user", &e),
    };

    let resp = Response::from_json(&profile_json(&saved))?;
    json_with_cors(&req, resp)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AvatarData {
    avatar_color: Option<String>,
}

/// PUT /api/accounts/avatar
pub async fn handle_avatar_update(mut req: Request, env: &Env) -> Result<Response> {
    if req.method() != Method::Put {
        return error_response(&req, 405, "method_not_allowed", "Method not allowed");
    }

    let payload: AvatarData = match req.json().await {
        Ok(p) => p,
        Err(e) => {
            worker::console_log!("Invalid JSON in accounts/avatar: {e}");
            return error_response(&req, 400, "invalid_json", "Invalid JSON body");
        }
    };

    if let Some(color) = payload.avatar_color.as_ref() {
        if color.len() != 7 {
            return error_response(
                &req,
                400,
                "invalid_avatar_color",
                "The field AvatarColor must be a HTML/Hex color code with a length of 7 characters",
            );
        }
    }

    let db = match db_connect(env).await {
        Ok(db) => db,
        Err(e) => return internal_error_response(&req, "Failed to open libSQL connection", &e),
    };

    let auth = match authenticate(&req, &db).await? {
        AuthResult::Authorized(a) => a,
        AuthResult::Unauthorized(resp) => return Ok(resp),
    };

    let now = now_ts();
    let mut active: user::ActiveModel = auth.user.into();
    active.avatar_color = Set(payload.avatar_color);
    active.updated_at = Set(now);

    let saved = match active.update(&db).await {
        Ok(u) => u,
        Err(e) => return internal_error_response(&req, "Failed to save user", &e),
    };

    let resp = Response::from_json(&profile_json(&saved))?;
    json_with_cors(&req, resp)
}

/// POST /api/accounts/keys
pub async fn handle_post_keys(mut req: Request, env: &Env) -> Result<Response> {
    if req.method() != Method::Post {
        return error_response(&req, 405, "method_not_allowed", "Method not allowed");
    }

    let payload: KeysData = match req.json().await {
        Ok(p) => p,
        Err(e) => {
            worker::console_log!("Invalid JSON in accounts/keys: {e}");
            return error_response(&req, 400, "invalid_json", "Invalid JSON body");
        }
    };

    let db = match db_connect(env).await {
        Ok(db) => db,
        Err(e) => return internal_error_response(&req, "Failed to open libSQL connection", &e),
    };

    let auth = match authenticate(&req, &db).await? {
        AuthResult::Authorized(a) => a,
        AuthResult::Unauthorized(resp) => return Ok(resp),
    };

    let now = now_ts();
    let mut active: user::ActiveModel = auth.user.into();
    active.private_key = Set(Some(payload.encrypted_private_key));
    active.public_key = Set(Some(payload.public_key));
    active.updated_at = Set(now);

    let saved = match active.update(&db).await {
        Ok(u) => u,
        Err(e) => return internal_error_response(&req, "Failed to save user", &e),
    };

    let resp = Response::from_json(&serde_json::json!({
        "privateKey": saved.private_key,
        "publicKey": saved.public_key,
        "object": "keys",
    }))?;

    json_with_cors(&req, resp)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChangePassData {
    master_password_hash: String,
    new_master_password_hash: String,
    master_password_hint: Option<String>,
    key: String,
}

/// POST /api/accounts/password
pub async fn handle_post_password(mut req: Request, env: &Env) -> Result<Response> {
    if req.method() != Method::Post {
        return error_response(&req, 405, "method_not_allowed", "Method not allowed");
    }

    let payload: ChangePassData = match req.json().await {
        Ok(p) => p,
        Err(e) => {
            worker::console_log!("Invalid JSON in accounts/password: {e}");
            return error_response(&req, 400, "invalid_json", "Invalid JSON body");
        }
    };

    let db = match db_connect(env).await {
        Ok(db) => db,
        Err(e) => return internal_error_response(&req, "Failed to open libSQL connection", &e),
    };

    let auth = match authenticate(&req, &db).await? {
        AuthResult::Authorized(a) => a,
        AuthResult::Unauthorized(resp) => return Ok(resp),
    };

    if !verify_master_password_hash(&auth.user, &payload.master_password_hash) {
        return error_response(&req, 400, "invalid_password", "Invalid password");
    }

    let now = now_ts();
    let salt = random_bytes(64);
    let server_iterations: i32 = 100_000;
    let pwd_hash = crypto::hash_password(
        payload.new_master_password_hash.as_bytes(),
        &salt,
        server_iterations as u32,
    );

    let mut active: user::ActiveModel = auth.user.into();
    active.password_hash = Set(Some(pwd_hash));
    active.salt = Set(Some(salt));
    active.password_iterations = Set(server_iterations);
    active.password_hint = Set(clean_password_hint(&payload.master_password_hint));
    active.akey = Set(payload.key);
    active.security_stamp = Set(generate_security_stamp());
    active.updated_at = Set(now);

    if let Err(e) = active.update(&db).await {
        return internal_error_response(&req, "Failed to save user", &e);
    }

    // Invalidate other sessions.
    if let Err(e) = delete_other_devices(&db, &auth.device.user_id, &auth.device.id).await {
        worker::console_log!("Failed to delete other devices after password change: {e}");
    }

    let resp = Response::empty()?.with_status(200);
    json_with_cors(&req, resp)
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct KdfData {
    #[serde(alias = "kdfType")]
    kdf: i32,
    #[serde(alias = "iterations")]
    kdf_iterations: i32,
    #[serde(alias = "memory")]
    kdf_memory: Option<i32>,
    #[serde(alias = "parallelism")]
    kdf_parallelism: Option<i32>,
}

fn validate_kdf_settings(data: &KdfData) -> std::result::Result<(), &'static str> {
    // 0 = PBKDF2, 1 = Argon2id
    if data.kdf == 0 {
        if data.kdf_iterations < 100_000 {
            return Err("PBKDF2 KDF iterations must be at least 100000.");
        }
        return Ok(());
    }

    if data.kdf == 1 {
        if data.kdf_iterations < 1 {
            return Err("Argon2 KDF iterations must be at least 1.");
        }
        let Some(m) = data.kdf_memory else {
            return Err("Argon2 memory parameter is required.");
        };
        if !(15..=1024).contains(&m) {
            return Err("Argon2 memory must be between 15 MB and 1024 MB.");
        }
        let Some(p) = data.kdf_parallelism else {
            return Err("Argon2 parallelism parameter is required.");
        };
        if !(1..=16).contains(&p) {
            return Err("Argon2 parallelism must be between 1 and 16.");
        }
        return Ok(());
    }

    Err("Unsupported KDF type")
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuthenticationData {
    salt: String,
    kdf: KdfData,
    master_password_authentication_hash: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UnlockData {
    salt: String,
    kdf: KdfData,
    master_key_wrapped_user_key: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChangeKdfData {
    // Kept for compatibility but not used by Vaultwarden for the update itself.
    new_master_password_hash: Option<String>,
    key: Option<String>,
    authentication_data: AuthenticationData,
    unlock_data: UnlockData,
    master_password_hash: String,
}

/// POST /api/accounts/kdf
pub async fn handle_post_kdf(mut req: Request, env: &Env) -> Result<Response> {
    if req.method() != Method::Post {
        return error_response(&req, 405, "method_not_allowed", "Method not allowed");
    }

    let payload: ChangeKdfData = match req.json().await {
        Ok(p) => p,
        Err(e) => {
            worker::console_log!("Invalid JSON in accounts/kdf: {e}");
            return error_response(&req, 400, "invalid_json", "Invalid JSON body");
        }
    };

    if payload.authentication_data.kdf != payload.unlock_data.kdf {
        return error_response(
            &req,
            400,
            "invalid_kdf",
            "KDF settings must be equal for authentication and unlock",
        );
    }

    if let Err(msg) = validate_kdf_settings(&payload.unlock_data.kdf) {
        return error_response(&req, 400, "invalid_kdf", msg);
    }

    let db = match db_connect(env).await {
        Ok(db) => db,
        Err(e) => return internal_error_response(&req, "Failed to open libSQL connection", &e),
    };

    let auth = match authenticate(&req, &db).await? {
        AuthResult::Authorized(a) => a,
        AuthResult::Unauthorized(resp) => return Ok(resp),
    };

    if !verify_master_password_hash(&auth.user, &payload.master_password_hash) {
        return error_response(&req, 400, "invalid_password", "Invalid password");
    }

    // Salt must match email (Vaultwarden requirement).
    if auth.user.email != payload.authentication_data.salt || auth.user.email != payload.unlock_data.salt {
        return error_response(&req, 400, "invalid_salt", "Invalid master password salt");
    }

    let now = now_ts();
    let salt = random_bytes(64);
    let server_iterations: i32 = 100_000;
    let pwd_hash = crypto::hash_password(
        payload
            .authentication_data
            .master_password_authentication_hash
            .as_bytes(),
        &salt,
        server_iterations as u32,
    );

    let mut active: user::ActiveModel = auth.user.into();
    active.client_kdf_type = Set(payload.unlock_data.kdf.kdf);
    active.client_kdf_iter = Set(payload.unlock_data.kdf.kdf_iterations);
    active.client_kdf_memory = Set(payload.unlock_data.kdf.kdf_memory);
    active.client_kdf_parallelism = Set(payload.unlock_data.kdf.kdf_parallelism);

    active.password_hash = Set(Some(pwd_hash));
    active.salt = Set(Some(salt));
    active.password_iterations = Set(server_iterations);
    active.akey = Set(payload.unlock_data.master_key_wrapped_user_key);
    active.security_stamp = Set(generate_security_stamp());
    active.updated_at = Set(now);

    if let Err(e) = active.update(&db).await {
        return internal_error_response(&req, "Failed to save user", &e);
    }

    // Invalidate other sessions.
    if let Err(e) = delete_other_devices(&db, &auth.device.user_id, &auth.device.id).await {
        worker::console_log!("Failed to delete other devices after kdf change: {e}");
    }

    let resp = Response::empty()?.with_status(200);
    json_with_cors(&req, resp)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SecretVerificationRequest {
    master_password_hash: String,
}

/// POST /api/accounts/verify-password
pub async fn handle_verify_password(mut req: Request, env: &Env) -> Result<Response> {
    if req.method() != Method::Post {
        return error_response(&req, 405, "method_not_allowed", "Method not allowed");
    }

    let payload: SecretVerificationRequest = match req.json().await {
        Ok(p) => p,
        Err(e) => {
            worker::console_log!("Invalid JSON in accounts/verify-password: {e}");
            return error_response(&req, 400, "invalid_json", "Invalid JSON body");
        }
    };

    let db = match db_connect(env).await {
        Ok(db) => db,
        Err(e) => return internal_error_response(&req, "Failed to open libSQL connection", &e),
    };

    let auth = match authenticate(&req, &db).await? {
        AuthResult::Authorized(a) => a,
        AuthResult::Unauthorized(resp) => return Ok(resp),
    };

    if !verify_master_password_hash(&auth.user, &payload.master_password_hash) {
        return error_response(&req, 400, "invalid_password", "Invalid password");
    }

    let resp = Response::from_json(&master_password_policy_json())?;
    json_with_cors(&req, resp)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PasswordOrOtpData {
    #[serde(alias = "MasterPasswordHash")]
    master_password_hash: Option<String>,
    otp: Option<String>,
}

impl PasswordOrOtpData {
    fn master_password_hash(&self) -> Option<&str> {
        self.master_password_hash.as_deref().filter(|s| !s.trim().is_empty())
    }
}

async fn api_key_impl(mut req: Request, env: &Env, rotate: bool) -> Result<Response> {
    let payload: PasswordOrOtpData = match req.json().await {
        Ok(p) => p,
        Err(e) => {
            worker::console_log!("Invalid JSON in accounts/api-key: {e}");
            return error_response(&req, 400, "invalid_json", "Invalid JSON body");
        }
    };

    let db = match db_connect(env).await {
        Ok(db) => db,
        Err(e) => return internal_error_response(&req, "Failed to open libSQL connection", &e),
    };

    let auth = match authenticate(&req, &db).await? {
        AuthResult::Authorized(a) => a,
        AuthResult::Unauthorized(resp) => return Ok(resp),
    };

    // OTP is not supported yet in the Worker runtime.
    let Some(master_hash) = payload.master_password_hash() else {
        return error_response(&req, 400, "invalid_password", "Invalid password");
    };
    if !verify_master_password_hash(&auth.user, master_hash) {
        return error_response(&req, 400, "invalid_password", "Invalid password");
    }

    let now = now_ts();
    let should_rotate = rotate || auth.user.api_key.is_none();
    let mut active: user::ActiveModel = auth.user.into();

    if should_rotate {
        active.api_key = Set(Some(generate_access_token()));
    }
    active.updated_at = Set(now);

    let saved = match active.update(&db).await {
        Ok(u) => u,
        Err(e) => return internal_error_response(&req, "Failed to save user", &e),
    };

    let resp = Response::from_json(&serde_json::json!({
        "apiKey": saved.api_key,
        "revisionDate": ts_to_rfc3339(saved.updated_at),
        "object": "apiKey",
    }))?;

    json_with_cors(&req, resp)
}

/// POST /api/accounts/api-key
pub async fn handle_api_key(req: Request, env: &Env) -> Result<Response> {
    if req.method() != Method::Post {
        return error_response(&req, 405, "method_not_allowed", "Method not allowed");
    }
    api_key_impl(req, env, false).await
}

/// POST /api/accounts/rotate-api-key
pub async fn handle_rotate_api_key(req: Request, env: &Env) -> Result<Response> {
    if req.method() != Method::Post {
        return error_response(&req, 405, "method_not_allowed", "Method not allowed");
    }
    api_key_impl(req, env, true).await
}

/// POST /api/accounts/security-stamp
pub async fn handle_security_stamp(mut req: Request, env: &Env) -> Result<Response> {
    if req.method() != Method::Post {
        return error_response(&req, 405, "method_not_allowed", "Method not allowed");
    }

    let payload: PasswordOrOtpData = match req.json().await {
        Ok(p) => p,
        Err(e) => {
            worker::console_log!("Invalid JSON in accounts/security-stamp: {e}");
            return error_response(&req, 400, "invalid_json", "Invalid JSON body");
        }
    };

    let db = match db_connect(env).await {
        Ok(db) => db,
        Err(e) => return internal_error_response(&req, "Failed to open libSQL connection", &e),
    };

    let auth = match authenticate(&req, &db).await? {
        AuthResult::Authorized(a) => a,
        AuthResult::Unauthorized(resp) => return Ok(resp),
    };

    let Some(master_hash) = payload.master_password_hash() else {
        return error_response(&req, 400, "invalid_password", "Invalid password");
    };
    if !verify_master_password_hash(&auth.user, master_hash) {
        return error_response(&req, 400, "invalid_password", "Invalid password");
    }

    // Delete all devices (logs out everywhere) and rotate security stamp.
    if let Err(e) = delete_all_devices(&db, &auth.user.id).await {
        return internal_error_response(&req, "Failed to delete user devices", &e);
    }

    let now = now_ts();
    let mut active: user::ActiveModel = auth.user.into();
    active.security_stamp = Set(generate_security_stamp());
    active.updated_at = Set(now);
    if let Err(e) = active.update(&db).await {
        return internal_error_response(&req, "Failed to save user", &e);
    }

    let resp = Response::empty()?.with_status(200);
    json_with_cors(&req, resp)
}

pub async fn handle_user_public_key(req: Request, env: &Env, user_id: String) -> Result<Response> {
    let db = match db_connect(env).await {
        Ok(db) => db,
        Err(e) => return internal_error_response(&req, "Failed to open libSQL connection", &e),
    };

    // Matches legacy behavior: require authentication but allow fetching arbitrary users' public keys.
    let _auth = match authenticate(&req, &db).await? {
        AuthResult::Authorized(a) => a,
        AuthResult::Unauthorized(resp) => return Ok(resp),
    };

    let user_id = normalize_user_id_for_client(&user_id);
    let found = user::Entity::find_by_id(user_id.clone())
        .one(&db)
        .await
        .map_err(|e| worker::Error::RustError(e.to_string()))?;

    let Some(u) = found else {
        return error_response(&req, 404, "not_found", "User doesn't exist");
    };

    let Some(pk) = u.public_key.as_ref().filter(|s| !s.trim().is_empty()) else {
        return error_response(&req, 404, "not_found", "User has no public_key");
    };

    let resp = Response::from_json(&serde_json::json!({
        "userId": normalize_user_id_for_client(&u.id),
        "publicKey": pk,
        "object": "userKey",
    }))?;

    json_with_cors(&req, resp)
}

fn base_url(req: &Request, env: &Env) -> Result<String> {
    if let Some(v) = env_string(env, "BASE_URL") {
        return Ok(v.trim_end_matches('/').to_string());
    }

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

    Ok(origin.trim_end_matches('/').to_string())
}

async fn enumeration_delay() {
    // Approximate Vaultwarden's mitigation (1s +/- 100ms) to reduce timing side-channels.
    let jitter = {
        let b = random_bytes(2);
        let raw = u16::from_le_bytes([b[0], b[1]]) as i32;
        (raw % 201) - 100
    };
    let sleep_ms: i32 = 1_000 + jitter;
    worker::Delay::from(Duration::from_millis(sleep_ms.max(0) as u64)).await;
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreloginData {
    email: String,
}

pub async fn handle_prelogin(mut req: Request, env: &Env) -> Result<Response> {
    let db = match db_connect(env).await {
        Ok(db) => db,
        Err(e) => return internal_error_response(&req, "Failed to open libSQL connection", &e),
    };

    let payload: PreloginData = match req.json().await {
        Ok(p) => p,
        Err(e) => {
            worker::console_log!("Invalid JSON in prelogin: {e}");
            return error_response(&req, 400, "invalid_json", "Invalid JSON body");
        }
    };

    let email = payload.email.trim().to_lowercase();
    if email.is_empty() {
        return error_response(&req, 400, "invalid_email", "Email cannot be blank");
    }

    let found = UserEntity::find()
        .filter(user::Column::Email.eq(&email))
        .one(&db)
        .await
        .map_err(|e| worker::Error::RustError(e.to_string()))?;

    let (kdf_type, kdf_iter, kdf_mem, kdf_para) = match found {
        Some(u) => (
            u.client_kdf_type,
            u.client_kdf_iter,
            u.client_kdf_memory,
            u.client_kdf_parallelism,
        ),
        None => (0, 600_000, None, None),
    };

    let resp = Response::from_json(&serde_json::json!({
        "kdf": kdf_type,
        "kdfIterations": kdf_iter,
        "kdfMemory": kdf_mem,
        "kdfParallelism": kdf_para,
    }))?;

    json_with_cors(&req, resp)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeysData {
    encrypted_private_key: String,
    public_key: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RegisterData {
    pub(crate) email: String,

    #[serde(alias = "kdfType")]
    kdf: i32,
    #[serde(alias = "iterations")]
    kdf_iterations: i32,
    #[serde(alias = "memory")]
    kdf_memory: Option<i32>,
    #[serde(alias = "parallelism")]
    kdf_parallelism: Option<i32>,

    #[serde(alias = "userSymmetricKey")]
    key: String,
    #[serde(alias = "userAsymmetricKeys")]
    keys: Option<KeysData>,

    #[serde(rename = "masterPasswordHash")]
    master_password_hash: String,

    pub(crate) name: Option<String>,

    // Used by the identity register/finish flow.
    pub(crate) email_verification_token: Option<String>,
}

fn validate_kdf(data: &RegisterData) -> std::result::Result<(), &'static str> {
    // 0 = PBKDF2, 1 = Argon2id
    if data.kdf == 0 {
        if data.kdf_iterations < 100_000 {
            return Err("PBKDF2 KDF iterations must be at least 100000.");
        }
        return Ok(());
    }

    if data.kdf == 1 {
        if data.kdf_iterations < 1 {
            return Err("Argon2 KDF iterations must be at least 1.");
        }
        let Some(m) = data.kdf_memory else {
            return Err("Argon2 memory parameter is required.");
        };
        if !(15..=1024).contains(&m) {
            return Err("Argon2 memory must be between 15 MB and 1024 MB.");
        }
        let Some(p) = data.kdf_parallelism else {
            return Err("Argon2 parallelism parameter is required.");
        };
        if !(1..=16).contains(&p) {
            return Err("Argon2 parallelism must be between 1 and 16.");
        }
        return Ok(());
    }

    Err("Unsupported KDF type")
}

pub async fn handle_register(mut req: Request, env: &Env) -> Result<Response> {
    let db = match db_connect(env).await {
        Ok(db) => db,
        Err(e) => return internal_error_response(&req, "Failed to open libSQL connection", &e),
    };

    let payload: RegisterData = match req.json().await {
        Ok(p) => p,
        Err(e) => {
            worker::console_log!("Invalid JSON in register: {e}");
            return error_response(&req, 400, "invalid_json", "Invalid JSON body");
        }
    };

    register_with_db(&req, &db, payload, None).await
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordHintData {
    email: String,
}

pub async fn handle_password_hint(mut req: Request, env: &Env) -> Result<Response> {
    // NOTE: This endpoint should not reveal whether a user exists.
    // We return 200 with an empty body in all normal cases.

    let payload: PasswordHintData = match req.json().await {
        Ok(p) => p,
        Err(e) => {
            worker::console_log!("Invalid JSON in password-hint: {e}");
            return error_response(&req, 400, "invalid_json", "Invalid JSON body");
        }
    };

    let email = payload.email.trim().to_lowercase();
    if email.is_empty() {
        return error_response(&req, 400, "invalid_email", "Email cannot be blank");
    }

    // If email sending isn't configured, we still return success.
    // Vaultwarden can optionally display the hint without SMTP; we don't expose that here.
    let mail_enabled = brevo::brevo_is_configured(env);
    if !mail_enabled {
        let resp = Response::empty()?.with_status(200);
        return json_with_cors(&req, resp);
    }

    let db = match db_connect(env).await {
        Ok(db) => db,
        Err(e) => return internal_error_response(&req, "Failed to open libSQL connection", &e),
    };

    let found = UserEntity::find()
        .filter(user::Column::Email.eq(&email))
        .one(&db)
        .await
        .map_err(|e| worker::Error::RustError(e.to_string()))?;

    match found {
        None => {
            // Mitigate timing differences vs the email-sending path.
            enumeration_delay().await;
        }
        Some(u) => {
            // Password hints aren't persisted yet in the new minimal user schema.
            // Send the "no hint" email to keep behavior stable for clients.
            let hint: Option<String> = None;
            let url = base_url(&req, env).unwrap_or_default();

            let subject = "Your master password hint";
            let text = if let Some(h) = hint {
                format!(
                    "You (or someone) recently requested your master password hint.\n\nYour hint is: {h}\n\nLog in to the web vault: {url}/\n"
                )
            } else {
                format!(
                    "You (or someone) recently requested your master password hint. Unfortunately, your account does not have a master password hint.\n\nLog in to the web vault: {url}/\n"
                )
            };

            if let Err(e) = brevo::send_email(env, &email, u.name.as_deref(), subject, None, Some(text)).await {
                // Best-effort: do not fail the request (prevents enumeration + avoids client UX issues).
                worker::console_log!("Failed to send password hint email: {e}");
            }
        }
    }

    let resp = Response::empty()?.with_status(200);
    json_with_cors(&req, resp)
}

pub(crate) async fn register_with_db(
    req: &Request,
    db: &DatabaseConnection,
    payload: RegisterData,
    name_override: Option<String>,
) -> Result<Response> {
    let email = payload.email.trim().to_lowercase();
    if email.is_empty() {
        return error_response(req, 400, "invalid_email", "Email cannot be blank");
    }

    if let Some(ref name) = payload.name {
        if name.len() > 50 {
            return error_response(
                req,
                400,
                "invalid_name",
                "The field Name must be a string with a maximum length of 50.",
            );
        }
    }

    if let Err(msg) = validate_kdf(&payload) {
        return error_response(req, 400, "invalid_kdf", msg);
    }

    let existing = UserEntity::find()
        .filter(user::Column::Email.eq(&email))
        .one(db)
        .await
        .map_err(|e| worker::Error::RustError(e.to_string()))?;

    if let Some(u) = existing.as_ref() {
        // Treat any existing non-empty password hash as an already-registered user.
        if u.password_hash.as_ref().is_some_and(|v| !v.is_empty()) {
            return error_response(&req, 400, "already_registered", "User already exists");
        }
    }

    let now = now_ts();
    let salt = random_bytes(64);
    let server_iterations: i32 = 100_000;
    let pwd_hash =
        crypto::hash_password(payload.master_password_hash.as_bytes(), &salt, server_iterations as u32);

    let final_name = payload
        .name
        .clone()
        .or(name_override)
        .or_else(|| Some(email.clone()));

    let private_key = payload.keys.as_ref().map(|k| k.encrypted_private_key.clone());
    let public_key = payload.keys.as_ref().map(|k| k.public_key.clone());

    // Insert or update.
    // NOTE: SeaORM's `save()` will attempt UPDATE when the primary key is set.
    // Our IDs are client-generated strings, so new records must use INSERT explicitly.
    if let Some(u) = existing {
        let mut active: user::ActiveModel = u.into();
        active.email = Set(email.clone());
        active.enabled = Set(true);
        active.name = Set(final_name.clone());
        active.password_hash = Set(Some(pwd_hash.clone()));
        active.salt = Set(Some(salt.clone()));
        active.password_iterations = Set(server_iterations);
        active.akey = Set(payload.key.clone());
        active.private_key = Set(private_key.clone());
        active.public_key = Set(public_key.clone());
        active.security_stamp = Set(generate_security_stamp());
        active.client_kdf_type = Set(payload.kdf);
        active.client_kdf_iter = Set(payload.kdf_iterations);
        active.client_kdf_memory = Set(payload.kdf_memory);
        active.client_kdf_parallelism = Set(payload.kdf_parallelism);
        active.updated_at = Set(now);

        if let Err(e) = active.update(db).await {
            return internal_error_response(req, "Failed to save user", &e);
        }
    } else {
        let id = uuid_v4();
        let active: user::ActiveModel = user::ActiveModel {
            id: Set(id),
            email: Set(email.clone()),
            enabled: Set(true),
            name: Set(final_name.clone()),
            password_hash: Set(Some(pwd_hash.clone())),
            salt: Set(Some(salt.clone())),
            password_iterations: Set(server_iterations),
            password_hint: Set(None),
            akey: Set(payload.key.clone()),
            private_key: Set(private_key.clone()),
            public_key: Set(public_key.clone()),
            verified_at: Set(None),
            last_verifying_at: Set(None),
            login_verify_count: Set(0),
            email_new: Set(None),
            email_new_token: Set(None),
            totp_secret: Set(None),
            totp_recover: Set(None),
            security_stamp: Set(generate_security_stamp()),
            stamp_exception: Set(None),
            client_kdf_type: Set(payload.kdf),
            client_kdf_iter: Set(payload.kdf_iterations),
            client_kdf_memory: Set(payload.kdf_memory),
            client_kdf_parallelism: Set(payload.kdf_parallelism),
            equivalent_domains: Set("[]".to_string()),
            excluded_globals: Set("[]".to_string()),
            api_key: Set(None),
            avatar_color: Set(None),
            external_id: Set(None),
            created_at: Set(now),
            updated_at: Set(now),
        };

        if let Err(insert_err) = active.insert(db).await {
            // If we raced another request, retry by loading the user and updating it.
            match UserEntity::find()
                .filter(user::Column::Email.eq(&email))
                .one(db)
                .await
            {
                Ok(Some(u)) => {
                    if u.password_hash.as_ref().is_some_and(|v| !v.is_empty()) {
                        return error_response(req, 400, "already_registered", "User already exists");
                    }

                    let mut active: user::ActiveModel = u.into();
                    active.email = Set(email.clone());
                    active.enabled = Set(true);
                    active.name = Set(final_name.clone());
                    active.password_hash = Set(Some(pwd_hash.clone()));
                    active.salt = Set(Some(salt.clone()));
                    active.password_iterations = Set(server_iterations);
                    active.akey = Set(payload.key.clone());
                    active.private_key = Set(private_key.clone());
                    active.public_key = Set(public_key.clone());
                    active.security_stamp = Set(generate_security_stamp());
                    active.client_kdf_type = Set(payload.kdf);
                    active.client_kdf_iter = Set(payload.kdf_iterations);
                    active.client_kdf_memory = Set(payload.kdf_memory);
                    active.client_kdf_parallelism = Set(payload.kdf_parallelism);
                    active.updated_at = Set(now);

                    if let Err(e) = active.update(db).await {
                        return internal_error_response(req, "Failed to save user", &e);
                    }
                }
                Ok(None) => return internal_error_response(req, "Failed to save user", &insert_err),
                Err(e) => return internal_error_response(req, "Failed to save user", &e),
            }
        }
    }

    let resp = Response::from_json(&serde_json::json!({
        "object": "register",
        "captchaBypassToken": "",
    }))?;

    json_with_cors(req, resp)
}
