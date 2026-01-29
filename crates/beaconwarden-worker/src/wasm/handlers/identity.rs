use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use serde_json::Value;
use serde::Serialize;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use worker::{Env, FormData, Method, Request, Response, Result, Url};
use std::time::Duration;

use crate::worker_wasm::crypto;
use crate::worker_wasm::db::db_connect;
use crate::worker_wasm::http::{error_response, internal_error_response, json_with_cors};
use crate::worker_wasm::jwt;
use crate::worker_wasm::util::{generate_refresh_token, normalize_user_id_for_client, now_ts, random_bytes};
use crate::worker_wasm::{brevo, env::env_string};

use entity::{device, server_secret, user};
use entity::{register_verification, register_verification::Entity as RegisterVerificationEntity};

use super::accounts;

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
    let private_key = u.private_key.clone().unwrap_or_default();
    let public_key = u.public_key.clone().unwrap_or_default();

    serde_json::json!({
        "publicKeyEncryptionKeyPair": {
            "wrappedPrivateKey": private_key,
            "publicKey": public_key,
            "Object": "publicKeyEncryptionKeyPair"
        },
        "Object": "privateKeys"
    })
}

fn token_response_json(u: &user::Model, access_token: &str, refresh_token: &str, scope: &str, expires_in: i64) -> Value {
    let has_master_password = u.password_hash.as_ref().is_some_and(|v| !v.is_empty());
    let private_key = u.private_key.clone().unwrap_or_default();

    let mut result = serde_json::json!({
        "access_token": access_token,
        "expires_in": expires_in,
        "token_type": "Bearer",
        "refresh_token": refresh_token,
        "PrivateKey": private_key,

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

#[derive(Debug, Clone, Serialize)]
struct LoginJwtClaims {
    // Not before
    nbf: i64,
    // Expiration time
    exp: i64,
    // Issuer
    iss: String,
    // Subject (user id)
    sub: String,

    premium: bool,
    name: String,
    email: String,
    email_verified: bool,

    // user security_stamp
    sstamp: String,
    // device id
    device: String,
    // display name derived from device type
    devicetype: String,
    // client id (web/desktop/mobile/etc)
    client_id: String,

    // ["api", "offline_access"]
    scope: Vec<String>,
    // ["Application"]
    amr: Vec<String>,
}

fn login_issuer(req: &Request, env: &Env) -> Result<String> {
    Ok(format!("{}|login", base_url(req, env)?))
}

fn login_jwt_secret(env: &Env) -> Option<Vec<u8>> {
    env_string(env, "JWT_SECRET")
        .map(|s| s.trim().as_bytes().to_vec())
        .filter(|b| !b.is_empty())
}

async fn server_secret_get_or_create(
    db: &sea_orm::DatabaseConnection,
    name: &str,
) -> std::result::Result<String, sea_orm::DbErr> {
    // Read first.
    if let Some(rec) = server_secret::Entity::find_by_id(name.to_string()).one(db).await? {
        return Ok(rec.value);
    }

    // Create (best-effort). Keep the stored value ASCII so it can also be inspected/rotated manually.
    let value = crate::worker_wasm::util::hex_encode(&random_bytes(64));
    let now = now_ts();

    let active = server_secret::ActiveModel {
        name: Set(name.to_string()),
        value: Set(value.clone()),
        created_at: Set(now),
    };

    match active.insert(db).await {
        Ok(_) => Ok(value),
        Err(_) => {
            // Another request likely created it; fetch again.
            if let Some(rec) = server_secret::Entity::find_by_id(name.to_string()).one(db).await? {
                Ok(rec.value)
            } else {
                Ok(value)
            }
        }
    }
}

async fn login_jwt_secret_or_db(
    env: &Env,
    db: &sea_orm::DatabaseConnection,
) -> Option<Vec<u8>> {
    if let Some(secret) = login_jwt_secret(env) {
        return Some(secret);
    }

    match server_secret_get_or_create(db, "jwt_secret").await {
        Ok(v) if !v.trim().is_empty() => Some(v.into_bytes()),
        Ok(_) => None,
        Err(e) => {
            // Keep login working even if migrations haven't been applied yet.
            worker::console_log!(
                "Failed to read/create server_secrets.jwt_secret; falling back to opaque JWT: {e}"
            );
            None
        }
    }
}

fn scope_to_vec(scope: &str) -> Vec<String> {
    scope
        .split_whitespace()
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

fn device_type_display(value: i32) -> &'static str {
    // Mirrors Vaultwarden's `DeviceType::from_i32(..).to_string()` display strings.
    match value {
        0 => "Android",
        1 => "iOS",
        2 => "Chrome Extension",
        3 => "Firefox Extension",
        4 => "Opera Extension",
        5 => "Edge Extension",
        6 => "Windows",
        7 => "macOS",
        8 => "Linux",
        9 => "Chrome",
        10 => "Firefox",
        11 => "Opera",
        12 => "Edge",
        13 => "Internet Explorer",
        14 => "Unknown Browser",
        15 => "Android",
        16 => "UWP",
        17 => "Safari",
        18 => "Vivaldi",
        19 => "Vivaldi Extension",
        20 => "Safari Extension",
        21 => "SDK",
        22 => "Server",
        23 => "Windows CLI",
        24 => "macOS CLI",
        25 => "Linux CLI",
        _ => "Unknown Browser",
    }
}

fn encode_opaque_jwt<T: Serialize>(claims: &T) -> Result<String> {
    // Produce a JWT-shaped token (header.payload.signature) that clients can parse.
    // Server-side auth still treats the token as an opaque bearer value.
    // If JWT_SECRET is configured, we prefer a proper HS256 signature.
    let header = serde_json::json!({
        "alg": "HS256",
        "typ": "JWT",
    });
    let header_json = serde_json::to_vec(&header)
        .map_err(|e| worker::Error::RustError(format!("Failed to serialize JWT header: {e}")))?;
    let claims_json = serde_json::to_vec(claims)
        .map_err(|e| worker::Error::RustError(format!("Failed to serialize JWT claims: {e}")))?;

    let header_b64 = URL_SAFE_NO_PAD.encode(&header_json);
    let claims_b64 = URL_SAFE_NO_PAD.encode(&claims_json);

    // Random signature bytes to ensure uniqueness.
    let sig = random_bytes(32);
    let sig_b64 = URL_SAFE_NO_PAD.encode(&sig);

    Ok(format!("{header_b64}.{claims_b64}.{sig_b64}"))
}

fn issue_login_access_token(
    req: &Request,
    env: &Env,
    u: &user::Model,
    device_id: &str,
    device_type: i32,
    client_id: &str,
    scope: &str,
    expires_in: i64,
    now: i64,
    jwt_secret: Option<&[u8]>,
) -> Result<String> {
    let name = u
        .name
        .clone()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| u.email.clone());

    let claims = LoginJwtClaims {
        nbf: now,
        exp: now + expires_in,
        iss: login_issuer(req, env)?,
        sub: normalize_user_id_for_client(&u.id),
        premium: true,
        name,
        email: u.email.clone(),
        // Worker implementation currently has no persistent email verification flag.
        // Keep clients happy by reporting verified.
        email_verified: true,
        sstamp: u.security_stamp.clone(),
        device: device_id.to_string(),
        devicetype: device_type_display(device_type).to_string(),
        client_id: client_id.to_string(),
        scope: scope_to_vec(scope),
        amr: vec!["Application".to_string()],
    };

    if let Some(secret) = jwt_secret {
        jwt::encode_hs256(secret, &claims)
            .map_err(|e| worker::Error::RustError(format!("Failed to encode login JWT: {e}")))
    } else {
        encode_opaque_jwt(&claims)
    }
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

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct RegisterVerificationData {
    email: String,
    name: Option<String>,
    // receiveMarketingEmails: bool, // ignored
}

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

fn build_finish_signup_url(base: &str, email: &str, token: &str) -> Result<String> {
    // Build query string with correct URL encoding.
    let mut query = Url::parse("https://query.builder").map_err(|e| {
        worker::Error::RustError(format!("Failed to construct query builder URL: {e}"))
    })?;
    query.query_pairs_mut().append_pair("email", email).append_pair("token", token);
    let query_string = query.query().unwrap_or_default();
    Ok(format!("{base}/#/finish-signup/?{query_string}"))
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct RegisterVerifyClaims {
    // Not before
    nbf: i64,
    // Expiration time
    exp: i64,
    // Issuer
    iss: String,
    // Subject (email)
    sub: String,

    name: Option<String>,
    // True when the token was delivered via email (i.e., verification was required).
    verified: bool,
}

fn register_verify_issuer(req: &Request, env: &Env) -> Result<String> {
    Ok(format!("{}|register_verify", base_url(req, env)?))
}

fn register_verify_jwt_secret(env: &Env) -> Option<Vec<u8>> {
    env_string(env, "REGISTER_VERIFY_JWT_SECRET")
        .or_else(|| env_string(env, "JWT_SECRET"))
        .map(|s| s.trim().as_bytes().to_vec())
        .filter(|b| !b.is_empty())
}

async fn register_verify_jwt_secret_or_db(
    env: &Env,
    db: &sea_orm::DatabaseConnection,
) -> Option<Vec<u8>> {
    if let Some(secret) = register_verify_jwt_secret(env) {
        return Some(secret);
    }

    match server_secret_get_or_create(db, "jwt_secret").await {
        Ok(v) if !v.trim().is_empty() => Some(v.into_bytes()),
        Ok(_) => None,
        Err(e) => {
            worker::console_log!(
                "Failed to read/create server_secrets.jwt_secret for register verification; falling back to DB token: {e}"
            );
            None
        }
    }
}

async fn enumeration_delay() {
    // Approximate Vaultwarden's mitigation (1s +/- 100ms) to reduce timing side-channels.
    // Best-effort: if Delay is unavailable in the runtime, we simply skip the delay.
    let jitter = {
        let b = random_bytes(2);
        let raw = u16::from_le_bytes([b[0], b[1]]) as i32;
        (raw % 201) - 100
    };
    let sleep_ms: i32 = 1_000 + jitter;

    #[cfg(target_arch = "wasm32")]
    {
        // `worker::Delay` maps to JS timers.
        worker::Delay::from(Duration::from_millis(sleep_ms.max(0) as u64)).await;
    }
}

pub async fn handle_register_send_verification_email(mut req: Request, env: &Env) -> Result<Response> {
    let db = match db_connect(env).await {
        Ok(db) => db,
        Err(e) => return internal_error_response(&req, "Failed to open libSQL connection", &e),
    };

    if parse_bool_env(env, "DISABLE_USER_REGISTRATION") {
        return error_response(
            &req,
            400,
            "registration_not_allowed",
            "Registration not allowed or user already exists",
        );
    }

    let payload: RegisterVerificationData = match req.json().await {
        Ok(p) => p,
        Err(e) => {
            worker::console_log!("Invalid JSON in register/send-verification-email: {e}");
            return error_response(&req, 400, "invalid_json", "Invalid JSON body");
        }
    };

    let email = payload.email.trim().to_lowercase();
    if email.is_empty() {
        return error_response(&req, 400, "invalid_email", "Email cannot be blank");
    }

    let should_send_mail = brevo::brevo_is_configured(env) && parse_bool_env(env, "SIGNUPS_VERIFY");
    let jwt_secret = register_verify_jwt_secret_or_db(env, &db).await;

    // If we're going to send mail, don't send it to already-registered accounts.
    if should_send_mail {
        let existing = user::Entity::find()
            .filter(user::Column::Email.eq(&email))
            .one(&db)
            .await
            .map_err(|e| worker::Error::RustError(e.to_string()))?;

        // Match Vaultwarden behavior: treat a user with stored asymmetric keys as "already registered".
        // (Invited/pending users may exist without keys.)
        let registered = existing
            .as_ref()
            .and_then(|u| u.private_key.as_ref())
            .is_some_and(|k| !k.is_empty());

        if registered {
            enumeration_delay().await;
            let resp = Response::empty()?.with_status(204);
            return json_with_cors(&req, resp);
        }
    }

    // Vaultwarden uses a JWT token for this flow.
    // For backwards compatibility, we keep the older DB-backed opaque token path if a JWT secret is not configured.
    let now = now_ts();
    let token = if let Some(ref secret) = jwt_secret {
        let issuer = register_verify_issuer(&req, env)?;
        let claims = RegisterVerifyClaims {
            nbf: now,
            exp: now + 30 * 60,
            iss: issuer,
            sub: email.clone(),
            name: payload.name.clone(),
            verified: should_send_mail,
        };

        jwt::encode_hs256(secret, &claims).map_err(|e| worker::Error::RustError(e.to_string()))?
    } else {
        // Store an opaque token (30 minutes, like Vaultwarden).
        let token = crate::worker_wasm::util::hex_encode(&random_bytes(32));
        let expires_at = now + 30 * 60;

        let active = register_verification::ActiveModel {
            id: Set(token.clone()),
            email: Set(email.clone()),
            name: Set(payload.name.clone()),
            // Kept for compatibility; not currently used by the worker implementation.
            verified: Set(should_send_mail),
            created_at: Set(now),
            expires_at: Set(expires_at),
        };

        if let Err(e) = active.insert(&db).await {
            return internal_error_response(&req, "Failed to persist register verification token", &e);
        }

        token
    };

    if should_send_mail {
        let base = base_url(&req, env)?;
        let finish_url = build_finish_signup_url(&base, &email, &token)?;

        let subject = "Verify Your Email";
        let html = Some(format!(
            "<p>Verify this email address to finish creating your account:</p><p><a href=\"{finish_url}\">Verify Email Address Now</a></p><p>If you did not request this, you can safely ignore this email.</p>"
        ));
        let text = Some(format!(
            "Verify this email address to finish creating your account:\n\n{finish_url}\n\nIf you did not request this, you can safely ignore this email."
        ));

        if let Err(e) = brevo::send_email(env, &email, payload.name.as_deref(), subject, html, text).await {
            return internal_error_response(&req, "Failed to send Brevo verification email", &e);
        }

        let resp = Response::empty()?.with_status(204);
        return json_with_cors(&req, resp);
    }

    // If email verification is not required (or mail isn't configured), return the token directly.
    let resp = Response::from_json(&token)?;
    json_with_cors(&req, resp)
}

pub async fn handle_register_finish(mut req: Request, env: &Env) -> Result<Response> {
    let db = match db_connect(env).await {
        Ok(db) => db,
        Err(e) => return internal_error_response(&req, "Failed to open libSQL connection", &e),
    };

    let payload: accounts::RegisterData = match req.json().await {
        Ok(p) => p,
        Err(e) => {
            worker::console_log!("Invalid JSON in register/finish: {e}");
            return error_response(&req, 400, "invalid_json", "Invalid JSON body");
        }
    };

    let email = payload.email.trim().to_lowercase();
    if email.is_empty() {
        return error_response(&req, 400, "invalid_email", "Email cannot be blank");
    }

    let Some(token) = payload.email_verification_token.clone() else {
        return error_response(
            &req,
            400,
            "missing_email_verification_token",
            "Registration is missing required parameters",
        );
    };

    // Prefer Vaultwarden-compatible JWT validation when a secret is configured.
    // Otherwise, fall back to the legacy DB-backed opaque token.
    let now = now_ts();
    let mut name_override: Option<String> = None;

    if let Some(secret) = register_verify_jwt_secret_or_db(env, &db).await {
        match jwt::decode_hs256::<RegisterVerifyClaims>(&secret, &token) {
            Ok(claims) => {
                let expected_iss = register_verify_issuer(&req, env)?;
                let leeway: i64 = 30;

                if claims.iss != expected_iss {
                    return error_response(&req, 400, "invalid_email_verification_token", "Invalid claim");
                }

                if now + leeway < claims.nbf {
                    return error_response(&req, 400, "invalid_email_verification_token", "Invalid claim");
                }
                if now - leeway > claims.exp {
                    return error_response(&req, 400, "invalid_email_verification_token", "Invalid claim");
                }

                if claims.sub.to_lowercase() != email {
                    return error_response(
                        &req,
                        400,
                        "invalid_email_verification_token",
                        "Email verification token does not match email",
                    );
                }

                // Prefer explicit name from the finish payload; fall back to the name in the token.
                if payload.name.is_none() {
                    name_override = claims.name.clone();
                }
            }
            Err(_) => {
                // If the token isn't a valid JWT (or the secret changed), try the legacy DB-backed path.
                let Some(rec) = RegisterVerificationEntity::find_by_id(token.clone())
                    .one(&db)
                    .await
                    .map_err(|e| worker::Error::RustError(e.to_string()))?
                else {
                    return error_response(&req, 400, "invalid_email_verification_token", "Invalid claim");
                };

                if rec.email.to_lowercase() != email {
                    return error_response(
                        &req,
                        400,
                        "invalid_email_verification_token",
                        "Email verification token does not match email",
                    );
                }

                if rec.expires_at <= now {
                    return error_response(&req, 400, "invalid_email_verification_token", "Invalid claim");
                }

                if payload.name.is_none() {
                    name_override = rec.name.clone();
                }
            }
        }
    } else {
        let Some(rec) = RegisterVerificationEntity::find_by_id(token.clone())
            .one(&db)
            .await
            .map_err(|e| worker::Error::RustError(e.to_string()))?
        else {
            return error_response(&req, 400, "invalid_email_verification_token", "Invalid claim");
        };

        if rec.email.to_lowercase() != email {
            return error_response(
                &req,
                400,
                "invalid_email_verification_token",
                "Email verification token does not match email",
            );
        }

        if rec.expires_at <= now {
            return error_response(&req, 400, "invalid_email_verification_token", "Invalid claim");
        }

        if payload.name.is_none() {
            name_override = rec.name.clone();
        }
    }

    accounts::register_with_db(&req, &db, payload, name_override).await
}

async fn password_grant(
    req: &Request,
    env: &Env,
    db: &sea_orm::DatabaseConnection,
    form: &FormData,
) -> Result<Response> {
    let username = form_get_string(form, "username").unwrap_or_default().trim().to_lowercase();
    let password = form_get_string(form, "password").unwrap_or_default();

    let client_id = form_get_string(form, "client_id").unwrap_or_default();
    let scope = form_get_string(form, "scope").unwrap_or_else(|| "api offline_access".to_string());

    // Bitwarden clients are not consistent about field casing.
    // Desktop/mobile apps commonly send camelCase (deviceIdentifier/deviceName/deviceType).
    // Vaultwarden accepts multiple aliases; mirror that behavior.
    let device_identifier = form_get_string(form, "device_identifier")
        .or_else(|| form_get_string(form, "deviceidentifier"))
        .or_else(|| form_get_string(form, "deviceIdentifier"))
        .or_else(|| form_get_string(form, "DeviceIdentifier"))
        .unwrap_or_default();
    let device_name = form_get_string(form, "device_name")
        .or_else(|| form_get_string(form, "devicename"))
        .or_else(|| form_get_string(form, "deviceName"))
        .or_else(|| form_get_string(form, "DeviceName"))
        .unwrap_or_else(|| "Unknown".to_string());
    let device_type_str = form_get_string(form, "device_type")
        .or_else(|| form_get_string(form, "devicetype"))
        .or_else(|| form_get_string(form, "deviceType"))
        .or_else(|| form_get_string(form, "DeviceType"))
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

    let jwt_secret = login_jwt_secret_or_db(env, db).await;

    // Find or create device.
    let existing_device = device::Entity::find_by_id(device_identifier.clone())
        .one(db)
        .await
        .map_err(|e| worker::Error::RustError(e.to_string()))?;

    let (mut dev_active, is_new_device): (device::ActiveModel, bool) = match existing_device {
        Some(d) => {
            if d.user_id != u.id {
                return oauth_error(req, 400, "invalid_grant", "Device identifier is already registered");
            }
            let mut active: device::ActiveModel = d.into();
            active.name = Set(device_name.clone());
            active.device_type = Set(device_type);
            (active, false)
        }
        None => (
            device::ActiveModel {
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
            true,
        ),
    };

    // Rotate refresh token on successful login.
    let refresh_token = generate_refresh_token();
    dev_active.refresh_token = Set(refresh_token.clone());

    let expires_in: i64 = 3600;
    let access_token = issue_login_access_token(
        req,
        env,
        &u,
        &device_identifier,
        device_type,
        &client_id,
        &scope,
        expires_in,
        now,
        jwt_secret.as_deref(),
    )?;
    dev_active.access_token = Set(Some(access_token.clone()));
    dev_active.access_token_expires_at = Set(Some(now + expires_in));
    dev_active.updated_at = Set(now);

    let save_res = if is_new_device {
        dev_active.insert(db).await
    } else {
        dev_active.update(db).await
    };

    if let Err(e) = save_res {
        return internal_error_response(req, "Failed to save device", &e);
    }

    let json = token_response_json(&u, &access_token, &refresh_token, &scope, expires_in);
    let resp = Response::from_json(&json)?;
    json_with_cors(req, resp)
}

async fn refresh_grant(
    req: &Request,
    env: &Env,
    db: &sea_orm::DatabaseConnection,
    form: &FormData,
) -> Result<Response> {
    let refresh_token = form_get_string(form, "refresh_token")
        .or_else(|| form_get_string(form, "refreshtoken"))
        .or_else(|| form_get_string(form, "refreshToken"))
        .or_else(|| form_get_string(form, "RefreshToken"))
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

    let jwt_secret = login_jwt_secret_or_db(env, db).await;

    let new_refresh_token = generate_refresh_token();
    // Scope is not included in refresh requests by some clients. Keep the canonical one.
    let scope = form_get_string(form, "scope").unwrap_or_else(|| "api offline_access".to_string());
    let client_id = form_get_string(form, "client_id").unwrap_or_else(|| "desktop".to_string());
    let access_token = issue_login_access_token(
        req,
        env,
        &u,
        &dev.id,
        dev.device_type,
        &client_id,
        &scope,
        expires_in,
        now,
        jwt_secret.as_deref(),
    )?;

    let mut active: device::ActiveModel = dev.into();
    active.refresh_token = Set(new_refresh_token.clone());
    active.access_token = Set(Some(access_token.clone()));
    active.access_token_expires_at = Set(Some(now + expires_in));
    active.updated_at = Set(now);

    if let Err(e) = active.update(db).await {
        return internal_error_response(req, "Failed to save device", &e);
    }

    let json = token_response_json(&u, &access_token, &new_refresh_token, &scope, expires_in);
    let resp = Response::from_json(&json)?;
    json_with_cors(req, resp)
}
