use std::time::Duration;

use serde::Deserialize;
use worker::{Env, Request, Response, Result};

use sea_orm::{ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set};

use crate::worker_wasm::crypto;
use crate::worker_wasm::db::db_connect;
use crate::worker_wasm::env::env_string;
use crate::worker_wasm::http::{error_response, internal_error_response, json_with_cors};
use crate::worker_wasm::util::{generate_security_stamp, now_ts, random_bytes};
use crate::worker_wasm::{brevo};

use entity::{user, user::Entity as UserEntity};

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
        let id = crate::worker_wasm::util::hex_encode(&random_bytes(16));
        let active: user::ActiveModel = user::ActiveModel {
            id: Set(id),
            email: Set(email.clone()),
            enabled: Set(true),
            name: Set(final_name.clone()),
            password_hash: Set(Some(pwd_hash.clone())),
            salt: Set(Some(salt.clone())),
            password_iterations: Set(server_iterations),
            akey: Set(payload.key.clone()),
            private_key: Set(private_key.clone()),
            public_key: Set(public_key.clone()),
            security_stamp: Set(generate_security_stamp()),
            client_kdf_type: Set(payload.kdf),
            client_kdf_iter: Set(payload.kdf_iterations),
            client_kdf_memory: Set(payload.kdf_memory),
            client_kdf_parallelism: Set(payload.kdf_parallelism),
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
