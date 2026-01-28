use serde::Deserialize;
use worker::{Env, Request, Response, Result};

use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};

use crate::worker_wasm::crypto;
use crate::worker_wasm::db::db_connect;
use crate::worker_wasm::http::{error_response, internal_error_response, json_with_cors};
use crate::worker_wasm::util::{generate_security_stamp, now_ts, random_bytes};

use entity::{user, user::Entity as UserEntity};

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
struct RegisterData {
    email: String,

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

    name: Option<String>,
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

    let email = payload.email.trim().to_lowercase();
    if email.is_empty() {
        return error_response(&req, 400, "invalid_email", "Email cannot be blank");
    }

    if let Some(ref name) = payload.name {
        if name.len() > 50 {
            return error_response(
                &req,
                400,
                "invalid_name",
                "The field Name must be a string with a maximum length of 50.",
            );
        }
    }

    if let Err(msg) = validate_kdf(&payload) {
        return error_response(&req, 400, "invalid_kdf", msg);
    }

    let existing = UserEntity::find()
        .filter(user::Column::Email.eq(&email))
        .one(&db)
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
    let pwd_hash = crypto::hash_password(payload.master_password_hash.as_bytes(), &salt, server_iterations as u32);

    let id = existing
        .as_ref()
        .map(|u| u.id.clone())
        // 128-bit random id.
        .unwrap_or_else(|| crate::worker_wasm::util::hex_encode(&random_bytes(16)));

    let created_at = existing.as_ref().map(|u| u.created_at).unwrap_or(now);

    let active: user::ActiveModel = user::ActiveModel {
        id: Set(id),
        email: Set(email.clone()),
        enabled: Set(true),
        name: Set(payload.name.clone().or_else(|| Some(email.clone()))),
        password_hash: Set(Some(pwd_hash)),
        salt: Set(Some(salt)),
        password_iterations: Set(server_iterations),
        akey: Set(payload.key.clone()),
        private_key: Set(payload.keys.as_ref().map(|k| k.encrypted_private_key.clone())),
        public_key: Set(payload.keys.as_ref().map(|k| k.public_key.clone())),
        security_stamp: Set(generate_security_stamp()),
        client_kdf_type: Set(payload.kdf),
        client_kdf_iter: Set(payload.kdf_iterations),
        client_kdf_memory: Set(payload.kdf_memory),
        client_kdf_parallelism: Set(payload.kdf_parallelism),
        created_at: Set(created_at),
        updated_at: Set(now),
    };

    // Insert or update.
    // SeaORM's save requires primary key; it will do update if exists.
    if let Err(e) = active.save(&db).await {
        return internal_error_response(&req, "Failed to save user", &e);
    }

    let resp = Response::from_json(&serde_json::json!({
        "object": "register",
        "captchaBypassToken": "",
    }))?;

    json_with_cors(&req, resp)
}
