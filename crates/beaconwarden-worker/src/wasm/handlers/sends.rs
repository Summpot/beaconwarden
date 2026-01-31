use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, Duration, Utc};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use serde::Deserialize;
use serde_json::Value;
use worker::{Env, Method, Request, Response, Result};

use crate::worker_wasm::crypto::{hash_password, verify_password_hash};
use crate::worker_wasm::db::db_connect;
use crate::worker_wasm::handlers::auth::{authenticate, AuthResult};
use crate::worker_wasm::http::{error_response, internal_error_response, json_with_cors};
use crate::worker_wasm::util::{now_ts, random_bytes, ts_to_rfc3339, uuid_v4};

use entity::{send, user};

const SEND_INACCESSIBLE_MSG: &str = "Send does not exist or is no longer available";
const SEND_PASSWORD_ITER: u32 = 100_000;

fn parse_uuid_bytes(uuid: &str) -> Option<[u8; 16]> {
    // UUID format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    let s = uuid.trim();
    if s.len() != 36 {
        return None;
    }
    let mut hex = [0u8; 32];
    let mut j = 0usize;
    for (i, c) in s.bytes().enumerate() {
        if i == 8 || i == 13 || i == 18 || i == 23 {
            if c != b'-' {
                return None;
            }
            continue;
        }
        if !c.is_ascii_hexdigit() {
            return None;
        }
        if j >= 32 {
            return None;
        }
        hex[j] = c;
        j += 1;
    }
    if j != 32 {
        return None;
    }

    fn nibble(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }

    let mut out = [0u8; 16];
    for i in 0..16 {
        let hi = nibble(hex[i * 2])?;
        let lo = nibble(hex[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
    }

    Some(out)
}

fn uuid_string_from_bytes(b: &[u8; 16]) -> String {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(36);
    for (i, byte) in b.iter().enumerate() {
        if i == 4 || i == 6 || i == 8 || i == 10 {
            out.push('-');
        }
        out.push(LUT[(byte >> 4) as usize] as char);
        out.push(LUT[(byte & 0x0f) as usize] as char);
    }
    out
}

fn access_id_from_uuid(uuid: &str) -> Option<String> {
    let b = parse_uuid_bytes(uuid)?;
    Some(URL_SAFE_NO_PAD.encode(b))
}

fn uuid_from_access_id(access_id: &str) -> Option<String> {
    let b = URL_SAFE_NO_PAD.decode(access_id.as_bytes()).ok()?;
    let b: [u8; 16] = b.try_into().ok()?;
    Some(uuid_string_from_bytes(&b))
}

fn parse_i32_number_or_string(v: &Value) -> Option<i32> {
    match v {
        Value::Number(n) => n.as_i64().and_then(|x| i32::try_from(x).ok()),
        Value::String(s) => s.trim().parse::<i32>().ok(),
        _ => None,
    }
}

fn parse_rfc3339_ts(s: &str) -> Option<i64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let dt = DateTime::parse_from_rfc3339(s).ok()?;
    Some(dt.timestamp())
}

fn normalize_send_data_for_storage(send_type: i32, payload: &SendUpsertData) -> Result<String> {
    let mut data_val = match send_type {
        0 => payload.text.clone(),
        1 => payload.file.clone(),
        _ => None,
    }
    .ok_or_else(|| worker::Error::RustError("Send data not provided".to_string()))?;

    // Vaultwarden removes this key when present.
    if let Some(obj) = data_val.as_object_mut() {
        obj.remove("response");
    }

    Ok(data_val.to_string())
}

fn send_json(s: &send::Model) -> Value {
    let mut data: Value = serde_json::from_str(&s.data).unwrap_or(Value::Null);

    // Mobile clients sometimes expect "size" to be a string.
    if let Some(size) = data.get("size").and_then(|v| v.as_i64()) {
        if let Some(obj) = data.as_object_mut() {
            obj.insert("size".to_string(), Value::String(size.to_string()));
        }
    }

    let access_id = access_id_from_uuid(&s.id).unwrap_or_default();

    serde_json::json!({
        "id": s.id,
        "accessId": access_id,
        "type": s.r#type,

        "name": s.name,
        "notes": s.notes,
        "text": if s.r#type == 0 { Some(&data) } else { None },
        "file": if s.r#type == 1 { Some(&data) } else { None },

        "key": s.akey,
        "maxAccessCount": s.max_access_count,
        "accessCount": s.access_count,
        "password": s.password_hash.as_deref().map(|h| URL_SAFE_NO_PAD.encode(h)),
        "disabled": s.disabled,
        "hideEmail": s.hide_email,

        "revisionDate": ts_to_rfc3339(s.revision_date),
        "expirationDate": s.expiration_date.map(ts_to_rfc3339),
        "deletionDate": ts_to_rfc3339(s.deletion_date),
        "object": "send",
    })
}

async fn creator_identifier(db: &sea_orm::DatabaseConnection, s: &send::Model) -> Result<Option<String>> {
    if s.hide_email.unwrap_or(false) {
        return Ok(None);
    }

    let Some(user_id) = s.user_id.as_ref() else {
        return Ok(None);
    };

    let u = user::Entity::find_by_id(user_id.clone())
        .one(db)
        .await
        .map_err(|e| worker::Error::RustError(e.to_string()))?;

    Ok(u.map(|u| u.email))
}

async fn send_json_access(db: &sea_orm::DatabaseConnection, s: &send::Model) -> Result<Value> {
    let mut data: Value = serde_json::from_str(&s.data).unwrap_or(Value::Null);

    if let Some(size) = data.get("size").and_then(|v| v.as_i64()) {
        if let Some(obj) = data.as_object_mut() {
            obj.insert("size".to_string(), Value::String(size.to_string()));
        }
    }

    Ok(serde_json::json!({
        "id": s.id,
        "type": s.r#type,
        "name": s.name,
        "text": if s.r#type == 0 { Some(&data) } else { None },
        "file": if s.r#type == 1 { Some(&data) } else { None },
        "expirationDate": s.expiration_date.map(ts_to_rfc3339),
        "creatorIdentifier": creator_identifier(db, s).await?,
        "object": "send-access",
    }))
}

async fn touch_user_revision(db: &sea_orm::DatabaseConnection, user_id: &str, now: i64) -> Result<()> {
    user::Entity::update_many()
        .col_expr(user::Column::UpdatedAt, sea_orm::sea_query::Expr::value(now))
        .filter(user::Column::Id.eq(user_id))
        .exec(db)
        .await
        .map_err(|e| worker::Error::RustError(e.to_string()))?;
    Ok(())
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct SendUpsertData {
    #[serde(rename = "type")]
    r#type: i32,

    key: String,

    password: Option<String>,

    max_access_count: Option<Value>,
    expiration_date: Option<String>,
    deletion_date: String,

    disabled: bool,
    hide_email: Option<bool>,

    name: String,
    notes: Option<String>,

    text: Option<Value>,
    file: Option<Value>,

    // Used for key rotations.
    id: Option<String>,
}

/// GET/POST /api/sends
pub async fn handle_sends(mut req: Request, env: &Env) -> Result<Response> {
    let db = match db_connect(env).await {
        Ok(db) => db,
        Err(e) => return internal_error_response(&req, "Failed to open libSQL connection", &e),
    };

    let auth = match authenticate(&req, &db).await? {
        AuthResult::Authorized(a) => a,
        AuthResult::Unauthorized(resp) => return Ok(resp),
    };

    match req.method() {
        Method::Get => {
            let sends = send::Entity::find()
                .filter(send::Column::UserId.eq(auth.user.id.clone()))
                .all(&db)
                .await
                .map_err(|e| worker::Error::RustError(e.to_string()))?;

            let resp = Response::from_json(&serde_json::json!({
                "data": sends.iter().map(send_json).collect::<Vec<_>>(),
                "object": "list",
                "continuationToken": Value::Null,
            }))?;
            json_with_cors(&req, resp)
        }
        Method::Post => {
            let payload: SendUpsertData = match req.json().await {
                Ok(p) => p,
                Err(_) => return error_response(&req, 400, "invalid_json", "Invalid JSON body"),
            };

            // For now, we do not support file uploads in Workers; keep text sends working.
            if payload.r#type == 1 {
                return error_response(
                    &req,
                    501,
                    "not_implemented",
                    "File Sends are not implemented on this deployment yet",
                );
            }

            if payload.r#type != 0 {
                return error_response(&req, 400, "invalid_type", "Invalid Send type");
            }

            let deletion_ts = match parse_rfc3339_ts(&payload.deletion_date) {
                Some(ts) => ts,
                None => return error_response(&req, 400, "invalid_date", "Invalid deletionDate"),
            };

            // Vaultwarden enforces a max of 31 days from now.
            let now = now_ts();
            let max_allowed = (Utc::now() + Duration::days(31)).timestamp();
            if deletion_ts > max_allowed {
                return error_response(
                    &req,
                    400,
                    "invalid_deletion_date",
                    "You cannot have a Send with a deletion date that far into the future. Adjust the Deletion Date to a value less than 31 days from now and try again.",
                );
            }

            let expiration_ts = payload
                .expiration_date
                .as_deref()
                .and_then(parse_rfc3339_ts);

            let max_access_count = payload
                .max_access_count
                .as_ref()
                .and_then(parse_i32_number_or_string);

            let id = payload.id.clone().filter(|s| !s.trim().is_empty()).unwrap_or_else(uuid_v4);

            let data = match normalize_send_data_for_storage(payload.r#type, &payload) {
                Ok(d) => d,
                Err(_) => return error_response(&req, 400, "invalid_send_data", "Send data not provided"),
            };

            let (password_hash, password_salt, password_iter) = if let Some(pw) = payload.password.as_deref() {
                let salt = random_bytes(64);
                let hash = hash_password(pw.as_bytes(), &salt, SEND_PASSWORD_ITER);
                (Some(hash), Some(salt), Some(SEND_PASSWORD_ITER as i32))
            } else {
                (None, None, None)
            };

            let active = send::ActiveModel {
                id: Set(id.clone()),
                user_id: Set(Some(auth.user.id.clone())),
                organization_id: Set(None),
                name: Set(payload.name),
                notes: Set(payload.notes),
                r#type: Set(payload.r#type),
                data: Set(data),
                akey: Set(payload.key),
                password_hash: Set(password_hash),
                password_salt: Set(password_salt),
                password_iter: Set(password_iter),
                max_access_count: Set(max_access_count),
                access_count: Set(0),
                creation_date: Set(now),
                revision_date: Set(now),
                expiration_date: Set(expiration_ts),
                deletion_date: Set(deletion_ts),
                // No explicit deletionDate in the payload; Bitwarden clients also send deletionDate.
                // We store it in deletion_date. This field is a DB TTL timestamp.
                disabled: Set(payload.disabled),
                hide_email: Set(payload.hide_email),
            };

            let created = active
                .insert(&db)
                .await
                .map_err(|e| worker::Error::RustError(e.to_string()))?;

            touch_user_revision(&db, &auth.user.id, now_ts()).await?;

            let resp = Response::from_json(&send_json(&created))?;
            json_with_cors(&req, resp)
        }
        _ => error_response(&req, 405, "method_not_allowed", "Method not allowed"),
    }
}

/// GET/PUT/POST/DELETE /api/sends/<send_id>
/// PUT /api/sends/<send_id>/remove-password
pub async fn handle_send(mut req: Request, env: &Env, send_id: String, tail: Option<&str>) -> Result<Response> {
    let db = match db_connect(env).await {
        Ok(db) => db,
        Err(e) => return internal_error_response(&req, "Failed to open libSQL connection", &e),
    };

    let auth = match authenticate(&req, &db).await? {
        AuthResult::Authorized(a) => a,
        AuthResult::Unauthorized(resp) => return Ok(resp),
    };

    if tail == Some("remove-password") {
        if req.method() != Method::Put {
            return error_response(&req, 405, "method_not_allowed", "Method not allowed");
        }

        let found = send::Entity::find_by_id(send_id.clone())
            .filter(send::Column::UserId.eq(auth.user.id.clone()))
            .one(&db)
            .await
            .map_err(|e| worker::Error::RustError(e.to_string()))?;

        let Some(existing) = found else {
            return error_response(&req, 404, "not_found", "Send not found");
        };

        let now = now_ts();
        let mut active: send::ActiveModel = existing.into();
        active.password_iter = Set(None);
        active.password_salt = Set(None);
        active.password_hash = Set(None);
        active.revision_date = Set(now);

        let updated = active
            .update(&db)
            .await
            .map_err(|e| worker::Error::RustError(e.to_string()))?;

        touch_user_revision(&db, &auth.user.id, now_ts()).await?;

        let resp = Response::from_json(&send_json(&updated))?;
        return json_with_cors(&req, resp);
    }

    if tail.is_some() {
        // Unknown sub-route.
        return error_response(&req, 404, "not_found", "Not found");
    }

    match req.method() {
        Method::Get => {
            let found = send::Entity::find_by_id(send_id)
                .filter(send::Column::UserId.eq(auth.user.id.clone()))
                .one(&db)
                .await
                .map_err(|e| worker::Error::RustError(e.to_string()))?;

            let Some(s) = found else {
                return error_response(&req, 404, "not_found", "Send not found");
            };

            let resp = Response::from_json(&send_json(&s))?;
            json_with_cors(&req, resp)
        }
        Method::Put | Method::Post => {
            let payload: SendUpsertData = match req.json().await {
                Ok(p) => p,
                Err(_) => return error_response(&req, 400, "invalid_json", "Invalid JSON body"),
            };

            let found = send::Entity::find_by_id(send_id.clone())
                .filter(send::Column::UserId.eq(auth.user.id.clone()))
                .one(&db)
                .await
                .map_err(|e| worker::Error::RustError(e.to_string()))?;

            let Some(existing) = found else {
                return error_response(&req, 404, "not_found", "Send not found");
            };

            // Sends can't change type.
            if existing.r#type != payload.r#type {
                return error_response(&req, 400, "invalid_type", "Sends can't change type");
            }

            // For now, we do not support file uploads in Workers; keep text sends working.
            if payload.r#type == 1 {
                return error_response(
                    &req,
                    501,
                    "not_implemented",
                    "File Sends are not implemented on this deployment yet",
                );
            }

            let deletion_ts = match parse_rfc3339_ts(&payload.deletion_date) {
                Some(ts) => ts,
                None => return error_response(&req, 400, "invalid_date", "Invalid deletionDate"),
            };
            let max_allowed = (Utc::now() + Duration::days(31)).timestamp();
            if deletion_ts > max_allowed {
                return error_response(
                    &req,
                    400,
                    "invalid_deletion_date",
                    "You cannot have a Send with a deletion date that far into the future. Adjust the Deletion Date to a value less than 31 days from now and try again.",
                );
            }

            let expiration_ts = payload
                .expiration_date
                .as_deref()
                .and_then(parse_rfc3339_ts);
            let max_access_count = payload
                .max_access_count
                .as_ref()
                .and_then(parse_i32_number_or_string);

            let mut active: send::ActiveModel = existing.into();
            let now = now_ts();

            // Only update data for text sends.
            if payload.r#type == 0 {
                let data = match normalize_send_data_for_storage(payload.r#type, &payload) {
                    Ok(d) => d,
                    Err(_) => return error_response(&req, 400, "invalid_send_data", "Send data not provided"),
                };
                active.data = Set(data);
            }

            active.name = Set(payload.name);
            active.akey = Set(payload.key);
            active.deletion_date = Set(deletion_ts);
            active.notes = Set(payload.notes);
            active.max_access_count = Set(max_access_count);
            active.expiration_date = Set(expiration_ts);
            active.hide_email = Set(payload.hide_email);
            active.disabled = Set(payload.disabled);
            active.revision_date = Set(now);

            // Only change password if present (Vaultwarden behavior).
            if let Some(pw) = payload.password.as_deref() {
                let salt = random_bytes(64);
                let hash = hash_password(pw.as_bytes(), &salt, SEND_PASSWORD_ITER);
                active.password_iter = Set(Some(SEND_PASSWORD_ITER as i32));
                active.password_salt = Set(Some(salt));
                active.password_hash = Set(Some(hash));
            }

            let updated = active
                .update(&db)
                .await
                .map_err(|e| worker::Error::RustError(e.to_string()))?;

            touch_user_revision(&db, &auth.user.id, now_ts()).await?;

            let resp = Response::from_json(&send_json(&updated))?;
            json_with_cors(&req, resp)
        }
        Method::Delete => {
            let res = send::Entity::delete_many()
                .filter(send::Column::Id.eq(send_id))
                .filter(send::Column::UserId.eq(auth.user.id.clone()))
                .exec(&db)
                .await
                .map_err(|e| worker::Error::RustError(e.to_string()))?;

            if res.rows_affected == 0 {
                return error_response(&req, 404, "not_found", "Send not found");
            }

            touch_user_revision(&db, &auth.user.id, now_ts()).await?;

            let resp = Response::empty()?.with_status(200);
            json_with_cors(&req, resp)
        }
        _ => error_response(&req, 405, "method_not_allowed", "Method not allowed"),
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendAccessData {
    pub password: Option<String>,
}

/// POST /api/sends/access/<access_id>
pub async fn handle_send_access(mut req: Request, env: &Env, access_id: String) -> Result<Response> {
    if req.method() != Method::Post {
        return error_response(&req, 405, "method_not_allowed", "Method not allowed");
    }

    let db = match db_connect(env).await {
        Ok(db) => db,
        Err(e) => return internal_error_response(&req, "Failed to open libSQL connection", &e),
    };

    let payload: SendAccessData = match req.json().await {
        Ok(p) => p,
        Err(_) => SendAccessData { password: None },
    };

    let send_id = match uuid_from_access_id(access_id.trim()) {
        Some(id) => id,
        None => return error_response(&req, 404, "not_found", SEND_INACCESSIBLE_MSG),
    };

    let found = send::Entity::find_by_id(send_id)
        .one(&db)
        .await
        .map_err(|e| worker::Error::RustError(e.to_string()))?;

    let Some(mut s) = found else {
        return error_response(&req, 404, "not_found", SEND_INACCESSIBLE_MSG);
    };

    let now = now_ts();

    if let Some(max_access) = s.max_access_count {
        if s.access_count >= max_access {
            return error_response(&req, 404, "not_found", SEND_INACCESSIBLE_MSG);
        }
    }

    if let Some(exp) = s.expiration_date {
        if now >= exp {
            return error_response(&req, 404, "not_found", SEND_INACCESSIBLE_MSG);
        }
    }

    if now >= s.deletion_date {
        return error_response(&req, 404, "not_found", SEND_INACCESSIBLE_MSG);
    }

    if s.disabled {
        return error_response(&req, 404, "not_found", SEND_INACCESSIBLE_MSG);
    }

    if let (Some(hash), Some(salt), Some(iter)) = (&s.password_hash, &s.password_salt, s.password_iter) {
        match payload.password {
            Some(pw) => {
                if !verify_password_hash(pw.as_bytes(), salt, hash, iter as u32) {
                    return error_response(&req, 400, "invalid_password", "Invalid password");
                }
            }
            None => {
                return error_response(&req, 401, "password_required", "Password not provided");
            }
        }
    }

    // Only increment for text sends; file sends are incremented on download.
    if s.r#type == 0 {
        s.access_count = s.access_count.saturating_add(1);
    }

    let access_count = s.access_count;

    // Persist changes.
    let mut active: send::ActiveModel = s.into();
    active.access_count = Set(access_count);
    active.revision_date = Set(now);

    let updated = active
        .update(&db)
        .await
        .map_err(|e| worker::Error::RustError(e.to_string()))?;

    // Best-effort revision touch for owner.
    if let Some(user_id) = updated.user_id.as_ref() {
        let _ = touch_user_revision(&db, user_id, now_ts()).await;
    }

    let body = send_json_access(&db, &updated).await?;
    let resp = Response::from_json(&body)?;
    json_with_cors(&req, resp)
}

/// POST /api/sends/file, POST /api/sends/file/v2
///
/// Workers-only deployment: prefer direct-to-R2 uploads; not yet implemented.
pub async fn handle_send_file(req: Request, env: &Env) -> Result<Response> {
    // Some Bitwarden clients probe these endpoints; require auth so we don't leak details.
    let db = match db_connect(env).await {
        Ok(db) => db,
        Err(e) => return internal_error_response(&req, "Failed to open libSQL connection", &e),
    };

    match authenticate(&req, &db).await? {
        AuthResult::Authorized(_) => {}
        AuthResult::Unauthorized(resp) => return Ok(resp),
    };

    error_response(
        &req,
        501,
        "not_implemented",
        "File Sends are not implemented on this deployment yet",
    )
}
