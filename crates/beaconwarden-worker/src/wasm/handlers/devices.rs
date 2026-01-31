use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use serde::Deserialize;
use serde_json::Value;
use worker::{Env, Method, Request, Response, Result};

use crate::worker_wasm::db::db_connect;
use crate::worker_wasm::handlers::auth::{authenticate, AuthResult};
use crate::worker_wasm::http::{error_response, internal_error_response, json_with_cors};
use crate::worker_wasm::util::ts_to_rfc3339;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

use entity::{device, user};

fn device_json(d: &device::Model) -> Value {
    serde_json::json!({
        "id": d.id,
        "name": d.name,
        "type": d.device_type,
        "identifier": d.id,
        "creationDate": ts_to_rfc3339(d.created_at),
        "isTrusted": false,
        "object": "device",
    })
}

pub async fn handle_devices(req: Request, env: &Env) -> Result<Response> {
    if req.method() != Method::Get {
        return error_response(&req, 405, "method_not_allowed", "Method not allowed");
    }

    let db = match db_connect(env).await {
        Ok(db) => db,
        Err(e) => return internal_error_response(&req, "Failed to open libSQL connection", &e),
    };

    let auth = match authenticate(&req, &db).await? {
        AuthResult::Authorized(a) => a,
        AuthResult::Unauthorized(resp) => return Ok(resp),
    };

    let devices = device::Entity::find()
        .filter(device::Column::UserId.eq(auth.user.id))
        .all(&db)
        .await
        .map_err(|e| worker::Error::RustError(e.to_string()))?;

    let data: Vec<Value> = devices.iter().map(device_json).collect();

    let resp = Response::from_json(&serde_json::json!({
        "data": data,
        "continuationToken": Value::Null,
        "object": "list",
    }))?;

    json_with_cors(&req, resp)
}

pub async fn handle_device(req: Request, env: &Env, device_id: String) -> Result<Response> {
    if req.method() != Method::Get {
        return error_response(&req, 405, "method_not_allowed", "Method not allowed");
    }

    let db = match db_connect(env).await {
        Ok(db) => db,
        Err(e) => return internal_error_response(&req, "Failed to open libSQL connection", &e),
    };

    let auth = match authenticate(&req, &db).await? {
        AuthResult::Authorized(a) => a,
        AuthResult::Unauthorized(resp) => return Ok(resp),
    };

    let found = device::Entity::find_by_id(device_id.clone())
        .filter(device::Column::UserId.eq(auth.user.id))
        .one(&db)
        .await
        .map_err(|e| worker::Error::RustError(e.to_string()))?;

    let Some(d) = found else {
        return error_response(&req, 404, "not_found", "No device found");
    };

    let resp = Response::from_json(&device_json(&d))?;
    json_with_cors(&req, resp)
}

/// GET /api/devices/knowndevice
///
/// Clients send:
/// - X-Request-Email: base64url (no pad) encoded email
/// - X-Device-Identifier: device identifier
pub async fn handle_known_device(req: Request, env: &Env) -> Result<Response> {
    if req.method() != Method::Get {
        return error_response(&req, 405, "method_not_allowed", "Method not allowed");
    }

    let email_b64 = req.headers().get("X-Request-Email")?.unwrap_or_default();
    let device_id = req.headers().get("X-Device-Identifier")?.unwrap_or_default();

    if email_b64.trim().is_empty() {
        return error_response(&req, 400, "invalid_request", "X-Request-Email value is required");
    }
    if device_id.trim().is_empty() {
        return error_response(
            &req,
            400,
            "invalid_request",
            "X-Device-Identifier value is required",
        );
    }

    let email = match URL_SAFE_NO_PAD.decode(email_b64.trim().as_bytes()) {
        Ok(b) => match String::from_utf8(b) {
            Ok(s) => s,
            Err(_) => {
                return error_response(
                    &req,
                    400,
                    "invalid_request",
                    "X-Request-Email value failed to decode as UTF-8",
                )
            }
        },
        Err(_) => {
            return error_response(
                &req,
                400,
                "invalid_request",
                "X-Request-Email value failed to decode as base64url",
            )
        }
    };

    let db = match db_connect(env).await {
        Ok(db) => db,
        Err(e) => return internal_error_response(&req, "Failed to open libSQL connection", &e),
    };

    let result = if let Some(u) = user::Entity::find()
        .filter(user::Column::Email.eq(email.trim().to_lowercase()))
        .one(&db)
        .await
        .map_err(|e| worker::Error::RustError(e.to_string()))?
    {
        device::Entity::find_by_id(device_id.trim().to_string())
            .filter(device::Column::UserId.eq(u.id))
            .one(&db)
            .await
            .map_err(|e| worker::Error::RustError(e.to_string()))?
            .is_some()
    } else {
        false
    };

    let resp = Response::from_json(&result)?;
    json_with_cors(&req, resp)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PushTokenData {
    push_token: String,
}

/// POST/PUT /api/devices/identifier/<device_id>/token
pub async fn handle_device_token(mut req: Request, env: &Env, device_id: String) -> Result<Response> {
    if req.method() != Method::Post && req.method() != Method::Put {
        return error_response(&req, 405, "method_not_allowed", "Method not allowed");
    }

    let payload: PushTokenData = match req.json().await {
        Ok(p) => p,
        Err(e) => {
            worker::console_log!("Invalid JSON in devices/token: {e}");
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

    // Keep behavior strict: only allow updating the current device.
    if auth.device.id != device_id {
        return error_response(&req, 404, "not_found", "No device found");
    }

    let now = crate::worker_wasm::util::now_ts();
    let mut active: device::ActiveModel = auth.device.into();
    active.push_token = Set(Some(payload.push_token));
    active.updated_at = Set(now);

    if let Err(e) = active.update(&db).await {
        return internal_error_response(&req, "Failed to save device", &e);
    }

    let resp = Response::empty()?.with_status(200);
    json_with_cors(&req, resp)
}

/// POST/PUT /api/devices/identifier/<device_id>/clear-token
pub async fn handle_device_clear_token(req: Request, env: &Env, device_id: String) -> Result<Response> {
    if req.method() != Method::Post && req.method() != Method::Put {
        return error_response(&req, 405, "method_not_allowed", "Method not allowed");
    }

    let db = match db_connect(env).await {
        Ok(db) => db,
        Err(e) => return internal_error_response(&req, "Failed to open libSQL connection", &e),
    };

    let auth = match authenticate(&req, &db).await? {
        AuthResult::Authorized(a) => a,
        AuthResult::Unauthorized(resp) => return Ok(resp),
    };

    if auth.device.id != device_id {
        return error_response(&req, 404, "not_found", "No device found");
    }

    let now = crate::worker_wasm::util::now_ts();
    let mut active: device::ActiveModel = auth.device.into();
    active.push_token = Set(None);
    active.updated_at = Set(now);

    if let Err(e) = active.update(&db).await {
        return internal_error_response(&req, "Failed to save device", &e);
    }

    let resp = Response::empty()?.with_status(200);
    json_with_cors(&req, resp)
}
