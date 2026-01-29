use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use serde_json::Value;
use worker::{Env, Method, Request, Response, Result};

use crate::worker_wasm::db::db_connect;
use crate::worker_wasm::handlers::auth::{authenticate, AuthResult};
use crate::worker_wasm::http::{error_response, internal_error_response, json_with_cors};
use crate::worker_wasm::util::ts_to_rfc3339;

use entity::device;

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
