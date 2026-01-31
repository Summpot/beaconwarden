use serde::Deserialize;
use serde_json::Value;
use worker::{Env, Method, Request, Response, Result};

use crate::worker_wasm::db::db_connect;
use crate::worker_wasm::handlers::auth::{authenticate, AuthResult};
use crate::worker_wasm::http::{error_response, internal_error_response, json_with_cors};

fn empty_list_json() -> Value {
    serde_json::json!({
        "data": [],
        "object": "list",
        "continuationToken": Value::Null,
    })
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EventCollection {
    // Mandatory
    r#type: i32,
    date: String,

    // Optional
    cipher_id: Option<String>,
    organization_id: Option<String>,
}

/// POST /events/collect
///
/// This endpoint is used for telemetry/audit event collection.
/// For the Workers-only deployment, we currently treat org events as optional and no-op.
///
/// We still require authentication and accept the payload to avoid client errors.
pub async fn handle_collect(mut req: Request, env: &Env) -> Result<Response> {
    if req.method() != Method::Post {
        return error_response(&req, 405, "method_not_allowed", "Method not allowed");
    }

    let db = match db_connect(env).await {
        Ok(db) => db,
        Err(e) => return internal_error_response(&req, "Failed to open libSQL connection", &e),
    };

    // Require auth even though we no-op.
    let _auth = match authenticate(&req, &db).await? {
        AuthResult::Authorized(a) => a,
        AuthResult::Unauthorized(resp) => return Ok(resp),
    };

    // Parse body as best-effort; ignore invalid events rather than failing clients.
    // Vaultwarden stores some of these when org events are enabled.
    let parsed: Result<Vec<EventCollection>, _> = req.json().await;
    if let Err(e) = parsed {
        worker::console_log!("Invalid JSON in events/collect (ignored): {e}");
    }

    let resp = Response::empty()?.with_status(200);
    json_with_cors(&req, resp)
}

/// GET /api/organizations/<org_id>/events
pub async fn handle_org_events(req: Request, env: &Env, _org_id: String) -> Result<Response> {
    if req.method() != Method::Get {
        return error_response(&req, 405, "method_not_allowed", "Method not allowed");
    }

    let db = match db_connect(env).await {
        Ok(db) => db,
        Err(e) => return internal_error_response(&req, "Failed to open libSQL connection", &e),
    };

    let _auth = match authenticate(&req, &db).await? {
        AuthResult::Authorized(a) => a,
        AuthResult::Unauthorized(resp) => return Ok(resp),
    };

    // TODO: Implement event storage + paging once org/events are enabled.
    let resp = Response::from_json(&empty_list_json())?;
    json_with_cors(&req, resp)
}

/// GET /api/ciphers/<cipher_id>/events
pub async fn handle_cipher_events(req: Request, env: &Env, _cipher_id: String) -> Result<Response> {
    if req.method() != Method::Get {
        return error_response(&req, 405, "method_not_allowed", "Method not allowed");
    }

    let db = match db_connect(env).await {
        Ok(db) => db,
        Err(e) => return internal_error_response(&req, "Failed to open libSQL connection", &e),
    };

    let _auth = match authenticate(&req, &db).await? {
        AuthResult::Authorized(a) => a,
        AuthResult::Unauthorized(resp) => return Ok(resp),
    };

    let resp = Response::from_json(&empty_list_json())?;
    json_with_cors(&req, resp)
}

/// GET /api/organizations/<org_id>/users/<member_id>/events
pub async fn handle_user_events(
    req: Request,
    env: &Env,
    _org_id: String,
    _member_id: String,
) -> Result<Response> {
    if req.method() != Method::Get {
        return error_response(&req, 405, "method_not_allowed", "Method not allowed");
    }

    let db = match db_connect(env).await {
        Ok(db) => db,
        Err(e) => return internal_error_response(&req, "Failed to open libSQL connection", &e),
    };

    let _auth = match authenticate(&req, &db).await? {
        AuthResult::Authorized(a) => a,
        AuthResult::Unauthorized(resp) => return Ok(resp),
    };

    let resp = Response::from_json(&empty_list_json())?;
    json_with_cors(&req, resp)
}
