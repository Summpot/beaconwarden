use worker::{Env, Request, Response, Result};

use crate::worker_wasm::db::db_connect;
use crate::worker_wasm::http::{internal_error_response, json_with_cors};

use super::admin_auth::ensure_admin_authorized;

pub async fn handle_db_ping(req: &Request, env: &Env) -> Result<Response> {
    if let Some(resp) = ensure_admin_authorized(req, env).await? {
        return Ok(resp);
    }

    let db = match db_connect(env).await {
        Ok(db) => db,
        Err(e) => return internal_error_response(req, "Failed to open libSQL connection", &e),
    };

    // A minimal query to validate the connection.
    if let Err(e) = db.ping().await {
        return internal_error_response(req, "libSQL ping failed", &e);
    }

    let resp = Response::from_json(&serde_json::json!({
        "success": true,
        "db": { "ok": true }
    }))?;

    json_with_cors(req, resp)
}
