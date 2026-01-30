use std::fmt::Display;

use worker::{Env, Request, Response, Result};

use migration::MigratorTrait;

use crate::worker_wasm::db::db_connect;
use crate::worker_wasm::http::json_with_cors;

use super::admin_auth::ensure_admin_authorized;

pub async fn handle_migrations_up(req: &Request, env: &Env) -> Result<Response> {
    if let Some(resp) = ensure_admin_authorized(req, env).await? {
        return Ok(resp);
    }

    let db = match db_connect(env).await {
        Ok(db) => db,
        Err(e) => return migration_internal_error_response(req, "Failed to open libSQL connection", &e),
    };

    // Cloudflare Workers enforce a hard limit on the number of outgoing subrequests.
    // libSQL/hrana executes each SQL statement as a subrequest, so large migrations
    // must be applied across multiple HTTP requests.
    //
    // Default to 1 migration per request to stay safely below the subrequest limit.
    let steps: u32 = req
        .url()
        .ok()
        .and_then(|url| {
            url.query_pairs()
                .find(|(k, _)| k == "steps" || k == "limit")
                .and_then(|(_, v)| v.parse::<u32>().ok())
        })
        .filter(|n| *n > 0)
        .unwrap_or(1);

    // Apply at most `steps` migrations in this request.
    // Avoid pre-scanning pending migrations here: it costs extra Hrana subrequests.
    if let Err(e) = migration::Migrator::up(&db, Some(steps)).await {
        return migration_internal_error_response(req, "Failed to apply migrations", &e);
    }

    let pending_after = match migration::Migrator::get_pending_migrations(&db).await {
        Ok(p) => p,
        Err(e) => return migration_internal_error_response(req, "Failed to read pending migrations", &e),
    };
    let done = pending_after.is_empty();
    let next = pending_after.first().map(|m| m.name());

    let resp = Response::from_json(&serde_json::json!({
        "success": true,
        "migrations": {
            "requested_steps": steps,
            "pending": pending_after.len(),
            "done": done,
            "next": next,
        }
    }))?;

    json_with_cors(req, resp)
}

fn migration_internal_error_response<E: Display>(
    req: &Request,
    context: &str,
    err: &E,
) -> Result<Response> {
    // Keep a console log for `wrangler tail`, but also return details for CI.
    // This endpoint is admin-only, so the extra details are not exposed to public clients.
    worker::console_log!("{context}: {err}");

    let details = format!("{err}");
    let details = details
        .replace("\r\n", "\n")
        .replace("\r", "\n")
        .lines()
        .take(50)
        .collect::<Vec<_>>()
        .join("\n");

    let body = serde_json::json!({
        "success": false,
        "error": {
            "code": "internal_error",
            "message": context,
            "details": details,
        }
    });

    let resp = Response::from_json(&body)?.with_status(500);
    json_with_cors(req, resp)
}
