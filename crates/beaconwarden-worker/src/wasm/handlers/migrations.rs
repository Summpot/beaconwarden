use worker::{Env, Request, Response, Result};

use migration::MigratorTrait;

use crate::worker_wasm::db::db_connect;
use crate::worker_wasm::http::{internal_error_response, json_with_cors};

use super::admin_auth::ensure_admin_authorized;

pub async fn handle_migrations_up(req: &Request, env: &Env) -> Result<Response> {
    if let Some(resp) = ensure_admin_authorized(req, env).await? {
        return Ok(resp);
    }

    let db = match db_connect(env).await {
        Ok(db) => db,
        Err(e) => return internal_error_response(req, "Failed to open libSQL connection", &e),
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

    let pending_before = match migration::Migrator::get_pending_migrations(&db).await {
        Ok(p) => p,
        Err(e) => return internal_error_response(req, "Failed to read pending migrations", &e),
    };

    let steps_to_apply = steps.min(pending_before.len().try_into().unwrap_or(u32::MAX));

    if steps_to_apply > 0 {
        if let Err(e) = migration::Migrator::up(&db, Some(steps_to_apply)).await {
            return internal_error_response(req, "Failed to apply migrations", &e);
        }
    }

    let pending_after = match migration::Migrator::get_pending_migrations(&db).await {
        Ok(p) => p,
        Err(e) => return internal_error_response(req, "Failed to read pending migrations", &e),
    };

    let applied_now = pending_before.len().saturating_sub(pending_after.len());
    let done = pending_after.is_empty();
    let next = pending_after.first().map(|m| m.name());

    let resp = Response::from_json(&serde_json::json!({
        "success": true,
        "migrations": {
            "requested_steps": steps,
            "applied_steps": steps_to_apply,
            "applied_now": applied_now,
            "pending": pending_after.len(),
            "done": done,
            "next": next,
        }
    }))?;

    json_with_cors(req, resp)
}
