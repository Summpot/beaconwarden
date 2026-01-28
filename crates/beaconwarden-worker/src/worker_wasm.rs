use worker::*;

#[path = "wasm/db/mod.rs"]
pub mod db;
#[path = "wasm/crypto.rs"]
pub mod crypto;
#[path = "wasm/env.rs"]
pub mod env;
#[path = "wasm/handlers/mod.rs"]
pub mod handlers;
#[path = "wasm/http.rs"]
pub mod http;
#[path = "wasm/util.rs"]
pub mod util;

use http::{json_with_cors, not_found};

#[event(fetch)]
pub async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    console_error_panic_hook::set_once();

    if req.method() == Method::Options {
        let resp = Response::empty()?.with_status(204);
        return json_with_cors(&req, resp);
    }

    let url = req.url()?;
    let path = url.path();

    // Non-goals by design: websocket notifications and push.
    // Respond quickly with a stable error shape so clients don't hang.
    if path.starts_with("/notifications") {
        return http::error_response(
            &req,
            410,
            "notifications_disabled",
            "Notifications are disabled on this deployment",
        );
    }
    if path.starts_with("/push") {
        return http::error_response(
            &req,
            410,
            "push_disabled",
            "Push is disabled on this deployment",
        );
    }

    if req.method() == Method::Get && path == "/health" {
        let body = serde_json::json!({
            "ok": true,
            "service": "beaconwarden",
        });
        let resp = Response::from_json(&body)?;
        return json_with_cors(&req, resp);
    }

    // --- Bitwarden/Vaultwarden compatibility routes (minimum viable set) ---
    if req.method() == Method::Post && path == "/api/accounts/prelogin" {
        return handlers::accounts::handle_prelogin(req, &env).await;
    }
    if req.method() == Method::Post && path == "/api/accounts/register" {
        return handlers::accounts::handle_register(req, &env).await;
    }
    if req.method() == Method::Post && path == "/identity/connect/token" {
        return handlers::identity::handle_connect_token(req, &env).await;
    }
    if req.method() == Method::Get && path == "/api/sync" {
        return handlers::sync::handle_sync(req, &env).await;
    }

    if req.method() == Method::Post && path == "/v1/admin/migrations/up" {
        return handlers::migrations::handle_migrations_up(&req, &env).await;
    }

    if req.method() == Method::Get && path == "/v1/admin/db/ping" {
        return handlers::admin::handle_db_ping(&req, &env).await;
    }

    not_found(&req)
}
