use worker::*;

#[path = "wasm/db/mod.rs"]
pub mod db;
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

    if req.method() == Method::Get && path == "/health" {
        let body = serde_json::json!({
            "ok": true,
            "service": "beaconwarden",
        });
        let resp = Response::from_json(&body)?;
        return json_with_cors(&req, resp);
    }

    if req.method() == Method::Post && path == "/v1/admin/migrations/up" {
        return handlers::migrations::handle_migrations_up(&req, &env).await;
    }

    not_found(&req)
}
