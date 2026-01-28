use worker::*;

mod wasm;

use wasm::http::{json_with_cors, not_found};

#[event(fetch)]
pub async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    console_error_panic_hook::set_once();

    if req.method() == Method::Options {
        let resp = Response::empty()?.with_status(204);
        return json_with_cors(&req, resp);
    }

    let url = req.url()?;
    let path = url.path();

    // Minimal health endpoint to validate deployments.
    if req.method() == Method::Get && path == "/health" {
        let body = serde_json::json!({
            "ok": true,
            "service": "beaconwarden",
        });
        let resp = Response::from_json(&body)?;
        return json_with_cors(&req, resp);
    }

    // Admin: apply SeaORM migrations.
    if req.method() == Method::Post && path == "/v1/admin/migrations/up" {
        return wasm::handlers::migrations::handle_migrations_up(&req, &env).await;
    }

    not_found(&req)
}
