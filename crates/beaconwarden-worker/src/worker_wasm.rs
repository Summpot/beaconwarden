use worker::*;

#[path = "wasm/db/mod.rs"]
pub mod db;
#[path = "wasm/crypto.rs"]
pub mod crypto;
#[path = "wasm/brevo.rs"]
pub mod brevo;
#[path = "wasm/env.rs"]
pub mod env;
#[path = "wasm/handlers/mod.rs"]
pub mod handlers;
#[path = "wasm/domains.rs"]
pub mod domains;
#[path = "wasm/http.rs"]
pub mod http;
#[path = "wasm/jwt.rs"]
pub mod jwt;
#[path = "wasm/util.rs"]
pub mod util;

use http::{internal_error_response, json_with_cors, not_found};

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
    if req.method() == Method::Get && path == "/api/now" {
        let resp = Response::from_json(&util::ts_to_rfc3339(util::now_ts()))?;
        return json_with_cors(&req, resp);
    }
    if req.method() == Method::Get && path == "/api/version" {
        let version = "2025.12.0";
        let resp = Response::from_json(&version)?;
        return json_with_cors(&req, resp);
    }
    if req.method() == Method::Get && path == "/api/alive" {
        // Keep compatibility with Vaultwarden: also validate DB connectivity.
        if let Err(e) = db::db_connect(&env).await {
            return internal_error_response(&req, "Failed to open libSQL connection", &e);
        }
        let resp = Response::from_json(&util::ts_to_rfc3339(util::now_ts()))?;
        return json_with_cors(&req, resp);
    }
    if req.method() == Method::Get && path == "/api/webauthn" {
        // Vaultwarden returns an empty list to prevent key-rotation issues.
        let resp = Response::from_json(&serde_json::json!({
            "object": "list",
            "data": [],
            "continuationToken": null,
        }))?;
        return json_with_cors(&req, resp);
    }

    if req.method() == Method::Post && path == "/api/accounts/prelogin" {
        return handlers::accounts::handle_prelogin(req, &env).await;
    }
    if req.method() == Method::Post && path == "/api/accounts/password-hint" {
        return handlers::accounts::handle_password_hint(req, &env).await;
    }
    if req.method() == Method::Post && path == "/api/accounts/register" {
        return handlers::accounts::handle_register(req, &env).await;
    }
    if req.method() == Method::Get && path == "/api/accounts/profile" {
        return handlers::accounts::handle_profile(req, &env).await;
    }
    if req.method() == Method::Get && path == "/api/accounts/revision-date" {
        return handlers::accounts::handle_revision_date(req, &env).await;
    }
    if req.method() == Method::Get && path == "/api/tasks" {
        return handlers::accounts::handle_tasks(req, &env).await;
    }
    if req.method() == Method::Get && path == "/api/devices" {
        return handlers::devices::handle_devices(req, &env).await;
    }
    if let Some(rest) = path.strip_prefix("/api/devices/identifier/") {
        // Matches legacy: GET /devices/identifier/<device_id>
        let device_id = rest.split('/').next().unwrap_or("").to_string();
        return handlers::devices::handle_device(req, &env, device_id).await;
    }
    if let Some(rest) = path.strip_prefix("/api/users/") {
        // Matches legacy: GET /users/<user_id>/public-key
        if let Some(user_id) = rest.strip_suffix("/public-key") {
            let user_id = user_id.trim_matches('/').to_string();
            return handlers::accounts::handle_user_public_key(req, &env, user_id).await;
        }
    }
    if req.method() == Method::Get && path == "/api/config" {
        return handlers::config::handle_config(req, &env).await;
    }

    // Domains settings (sync settings).
    if path == "/api/settings/domains" {
        return handlers::settings::handle_settings_domains(req, &env).await;
    }
    if req.method() == Method::Post && path == "/identity/connect/token" {
        return handlers::identity::handle_connect_token(req, &env).await;
    }

    // Folders.
    if path == "/api/folders" {
        return handlers::folders::handle_folders(req, &env).await;
    }
    if let Some(rest) = path.strip_prefix("/api/folders/") {
        let (folder_id, tail) = rest.split_once('/').unwrap_or((rest, ""));
        let tail = if tail.is_empty() { None } else { Some(tail) };
        return handlers::folders::handle_folder(req, &env, folder_id.to_string(), tail).await;
    }

    // Ciphers.
    if req.method() == Method::Post && path == "/api/ciphers/import" {
        return handlers::ciphers::handle_ciphers_import(req, &env).await;
    }

    // Bulk cipher operations must be routed before the "/api/ciphers/<id>" prefix handler.
    if path == "/api/ciphers/delete" {
        return handlers::ciphers::handle_ciphers_delete(req, &env).await;
    }
    if path == "/api/ciphers/restore" {
        return handlers::ciphers::handle_ciphers_restore(req, &env).await;
    }
    if path == "/api/ciphers/move" {
        return handlers::ciphers::handle_ciphers_move(req, &env).await;
    }
    if path == "/api/ciphers" || path == "/api/ciphers/create" {
        return handlers::ciphers::handle_ciphers(req, &env).await;
    }
    if let Some(rest) = path.strip_prefix("/api/ciphers/") {
        let (cipher_id, tail) = rest.split_once('/').unwrap_or((rest, ""));
        let tail = if tail.is_empty() { None } else { Some(tail) };
        return handlers::ciphers::handle_cipher(req, &env, cipher_id.to_string(), tail).await;
    }

    // Identity registration flow (used by newer Bitwarden clients).
    if req.method() == Method::Post && path == "/identity/accounts/prelogin" {
        return handlers::accounts::handle_prelogin(req, &env).await;
    }
    if req.method() == Method::Post && path == "/identity/accounts/register" {
        return handlers::accounts::handle_register(req, &env).await;
    }
    if req.method() == Method::Post && path == "/identity/accounts/register/send-verification-email" {
        return handlers::identity::handle_register_send_verification_email(req, &env).await;
    }
    if req.method() == Method::Post && path == "/identity/accounts/register/finish" {
        return handlers::identity::handle_register_finish(req, &env).await;
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
