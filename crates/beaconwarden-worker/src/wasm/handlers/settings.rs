use sea_orm::{ActiveModelTrait, Set};
use serde::Deserialize;
use worker::{Env, Method, Request, Response, Result};

use crate::worker_wasm::db::db_connect;
use crate::worker_wasm::domains::domains_json_for_user;
use crate::worker_wasm::handlers::auth::{authenticate, AuthResult};
use crate::worker_wasm::http::{error_response, internal_error_response, json_with_cors};
use crate::worker_wasm::util::now_ts;

use entity::user;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EquivDomainData {
    excluded_global_equivalent_domains: Option<Vec<i32>>,
    equivalent_domains: Option<Vec<Vec<String>>>,
}

/// GET/POST/PUT /api/settings/domains
pub async fn handle_settings_domains(mut req: Request, env: &Env) -> Result<Response> {
    let db = match db_connect(env).await {
        Ok(db) => db,
        Err(e) => return internal_error_response(&req, "Failed to open libSQL connection", &e),
    };

    let auth = match authenticate(&req, &db).await? {
        AuthResult::Authorized(a) => a,
        AuthResult::Unauthorized(resp) => return Ok(resp),
    };

    match req.method() {
        Method::Get => {
            let resp = Response::from_json(&domains_json_for_user(&auth.user, false))?;
            json_with_cors(&req, resp)
        }
        Method::Post | Method::Put => {
            let data: EquivDomainData = match req.json().await {
                Ok(p) => p,
                Err(_) => return error_response(&req, 400, "invalid_json", "Invalid JSON body"),
            };

            let now = now_ts();
            let mut active: user::ActiveModel = auth.user.into();
            active.updated_at = Set(now);

            if let Some(eq) = data.equivalent_domains {
                active.equivalent_domains = Set(serde_json::to_string(&eq).unwrap_or_else(|_| "[]".to_string()));
            }
            if let Some(ex) = data.excluded_global_equivalent_domains {
                active.excluded_globals = Set(serde_json::to_string(&ex).unwrap_or_else(|_| "[]".to_string()));
            }

            let _ = active
                .update(&db)
                .await
                .map_err(|e| worker::Error::RustError(e.to_string()))?;

            let resp = Response::from_json(&serde_json::json!({}))?;
            json_with_cors(&req, resp)
        }
        _ => error_response(&req, 405, "method_not_allowed", "Method not allowed"),
    }
}
