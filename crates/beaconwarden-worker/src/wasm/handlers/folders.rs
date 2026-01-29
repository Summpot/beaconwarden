use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use serde::Deserialize;
use serde_json::Value;
use worker::{Env, Method, Request, Response, Result};

use crate::worker_wasm::db::db_connect;
use crate::worker_wasm::handlers::auth::{authenticate, AuthResult};
use crate::worker_wasm::http::{error_response, internal_error_response, json_with_cors};
use crate::worker_wasm::util::{now_ts, ts_to_rfc3339, uuid_v4};

use entity::{folder, user};

async fn touch_user_revision(db: &sea_orm::DatabaseConnection, user_id: &str, now: i64) -> Result<()> {
    user::Entity::update_many()
        .col_expr(user::Column::UpdatedAt, sea_orm::sea_query::Expr::value(now))
        .filter(user::Column::Id.eq(user_id))
        .exec(db)
        .await
        .map_err(|e| worker::Error::RustError(e.to_string()))?;
    Ok(())
}

fn folder_json(f: &folder::Model) -> Value {
    serde_json::json!({
        "id": f.id,
        "name": f.name,
        "revisionDate": ts_to_rfc3339(f.updated_at),
        "object": "folder",
    })
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FolderData {
    name: String,
    id: Option<String>,
}

pub async fn handle_folders(mut req: Request, env: &Env) -> Result<Response> {
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
            let folders = folder::Entity::find()
                .filter(folder::Column::UserId.eq(auth.user.id.clone()))
                .all(&db)
                .await
                .map_err(|e| worker::Error::RustError(e.to_string()))?;

            let data: Vec<Value> = folders.iter().map(folder_json).collect();
            let resp = Response::from_json(&serde_json::json!({
                "data": data,
                "object": "list",
                "continuationToken": Value::Null,
            }))?;

            json_with_cors(&req, resp)
        }
        Method::Post => {
            let payload: FolderData = match req.json().await {
                Ok(p) => p,
                Err(_) => {
                    return error_response(&req, 400, "invalid_json", "Invalid JSON body");
                }
            };

            let name = payload.name.trim();
            if name.is_empty() {
                return error_response(&req, 400, "invalid_name", "Folder name cannot be blank");
            }

            let now = now_ts();
            let id = payload.id.unwrap_or_else(uuid_v4);

            let active = folder::ActiveModel {
                id: Set(id.clone()),
                user_id: Set(auth.user.id.clone()),
                name: Set(name.to_string()),
                created_at: Set(now),
                updated_at: Set(now),
            };

            let created = active
                .insert(&db)
                .await
                .map_err(|e| worker::Error::RustError(e.to_string()))?;

            touch_user_revision(&db, &auth.user.id, now).await?;

            let resp = Response::from_json(&folder_json(&created))?;
            json_with_cors(&req, resp)
        }
        _ => error_response(&req, 405, "method_not_allowed", "Method not allowed"),
    }
}

pub async fn handle_folder(mut req: Request, env: &Env, folder_id: String, tail: Option<&str>) -> Result<Response> {
    let db = match db_connect(env).await {
        Ok(db) => db,
        Err(e) => return internal_error_response(&req, "Failed to open libSQL connection", &e),
    };

    let auth = match authenticate(&req, &db).await? {
        AuthResult::Authorized(a) => a,
        AuthResult::Unauthorized(resp) => return Ok(resp),
    };

    // Compatibility: POST /folders/<id> behaves like PUT /folders/<id>.
    // Compatibility: POST /folders/<id>/delete behaves like DELETE /folders/<id>.
    let method = req.method();
    let is_delete_alias = method == Method::Post && tail == Some("delete");
    let effective_method = if is_delete_alias { Method::Delete } else { method.clone() };

    match effective_method {
        Method::Get => {
            let found = folder::Entity::find_by_id(folder_id.clone())
                .filter(folder::Column::UserId.eq(auth.user.id.clone()))
                .one(&db)
                .await
                .map_err(|e| worker::Error::RustError(e.to_string()))?;

            let Some(f) = found else {
                return error_response(&req, 404, "not_found", "Invalid folder");
            };

            let resp = Response::from_json(&folder_json(&f))?;
            json_with_cors(&req, resp)
        }
        Method::Put | Method::Post => {
            let payload: FolderData = match req.json().await {
                Ok(p) => p,
                Err(_) => {
                    return error_response(&req, 400, "invalid_json", "Invalid JSON body");
                }
            };

            let name = payload.name.trim();
            if name.is_empty() {
                return error_response(&req, 400, "invalid_name", "Folder name cannot be blank");
            }

            let found = folder::Entity::find_by_id(folder_id.clone())
                .filter(folder::Column::UserId.eq(auth.user.id.clone()))
                .one(&db)
                .await
                .map_err(|e| worker::Error::RustError(e.to_string()))?;

            let Some(f) = found else {
                return error_response(&req, 404, "not_found", "Invalid folder");
            };

            let now = now_ts();
            let mut active: folder::ActiveModel = f.into();
            active.name = Set(name.to_string());
            active.updated_at = Set(now);

            let updated = active
                .update(&db)
                .await
                .map_err(|e| worker::Error::RustError(e.to_string()))?;

            touch_user_revision(&db, &auth.user.id, now).await?;

            let resp = Response::from_json(&folder_json(&updated))?;
            json_with_cors(&req, resp)
        }
        Method::Delete => {
            let now = now_ts();
            let res = folder::Entity::delete_many()
                .filter(folder::Column::Id.eq(folder_id))
                .filter(folder::Column::UserId.eq(auth.user.id.clone()))
                .exec(&db)
                .await
                .map_err(|e| worker::Error::RustError(e.to_string()))?;

            if res.rows_affected == 0 {
                return error_response(&req, 404, "not_found", "Invalid folder");
            }

            touch_user_revision(&db, &auth.user.id, now).await?;

            let resp = Response::empty()?.with_status(200);
            json_with_cors(&req, resp)
        }
        _ => error_response(&req, 405, "method_not_allowed", "Method not allowed"),
    }
}
