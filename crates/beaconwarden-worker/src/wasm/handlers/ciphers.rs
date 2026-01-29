use std::collections::HashMap;

use sea_orm::{ActiveModelTrait, ActiveValue::NotSet, ColumnTrait, EntityTrait, QueryFilter, Set};
use serde_json::Value;
use worker::{Env, Method, Request, Response, Result};

use crate::worker_wasm::db::db_connect;
use crate::worker_wasm::handlers::auth::{authenticate, AuthResult};
use crate::worker_wasm::http::{error_response, internal_error_response, json_with_cors};
use crate::worker_wasm::util::{now_ts, ts_to_rfc3339, uuid_v4};

use entity::{cipher, folder, folder_cipher, user};

async fn touch_user_revision(db: &sea_orm::DatabaseConnection, user_id: &str, now: i64) -> Result<()> {
    user::Entity::update_many()
        .col_expr(user::Column::UpdatedAt, sea_orm::sea_query::Expr::value(now))
        .filter(user::Column::Id.eq(user_id))
        .exec(db)
        .await
        .map_err(|e| worker::Error::RustError(e.to_string()))?;
    Ok(())
}

fn cipher_json(c: &cipher::Model, folder_id: Option<String>) -> Value {
    let mut obj: Value = serde_json::from_str(&c.data).unwrap_or_else(|_| serde_json::json!({}));

    // Ensure stable server-controlled fields.
    obj["id"] = Value::String(c.id.clone());
    obj["revisionDate"] = Value::String(ts_to_rfc3339(c.updated_at));
    obj["creationDate"] = Value::String(ts_to_rfc3339(c.created_at));
    obj["deletedDate"] = match c.deleted_at {
        Some(ts) => Value::String(ts_to_rfc3339(ts)),
        None => Value::Null,
    };
    obj["folderId"] = folder_id.map(Value::String).unwrap_or(Value::Null);

    if obj.get("object").and_then(|v| v.as_str()).is_none() {
        obj["object"] = Value::String("cipher".to_string());
    }

    obj
}

fn value_get_string(v: &Value, key: &str) -> Option<String> {
    v.get(key).and_then(|x| x.as_str()).map(|s| s.to_string())
}

fn value_get_i32(v: &Value, key: &str) -> Option<i32> {
    v.get(key)
        .and_then(|x| x.as_i64())
        .and_then(|n| i32::try_from(n).ok())
}

async fn folder_map_for_ciphers(
    db: &sea_orm::DatabaseConnection,
    cipher_ids: &[String],
) -> Result<HashMap<String, String>> {
    if cipher_ids.is_empty() {
        return Ok(HashMap::new());
    }

    let mappings = folder_cipher::Entity::find()
        .filter(folder_cipher::Column::CipherId.is_in(cipher_ids.to_vec()))
        .all(db)
        .await
        .map_err(|e| worker::Error::RustError(e.to_string()))?;

    let mut map = HashMap::new();
    for m in mappings {
        // If a cipher ends up in multiple folders, pick an arbitrary one.
        map.entry(m.cipher_id).or_insert(m.folder_id);
    }

    Ok(map)
}

async fn set_cipher_folder(
    req: &Request,
    db: &sea_orm::DatabaseConnection,
    user_id: &str,
    cipher_id: &str,
    folder_id: Option<String>,
) -> Result<Option<Response>> {
    // Clear existing mapping(s) for this cipher.
    folder_cipher::Entity::delete_many()
        .filter(folder_cipher::Column::CipherId.eq(cipher_id))
        .exec(db)
        .await
        .map_err(|e| worker::Error::RustError(e.to_string()))?;

    let Some(folder_id) = folder_id else {
        return Ok(None);
    };

    // Validate that the folder exists and belongs to the current user.
    let exists = folder::Entity::find_by_id(folder_id.clone())
        .filter(folder::Column::UserId.eq(user_id))
        .one(db)
        .await
        .map_err(|e| worker::Error::RustError(e.to_string()))?;

    if exists.is_none() {
        return Ok(Some(error_response(
            req,
            400,
            "invalid_folder",
            "Folder does not exist or belongs to another user",
        )?));
    }

    let active = folder_cipher::ActiveModel {
        id: NotSet,
        folder_id: Set(folder_id),
        cipher_id: Set(cipher_id.to_string()),
    };

    let _ = active
        .insert(db)
        .await
        .map_err(|e| worker::Error::RustError(e.to_string()))?;

    Ok(None)
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ImportFolderData {
    name: String,
    id: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ImportRelationsData {
    // Cipher index
    key: usize,
    // Folder index
    value: usize,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ImportData {
    ciphers: Vec<Value>,
    folders: Vec<ImportFolderData>,
    folder_relationships: Vec<ImportRelationsData>,
}

pub async fn handle_ciphers_import(mut req: Request, env: &Env) -> Result<Response> {
    let db = match db_connect(env).await {
        Ok(db) => db,
        Err(e) => return internal_error_response(&req, "Failed to open libSQL connection", &e),
    };

    let auth = match authenticate(&req, &db).await? {
        AuthResult::Authorized(a) => a,
        AuthResult::Unauthorized(resp) => return Ok(resp),
    };

    if req.method() != Method::Post {
        return error_response(&req, 405, "method_not_allowed", "Method not allowed");
    }

    let payload: ImportData = match req.json().await {
        Ok(p) => p,
        Err(_) => return error_response(&req, 400, "invalid_json", "Invalid JSON body"),
    };

    // Pre-validate to avoid partial imports.
    for cipher in &payload.ciphers {
        let name = value_get_string(cipher, "name").unwrap_or_default();
        if name.trim().is_empty() {
            return error_response(&req, 400, "invalid_name", "Cipher name cannot be blank");
        }
    }
    for folder in &payload.folders {
        if folder.name.trim().is_empty() {
            return error_response(&req, 400, "invalid_name", "Folder name cannot be blank");
        }
    }

    // Create or reuse folders.
    let existing_folders: std::collections::HashMap<String, String> = folder::Entity::find()
        .filter(folder::Column::UserId.eq(auth.user.id.clone()))
        .all(&db)
        .await
        .map_err(|e| worker::Error::RustError(e.to_string()))?
        .into_iter()
        .map(|f| (f.id.clone(), f.id))
        .collect();

    let mut folder_ids: Vec<String> = Vec::with_capacity(payload.folders.len());
    for f in payload.folders {
        // Vaultwarden behavior: only reuse a folder if it already exists for this user.
        // Otherwise create a new folder with a new id (ignore imported id to avoid collisions).
        if let Some(id) = f.id.as_ref().and_then(|id| existing_folders.get(id)).cloned() {
            folder_ids.push(id);
            continue;
        }

        let now = now_ts();
        let folder_id = uuid_v4();
        let active = folder::ActiveModel {
            id: Set(folder_id.clone()),
            user_id: Set(auth.user.id.clone()),
            name: Set(f.name.trim().to_string()),
            created_at: Set(now),
            updated_at: Set(now),
        };

        let _ = active
            .insert(&db)
            .await
            .map_err(|e| worker::Error::RustError(e.to_string()))?;

        folder_ids.push(folder_id);
    }

    // Build cipher-index -> folder-id map.
    let mut relations_map: HashMap<usize, usize> = HashMap::with_capacity(payload.folder_relationships.len());
    for rel in payload.folder_relationships {
        relations_map.insert(rel.key, rel.value);
    }

    // Create ciphers.
    for (idx, cipher_payload) in payload.ciphers.into_iter().enumerate() {
        let name = value_get_string(&cipher_payload, "name").unwrap_or_default();
        let cipher_type = value_get_i32(&cipher_payload, "type").unwrap_or(1);

        // Always create new ids during import, matching Vaultwarden.
        let id = uuid_v4();
        let now = now_ts();

        let folder_id = relations_map
            .get(&idx)
            .and_then(|folder_idx| folder_ids.get(*folder_idx))
            .cloned();

        let active = cipher::ActiveModel {
            id: Set(id.clone()),
            created_at: Set(now),
            updated_at: Set(now),
            user_id: Set(Some(auth.user.id.clone())),
            organization_id: Set(value_get_string(&cipher_payload, "organizationId")),
            key: Set(value_get_string(&cipher_payload, "key")),
            r#type: Set(cipher_type),
            name: Set(name),
            notes: Set(value_get_string(&cipher_payload, "notes")),
            fields: Set(cipher_payload.get("fields").map(|v| v.to_string())),
            data: Set(cipher_payload.to_string()),
            password_history: Set(cipher_payload.get("passwordHistory").map(|v| v.to_string())),
            deleted_at: Set(None),
            reprompt: Set(value_get_i32(&cipher_payload, "reprompt")),
        };

        let _ = active
            .insert(&db)
            .await
            .map_err(|e| worker::Error::RustError(e.to_string()))?;

        if let Some(resp) = set_cipher_folder(&req, &db, &auth.user.id, &id, folder_id).await? {
            return Ok(resp);
        }
    }

    // Touch user revision so clients resync.
    touch_user_revision(&db, &auth.user.id, now_ts()).await?;

    let resp = Response::empty()?.with_status(200);
    json_with_cors(&req, resp)
}

pub async fn handle_ciphers(mut req: Request, env: &Env) -> Result<Response> {
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
            let ciphers = cipher::Entity::find()
                .filter(cipher::Column::UserId.eq(auth.user.id.clone()))
                .all(&db)
                .await
                .map_err(|e| worker::Error::RustError(e.to_string()))?;

            let ids: Vec<String> = ciphers.iter().map(|c| c.id.clone()).collect();
            let folder_map = folder_map_for_ciphers(&db, &ids).await?;

            let data: Vec<Value> = ciphers
                .iter()
                .map(|c| cipher_json(c, folder_map.get(&c.id).cloned()))
                .collect();

            let resp = Response::from_json(&serde_json::json!({
                "data": data,
                "object": "list",
                "continuationToken": Value::Null,
            }))?;

            json_with_cors(&req, resp)
        }
        Method::Post => {
            let payload: Value = match req.json().await {
                Ok(p) => p,
                Err(_) => return error_response(&req, 400, "invalid_json", "Invalid JSON body"),
            };

            let name = value_get_string(&payload, "name").unwrap_or_default();
            let cipher_type = value_get_i32(&payload, "type").unwrap_or(1);

            if name.trim().is_empty() {
                return error_response(&req, 400, "invalid_name", "Cipher name cannot be blank");
            }

            let id = value_get_string(&payload, "id").unwrap_or_else(uuid_v4);

            // Do not accidentally overwrite an existing cipher on create.
            let exists = cipher::Entity::find_by_id(id.clone())
                .one(&db)
                .await
                .map_err(|e| worker::Error::RustError(e.to_string()))?
                .is_some();
            if exists {
                return error_response(&req, 409, "conflict", "Cipher already exists");
            }

            let now = now_ts();
            let folder_id = value_get_string(&payload, "folderId");

            let active = cipher::ActiveModel {
                id: Set(id.clone()),
                created_at: Set(now),
                updated_at: Set(now),
                user_id: Set(Some(auth.user.id.clone())),
                organization_id: Set(value_get_string(&payload, "organizationId")),
                key: Set(value_get_string(&payload, "key")),
                r#type: Set(cipher_type),
                name: Set(name),
                notes: Set(value_get_string(&payload, "notes")),
                fields: Set(payload.get("fields").map(|v| v.to_string())),
                data: Set(payload.to_string()),
                password_history: Set(payload.get("passwordHistory").map(|v| v.to_string())),
                deleted_at: Set(None),
                reprompt: Set(value_get_i32(&payload, "reprompt")),
            };

            let created = active
                .insert(&db)
                .await
                .map_err(|e| worker::Error::RustError(e.to_string()))?;

            // Touch user revision so clients resync.
            touch_user_revision(&db, &auth.user.id, now).await?;

            // Folder mapping.
            if let Some(resp) = set_cipher_folder(&req, &db, &auth.user.id, &id, folder_id).await? {
                return Ok(resp);
            }

            let folder_map = folder_map_for_ciphers(&db, &[id.clone()]).await?;
            let resp = Response::from_json(&cipher_json(&created, folder_map.get(&id).cloned()))?;
            json_with_cors(&req, resp)
        }
        _ => error_response(&req, 405, "method_not_allowed", "Method not allowed"),
    }
}

pub async fn handle_cipher(mut req: Request, env: &Env, cipher_id: String, tail: Option<&str>) -> Result<Response> {
    let db = match db_connect(env).await {
        Ok(db) => db,
        Err(e) => return internal_error_response(&req, "Failed to open libSQL connection", &e),
    };

    let auth = match authenticate(&req, &db).await? {
        AuthResult::Authorized(a) => a,
        AuthResult::Unauthorized(resp) => return Ok(resp),
    };

    // Compatibility aliases:
    // - POST /ciphers/<id> behaves like PUT /ciphers/<id>
    // - PUT /ciphers/<id>/delete is soft-delete
    // - POST /ciphers/<id>/delete is hard-delete
    // - PUT /ciphers/<id>/restore restores a soft-deleted cipher

    let method = req.method();

    if tail == Some("delete") && method == Method::Put {
        // Soft delete.
        let now = now_ts();
        let res = cipher::Entity::update_many()
            .col_expr(cipher::Column::DeletedAt, sea_orm::sea_query::Expr::value(Some(now)))
            .col_expr(cipher::Column::UpdatedAt, sea_orm::sea_query::Expr::value(now))
            .filter(cipher::Column::Id.eq(cipher_id.clone()))
            .filter(cipher::Column::UserId.eq(auth.user.id.clone()))
            .exec(&db)
            .await
            .map_err(|e| worker::Error::RustError(e.to_string()))?;

        if res.rows_affected == 0 {
            return error_response(&req, 404, "not_found", "Invalid cipher");
        }

        touch_user_revision(&db, &auth.user.id, now).await?;

        let resp = Response::empty()?.with_status(200);
        return json_with_cors(&req, resp);
    }

    if tail == Some("delete") && method == Method::Post {
        // Hard delete.
        let now = now_ts();
        let res = cipher::Entity::delete_many()
            .filter(cipher::Column::Id.eq(cipher_id.clone()))
            .filter(cipher::Column::UserId.eq(auth.user.id.clone()))
            .exec(&db)
            .await
            .map_err(|e| worker::Error::RustError(e.to_string()))?;

        if res.rows_affected == 0 {
            return error_response(&req, 404, "not_found", "Invalid cipher");
        }

        touch_user_revision(&db, &auth.user.id, now).await?;

        let resp = Response::empty()?.with_status(200);
        return json_with_cors(&req, resp);
    }

    if tail == Some("restore") && method == Method::Put {
        let now = now_ts();
        let res = cipher::Entity::update_many()
            .col_expr(cipher::Column::DeletedAt, sea_orm::sea_query::Expr::value::<Option<i64>>(None))
            .col_expr(cipher::Column::UpdatedAt, sea_orm::sea_query::Expr::value(now))
            .filter(cipher::Column::Id.eq(cipher_id.clone()))
            .filter(cipher::Column::UserId.eq(auth.user.id.clone()))
            .exec(&db)
            .await
            .map_err(|e| worker::Error::RustError(e.to_string()))?;

        if res.rows_affected == 0 {
            return error_response(&req, 404, "not_found", "Invalid cipher");
        }

        touch_user_revision(&db, &auth.user.id, now).await?;

        let resp = Response::empty()?.with_status(200);
        return json_with_cors(&req, resp);
    }

    match method {
        Method::Get => {
            let found = cipher::Entity::find_by_id(cipher_id.clone())
                .filter(cipher::Column::UserId.eq(auth.user.id.clone()))
                .one(&db)
                .await
                .map_err(|e| worker::Error::RustError(e.to_string()))?;

            let Some(c) = found else {
                return error_response(&req, 404, "not_found", "Invalid cipher");
            };

            let folder_map = folder_map_for_ciphers(&db, &[cipher_id.clone()]).await?;
            let resp = Response::from_json(&cipher_json(&c, folder_map.get(&cipher_id).cloned()))?;
            json_with_cors(&req, resp)
        }
        Method::Put | Method::Post => {
            let payload: Value = match req.json().await {
                Ok(p) => p,
                Err(_) => return error_response(&req, 400, "invalid_json", "Invalid JSON body"),
            };

            let name = value_get_string(&payload, "name").unwrap_or_default();
            let cipher_type = value_get_i32(&payload, "type").unwrap_or(1);

            if name.trim().is_empty() {
                return error_response(&req, 400, "invalid_name", "Cipher name cannot be blank");
            }

            let found = cipher::Entity::find_by_id(cipher_id.clone())
                .filter(cipher::Column::UserId.eq(auth.user.id.clone()))
                .one(&db)
                .await
                .map_err(|e| worker::Error::RustError(e.to_string()))?;

            let Some(existing) = found else {
                return error_response(&req, 404, "not_found", "Invalid cipher");
            };

            let now = now_ts();
            let folder_id = value_get_string(&payload, "folderId");

            let mut active: cipher::ActiveModel = existing.into();
            active.updated_at = Set(now);
            active.organization_id = Set(value_get_string(&payload, "organizationId"));
            active.key = Set(value_get_string(&payload, "key"));
            active.r#type = Set(cipher_type);
            active.name = Set(name);
            active.notes = Set(value_get_string(&payload, "notes"));
            active.fields = Set(payload.get("fields").map(|v| v.to_string()));
            active.data = Set(payload.to_string());
            active.password_history = Set(payload.get("passwordHistory").map(|v| v.to_string()));
            active.reprompt = Set(value_get_i32(&payload, "reprompt"));

            let updated = active
                .update(&db)
                .await
                .map_err(|e| worker::Error::RustError(e.to_string()))?;

            touch_user_revision(&db, &auth.user.id, now).await?;

            if let Some(resp) = set_cipher_folder(&req, &db, &auth.user.id, &cipher_id, folder_id).await? {
                return Ok(resp);
            }

            let folder_map = folder_map_for_ciphers(&db, &[cipher_id.clone()]).await?;
            let resp = Response::from_json(&cipher_json(&updated, folder_map.get(&cipher_id).cloned()))?;
            json_with_cors(&req, resp)
        }
        Method::Delete => {
            // Hard delete.
            let now = now_ts();
            let res = cipher::Entity::delete_many()
                .filter(cipher::Column::Id.eq(cipher_id.clone()))
                .filter(cipher::Column::UserId.eq(auth.user.id.clone()))
                .exec(&db)
                .await
                .map_err(|e| worker::Error::RustError(e.to_string()))?;

            if res.rows_affected == 0 {
                return error_response(&req, 404, "not_found", "Invalid cipher");
            }

            touch_user_revision(&db, &auth.user.id, now).await?;

            let resp = Response::empty()?.with_status(200);
            json_with_cors(&req, resp)
        }
        _ => error_response(&req, 405, "method_not_allowed", "Method not allowed"),
    }
}
