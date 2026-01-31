use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use serde::Deserialize;
use serde_json::Value;
use worker::{Env, Method, Request, Response, Result};

use crate::worker_wasm::db::db_connect;
use crate::worker_wasm::handlers::auth::{authenticate, AuthResult};
use crate::worker_wasm::http::{error_response, internal_error_response, json_with_cors};
use crate::worker_wasm::util::{now_ts, uuid_v4};

use entity::{collection, collection_user, membership, org_policy, organization, user};

fn empty_list_json() -> Value {
    serde_json::json!({
        "object": "list",
        "data": [],
        "continuationToken": Value::Null,
    })
}

fn collection_json(c: &collection::Model) -> Value {
    serde_json::json!({
        "externalId": c.external_id,
        "id": c.id,
        "organizationId": c.organization_id,
        "name": c.name,
        "object": "collection",
    })
}

fn organization_json(org: &organization::Model) -> Value {
    // Modeled after Vaultwarden's Organization::to_json, with safe defaults.
    let has_keys = org.private_key.is_some() && org.public_key.is_some();

    serde_json::json!({
        "id": org.id,
        "name": org.name,
        "seats": Value::Null,
        "maxCollections": Value::Null,
        "maxStorageGb": i16::MAX,
        "use2fa": true,
        "useCustomPermissions": true,
        "useDirectory": false,
        "useEvents": false,
        "useGroups": false,
        "useTotp": true,
        "usePolicies": true,
        "useScim": false,
        "useSso": false,
        "useKeyConnector": false,
        "usePasswordManager": true,
        "useSecretsManager": false,
        "selfHost": true,
        "useApi": true,
        "hasPublicAndPrivateKeys": has_keys,
        "useResetPassword": false,
        "allowAdminAccessToAllCollectionItems": true,
        "limitCollectionCreation": true,
        "limitCollectionDeletion": true,

        "businessName": org.name,
        "businessAddress1": Value::Null,
        "businessAddress2": Value::Null,
        "businessAddress3": Value::Null,
        "businessCountry": Value::Null,
        "businessTaxNumber": Value::Null,

        "maxAutoscaleSeats": Value::Null,
        "maxAutoscaleSmSeats": Value::Null,
        "maxAutoscaleSmServiceAccounts": Value::Null,

        "secretsManagerPlan": Value::Null,
        "smSeats": Value::Null,
        "smServiceAccounts": Value::Null,

        "billingEmail": org.billing_email,
        "planType": 6,
        "usersGetPremium": true,
        "object": "organization",
    })
}

fn policy_json(p: &org_policy::Model) -> Value {
    let data_json: Value = serde_json::from_str(&p.data).unwrap_or(Value::Null);
    let mut obj = serde_json::json!({
        "id": p.id,
        "organizationId": p.organization_id,
        "type": p.r#type,
        "data": data_json,
        "enabled": p.enabled,
        "object": "policy",
    });

    // Vaultwarden adds this key for ResetPassword policy (type=8) to allow toggling.
    if p.r#type == 8 {
        obj["canToggleState"] = Value::Bool(true);
    }

    obj
}

async fn ensure_member(db: &sea_orm::DatabaseConnection, user_id: &str, org_id: &str) -> Result<Option<membership::Model>> {
    membership::Entity::find()
        .filter(membership::Column::UserId.eq(user_id))
        .filter(membership::Column::OrganizationId.eq(org_id))
        .one(db)
        .await
        .map_err(|e| worker::Error::RustError(e.to_string()))
}

async fn touch_user_revision(db: &sea_orm::DatabaseConnection, user_id: &str, now: i64) -> Result<()> {
    user::Entity::update_many()
        .col_expr(user::Column::UpdatedAt, sea_orm::sea_query::Expr::value(now))
        .filter(user::Column::Id.eq(user_id))
        .exec(db)
        .await
        .map_err(|e| worker::Error::RustError(e.to_string()))?;
    Ok(())
}

// --- /api/collections ---

pub async fn handle_user_collections(req: Request, env: &Env) -> Result<Response> {
    let db = match db_connect(env).await {
        Ok(db) => db,
        Err(e) => return internal_error_response(&req, "Failed to open libSQL connection", &e),
    };

    let auth = match authenticate(&req, &db).await? {
        AuthResult::Authorized(a) => a,
        AuthResult::Unauthorized(resp) => return Ok(resp),
    };

    if req.method() != Method::Get {
        return error_response(&req, 405, "method_not_allowed", "Method not allowed");
    }

    let memberships = collection_user::Entity::find()
        .filter(collection_user::Column::UserId.eq(auth.user.id.clone()))
        .all(&db)
        .await
        .map_err(|e| worker::Error::RustError(e.to_string()))?;

    let collection_ids: Vec<String> = memberships.into_iter().map(|m| m.collection_id).collect();
    if collection_ids.is_empty() {
        let resp = Response::from_json(&empty_list_json())?;
        return json_with_cors(&req, resp);
    }

    let cols = collection::Entity::find()
        .filter(collection::Column::Id.is_in(collection_ids))
        .all(&db)
        .await
        .map_err(|e| worker::Error::RustError(e.to_string()))?;

    let resp = Response::from_json(&serde_json::json!({
        "data": cols.iter().map(collection_json).collect::<Vec<_>>(),
        "object": "list",
        "continuationToken": Value::Null,
    }))?;

    json_with_cors(&req, resp)
}

// --- /api/organizations ---

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OrgKeyData {
    encrypted_private_key: String,
    public_key: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OrgCreateData {
    billing_email: String,
    collection_name: String,
    key: String,
    name: String,
    keys: Option<OrgKeyData>,

    // Ignored in Vaultwarden (always uses same plan); keep for compatibility.
    #[allow(dead_code)]
    plan_type: Option<Value>,
}

pub async fn handle_organizations(mut req: Request, env: &Env) -> Result<Response> {
    let db = match db_connect(env).await {
        Ok(db) => db,
        Err(e) => return internal_error_response(&req, "Failed to open libSQL connection", &e),
    };

    let auth = match authenticate(&req, &db).await? {
        AuthResult::Authorized(a) => a,
        AuthResult::Unauthorized(resp) => return Ok(resp),
    };

    match req.method() {
        Method::Post => {
            let payload: OrgCreateData = match req.json().await {
                Ok(p) => p,
                Err(_) => return error_response(&req, 400, "invalid_json", "Invalid JSON body"),
            };

            let name = payload.name.trim();
            if name.is_empty() {
                return error_response(&req, 400, "invalid_name", "Organization name cannot be blank");
            }

            let billing_email = payload.billing_email.trim().to_lowercase();
            if billing_email.is_empty() {
                return error_response(&req, 400, "invalid_email", "Billing email cannot be blank");
            }

            let collection_name = payload.collection_name.trim();
            if collection_name.is_empty() {
                return error_response(&req, 400, "invalid_name", "Collection name cannot be blank");
            }

            let (private_key, public_key) = payload
                .keys
                .map(|k| (Some(k.encrypted_private_key), Some(k.public_key)))
                .unwrap_or((None, None));

            let now = now_ts();
            let org_id = uuid_v4();

            let org_active = organization::ActiveModel {
                id: Set(org_id.clone()),
                name: Set(name.to_string()),
                billing_email: Set(billing_email),
                private_key: Set(private_key),
                public_key: Set(public_key),
                created_at: Set(now),
                updated_at: Set(now),
            };

            let org = org_active
                .insert(&db)
                .await
                .map_err(|e| worker::Error::RustError(e.to_string()))?;

            // Create owner membership.
            // NOTE: We currently do not enforce membership status semantics; this is a best-effort.
            let member_active = membership::ActiveModel {
                id: Set(uuid_v4()),
                user_id: Set(auth.user.id.clone()),
                organization_id: Set(org_id.clone()),
                invited_by_email: Set(None),
                access_all: Set(true),
                akey: Set(payload.key),
                status: Set(2),
                r#type: Set(0),
                reset_password_key: Set(None),
                external_id: Set(None),
                created_at: Set(now),
                updated_at: Set(now),
            };

            member_active
                .insert(&db)
                .await
                .map_err(|e| worker::Error::RustError(e.to_string()))?;

            // Create default collection.
            let col_active = collection::ActiveModel {
                id: Set(uuid_v4()),
                organization_id: Set(org_id),
                name: Set(collection_name.to_string()),
                external_id: Set(None),
                created_at: Set(now),
                updated_at: Set(now),
            };

            col_active
                .insert(&db)
                .await
                .map_err(|e| worker::Error::RustError(e.to_string()))?;

            touch_user_revision(&db, &auth.user.id, now).await?;

            let resp = Response::from_json(&organization_json(&org))?;
            json_with_cors(&req, resp)
        }
        // Compatibility: some clients/UI paths want these endpoints present.
        Method::Get => {
            // We do not yet implement a full organization directory view. For now return an empty list.
            let resp = Response::from_json(&empty_list_json())?;
            json_with_cors(&req, resp)
        }
        _ => error_response(&req, 405, "method_not_allowed", "Method not allowed"),
    }
}

pub async fn handle_organization(req: Request, env: &Env, org_id: String, tail: Option<&str>) -> Result<Response> {
    let db = match db_connect(env).await {
        Ok(db) => db,
        Err(e) => return internal_error_response(&req, "Failed to open libSQL connection", &e),
    };

    let auth = match authenticate(&req, &db).await? {
        AuthResult::Authorized(a) => a,
        AuthResult::Unauthorized(resp) => return Ok(resp),
    };

    // Require membership for all org-scoped routes.
    if ensure_member(&db, &auth.user.id, &org_id).await?.is_none() {
        return error_response(&req, 404, "not_found", "Organization not found");
    }

    match (req.method(), tail.unwrap_or("")) {
        (Method::Get, "") => {
            let Some(org) = organization::Entity::find_by_id(org_id)
                .one(&db)
                .await
                .map_err(|e| worker::Error::RustError(e.to_string()))?
            else {
                return error_response(&req, 404, "not_found", "Organization not found");
            };

            let resp = Response::from_json(&organization_json(&org))?;
            json_with_cors(&req, resp)
        }

        (Method::Get, "collections") => {
            let cols = collection::Entity::find()
                .filter(collection::Column::OrganizationId.eq(org_id))
                .all(&db)
                .await
                .map_err(|e| worker::Error::RustError(e.to_string()))?;

            let resp = Response::from_json(&serde_json::json!({
                "data": cols.iter().map(collection_json).collect::<Vec<_>>(),
                "object": "list",
                "continuationToken": Value::Null,
            }))?;

            json_with_cors(&req, resp)
        }

        (Method::Get, "policies") => {
            let policies = org_policy::Entity::find()
                .filter(org_policy::Column::OrganizationId.eq(org_id))
                .all(&db)
                .await
                .map_err(|e| worker::Error::RustError(e.to_string()))?;

            let resp = Response::from_json(&serde_json::json!({
                "data": policies.iter().map(policy_json).collect::<Vec<_>>(),
                "object": "list",
                "continuationToken": Value::Null,
            }))?;

            json_with_cors(&req, resp)
        }

        (Method::Get, "public-key") | (Method::Get, "keys") => {
            let Some(org) = organization::Entity::find_by_id(org_id)
                .one(&db)
                .await
                .map_err(|e| worker::Error::RustError(e.to_string()))?
            else {
                return error_response(&req, 404, "not_found", "Organization not found");
            };

            let resp = Response::from_json(&serde_json::json!({
                "object": "organizationPublicKey",
                "publicKey": org.public_key,
            }))?;

            json_with_cors(&req, resp)
        }

        // Web-vault convenience endpoints: prevent JS 404 noise.
        (Method::Get, "tax") => {
            let resp = Response::from_json(&empty_list_json())?;
            json_with_cors(&req, resp)
        }
        (Method::Get, "billing/metadata") => {
            let resp = Response::from_json(&empty_list_json())?;
            json_with_cors(&req, resp)
        }
        (Method::Get, "billing/vnext/warnings") => {
            let resp = Response::from_json(&serde_json::json!({
                "freeTrial": Value::Null,
                "inactiveSubscription": Value::Null,
                "resellerRenewal": Value::Null,
                "taxId": Value::Null,
            }))?;
            json_with_cors(&req, resp)
        }

        _ => error_response(&req, 404, "not_found", "Not found"),
    }
}

// --- /api/plans ---

pub async fn handle_plans(req: Request, env: &Env) -> Result<Response> {
    let db = match db_connect(env).await {
        Ok(db) => db,
        Err(e) => return internal_error_response(&req, "Failed to open libSQL connection", &e),
    };

    // Vaultwarden requires auth; keep that behavior.
    match authenticate(&req, &db).await? {
        AuthResult::Authorized(_) => {}
        AuthResult::Unauthorized(resp) => return Ok(resp),
    };

    if req.method() != Method::Get {
        return error_response(&req, 405, "method_not_allowed", "Method not allowed");
    }

    // Minimal response to allow the web-vault UI to render the organization creation flow.
    let resp = Response::from_json(&serde_json::json!({
        "object": "list",
        "data": [{
            "object": "plan",
            "type": 0,
            "product": 0,
            "name": "Free",
            "nameLocalizationKey": "planNameFree",
            "bitwardenProduct": 0,
            "maxUsers": 0,
            "descriptionLocalizationKey": "planDescFree"
        },{
            "object": "plan",
            "type": 0,
            "product": 1,
            "name": "Free",
            "nameLocalizationKey": "planNameFree",
            "bitwardenProduct": 1,
            "maxUsers": 0,
            "descriptionLocalizationKey": "planDescFree"
        }],
        "continuationToken": Value::Null,
    }))?;

    json_with_cors(&req, resp)
}

pub async fn handle_plans_all(req: Request, env: &Env) -> Result<Response> {
    handle_plans(req, env).await
}

pub async fn handle_plans_tax_rates(req: Request, env: &Env) -> Result<Response> {
    let db = match db_connect(env).await {
        Ok(db) => db,
        Err(e) => return internal_error_response(&req, "Failed to open libSQL connection", &e),
    };

    match authenticate(&req, &db).await? {
        AuthResult::Authorized(_) => {}
        AuthResult::Unauthorized(resp) => return Ok(resp),
    };

    if req.method() != Method::Get {
        return error_response(&req, 405, "method_not_allowed", "Method not allowed");
    }

    let resp = Response::from_json(&empty_list_json())?;
    json_with_cors(&req, resp)
}
