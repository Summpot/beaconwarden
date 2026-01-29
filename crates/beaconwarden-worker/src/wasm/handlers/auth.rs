use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use worker::{Request, Response, Result};

use crate::worker_wasm::http::{error_response, internal_error_response};
use crate::worker_wasm::util::now_ts;

use entity::{device, user};

use super::admin_auth::extract_bearer_token;

pub struct Authenticated {
    pub device: device::Model,
    pub user: user::Model,
}

pub enum AuthResult {
    Authorized(Authenticated),
    Unauthorized(Response),
}

/// Validate the request bearer token against the `devices` table and load the owning user.
///
/// This is the primary auth mechanism for Bitwarden-compatible endpoints on Workers.
pub async fn authenticate(req: &Request, db: &sea_orm::DatabaseConnection) -> Result<AuthResult> {
    let Some(token) = extract_bearer_token(req)? else {
        return Ok(AuthResult::Unauthorized(error_response(
            req,
            401,
            "unauthorized",
            "Missing bearer token",
        )?));
    };

    let now = now_ts();
    let Some(dev) = device::Entity::find()
        .filter(device::Column::AccessToken.eq(&token))
        .one(db)
        .await
        .map_err(|e| worker::Error::RustError(e.to_string()))?
    else {
        return Ok(AuthResult::Unauthorized(error_response(
            req,
            401,
            "unauthorized",
            "Invalid token",
        )?));
    };

    if let Some(exp) = dev.access_token_expires_at {
        if exp <= now {
            return Ok(AuthResult::Unauthorized(error_response(
                req,
                401,
                "unauthorized",
                "Token expired",
            )?));
        }
    }

    let Some(u) = user::Entity::find_by_id(dev.user_id.clone())
        .one(db)
        .await
        .map_err(|e| worker::Error::RustError(e.to_string()))?
    else {
        return Ok(AuthResult::Unauthorized(error_response(
            req,
            401,
            "unauthorized",
            "Invalid token",
        )?));
    };

    if !u.enabled {
        return Ok(AuthResult::Unauthorized(error_response(
            req,
            403,
            "forbidden",
            "User disabled",
        )?));
    }

    Ok(AuthResult::Authorized(Authenticated { device: dev, user: u }))
}

pub fn map_internal_error(req: &Request, context: &str, err: &impl std::fmt::Display) -> Result<Response> {
    internal_error_response(req, context, err)
}
