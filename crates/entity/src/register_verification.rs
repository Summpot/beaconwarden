use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// Register verification tokens used by the `/identity/accounts/register/*` flow.
///
/// Vaultwarden uses a JWT for this flow. BeaconWarden prefers the JWT path as well, but keeps
/// a DB-backed opaque token table as a compatibility fallback (e.g., if the JWT secret is not
/// available yet or tokens were issued by an older deployment).
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize, Deserialize)]
#[sea_orm(table_name = "register_verifications")]
pub struct Model {
    /// Opaque verification token (hex).
    #[sea_orm(primary_key)]
    pub id: String,

    pub email: String,

    pub name: Option<String>,

    /// When `true`, possession of the token implies the email address was verified
    /// (because the token was delivered via email).
    pub verified: bool,

    /// Unix timestamp (seconds).
    pub created_at: i64,

    /// Unix timestamp (seconds).
    pub expires_at: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
