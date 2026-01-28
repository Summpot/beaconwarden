use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// Bitwarden/Vaultwarden device registration.
///
/// This is a core auth primitive: refresh tokens and 2FA remember tokens are
/// tied to a device.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "devices")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: String,

    pub user_id: String,

    pub name: String,

    /// Bitwarden device type enum value.
    pub device_type: i32,

    pub push_uuid: Option<String>,
    pub push_token: Option<String>,

    pub refresh_token: String,
    pub twofactor_remember: Option<String>,

    /// Unix timestamp (seconds).
    pub created_at: i64,

    /// Unix timestamp (seconds).
    pub updated_at: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
