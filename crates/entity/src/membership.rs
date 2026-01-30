use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// Organization membership mapping (users_organizations).
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "users_organizations")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: String,

    pub user_id: String,
    pub organization_id: String,

    pub invited_by_email: Option<String>,

    pub access_all: bool,

    /// Organization key for this user (encrypted).
    pub akey: String,

    /// Membership status.
    pub status: i32,

    /// Membership type (owner/admin/user/manager).
    pub r#type: i32,

    pub reset_password_key: Option<String>,

    pub external_id: Option<String>,

    /// Unix timestamp (seconds).
    pub created_at: i64,

    /// Unix timestamp (seconds).
    pub updated_at: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
