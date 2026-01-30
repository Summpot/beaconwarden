use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// Two-factor auth configuration.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "twofactor")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: String,

    pub user_id: String,

    pub r#type: i32,

    pub enabled: bool,

    /// JSON payload.
    pub data: String,

    /// Unix timestamp (seconds).
    pub last_used: i64,

    /// Unix timestamp (seconds).
    pub created_at: i64,

    /// Unix timestamp (seconds).
    pub updated_at: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
