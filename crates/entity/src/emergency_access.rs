use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// Emergency access (Bitwarden feature).
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "emergency_access")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: String,

    pub grantor_id: String,
    pub grantee_id: Option<String>,
    pub email: Option<String>,
    pub key_encrypted: Option<String>,

    pub r#type: i32,
    pub status: i32,
    pub wait_time_days: i32,

    /// Unix timestamp (seconds).
    pub recovery_initiated_at: Option<i64>,

    /// Unix timestamp (seconds).
    pub last_notification_at: Option<i64>,

    /// Unix timestamp (seconds).
    pub updated_at: i64,

    /// Unix timestamp (seconds).
    pub created_at: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
