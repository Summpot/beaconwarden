use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// Incomplete 2FA attempt record.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "twofactor_incomplete")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub user_id: String,

    #[sea_orm(primary_key, auto_increment = false)]
    pub device_id: String,

    pub device_name: String,
    pub device_type: i32,

    /// Unix timestamp (seconds).
    pub login_time: i64,

    pub ip_address: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
