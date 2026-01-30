use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// Organization API key.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "organization_api_key")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,

    #[sea_orm(primary_key, auto_increment = false)]
    pub organization_id: String,

    pub r#type: i32,

    pub api_key: String,

    /// Unix timestamp (seconds).
    pub revision_date: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
