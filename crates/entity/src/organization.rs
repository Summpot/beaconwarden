use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// Organization (Bitwarden/Vaultwarden org).
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "organizations")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: String,

    pub name: String,

    pub billing_email: String,

    pub private_key: Option<String>,
    pub public_key: Option<String>,

    /// Unix timestamp (seconds).
    pub created_at: i64,

    /// Unix timestamp (seconds).
    pub updated_at: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
