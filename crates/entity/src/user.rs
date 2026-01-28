use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// Minimal placeholder user model.
///
/// This will be expanded to match Bitwarden/Vaultwarden semantics during migration.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize, Deserialize)]
#[sea_orm(table_name = "users")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: String,

    #[sea_orm(unique)]
    pub email: String,

    /// Unix timestamp (seconds).
    pub created_at: i64,

    /// Unix timestamp (seconds).
    pub updated_at: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
