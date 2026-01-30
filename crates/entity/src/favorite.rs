use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// User-specific favorite flags for ciphers.
///
/// Vaultwarden stores favorites as a per-user mapping, not as a field on the cipher.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "favorites")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub user_id: String,

    #[sea_orm(primary_key, auto_increment = false)]
    pub cipher_id: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
