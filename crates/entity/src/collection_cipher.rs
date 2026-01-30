use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// Cipher to collection mapping (ciphers_collections).
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "ciphers_collections")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub cipher_id: String,

    #[sea_orm(primary_key, auto_increment = false)]
    pub collection_id: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
