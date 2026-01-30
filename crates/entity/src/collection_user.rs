use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// Collection membership (users_collections).
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "users_collections")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub user_id: String,

    #[sea_orm(primary_key, auto_increment = false)]
    pub collection_id: String,

    pub read_only: bool,
    pub hide_passwords: bool,
    pub manage: bool,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
