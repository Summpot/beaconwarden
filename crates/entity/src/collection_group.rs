use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// Collection to group permissions mapping (collections_groups).
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "collections_groups")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub collection_id: String,

    #[sea_orm(primary_key, auto_increment = false)]
    pub group_id: String,

    pub read_only: bool,
    pub hide_passwords: bool,
    pub manage: bool,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
