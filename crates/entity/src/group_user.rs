use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// Group membership mapping (groups_users).
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "groups_users")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub group_id: String,

    #[sea_orm(primary_key, auto_increment = false)]
    pub membership_id: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
