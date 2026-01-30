use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// SSO user link.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "sso_users")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub user_id: String,

    pub identifier: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
