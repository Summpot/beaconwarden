use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// Invite-only allowlist entry.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "invitations")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub email: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
