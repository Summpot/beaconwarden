use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// Duo 2FA context.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "twofactor_duo_ctx")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub state: String,

    pub user_email: String,
    pub nonce: String,

    /// Unix timestamp (seconds).
    pub exp: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
