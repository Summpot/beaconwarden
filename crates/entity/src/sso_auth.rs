use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// Temporary SSO auth state.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "sso_auth")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub state: String,

    pub client_challenge: String,
    pub nonce: String,
    pub redirect_uri: String,

    pub code_response: Option<String>,
    pub auth_response: Option<String>,

    /// Unix timestamp (seconds).
    pub created_at: i64,

    /// Unix timestamp (seconds).
    pub updated_at: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
