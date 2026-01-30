use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// Bitwarden Send.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "sends")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: String,

    pub user_id: Option<String>,
    pub organization_id: Option<String>,

    pub name: String,
    pub notes: Option<String>,

    pub r#type: i32,

    /// Encrypted JSON payload.
    pub data: String,

    pub akey: String,

    pub password_hash: Option<Vec<u8>>,
    pub password_salt: Option<Vec<u8>>,
    pub password_iter: Option<i32>,

    pub max_access_count: Option<i32>,
    pub access_count: i32,

    /// Unix timestamp (seconds).
    pub creation_date: i64,

    /// Unix timestamp (seconds).
    pub revision_date: i64,

    /// Unix timestamp (seconds).
    pub expiration_date: Option<i64>,

    /// Unix timestamp (seconds).
    pub deletion_date: i64,

    pub disabled: bool,

    pub hide_email: Option<bool>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
