use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// Encrypted vault item.
///
/// Most fields are opaque encrypted strings that must be preserved byte-for-byte
/// for client compatibility.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "ciphers")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: String,

    /// Unix timestamp (seconds).
    pub created_at: i64,

    /// Unix timestamp (seconds).
    pub updated_at: i64,

    /// Direct owner (nullable for org-owned ciphers).
    pub user_id: Option<String>,

    /// Owning organization (nullable for user-owned ciphers).
    pub organization_id: Option<String>,

    /// Cipher-specific key (optional).
    pub key: Option<String>,

    /// 1=Login, 2=SecureNote, 3=Card, 4=Identity, 5=SshKey.
    pub r#type: i32,

    pub name: String,

    pub notes: Option<String>,
    pub fields: Option<String>,

    /// Encrypted JSON payload.
    pub data: String,

    pub password_history: Option<String>,

    /// Unix timestamp (seconds).
    pub deleted_at: Option<i64>,

    pub reprompt: Option<i32>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
