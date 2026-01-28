use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// Minimal placeholder user model.
///
/// This will be expanded to match Bitwarden/Vaultwarden semantics during migration.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize, Deserialize)]
#[sea_orm(table_name = "users")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: String,

    #[sea_orm(unique)]
    pub email: String,

    /// Whether the account is enabled.
    pub enabled: bool,

    /// Display name. When null, callers should fall back to email.
    pub name: Option<String>,

    /// PBKDF2 hash of the client-provided master password hash.
    pub password_hash: Option<Vec<u8>>,

    /// Random salt for `password_hash`.
    pub salt: Option<Vec<u8>>,

    /// Server-side PBKDF2 iterations for `password_hash`.
    pub password_iterations: i32,

    /// Bitwarden user symmetric key (encrypted/wrapped) as provided by clients.
    pub akey: String,

    pub private_key: Option<String>,
    pub public_key: Option<String>,

    /// Security stamp used by Bitwarden clients to invalidate sessions.
    pub security_stamp: String,

    /// Client KDF settings returned by `/api/accounts/prelogin`.
    pub client_kdf_type: i32,
    pub client_kdf_iter: i32,
    pub client_kdf_memory: Option<i32>,
    pub client_kdf_parallelism: Option<i32>,

    /// Unix timestamp (seconds).
    pub created_at: i64,

    /// Unix timestamp (seconds).
    pub updated_at: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
