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

    /// Optional password hint.
    pub password_hint: Option<String>,

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

    /// User-managed equivalent domains JSON.
    /// Stored as a JSON string for maximum forward-compatibility.
    pub equivalent_domains: String,

    /// User-managed list of excluded global equivalent domain types (JSON array).
    /// Stored as a JSON string for maximum forward-compatibility.
    pub excluded_globals: String,

    /// Unix timestamp (seconds).
    pub created_at: i64,

    /// Unix timestamp (seconds).
    pub updated_at: i64,

    /// Unix timestamp (seconds) when the account was verified.
    pub verified_at: Option<i64>,

    /// Unix timestamp (seconds) for the last verification attempt.
    pub last_verifying_at: Option<i64>,

    /// Counter used for verification throttling.
    pub login_verify_count: i32,

    /// Pending new email (change-email flow).
    pub email_new: Option<String>,

    /// Token used to confirm `email_new`.
    pub email_new_token: Option<String>,

    /// Encrypted TOTP secret.
    pub totp_secret: Option<String>,

    /// Encrypted recovery code set for TOTP.
    pub totp_recover: Option<String>,

    /// Optional security-stamp exception payload.
    pub stamp_exception: Option<String>,

    /// Optional API key.
    pub api_key: Option<String>,

    /// Optional avatar color.
    pub avatar_color: Option<String>,

    /// Optional external identifier.
    pub external_id: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
