use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// Persistent server-level secrets stored in libSQL.
///
/// Cloudflare Workers are stateless, so values like JWT signing secrets must be persisted
/// in the database to remain stable across deployments/isolates.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize, Deserialize)]
#[sea_orm(table_name = "server_secrets")]
pub struct Model {
    /// Secret name (e.g., "jwt_secret").
    #[sea_orm(primary_key)]
    pub name: String,

    /// Secret value (stored as a string).
    pub value: String,

    /// Unix timestamp (seconds).
    pub created_at: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
