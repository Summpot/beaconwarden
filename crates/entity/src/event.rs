use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// Organization event log record.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "event")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: String,

    pub event_type: i32,

    pub user_id: Option<String>,
    pub organization_id: Option<String>,
    pub cipher_id: Option<String>,
    pub collection_id: Option<String>,
    pub group_id: Option<String>,
    pub org_user_id: Option<String>,
    pub act_user_id: Option<String>,

    pub device_type: Option<i32>,
    pub ip_address: Option<String>,

    /// Unix timestamp (seconds).
    pub event_date: i64,

    pub policy_id: Option<String>,
    pub provider_uuid: Option<String>,
    pub provider_user_uuid: Option<String>,
    pub provider_org_uuid: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
