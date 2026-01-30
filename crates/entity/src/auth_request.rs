use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// Auth request (used for device approval flows).
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "auth_requests")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: String,

    pub user_id: String,
    pub organization_id: Option<String>,

    pub request_device_identifier: String,
    pub device_type: i32,
    pub request_ip: String,

    pub response_device_id: Option<String>,
    pub access_code: String,
    pub public_key: String,
    pub enc_key: Option<String>,
    pub master_password_hash: Option<String>,
    pub approved: Option<bool>,

    /// Unix timestamp (seconds).
    pub creation_date: i64,

    /// Unix timestamp (seconds).
    pub response_date: Option<i64>,

    /// Unix timestamp (seconds).
    pub authentication_date: Option<i64>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
