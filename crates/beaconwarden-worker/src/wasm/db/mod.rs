use std::time::Duration;

use sea_orm::{ConnectOptions, Database, DatabaseConnection};
use worker::{Env, Error, Result};

use super::env::env_string;

fn map_db_err(e: sea_orm::DbErr) -> Error {
    Error::RustError(e.to_string())
}

pub async fn db_connect(env: &Env) -> Result<DatabaseConnection> {
    let url = env_string(env, "LIBSQL_URL").ok_or_else(|| {
        Error::RustError("LIBSQL_URL is required for libsql connections".to_string())
    })?;

    let mut options = ConnectOptions::new(url);
    if let Some(token) = env_string(env, "LIBSQL_AUTH_TOKEN") {
        options.libsql_auth_token(token);
    }

    // Edge runtime friendly settings: keep pool tiny and timeouts short.
    options.max_connections(1);
    options.min_connections(0);
    options.connect_timeout(Duration::from_secs(5));
    options.acquire_timeout(Duration::from_secs(5));
    options.idle_timeout(Duration::from_secs(30));
    options.sqlx_logging(false);

    Database::connect(options).await.map_err(map_db_err)
}
