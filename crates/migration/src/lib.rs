pub use sea_orm_migration::prelude::*;

mod m20260128_000001_init;
mod m20260128_000002_core_tables;
mod m20260128_000003_auth_fields;
mod m20260129_000004_register_verifications;
mod m20260129_000005_fix_users_akey_column;
mod m20260129_000006_server_secrets;
mod m20260130_000007_favorites_and_domains;
mod m20260130_000008_more_entities;

pub struct Migrator;

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20260128_000001_init::Migration),
            Box::new(m20260128_000002_core_tables::Migration),
            Box::new(m20260128_000003_auth_fields::Migration),
            Box::new(m20260129_000004_register_verifications::Migration),
            Box::new(m20260129_000005_fix_users_akey_column::Migration),
            Box::new(m20260129_000006_server_secrets::Migration),
            Box::new(m20260130_000007_favorites_and_domains::Migration),
            Box::new(m20260130_000008_more_entities::Migration),
        ]
    }
}
