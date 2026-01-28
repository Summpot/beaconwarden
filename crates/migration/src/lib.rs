pub use sea_orm_migration::prelude::*;

mod m20260128_000001_init;
mod m20260128_000002_core_tables;
mod m20260128_000003_auth_fields;

pub struct Migrator;

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20260128_000001_init::Migration),
            Box::new(m20260128_000002_core_tables::Migration),
            Box::new(m20260128_000003_auth_fields::Migration),
        ]
    }
}
