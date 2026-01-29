use sea_orm_migration::prelude::*;
use sea_orm_migration::sea_query::Alias;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Fix a historical naming bug:
        // - The intended Vaultwarden column name is `users.akey`.
        // - A previous migration accidentally created `users.a_key`.
        //
        // This migration is intentionally simple: rename the known-wrong column
        // `a_key` to the expected Vaultwarden name `akey`.
        //
        // NOTE: `SchemaManager::has_table` is not supported by the Sqlite backend
        // in sea-orm-migration, so we do not use it here.
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("users"))
                    .rename_column(Alias::new("a_key"), Alias::new("akey"))
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Best-effort rollback.
        let _ = manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("users"))
                    .rename_column(Alias::new("akey"), Alias::new("a_key"))
                    .to_owned(),
            )
            .await;

        Ok(())
    }
}

// Intentionally avoid `#[derive(DeriveIden)]` here because we need exact
// column names (`a_key` vs `akey`) and `DeriveIden` does not support the
// `#[iden = "..."]` override attribute.
