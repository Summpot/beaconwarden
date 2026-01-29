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
        // This migration renames `a_key` -> `akey` when needed and is safe to
        // run against databases that already have the correct column.

        if !manager.has_table("users").await? {
            return Ok(());
        }

        let has_akey = manager.has_column("users", "akey").await?;
        let has_a_key = manager.has_column("users", "a_key").await?;

        if !has_akey && has_a_key {
            manager
                .alter_table(
                    Table::alter()
                        .table(Alias::new("users"))
                        .rename_column(Alias::new("a_key"), Alias::new("akey"))
                        .to_owned(),
                )
                .await?;
            return Ok(());
        }

        if !has_akey {
            // Best-effort: older DBs might have neither column (e.g. partially migrated).
            manager
                .alter_table(
                    Table::alter()
                        .table(Alias::new("users"))
                        .add_column(
                            ColumnDef::new(Alias::new("akey"))
                                .text()
                                .not_null()
                                .default(""),
                        )
                        .to_owned(),
                )
                .await?;
        }

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Best-effort rollback. We avoid dropping columns on SQLite/libSQL.
        if !manager.has_table("users").await? {
            return Ok(());
        }

        let has_akey = manager.has_column("users", "akey").await?;
        let has_a_key = manager.has_column("users", "a_key").await?;

        if has_akey && !has_a_key {
            let _ = manager
                .alter_table(
                    Table::alter()
                        .table(Alias::new("users"))
                        .rename_column(Alias::new("akey"), Alias::new("a_key"))
                        .to_owned(),
                )
                .await;
        }

        Ok(())
    }
}

// Intentionally avoid `#[derive(DeriveIden)]` here because we need exact
// column names (`a_key` vs `akey`) and `DeriveIden` does not support the
// `#[iden = "..."]` override attribute.
