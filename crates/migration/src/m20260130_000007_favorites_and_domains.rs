use sea_orm_migration::prelude::*;
use sea_orm_migration::sea_orm::DbBackend;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // User domains settings used by /api/settings/domains and returned by /api/sync.
        // Stored as JSON strings for forward compatibility.

        // NOTE: SQLite/libSQL only supports a single ALTER TABLE operation per statement.
        manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .add_column(
                        ColumnDef::new(Users::EquivalentDomains)
                            .text()
                            .not_null()
                            .default("[]"),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .add_column(
                        ColumnDef::new(Users::ExcludedGlobals)
                            .text()
                            .not_null()
                            .default("[]"),
                    )
                    .to_owned(),
            )
            .await?;

        // Favorites mapping (per-user, per-cipher).
        manager
            .create_table(
                Table::create()
                    .table(Favorites::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(Favorites::UserId).string().not_null())
                    .col(ColumnDef::new(Favorites::CipherId).string().not_null())
                    .primary_key(
                        Index::create()
                            .name("pk_favorites_user_cipher")
                            .col(Favorites::UserId)
                            .col(Favorites::CipherId),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_favorites_user_id")
                            .from(Favorites::Table, Favorites::UserId)
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_favorites_cipher_id")
                            .from(Favorites::Table, Favorites::CipherId)
                            .to(Ciphers::Table, Ciphers::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_favorites_user_id")
                    .table(Favorites::Table)
                    .col(Favorites::UserId)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_favorites_cipher_id")
                    .table(Favorites::Table)
                    .col(Favorites::CipherId)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Best-effort rollback.
        let _ = manager
            .drop_index(Index::drop().name("idx_favorites_cipher_id").to_owned())
            .await;
        let _ = manager
            .drop_index(Index::drop().name("idx_favorites_user_id").to_owned())
            .await;

        let _ = manager
            .drop_table(Table::drop().table(Favorites::Table).to_owned())
            .await;

        if manager.get_database_backend() == DbBackend::Sqlite {
            // SQLite/libSQL: dropping columns is not supported.
            return Ok(());
        }

        let _ = manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .drop_column(Users::EquivalentDomains)
                    .to_owned(),
            )
            .await;

        let _ = manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .drop_column(Users::ExcludedGlobals)
                    .to_owned(),
            )
            .await;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum Users {
    Table,
    Id,
    EquivalentDomains,
    ExcludedGlobals,
}

#[derive(DeriveIden)]
enum Ciphers {
    Table,
    Id,
}

#[derive(DeriveIden)]
enum Favorites {
    Table,
    UserId,
    CipherId,
}
