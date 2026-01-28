use sea_orm_migration::prelude::*;
use sea_orm_migration::sea_orm::DbBackend;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Add Bitwarden/Vaultwarden-compatible auth fields.
        // Schema changes are additive to preserve compatibility.

        // NOTE: SQLite/libSQL only supports a single ALTER TABLE operation per statement.
        // SeaQuery will panic if multiple options are included. Keep each add_column separate.
        manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .add_column(ColumnDef::new(Users::Enabled).boolean().not_null().default(true))
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .add_column(ColumnDef::new(Users::Name).string())
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .add_column(ColumnDef::new(Users::PasswordHash).binary())
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .add_column(ColumnDef::new(Users::Salt).binary())
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .add_column(
                        ColumnDef::new(Users::PasswordIterations)
                            .integer()
                            .not_null()
                            .default(100_000),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .add_column(ColumnDef::new(Users::PasswordHint).text())
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .add_column(ColumnDef::new(Users::AKey).text().not_null().default(""))
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .add_column(ColumnDef::new(Users::PrivateKey).text())
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .add_column(ColumnDef::new(Users::PublicKey).text())
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .add_column(ColumnDef::new(Users::SecurityStamp).text().not_null().default(""))
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .add_column(
                        ColumnDef::new(Users::ClientKdfType)
                            .integer()
                            .not_null()
                            .default(0),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .add_column(
                        ColumnDef::new(Users::ClientKdfIter)
                            .integer()
                            .not_null()
                            .default(600_000),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .add_column(ColumnDef::new(Users::ClientKdfMemory).integer())
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .add_column(ColumnDef::new(Users::ClientKdfParallelism).integer())
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Devices::Table)
                    .add_column(ColumnDef::new(Devices::AccessToken).text())
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Devices::Table)
                    .add_column(ColumnDef::new(Devices::AccessTokenExpiresAt).big_integer())
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_devices_access_token")
                    .table(Devices::Table)
                    .col(Devices::AccessToken)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Best-effort rollback.
        // Note: SQLite has limited ALTER TABLE support for dropping columns.

        if manager.get_database_backend() == DbBackend::Sqlite {
            // Avoid panics from SeaQuery due to unsupported/multi-option ALTER TABLE.
            let _ = manager
                .drop_index(Index::drop().name("idx_devices_access_token").to_owned())
                .await;
            return Ok(());
        }

        let _ = manager
            .drop_index(Index::drop().name("idx_devices_access_token").to_owned())
            .await;

        let _ = manager
            .alter_table(
                Table::alter()
                    .table(Devices::Table)
                    .drop_column(Devices::AccessToken)
                    .to_owned(),
            )
            .await;

        let _ = manager
            .alter_table(
                Table::alter()
                    .table(Devices::Table)
                    .drop_column(Devices::AccessTokenExpiresAt)
                    .to_owned(),
            )
            .await;

        let _ = manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .drop_column(Users::Enabled)
                    .to_owned(),
            )
            .await;
        let _ = manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .drop_column(Users::Name)
                    .to_owned(),
            )
            .await;
        let _ = manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .drop_column(Users::PasswordHash)
                    .to_owned(),
            )
            .await;
        let _ = manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .drop_column(Users::Salt)
                    .to_owned(),
            )
            .await;
        let _ = manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .drop_column(Users::PasswordIterations)
                    .to_owned(),
            )
            .await;
        let _ = manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .drop_column(Users::PasswordHint)
                    .to_owned(),
            )
            .await;
        let _ = manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .drop_column(Users::AKey)
                    .to_owned(),
            )
            .await;
        let _ = manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .drop_column(Users::PrivateKey)
                    .to_owned(),
            )
            .await;
        let _ = manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .drop_column(Users::PublicKey)
                    .to_owned(),
            )
            .await;
        let _ = manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .drop_column(Users::SecurityStamp)
                    .to_owned(),
            )
            .await;
        let _ = manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .drop_column(Users::ClientKdfType)
                    .to_owned(),
            )
            .await;
        let _ = manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .drop_column(Users::ClientKdfIter)
                    .to_owned(),
            )
            .await;
        let _ = manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .drop_column(Users::ClientKdfMemory)
                    .to_owned(),
            )
            .await;
        let _ = manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .drop_column(Users::ClientKdfParallelism)
                    .to_owned(),
            )
            .await;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum Users {
    Table,
    Enabled,
    Name,
    PasswordHash,
    Salt,
    PasswordIterations,
    PasswordHint,
    AKey,
    PrivateKey,
    PublicKey,
    SecurityStamp,
    ClientKdfType,
    ClientKdfIter,
    ClientKdfMemory,
    ClientKdfParallelism,
}

#[derive(DeriveIden)]
enum Devices {
    Table,
    AccessToken,
    AccessTokenExpiresAt,
}
