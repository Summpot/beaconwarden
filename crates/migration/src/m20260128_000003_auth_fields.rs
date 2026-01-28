use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Add Bitwarden/Vaultwarden-compatible auth fields.
        // Schema changes are additive to preserve compatibility.

        manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .add_column(ColumnDef::new(Users::Enabled).boolean().not_null().default(true))
                    .add_column(ColumnDef::new(Users::Name).string())
                    .add_column(ColumnDef::new(Users::PasswordHash).binary())
                    .add_column(ColumnDef::new(Users::Salt).binary())
                    .add_column(
                        ColumnDef::new(Users::PasswordIterations)
                            .integer()
                            .not_null()
                            .default(100_000),
                    )
                    .add_column(ColumnDef::new(Users::PasswordHint).text())
                    .add_column(ColumnDef::new(Users::AKey).text().not_null().default(""))
                    .add_column(ColumnDef::new(Users::PrivateKey).text())
                    .add_column(ColumnDef::new(Users::PublicKey).text())
                    .add_column(ColumnDef::new(Users::SecurityStamp).text().not_null().default(""))
                    .add_column(
                        ColumnDef::new(Users::ClientKdfType)
                            .integer()
                            .not_null()
                            .default(0),
                    )
                    .add_column(
                        ColumnDef::new(Users::ClientKdfIter)
                            .integer()
                            .not_null()
                            .default(600_000),
                    )
                    .add_column(ColumnDef::new(Users::ClientKdfMemory).integer())
                    .add_column(ColumnDef::new(Users::ClientKdfParallelism).integer())
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Devices::Table)
                    .add_column(ColumnDef::new(Devices::AccessToken).text())
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

        let _ = manager
            .drop_index(Index::drop().name("idx_devices_access_token").to_owned())
            .await;

        let _ = manager
            .alter_table(
                Table::alter()
                    .table(Devices::Table)
                    .drop_column(Devices::AccessToken)
                    .drop_column(Devices::AccessTokenExpiresAt)
                    .to_owned(),
            )
            .await;

        let _ = manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .drop_column(Users::Enabled)
                    .drop_column(Users::Name)
                    .drop_column(Users::PasswordHash)
                    .drop_column(Users::Salt)
                    .drop_column(Users::PasswordIterations)
                    .drop_column(Users::PasswordHint)
                    .drop_column(Users::AKey)
                    .drop_column(Users::PrivateKey)
                    .drop_column(Users::PublicKey)
                    .drop_column(Users::SecurityStamp)
                    .drop_column(Users::ClientKdfType)
                    .drop_column(Users::ClientKdfIter)
                    .drop_column(Users::ClientKdfMemory)
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
