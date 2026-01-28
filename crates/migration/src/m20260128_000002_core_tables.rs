use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Devices table (Bitwarden/Vaultwarden concept).
        manager
            .create_table(
                Table::create()
                    .table(Devices::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(Devices::Id).string().not_null().primary_key())
                    .col(ColumnDef::new(Devices::UserId).string().not_null())
                    .col(ColumnDef::new(Devices::Name).string().not_null())
                    .col(ColumnDef::new(Devices::DeviceType).integer().not_null())
                    .col(ColumnDef::new(Devices::PushUuid).string())
                    .col(ColumnDef::new(Devices::PushToken).string())
                    .col(ColumnDef::new(Devices::RefreshToken).string().not_null())
                    .col(ColumnDef::new(Devices::TwofactorRemember).string())
                    .col(ColumnDef::new(Devices::CreatedAt).big_integer().not_null())
                    .col(ColumnDef::new(Devices::UpdatedAt).big_integer().not_null())
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_devices_user_id")
                            .from(Devices::Table, Devices::UserId)
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // SQLite cannot represent non-unique indexes as constraints.
        manager
            .create_index(
                Index::create()
                    .name("idx_devices_user_id")
                    .table(Devices::Table)
                    .col(Devices::UserId)
                    .to_owned(),
            )
            .await?;

        // Folders table.
        manager
            .create_table(
                Table::create()
                    .table(Folders::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(Folders::Id).string().not_null().primary_key())
                    .col(ColumnDef::new(Folders::UserId).string().not_null())
                    .col(ColumnDef::new(Folders::Name).string().not_null())
                    .col(ColumnDef::new(Folders::CreatedAt).big_integer().not_null())
                    .col(ColumnDef::new(Folders::UpdatedAt).big_integer().not_null())
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_folders_user_id")
                            .from(Folders::Table, Folders::UserId)
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_folders_user_id")
                    .table(Folders::Table)
                    .col(Folders::UserId)
                    .to_owned(),
            )
            .await?;

        // Ciphers table (stores encrypted item payloads).
        manager
            .create_table(
                Table::create()
                    .table(Ciphers::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(Ciphers::Id).string().not_null().primary_key())
                    .col(ColumnDef::new(Ciphers::CreatedAt).big_integer().not_null())
                    .col(ColumnDef::new(Ciphers::UpdatedAt).big_integer().not_null())
                    .col(ColumnDef::new(Ciphers::UserId).string())
                    .col(ColumnDef::new(Ciphers::OrganizationId).string())
                    .col(ColumnDef::new(Ciphers::Key).text())
                    .col(ColumnDef::new(Ciphers::Type).integer().not_null())
                    .col(ColumnDef::new(Ciphers::Name).string().not_null())
                    .col(ColumnDef::new(Ciphers::Notes).text())
                    .col(ColumnDef::new(Ciphers::Fields).text())
                    .col(ColumnDef::new(Ciphers::Data).text().not_null())
                    .col(ColumnDef::new(Ciphers::PasswordHistory).text())
                    .col(ColumnDef::new(Ciphers::DeletedAt).big_integer())
                    .col(ColumnDef::new(Ciphers::Reprompt).integer())
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_ciphers_user_id")
                            .from(Ciphers::Table, Ciphers::UserId)
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_ciphers_user_id")
                    .table(Ciphers::Table)
                    .col(Ciphers::UserId)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_ciphers_organization_id")
                    .table(Ciphers::Table)
                    .col(Ciphers::OrganizationId)
                    .to_owned(),
            )
            .await?;

        // folders_ciphers join table (many-to-many mapping).
        manager
            .create_table(
                Table::create()
                    .table(FoldersCiphers::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(FoldersCiphers::Id)
                            .big_integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(FoldersCiphers::FolderId).string().not_null())
                    .col(ColumnDef::new(FoldersCiphers::CipherId).string().not_null())
                    .index(
                        Index::create()
                            .name("uidx_folders_ciphers_folder_cipher")
                            .col(FoldersCiphers::FolderId)
                            .col(FoldersCiphers::CipherId)
                            .unique(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_folders_ciphers_folder_id")
                            .from(FoldersCiphers::Table, FoldersCiphers::FolderId)
                            .to(Folders::Table, Folders::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_folders_ciphers_cipher_id")
                            .from(FoldersCiphers::Table, FoldersCiphers::CipherId)
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
                    .name("idx_folders_ciphers_folder_id")
                    .table(FoldersCiphers::Table)
                    .col(FoldersCiphers::FolderId)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_folders_ciphers_cipher_id")
                    .table(FoldersCiphers::Table)
                    .col(FoldersCiphers::CipherId)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Drop tables in reverse dependency order.
        manager
            .drop_table(Table::drop().table(FoldersCiphers::Table).to_owned())
            .await?;

        manager
            .drop_table(Table::drop().table(Ciphers::Table).to_owned())
            .await?;

        manager
            .drop_table(Table::drop().table(Folders::Table).to_owned())
            .await?;

        manager
            .drop_table(Table::drop().table(Devices::Table).to_owned())
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum Users {
    Table,
    Id,
}

#[derive(DeriveIden)]
enum Devices {
    Table,
    Id,
    UserId,
    Name,
    DeviceType,
    PushUuid,
    PushToken,
    RefreshToken,
    TwofactorRemember,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum Folders {
    Table,
    Id,
    UserId,
    Name,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum Ciphers {
    Table,
    Id,
    CreatedAt,
    UpdatedAt,
    UserId,
    OrganizationId,
    Key,
    Type,
    Name,
    Notes,
    Fields,
    Data,
    PasswordHistory,
    DeletedAt,
    Reprompt,
}

#[derive(DeriveIden)]
enum FoldersCiphers {
    Table,
    Id,
    FolderId,
    CipherId,
}
