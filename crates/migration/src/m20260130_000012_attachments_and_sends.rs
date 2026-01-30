use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Attachments metadata (bytes live in R2; metadata lives in libSQL).
        manager
            .create_table(
                Table::create()
                    .table(Attachments::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(Attachments::Id).string().not_null().primary_key())
                    .col(ColumnDef::new(Attachments::CipherId).string().not_null())
                    .col(ColumnDef::new(Attachments::FileName).string().not_null())
                    .col(ColumnDef::new(Attachments::FileSize).big_integer().not_null())
                    .col(ColumnDef::new(Attachments::AKey).text())
                    .col(ColumnDef::new(Attachments::CreatedAt).big_integer().not_null())
                    .col(ColumnDef::new(Attachments::UpdatedAt).big_integer().not_null())
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_attachments_cipher_id")
                            .from(Attachments::Table, Attachments::CipherId)
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
                    .name("idx_attachments_cipher_id")
                    .table(Attachments::Table)
                    .col(Attachments::CipherId)
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;

        // Sends
        manager
            .create_table(
                Table::create()
                    .table(Sends::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(Sends::Id).string().not_null().primary_key())
                    .col(ColumnDef::new(Sends::UserId).string())
                    .col(ColumnDef::new(Sends::OrganizationId).string())
                    .col(ColumnDef::new(Sends::Name).string().not_null())
                    .col(ColumnDef::new(Sends::Notes).text())
                    .col(ColumnDef::new(Sends::Type).integer().not_null())
                    .col(ColumnDef::new(Sends::Data).text().not_null())
                    .col(ColumnDef::new(Sends::AKey).text().not_null())
                    .col(ColumnDef::new(Sends::PasswordHash).binary())
                    .col(ColumnDef::new(Sends::PasswordSalt).binary())
                    .col(ColumnDef::new(Sends::PasswordIter).integer())
                    .col(ColumnDef::new(Sends::MaxAccessCount).integer())
                    .col(ColumnDef::new(Sends::AccessCount).integer().not_null().default(0))
                    .col(ColumnDef::new(Sends::CreationDate).big_integer().not_null())
                    .col(ColumnDef::new(Sends::RevisionDate).big_integer().not_null())
                    .col(ColumnDef::new(Sends::ExpirationDate).big_integer())
                    .col(ColumnDef::new(Sends::DeletionDate).big_integer().not_null())
                    .col(ColumnDef::new(Sends::Disabled).boolean().not_null().default(false))
                    .col(ColumnDef::new(Sends::HideEmail).boolean())
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_sends_user_id")
                    .table(Sends::Table)
                    .col(Sends::UserId)
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_sends_organization_id")
                    .table(Sends::Table)
                    .col(Sends::OrganizationId)
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_sends_deletion_date")
                    .table(Sends::Table)
                    .col(Sends::DeletionDate)
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum Ciphers {
    Table,
    Id,
}

#[derive(DeriveIden)]
enum Attachments {
    Table,
    Id,
    CipherId,
    FileName,
    FileSize,
    AKey,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum Sends {
    Table,
    Id,
    UserId,
    OrganizationId,
    Name,
    Notes,
    Type,
    Data,
    AKey,
    PasswordHash,
    PasswordSalt,
    PasswordIter,
    MaxAccessCount,
    AccessCount,
    CreationDate,
    RevisionDate,
    ExpirationDate,
    DeletionDate,
    Disabled,
    HideEmail,
}
