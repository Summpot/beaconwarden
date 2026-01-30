use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Auth requests
        manager
            .create_table(
                Table::create()
                    .table(AuthRequests::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(AuthRequests::Id).string().not_null().primary_key())
                    .col(ColumnDef::new(AuthRequests::UserId).string().not_null())
                    .col(ColumnDef::new(AuthRequests::OrganizationId).string())
                    .col(ColumnDef::new(AuthRequests::RequestDeviceIdentifier).string().not_null())
                    .col(ColumnDef::new(AuthRequests::DeviceType).integer().not_null())
                    .col(ColumnDef::new(AuthRequests::RequestIp).string().not_null())
                    .col(ColumnDef::new(AuthRequests::ResponseDeviceId).string())
                    .col(ColumnDef::new(AuthRequests::AccessCode).string().not_null())
                    .col(ColumnDef::new(AuthRequests::PublicKey).text().not_null())
                    .col(ColumnDef::new(AuthRequests::EncKey).text())
                    .col(ColumnDef::new(AuthRequests::MasterPasswordHash).text())
                    .col(ColumnDef::new(AuthRequests::Approved).boolean())
                    .col(ColumnDef::new(AuthRequests::CreationDate).big_integer().not_null())
                    .col(ColumnDef::new(AuthRequests::ResponseDate).big_integer())
                    .col(ColumnDef::new(AuthRequests::AuthenticationDate).big_integer())
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_auth_requests_user_id")
                            .from(AuthRequests::Table, AuthRequests::UserId)
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
                    .name("idx_auth_requests_user_id")
                    .table(AuthRequests::Table)
                    .col(AuthRequests::UserId)
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;

        // Invitations
        manager
            .create_table(
                Table::create()
                    .table(Invitations::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(Invitations::Email).string().not_null().primary_key())
                    .to_owned(),
            )
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
enum AuthRequests {
    Table,
    Id,
    UserId,
    OrganizationId,
    RequestDeviceIdentifier,
    DeviceType,
    RequestIp,
    ResponseDeviceId,
    AccessCode,
    PublicKey,
    EncKey,
    MasterPasswordHash,
    Approved,
    CreationDate,
    ResponseDate,
    AuthenticationDate,
}

#[derive(DeriveIden)]
enum Invitations {
    Table,
    Email,
}
