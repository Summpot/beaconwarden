use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Two-factor auth
        manager
            .create_table(
                Table::create()
                    .table(TwoFactor::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(TwoFactor::Id).string().not_null().primary_key())
                    .col(ColumnDef::new(TwoFactor::UserId).string().not_null())
                    .col(ColumnDef::new(TwoFactor::Type).integer().not_null())
                    .col(ColumnDef::new(TwoFactor::Enabled).boolean().not_null().default(false))
                    .col(ColumnDef::new(TwoFactor::Data).text().not_null().default("{}"))
                    .col(ColumnDef::new(TwoFactor::LastUsed).big_integer().not_null().default(0))
                    .col(ColumnDef::new(TwoFactor::CreatedAt).big_integer().not_null())
                    .col(ColumnDef::new(TwoFactor::UpdatedAt).big_integer().not_null())
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_twofactor_user_id")
                            .from(TwoFactor::Table, TwoFactor::UserId)
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
                    .name("idx_twofactor_user_id")
                    .table(TwoFactor::Table)
                    .col(TwoFactor::UserId)
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(TwoFactorIncomplete::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(TwoFactorIncomplete::UserId).string().not_null())
                    .col(ColumnDef::new(TwoFactorIncomplete::DeviceId).string().not_null())
                    .col(ColumnDef::new(TwoFactorIncomplete::DeviceName).string().not_null())
                    .col(ColumnDef::new(TwoFactorIncomplete::DeviceType).integer().not_null())
                    .col(ColumnDef::new(TwoFactorIncomplete::LoginTime).big_integer().not_null())
                    .col(ColumnDef::new(TwoFactorIncomplete::IpAddress).string().not_null())
                    .primary_key(
                        Index::create()
                            .name("pk_twofactor_incomplete")
                            .col(TwoFactorIncomplete::UserId)
                            .col(TwoFactorIncomplete::DeviceId),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_twofactor_incomplete_user_id")
                    .table(TwoFactorIncomplete::Table)
                    .col(TwoFactorIncomplete::UserId)
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(TwoFactorDuoCtx::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(TwoFactorDuoCtx::State).string().not_null().primary_key())
                    .col(ColumnDef::new(TwoFactorDuoCtx::UserEmail).string().not_null())
                    .col(ColumnDef::new(TwoFactorDuoCtx::Nonce).string().not_null())
                    .col(ColumnDef::new(TwoFactorDuoCtx::Exp).big_integer().not_null())
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
enum TwoFactor {
    Table,
    Id,
    UserId,
    Type,
    Enabled,
    Data,
    LastUsed,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum TwoFactorIncomplete {
    Table,
    UserId,
    DeviceId,
    DeviceName,
    DeviceType,
    LoginTime,
    IpAddress,
}

#[derive(DeriveIden)]
enum TwoFactorDuoCtx {
    Table,
    State,
    UserEmail,
    Nonce,
    Exp,
}
