use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // SSO
        manager
            .create_table(
                Table::create()
                    .table(SsoAuth::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(SsoAuth::State).string().not_null().primary_key())
                    .col(ColumnDef::new(SsoAuth::ClientChallenge).text().not_null())
                    .col(ColumnDef::new(SsoAuth::Nonce).text().not_null())
                    .col(ColumnDef::new(SsoAuth::RedirectUri).text().not_null())
                    .col(ColumnDef::new(SsoAuth::CodeResponse).text())
                    .col(ColumnDef::new(SsoAuth::AuthResponse).text())
                    .col(ColumnDef::new(SsoAuth::CreatedAt).big_integer().not_null())
                    .col(ColumnDef::new(SsoAuth::UpdatedAt).big_integer().not_null())
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(SsoUsers::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(SsoUsers::UserId).string().not_null().primary_key())
                    .col(ColumnDef::new(SsoUsers::Identifier).text().not_null())
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_sso_users_user_id")
                            .from(SsoUsers::Table, SsoUsers::UserId)
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
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
enum SsoAuth {
    Table,
    State,
    ClientChallenge,
    Nonce,
    RedirectUri,
    CodeResponse,
    AuthResponse,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum SsoUsers {
    Table,
    UserId,
    Identifier,
}
