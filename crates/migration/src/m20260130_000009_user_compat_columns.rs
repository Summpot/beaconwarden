use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Users: additional compatibility columns used by legacy flows and future endpoints.
        // NOTE: SQLite/libSQL only supports a single ALTER TABLE operation per statement.

        if !manager.has_column("users", "verified_at").await? {
            manager
                .alter_table(
                    Table::alter()
                        .table(Users::Table)
                        .add_column(ColumnDef::new(Users::VerifiedAt).big_integer())
                        .to_owned(),
                )
                .await?;
        }

        if !manager.has_column("users", "last_verifying_at").await? {
            manager
                .alter_table(
                    Table::alter()
                        .table(Users::Table)
                        .add_column(ColumnDef::new(Users::LastVerifyingAt).big_integer())
                        .to_owned(),
                )
                .await?;
        }

        if !manager.has_column("users", "login_verify_count").await? {
            manager
                .alter_table(
                    Table::alter()
                        .table(Users::Table)
                        .add_column(
                            ColumnDef::new(Users::LoginVerifyCount)
                                .integer()
                                .not_null()
                                .default(0),
                        )
                        .to_owned(),
                )
                .await?;
        }

        if !manager.has_column("users", "email_new").await? {
            manager
                .alter_table(
                    Table::alter()
                        .table(Users::Table)
                        .add_column(ColumnDef::new(Users::EmailNew).string())
                        .to_owned(),
                )
                .await?;
        }

        if !manager.has_column("users", "email_new_token").await? {
            manager
                .alter_table(
                    Table::alter()
                        .table(Users::Table)
                        .add_column(ColumnDef::new(Users::EmailNewToken).string())
                        .to_owned(),
                )
                .await?;
        }

        if !manager.has_column("users", "totp_secret").await? {
            manager
                .alter_table(
                    Table::alter()
                        .table(Users::Table)
                        .add_column(ColumnDef::new(Users::TotpSecret).text())
                        .to_owned(),
                )
                .await?;
        }

        if !manager.has_column("users", "totp_recover").await? {
            manager
                .alter_table(
                    Table::alter()
                        .table(Users::Table)
                        .add_column(ColumnDef::new(Users::TotpRecover).text())
                        .to_owned(),
                )
                .await?;
        }

        if !manager.has_column("users", "stamp_exception").await? {
            manager
                .alter_table(
                    Table::alter()
                        .table(Users::Table)
                        .add_column(ColumnDef::new(Users::StampException).text())
                        .to_owned(),
                )
                .await?;
        }

        if !manager.has_column("users", "api_key").await? {
            manager
                .alter_table(
                    Table::alter()
                        .table(Users::Table)
                        .add_column(ColumnDef::new(Users::ApiKey).text())
                        .to_owned(),
                )
                .await?;
        }

        if !manager.has_column("users", "avatar_color").await? {
            manager
                .alter_table(
                    Table::alter()
                        .table(Users::Table)
                        .add_column(ColumnDef::new(Users::AvatarColor).string())
                        .to_owned(),
                )
                .await?;
        }

        if !manager.has_column("users", "external_id").await? {
            manager
                .alter_table(
                    Table::alter()
                        .table(Users::Table)
                        .add_column(ColumnDef::new(Users::ExternalId).string())
                        .to_owned(),
                )
                .await?;
        }

        Ok(())
    }
}

#[derive(DeriveIden)]
enum Users {
    Table,
    Id,
    VerifiedAt,
    LastVerifyingAt,
    LoginVerifyCount,
    EmailNew,
    EmailNewToken,
    TotpSecret,
    TotpRecover,
    StampException,
    ApiKey,
    AvatarColor,
    ExternalId,
}
