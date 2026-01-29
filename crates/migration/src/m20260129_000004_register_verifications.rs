use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(RegisterVerifications::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(RegisterVerifications::Id)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(RegisterVerifications::Email).string().not_null())
                    .col(ColumnDef::new(RegisterVerifications::Name).string())
                    .col(
                        ColumnDef::new(RegisterVerifications::Verified)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .col(
                        ColumnDef::new(RegisterVerifications::CreatedAt)
                            .big_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(RegisterVerifications::ExpiresAt)
                            .big_integer()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_register_verifications_email")
                    .table(RegisterVerifications::Table)
                    .col(RegisterVerifications::Email)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let _ = manager
            .drop_index(
                Index::drop()
                    .name("idx_register_verifications_email")
                    .to_owned(),
            )
            .await;

        manager
            .drop_table(Table::drop().table(RegisterVerifications::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
enum RegisterVerifications {
    Table,
    Id,
    Email,
    Name,
    Verified,
    CreatedAt,
    ExpiresAt,
}
