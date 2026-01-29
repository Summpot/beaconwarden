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
                    .table(ServerSecrets::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(ServerSecrets::Name)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(ServerSecrets::Value).string().not_null())
                    .col(ColumnDef::new(ServerSecrets::CreatedAt).big_integer().not_null())
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(ServerSecrets::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
enum ServerSecrets {
    Table,
    Name,
    Value,
    CreatedAt,
}
