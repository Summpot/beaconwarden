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
                    .table(Organizations::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Organizations::Id)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Organizations::Name).string().not_null())
                    .col(ColumnDef::new(Organizations::BillingEmail).string().not_null())
                    .col(ColumnDef::new(Organizations::PrivateKey).text())
                    .col(ColumnDef::new(Organizations::PublicKey).text())
                    .col(ColumnDef::new(Organizations::CreatedAt).big_integer().not_null())
                    .col(ColumnDef::new(Organizations::UpdatedAt).big_integer().not_null())
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_organizations_name")
                    .table(Organizations::Table)
                    .col(Organizations::Name)
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(UsersOrganizations::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(UsersOrganizations::Id)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(UsersOrganizations::UserId).string().not_null())
                    .col(
                        ColumnDef::new(UsersOrganizations::OrganizationId)
                            .string()
                            .not_null(),
                    )
                    .col(ColumnDef::new(UsersOrganizations::InvitedByEmail).string())
                    .col(
                        ColumnDef::new(UsersOrganizations::AccessAll)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .col(
                        ColumnDef::new(UsersOrganizations::AKey)
                            .text()
                            .not_null()
                            .default(""),
                    )
                    .col(
                        ColumnDef::new(UsersOrganizations::Status)
                            .integer()
                            .not_null()
                            .default(0),
                    )
                    .col(
                        ColumnDef::new(UsersOrganizations::Type)
                            .integer()
                            .not_null()
                            .default(0),
                    )
                    .col(ColumnDef::new(UsersOrganizations::ResetPasswordKey).text())
                    .col(ColumnDef::new(UsersOrganizations::ExternalId).text())
                    .col(ColumnDef::new(UsersOrganizations::CreatedAt).big_integer().not_null())
                    .col(ColumnDef::new(UsersOrganizations::UpdatedAt).big_integer().not_null())
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_users_organizations_user_id")
                            .from(UsersOrganizations::Table, UsersOrganizations::UserId)
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_users_organizations_org_id")
                            .from(UsersOrganizations::Table, UsersOrganizations::OrganizationId)
                            .to(Organizations::Table, Organizations::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_users_organizations_user_id")
                    .table(UsersOrganizations::Table)
                    .col(UsersOrganizations::UserId)
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_users_organizations_org_id")
                    .table(UsersOrganizations::Table)
                    .col(UsersOrganizations::OrganizationId)
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(Collections::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(Collections::Id).string().not_null().primary_key())
                    .col(
                        ColumnDef::new(Collections::OrganizationId)
                            .string()
                            .not_null(),
                    )
                    .col(ColumnDef::new(Collections::Name).string().not_null())
                    .col(ColumnDef::new(Collections::ExternalId).string())
                    .col(ColumnDef::new(Collections::CreatedAt).big_integer().not_null())
                    .col(ColumnDef::new(Collections::UpdatedAt).big_integer().not_null())
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_collections_org_id")
                            .from(Collections::Table, Collections::OrganizationId)
                            .to(Organizations::Table, Organizations::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_collections_org_id")
                    .table(Collections::Table)
                    .col(Collections::OrganizationId)
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(UsersCollections::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(UsersCollections::UserId).string().not_null())
                    .col(ColumnDef::new(UsersCollections::CollectionId).string().not_null())
                    .col(
                        ColumnDef::new(UsersCollections::ReadOnly)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .col(
                        ColumnDef::new(UsersCollections::HidePasswords)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .col(
                        ColumnDef::new(UsersCollections::Manage)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .primary_key(
                        Index::create()
                            .name("pk_users_collections")
                            .col(UsersCollections::UserId)
                            .col(UsersCollections::CollectionId),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_users_collections_user_id")
                            .from(UsersCollections::Table, UsersCollections::UserId)
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_users_collections_collection_id")
                            .from(UsersCollections::Table, UsersCollections::CollectionId)
                            .to(Collections::Table, Collections::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_users_collections_user_id")
                    .table(UsersCollections::Table)
                    .col(UsersCollections::UserId)
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_users_collections_collection_id")
                    .table(UsersCollections::Table)
                    .col(UsersCollections::CollectionId)
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(CiphersCollections::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(CiphersCollections::CipherId).string().not_null())
                    .col(
                        ColumnDef::new(CiphersCollections::CollectionId)
                            .string()
                            .not_null(),
                    )
                    .primary_key(
                        Index::create()
                            .name("pk_ciphers_collections")
                            .col(CiphersCollections::CipherId)
                            .col(CiphersCollections::CollectionId),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_ciphers_collections_cipher_id")
                            .from(CiphersCollections::Table, CiphersCollections::CipherId)
                            .to(Ciphers::Table, Ciphers::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_ciphers_collections_collection_id")
                            .from(CiphersCollections::Table, CiphersCollections::CollectionId)
                            .to(Collections::Table, Collections::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_ciphers_collections_cipher_id")
                    .table(CiphersCollections::Table)
                    .col(CiphersCollections::CipherId)
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_ciphers_collections_collection_id")
                    .table(CiphersCollections::Table)
                    .col(CiphersCollections::CollectionId)
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(OrgPolicies::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(OrgPolicies::Id).string().not_null().primary_key())
                    .col(
                        ColumnDef::new(OrgPolicies::OrganizationId)
                            .string()
                            .not_null(),
                    )
                    .col(ColumnDef::new(OrgPolicies::Type).integer().not_null())
                    .col(
                        ColumnDef::new(OrgPolicies::Enabled)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .col(ColumnDef::new(OrgPolicies::Data).text().not_null().default("{}"))
                    .col(ColumnDef::new(OrgPolicies::CreatedAt).big_integer().not_null())
                    .col(ColumnDef::new(OrgPolicies::UpdatedAt).big_integer().not_null())
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_org_policies_org_id")
                            .from(OrgPolicies::Table, OrgPolicies::OrganizationId)
                            .to(Organizations::Table, Organizations::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_org_policies_org_id")
                    .table(OrgPolicies::Table)
                    .col(OrgPolicies::OrganizationId)
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(OrganizationApiKey::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(OrganizationApiKey::Id).string().not_null())
                    .col(
                        ColumnDef::new(OrganizationApiKey::OrganizationId)
                            .string()
                            .not_null(),
                    )
                    .col(ColumnDef::new(OrganizationApiKey::Type).integer().not_null())
                    .col(ColumnDef::new(OrganizationApiKey::ApiKey).text().not_null())
                    .col(
                        ColumnDef::new(OrganizationApiKey::RevisionDate)
                            .big_integer()
                            .not_null(),
                    )
                    .primary_key(
                        Index::create()
                            .name("pk_organization_api_key")
                            .col(OrganizationApiKey::Id)
                            .col(OrganizationApiKey::OrganizationId),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_organization_api_key_org_id")
                            .from(OrganizationApiKey::Table, OrganizationApiKey::OrganizationId)
                            .to(Organizations::Table, Organizations::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_organization_api_key_org_id")
                    .table(OrganizationApiKey::Table)
                    .col(OrganizationApiKey::OrganizationId)
                    .if_not_exists()
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
enum Ciphers {
    Table,
    Id,
}

#[derive(DeriveIden)]
enum Organizations {
    Table,
    Id,
    Name,
    BillingEmail,
    PrivateKey,
    PublicKey,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum UsersOrganizations {
    Table,
    Id,
    UserId,
    OrganizationId,
    InvitedByEmail,
    AccessAll,
    AKey,
    Status,
    Type,
    ResetPasswordKey,
    ExternalId,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum Collections {
    Table,
    Id,
    OrganizationId,
    Name,
    ExternalId,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum UsersCollections {
    Table,
    UserId,
    CollectionId,
    ReadOnly,
    HidePasswords,
    Manage,
}

#[derive(DeriveIden)]
enum CiphersCollections {
    Table,
    CipherId,
    CollectionId,
}

#[derive(DeriveIden)]
enum OrgPolicies {
    Table,
    Id,
    OrganizationId,
    Type,
    Enabled,
    Data,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum OrganizationApiKey {
    Table,
    Id,
    OrganizationId,
    Type,
    ApiKey,
    RevisionDate,
}
