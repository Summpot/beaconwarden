use sea_orm_migration::prelude::*;
use sea_orm_migration::sea_orm::DbBackend;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // ---------------------------------------------------------------------
        // Users: additional compatibility columns used by legacy flows and future endpoints.
        // Stored as simple scalars to keep migrations wasm/libSQL-friendly.
        // ---------------------------------------------------------------------

        // NOTE: SQLite/libSQL only supports a single ALTER TABLE operation per statement.
        manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .add_column(ColumnDef::new(Users::VerifiedAt).big_integer())
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .add_column(ColumnDef::new(Users::LastVerifyingAt).big_integer())
                    .to_owned(),
            )
            .await?;

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

        manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .add_column(ColumnDef::new(Users::EmailNew).string())
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .add_column(ColumnDef::new(Users::EmailNewToken).string())
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .add_column(ColumnDef::new(Users::TotpSecret).text())
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .add_column(ColumnDef::new(Users::TotpRecover).text())
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .add_column(ColumnDef::new(Users::StampException).text())
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .add_column(ColumnDef::new(Users::ApiKey).text())
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .add_column(ColumnDef::new(Users::AvatarColor).string())
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .add_column(ColumnDef::new(Users::ExternalId).string())
                    .to_owned(),
            )
            .await?;

        // ---------------------------------------------------------------------
        // Organizations / collections / memberships / policies
        // ---------------------------------------------------------------------

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
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_users_organizations_org_id")
                    .table(UsersOrganizations::Table)
                    .col(UsersOrganizations::OrganizationId)
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
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_users_collections_collection_id")
                    .table(UsersCollections::Table)
                    .col(UsersCollections::CollectionId)
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
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_ciphers_collections_collection_id")
                    .table(CiphersCollections::Table)
                    .col(CiphersCollections::CollectionId)
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
                    .to_owned(),
            )
            .await?;

        // ---------------------------------------------------------------------
        // Groups (optional feature)
        // ---------------------------------------------------------------------

        manager
            .create_table(
                Table::create()
                    .table(Groups::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(Groups::Id).string().not_null().primary_key())
                    .col(ColumnDef::new(Groups::OrganizationId).string().not_null())
                    .col(ColumnDef::new(Groups::Name).string().not_null())
                    .col(
                        ColumnDef::new(Groups::AccessAll)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .col(ColumnDef::new(Groups::ExternalId).text())
                    .col(ColumnDef::new(Groups::CreatedAt).big_integer().not_null())
                    .col(ColumnDef::new(Groups::UpdatedAt).big_integer().not_null())
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_groups_org_id")
                            .from(Groups::Table, Groups::OrganizationId)
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
                    .name("idx_groups_org_id")
                    .table(Groups::Table)
                    .col(Groups::OrganizationId)
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(GroupsUsers::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(GroupsUsers::GroupId).string().not_null())
                    .col(ColumnDef::new(GroupsUsers::MembershipId).string().not_null())
                    .primary_key(
                        Index::create()
                            .name("pk_groups_users")
                            .col(GroupsUsers::GroupId)
                            .col(GroupsUsers::MembershipId),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_groups_users_group_id")
                            .from(GroupsUsers::Table, GroupsUsers::GroupId)
                            .to(Groups::Table, Groups::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_groups_users_membership_id")
                            .from(GroupsUsers::Table, GroupsUsers::MembershipId)
                            .to(UsersOrganizations::Table, UsersOrganizations::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_groups_users_group_id")
                    .table(GroupsUsers::Table)
                    .col(GroupsUsers::GroupId)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_groups_users_membership_id")
                    .table(GroupsUsers::Table)
                    .col(GroupsUsers::MembershipId)
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(CollectionsGroups::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(CollectionsGroups::CollectionId)
                            .string()
                            .not_null(),
                    )
                    .col(ColumnDef::new(CollectionsGroups::GroupId).string().not_null())
                    .col(
                        ColumnDef::new(CollectionsGroups::ReadOnly)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .col(
                        ColumnDef::new(CollectionsGroups::HidePasswords)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .col(
                        ColumnDef::new(CollectionsGroups::Manage)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .primary_key(
                        Index::create()
                            .name("pk_collections_groups")
                            .col(CollectionsGroups::CollectionId)
                            .col(CollectionsGroups::GroupId),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_collections_groups_collection_id")
                            .from(CollectionsGroups::Table, CollectionsGroups::CollectionId)
                            .to(Collections::Table, Collections::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_collections_groups_group_id")
                            .from(CollectionsGroups::Table, CollectionsGroups::GroupId)
                            .to(Groups::Table, Groups::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_collections_groups_collection_id")
                    .table(CollectionsGroups::Table)
                    .col(CollectionsGroups::CollectionId)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_collections_groups_group_id")
                    .table(CollectionsGroups::Table)
                    .col(CollectionsGroups::GroupId)
                    .to_owned(),
            )
            .await?;

        // ---------------------------------------------------------------------
        // Attachments metadata (bytes live in R2; metadata lives in libSQL).
        // ---------------------------------------------------------------------

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
                    .to_owned(),
            )
            .await?;

        // ---------------------------------------------------------------------
        // Sends
        // ---------------------------------------------------------------------

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
                    .col(
                        ColumnDef::new(Sends::AccessCount)
                            .integer()
                            .not_null()
                            .default(0),
                    )
                    .col(ColumnDef::new(Sends::CreationDate).big_integer().not_null())
                    .col(ColumnDef::new(Sends::RevisionDate).big_integer().not_null())
                    .col(ColumnDef::new(Sends::ExpirationDate).big_integer())
                    .col(ColumnDef::new(Sends::DeletionDate).big_integer().not_null())
                    .col(
                        ColumnDef::new(Sends::Disabled)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
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
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_sends_organization_id")
                    .table(Sends::Table)
                    .col(Sends::OrganizationId)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_sends_deletion_date")
                    .table(Sends::Table)
                    .col(Sends::DeletionDate)
                    .to_owned(),
            )
            .await?;

        // ---------------------------------------------------------------------
        // Two-factor auth
        // ---------------------------------------------------------------------

        manager
            .create_table(
                Table::create()
                    .table(TwoFactor::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(TwoFactor::Id).string().not_null().primary_key())
                    .col(ColumnDef::new(TwoFactor::UserId).string().not_null())
                    .col(ColumnDef::new(TwoFactor::Type).integer().not_null())
                    .col(
                        ColumnDef::new(TwoFactor::Enabled)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
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
                    .col(
                        ColumnDef::new(TwoFactorIncomplete::DeviceName)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(TwoFactorIncomplete::DeviceType)
                            .integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(TwoFactorIncomplete::LoginTime)
                            .big_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(TwoFactorIncomplete::IpAddress)
                            .string()
                            .not_null(),
                    )
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
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(TwoFactorDuoCtx::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(TwoFactorDuoCtx::State)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(TwoFactorDuoCtx::UserEmail).string().not_null())
                    .col(ColumnDef::new(TwoFactorDuoCtx::Nonce).string().not_null())
                    .col(ColumnDef::new(TwoFactorDuoCtx::Exp).big_integer().not_null())
                    .to_owned(),
            )
            .await?;

        // ---------------------------------------------------------------------
        // SSO
        // ---------------------------------------------------------------------

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

        // ---------------------------------------------------------------------
        // Emergency access
        // ---------------------------------------------------------------------

        manager
            .create_table(
                Table::create()
                    .table(EmergencyAccess::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(EmergencyAccess::Id)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(EmergencyAccess::GrantorId)
                            .string()
                            .not_null(),
                    )
                    .col(ColumnDef::new(EmergencyAccess::GranteeId).string())
                    .col(ColumnDef::new(EmergencyAccess::Email).string())
                    .col(ColumnDef::new(EmergencyAccess::KeyEncrypted).text())
                    .col(ColumnDef::new(EmergencyAccess::Type).integer().not_null())
                    .col(ColumnDef::new(EmergencyAccess::Status).integer().not_null())
                    .col(
                        ColumnDef::new(EmergencyAccess::WaitTimeDays)
                            .integer()
                            .not_null()
                            .default(0),
                    )
                    .col(ColumnDef::new(EmergencyAccess::RecoveryInitiatedAt).big_integer())
                    .col(ColumnDef::new(EmergencyAccess::LastNotificationAt).big_integer())
                    .col(ColumnDef::new(EmergencyAccess::UpdatedAt).big_integer().not_null())
                    .col(ColumnDef::new(EmergencyAccess::CreatedAt).big_integer().not_null())
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_emergency_access_grantor_id")
                            .from(EmergencyAccess::Table, EmergencyAccess::GrantorId)
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
                    .name("idx_emergency_access_grantor_id")
                    .table(EmergencyAccess::Table)
                    .col(EmergencyAccess::GrantorId)
                    .to_owned(),
            )
            .await?;

        // ---------------------------------------------------------------------
        // Events
        // ---------------------------------------------------------------------

        manager
            .create_table(
                Table::create()
                    .table(Events::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(Events::Id).string().not_null().primary_key())
                    .col(ColumnDef::new(Events::EventType).integer().not_null())
                    .col(ColumnDef::new(Events::UserId).string())
                    .col(ColumnDef::new(Events::OrganizationId).string())
                    .col(ColumnDef::new(Events::CipherId).string())
                    .col(ColumnDef::new(Events::CollectionId).string())
                    .col(ColumnDef::new(Events::GroupId).string())
                    .col(ColumnDef::new(Events::OrgUserId).string())
                    .col(ColumnDef::new(Events::ActUserId).string())
                    .col(ColumnDef::new(Events::DeviceType).integer())
                    .col(ColumnDef::new(Events::IpAddress).string())
                    .col(ColumnDef::new(Events::EventDate).big_integer().not_null())
                    .col(ColumnDef::new(Events::PolicyId).string())
                    .col(ColumnDef::new(Events::ProviderUuid).string())
                    .col(ColumnDef::new(Events::ProviderUserUuid).string())
                    .col(ColumnDef::new(Events::ProviderOrgUuid).string())
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_events_org_id")
                    .table(Events::Table)
                    .col(Events::OrganizationId)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_events_user_id")
                    .table(Events::Table)
                    .col(Events::UserId)
                    .to_owned(),
            )
            .await?;

        // ---------------------------------------------------------------------
        // Auth requests
        // ---------------------------------------------------------------------

        manager
            .create_table(
                Table::create()
                    .table(AuthRequests::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(AuthRequests::Id)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(AuthRequests::UserId).string().not_null())
                    .col(ColumnDef::new(AuthRequests::OrganizationId).string())
                    .col(
                        ColumnDef::new(AuthRequests::RequestDeviceIdentifier)
                            .string()
                            .not_null(),
                    )
                    .col(ColumnDef::new(AuthRequests::DeviceType).integer().not_null())
                    .col(ColumnDef::new(AuthRequests::RequestIp).string().not_null())
                    .col(ColumnDef::new(AuthRequests::ResponseDeviceId).string())
                    .col(ColumnDef::new(AuthRequests::AccessCode).string().not_null())
                    .col(ColumnDef::new(AuthRequests::PublicKey).text().not_null())
                    .col(ColumnDef::new(AuthRequests::EncKey).text())
                    .col(ColumnDef::new(AuthRequests::MasterPasswordHash).text())
                    .col(ColumnDef::new(AuthRequests::Approved).boolean())
                    .col(
                        ColumnDef::new(AuthRequests::CreationDate)
                            .big_integer()
                            .not_null(),
                    )
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
                    .to_owned(),
            )
            .await?;

        // ---------------------------------------------------------------------
        // Invitations
        // ---------------------------------------------------------------------

        manager
            .create_table(
                Table::create()
                    .table(Invitations::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Invitations::Email)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Best-effort rollback.
        let _ = manager
            .drop_table(Table::drop().table(Invitations::Table).to_owned())
            .await;
        let _ = manager
            .drop_table(Table::drop().table(AuthRequests::Table).to_owned())
            .await;
        let _ = manager
            .drop_table(Table::drop().table(Events::Table).to_owned())
            .await;
        let _ = manager
            .drop_table(Table::drop().table(EmergencyAccess::Table).to_owned())
            .await;
        let _ = manager
            .drop_table(Table::drop().table(SsoUsers::Table).to_owned())
            .await;
        let _ = manager
            .drop_table(Table::drop().table(SsoAuth::Table).to_owned())
            .await;
        let _ = manager
            .drop_table(Table::drop().table(TwoFactorDuoCtx::Table).to_owned())
            .await;
        let _ = manager
            .drop_table(Table::drop().table(TwoFactorIncomplete::Table).to_owned())
            .await;
        let _ = manager
            .drop_table(Table::drop().table(TwoFactor::Table).to_owned())
            .await;
        let _ = manager
            .drop_table(Table::drop().table(Sends::Table).to_owned())
            .await;
        let _ = manager
            .drop_table(Table::drop().table(Attachments::Table).to_owned())
            .await;
        let _ = manager
            .drop_table(Table::drop().table(CollectionsGroups::Table).to_owned())
            .await;
        let _ = manager
            .drop_table(Table::drop().table(GroupsUsers::Table).to_owned())
            .await;
        let _ = manager
            .drop_table(Table::drop().table(Groups::Table).to_owned())
            .await;
        let _ = manager
            .drop_table(Table::drop().table(OrganizationApiKey::Table).to_owned())
            .await;
        let _ = manager
            .drop_table(Table::drop().table(OrgPolicies::Table).to_owned())
            .await;
        let _ = manager
            .drop_table(Table::drop().table(CiphersCollections::Table).to_owned())
            .await;
        let _ = manager
            .drop_table(Table::drop().table(UsersCollections::Table).to_owned())
            .await;
        let _ = manager
            .drop_table(Table::drop().table(Collections::Table).to_owned())
            .await;
        let _ = manager
            .drop_table(Table::drop().table(UsersOrganizations::Table).to_owned())
            .await;
        let _ = manager
            .drop_table(Table::drop().table(Organizations::Table).to_owned())
            .await;

        if manager.get_database_backend() == DbBackend::Sqlite {
            // SQLite/libSQL: dropping columns is not supported.
            return Ok(());
        }

        let _ = manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .drop_column(Users::VerifiedAt)
                    .to_owned(),
            )
            .await;
        let _ = manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .drop_column(Users::LastVerifyingAt)
                    .to_owned(),
            )
            .await;
        let _ = manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .drop_column(Users::LoginVerifyCount)
                    .to_owned(),
            )
            .await;
        let _ = manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .drop_column(Users::EmailNew)
                    .to_owned(),
            )
            .await;
        let _ = manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .drop_column(Users::EmailNewToken)
                    .to_owned(),
            )
            .await;
        let _ = manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .drop_column(Users::TotpSecret)
                    .to_owned(),
            )
            .await;
        let _ = manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .drop_column(Users::TotpRecover)
                    .to_owned(),
            )
            .await;
        let _ = manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .drop_column(Users::StampException)
                    .to_owned(),
            )
            .await;
        let _ = manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .drop_column(Users::ApiKey)
                    .to_owned(),
            )
            .await;
        let _ = manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .drop_column(Users::AvatarColor)
                    .to_owned(),
            )
            .await;
        let _ = manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .drop_column(Users::ExternalId)
                    .to_owned(),
            )
            .await;

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

#[derive(DeriveIden)]
enum Groups {
    Table,
    Id,
    OrganizationId,
    Name,
    AccessAll,
    ExternalId,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum GroupsUsers {
    Table,
    GroupId,
    MembershipId,
}

#[derive(DeriveIden)]
enum CollectionsGroups {
    Table,
    CollectionId,
    GroupId,
    ReadOnly,
    HidePasswords,
    Manage,
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

#[derive(DeriveIden)]
enum EmergencyAccess {
    Table,
    Id,
    GrantorId,
    GranteeId,
    Email,
    KeyEncrypted,
    Type,
    Status,
    WaitTimeDays,
    RecoveryInitiatedAt,
    LastNotificationAt,
    UpdatedAt,
    CreatedAt,
}

#[derive(DeriveIden)]
enum Events {
    Table,
    Id,
    EventType,
    UserId,
    OrganizationId,
    CipherId,
    CollectionId,
    GroupId,
    OrgUserId,
    ActUserId,
    DeviceType,
    IpAddress,
    EventDate,
    PolicyId,
    ProviderUuid,
    ProviderUserUuid,
    ProviderOrgUuid,
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
