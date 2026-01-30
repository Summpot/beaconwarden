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
                    .if_not_exists()
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
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_groups_users_membership_id")
                    .table(GroupsUsers::Table)
                    .col(GroupsUsers::MembershipId)
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(CollectionsGroups::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(CollectionsGroups::CollectionId).string().not_null())
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
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_collections_groups_group_id")
                    .table(CollectionsGroups::Table)
                    .col(CollectionsGroups::GroupId)
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum Organizations {
    Table,
    Id,
}

#[derive(DeriveIden)]
enum UsersOrganizations {
    Table,
    Id,
}

#[derive(DeriveIden)]
enum Collections {
    Table,
    Id,
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
