use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Emergency access
        manager
            .create_table(
                Table::create()
                    .table(EmergencyAccess::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(EmergencyAccess::Id).string().not_null().primary_key())
                    .col(ColumnDef::new(EmergencyAccess::GrantorId).string().not_null())
                    .col(ColumnDef::new(EmergencyAccess::GranteeId).string())
                    .col(ColumnDef::new(EmergencyAccess::Email).string())
                    .col(ColumnDef::new(EmergencyAccess::KeyEncrypted).text())
                    .col(ColumnDef::new(EmergencyAccess::Type).integer().not_null())
                    .col(ColumnDef::new(EmergencyAccess::Status).integer().not_null())
                    .col(ColumnDef::new(EmergencyAccess::WaitTimeDays).integer().not_null().default(0))
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
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;

        // Events
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
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_events_user_id")
                    .table(Events::Table)
                    .col(Events::UserId)
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
