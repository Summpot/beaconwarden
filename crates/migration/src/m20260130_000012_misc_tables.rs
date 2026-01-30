use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Attachments metadata (bytes live in R2; metadata lives in libSQL).
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
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;

        // Sends
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
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_sends_organization_id")
                    .table(Sends::Table)
                    .col(Sends::OrganizationId)
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_sends_deletion_date")
                    .table(Sends::Table)
                    .col(Sends::DeletionDate)
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;

        // Two-factor auth
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
                    .if_not_exists()
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

        // Emergency access
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

        // Auth requests
        manager
            .create_table(
                Table::create()
                    .table(AuthRequests::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(AuthRequests::Id).string().not_null().primary_key())
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
}

#[derive(DeriveIden)]
enum Collections {
    Table,
    Id,
}

#[derive(DeriveIden)]
enum UsersOrganizations {
    Table,
    Id,
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
