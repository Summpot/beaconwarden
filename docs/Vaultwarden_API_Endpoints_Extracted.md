# Vaultwarden API endpoint inventory (extracted)

This file is auto-extracted from the legacy Rocket API under `src/api/**` in this repository.
It represents the **target** Vaultwarden-compatible surface area that the Workers implementation should eventually cover.

> Note: some endpoints may be admin-only, optional, or intentionally dropped (e.g. websocket notifications).

## `src/api/admin.rs` 

- `DELETE /users/<user_id>/sso`
- `GET /`
- `GET /`
- `GET /`
- `GET /diagnostics`
- `GET /diagnostics/config`
- `GET /diagnostics/http?<code>`
- `GET /logout`
- `GET /organizations/overview`
- `GET /users`
- `GET /users/<user_id>`
- `GET /users/by-mail/<mail>`
- `GET /users/overview`
- `POST /`
- `POST /config`
- `POST /config/backup_db`
- `POST /config/delete`
- `POST /invite`
- `POST /organizations/<org_id>/delete`
- `POST /test/smtp`
- `POST /users/<user_id>/deauth`
- `POST /users/<user_id>/delete`
- `POST /users/<user_id>/disable`
- `POST /users/<user_id>/enable`
- `POST /users/<user_id>/invite/resend`
- `POST /users/<user_id>/remove-2fa`
- `POST /users/org_type`
- `POST /users/update_revision`

## `src/api/core/accounts.rs`

- `DELETE /accounts`
- `GET /accounts/profile`
- `GET /accounts/revision-date`
- `GET /auth-requests`
- `GET /auth-requests/<auth_request_id>`
- `GET /auth-requests/<auth_request_id>/response?<code>`
- `GET /auth-requests/pending`
- `GET /devices`
- `GET /devices/identifier/<device_id>`
- `GET /devices/knowndevice`
- `GET /tasks`
- `GET /users/<user_id>/public-key`
- `POST /accounts/api-key`
- `POST /accounts/delete`
- `POST /accounts/delete-recover`
- `POST /accounts/delete-recover-token`
- `POST /accounts/email`
- `POST /accounts/email-token`
- `POST /accounts/kdf`
- `POST /accounts/key-management/rotate-user-account-keys`
- `POST /accounts/keys`
- `POST /accounts/password`
- `POST /accounts/password-hint`
- `POST /accounts/prelogin`
- `POST /accounts/profile`
- `POST /accounts/register`
- `POST /accounts/rotate-api-key`
- `POST /accounts/security-stamp`
- `POST /accounts/set-password`
- `POST /accounts/verify-email`
- `POST /accounts/verify-email-token`
- `POST /accounts/verify-password`
- `POST /auth-requests`
- `POST /devices/identifier/<device_id>/clear-token`
- `POST /devices/identifier/<device_id>/token`
- `PUT /accounts/avatar`
- `PUT /accounts/profile`
- `PUT /auth-requests/<auth_request_id>`
- `PUT /devices/identifier/<device_id>/clear-token`
- `PUT /devices/identifier/<device_id>/token`

## `src/api/core/ciphers.rs`

- `DELETE /ciphers`
- `DELETE /ciphers/<cipher_id>`
- `DELETE /ciphers/<cipher_id>/admin`
- `DELETE /ciphers/<cipher_id>/attachment/<attachment_id>`
- `DELETE /ciphers/<cipher_id>/attachment/<attachment_id>/admin`
- `DELETE /ciphers/admin`
- `GET /ciphers`
- `GET /ciphers/<cipher_id>`
- `GET /ciphers/<cipher_id>/admin`
- `GET /ciphers/<cipher_id>/attachment/<attachment_id>`
- `GET /ciphers/<cipher_id>/details`
- `GET /sync?<data..>`
- `POST /ciphers`
- `POST /ciphers/<cipher_id>`
- `POST /ciphers/<cipher_id>/admin`
- `POST /ciphers/<cipher_id>/attachment`
- `POST /ciphers/<cipher_id>/attachment-admin`
- `POST /ciphers/<cipher_id>/attachment/<attachment_id>`
- `POST /ciphers/<cipher_id>/attachment/<attachment_id>/delete`
- `POST /ciphers/<cipher_id>/attachment/<attachment_id>/delete-admin`
- `POST /ciphers/<cipher_id>/attachment/<attachment_id>/share`
- `POST /ciphers/<cipher_id>/attachment/v2`
- `POST /ciphers/<cipher_id>/collections`
- `POST /ciphers/<cipher_id>/collections-admin`
- `POST /ciphers/<cipher_id>/collections_v2`
- `POST /ciphers/<cipher_id>/delete`
- `POST /ciphers/<cipher_id>/delete-admin`
- `POST /ciphers/<cipher_id>/partial`
- `POST /ciphers/<cipher_id>/share`
- `POST /ciphers/admin`
- `POST /ciphers/create`
- `POST /ciphers/delete`
- `POST /ciphers/delete-admin`
- `POST /ciphers/import`
- `POST /ciphers/move`
- `POST /ciphers/purge?<organization..>`
- `PUT /ciphers/<cipher_id>`
- `PUT /ciphers/<cipher_id>/admin`
- `PUT /ciphers/<cipher_id>/collections`
- `PUT /ciphers/<cipher_id>/collections-admin`
- `PUT /ciphers/<cipher_id>/collections_v2`
- `PUT /ciphers/<cipher_id>/delete`
- `PUT /ciphers/<cipher_id>/delete-admin`
- `PUT /ciphers/<cipher_id>/partial`
- `PUT /ciphers/<cipher_id>/restore`
- `PUT /ciphers/<cipher_id>/restore-admin`
- `PUT /ciphers/<cipher_id>/share`
- `PUT /ciphers/delete`
- `PUT /ciphers/delete-admin`
- `PUT /ciphers/move`
- `PUT /ciphers/restore`
- `PUT /ciphers/restore-admin`
- `PUT /ciphers/share`

## `src/api/core/emergency_access.rs`

- `DELETE /emergency-access/<emer_id>`
- `GET /emergency-access/<emer_id>`
- `GET /emergency-access/<emer_id>/policies`
- `GET /emergency-access/granted`
- `GET /emergency-access/trusted`
- `POST /emergency-access/<emer_id>`
- `POST /emergency-access/<emer_id>/accept`
- `POST /emergency-access/<emer_id>/approve`
- `POST /emergency-access/<emer_id>/confirm`
- `POST /emergency-access/<emer_id>/delete`
- `POST /emergency-access/<emer_id>/initiate`
- `POST /emergency-access/<emer_id>/password`
- `POST /emergency-access/<emer_id>/reinvite`
- `POST /emergency-access/<emer_id>/reject`
- `POST /emergency-access/<emer_id>/takeover`
- `POST /emergency-access/<emer_id>/view`
- `POST /emergency-access/invite`
- `PUT /emergency-access/<emer_id>`

## `src/api/core/events.rs`

- `GET /ciphers/<cipher_id>/events?<data..>`
- `GET /organizations/<org_id>/events?<data..>`
- `GET /organizations/<org_id>/users/<member_id>/events?<data..>`
- `POST /collect`

## `src/api/core/folders.rs`

- `DELETE /folders/<folder_id>`
- `GET /folders`
- `GET /folders/<folder_id>`
- `POST /folders`
- `POST /folders/<folder_id>`
- `POST /folders/<folder_id>/delete`
- `PUT /folders/<folder_id>`

## `src/api/core/mod.rs`

- `GET /alive`
- `GET /config`
- `GET /hibp/breach?<username>`
- `GET /now`
- `GET /settings/domains`
- `GET /version`
- `GET /webauthn`
- `POST /settings/domains`
- `PUT /settings/domains`

## `src/api/core/organizations.rs`

- `DELETE /organizations/<org_id>`
- `DELETE /organizations/<org_id>/collections`
- `DELETE /organizations/<org_id>/collections/<col_id>`
- `DELETE /organizations/<org_id>/collections/<col_id>/user/<member_id>`
- `DELETE /organizations/<org_id>/groups`
- `DELETE /organizations/<org_id>/groups/<group_id>`
- `DELETE /organizations/<org_id>/groups/<group_id>/users/<member_id>`
- `DELETE /organizations/<org_id>/users`
- `DELETE /organizations/<org_id>/users/<member_id>`
- `GET /ciphers/organization-details?<data..>`
- `GET /collections`
- `GET /organizations/<_org_id>/billing/metadata`
- `GET /organizations/<_org_id>/billing/vnext/warnings`
- `GET /organizations/<identifier>/auto-enroll-status`
- `GET /organizations/<org_id>`
- `GET /organizations/<org_id>/collections`
- `GET /organizations/<org_id>/collections/<col_id>/details`
- `GET /organizations/<org_id>/collections/<col_id>/users`
- `GET /organizations/<org_id>/collections/details`
- `GET /organizations/<org_id>/export`
- `GET /organizations/<org_id>/groups`
- `GET /organizations/<org_id>/groups/<group_id>`
- `GET /organizations/<org_id>/groups/<group_id>/details`
- `GET /organizations/<org_id>/groups/<group_id>/users`
- `GET /organizations/<org_id>/groups/details`
- `GET /organizations/<org_id>/keys`
- `GET /organizations/<org_id>/policies`
- `GET /organizations/<org_id>/policies/<pol_type>`
- `GET /organizations/<org_id>/policies/master-password`
- `GET /organizations/<org_id>/policies/token?<token>`
- `GET /organizations/<org_id>/public-key`
- `GET /organizations/<org_id>/tax`
- `GET /organizations/<org_id>/users/<member_id>/groups`
- `GET /organizations/<org_id>/users/<member_id>/reset-password-details`
- `GET /organizations/<org_id>/users/<member_id>?<data..>`
- `GET /organizations/<org_id>/users/mini-details`
- `GET /organizations/<org_id>/users?<data..>`
- `GET /plans`
- `GET /plans/all`
- `GET /plans/sales-tax-rates`
- `POST /ciphers/bulk-collections`
- `POST /ciphers/import-organization?<query..>`
- `POST /organizations`
- `POST /organizations/<org_id>`
- `POST /organizations/<org_id>/api-key`
- `POST /organizations/<org_id>/collections`
- `POST /organizations/<org_id>/collections/<col_id>`
- `POST /organizations/<org_id>/collections/<col_id>/delete`
- `POST /organizations/<org_id>/collections/<col_id>/delete-user/<member_id>`
- `POST /organizations/<org_id>/collections/bulk-access`
- `POST /organizations/<org_id>/delete`
- `POST /organizations/<org_id>/groups`
- `POST /organizations/<org_id>/groups/<group_id>`
- `POST /organizations/<org_id>/groups/<group_id>/delete`
- `POST /organizations/<org_id>/groups/<group_id>/delete-user/<member_id>`
- `POST /organizations/<org_id>/import`
- `POST /organizations/<org_id>/keys`
- `POST /organizations/<org_id>/leave`
- `POST /organizations/<org_id>/rotate-api-key`
- `POST /organizations/<org_id>/users/<member_id>`
- `POST /organizations/<org_id>/users/<member_id>/accept`
- `POST /organizations/<org_id>/users/<member_id>/confirm`
- `POST /organizations/<org_id>/users/<member_id>/delete`
- `POST /organizations/<org_id>/users/<member_id>/groups`
- `POST /organizations/<org_id>/users/<member_id>/reinvite`
- `POST /organizations/<org_id>/users/confirm`
- `POST /organizations/<org_id>/users/invite`
- `POST /organizations/<org_id>/users/public-keys`
- `POST /organizations/<org_id>/users/reinvite`
- `POST /organizations/domain/sso/verified`
- `PUT /organizations/<org_id>`
- `PUT /organizations/<org_id>/collections/<col_id>`
- `PUT /organizations/<org_id>/collections/<col_id>/users`
- `PUT /organizations/<org_id>/groups/<group_id>`
- `PUT /organizations/<org_id>/groups/<group_id>/users`
- `PUT /organizations/<org_id>/policies/<pol_type>`
- `PUT /organizations/<org_id>/users/<member_id>`
- `PUT /organizations/<org_id>/users/<member_id>/activate`
- `PUT /organizations/<org_id>/users/<member_id>/deactivate`
- `PUT /organizations/<org_id>/users/<member_id>/groups`
- `PUT /organizations/<org_id>/users/<member_id>/reset-password`
- `PUT /organizations/<org_id>/users/<member_id>/reset-password-enrollment`
- `PUT /organizations/<org_id>/users/<member_id>/restore`
- `PUT /organizations/<org_id>/users/<member_id>/revoke`
- `PUT /organizations/<org_id>/users/activate`
- `PUT /organizations/<org_id>/users/deactivate`
- `PUT /organizations/<org_id>/users/restore`
- `PUT /organizations/<org_id>/users/revoke`

## `src/api/core/public.rs`

- `POST /public/organization/import`

## `src/api/core/sends.rs`

- `DELETE /sends/<send_id>`
- `GET /sends`
- `GET /sends/<send_id>`
- `GET /sends/<send_id>/<file_id>?<t>`
- `POST /sends`
- `POST /sends/<send_id>/access/file/<file_id>`
- `POST /sends/<send_id>/file/<file_id>`
- `POST /sends/access/<access_id>`
- `POST /sends/file`
- `POST /sends/file/v2`
- `PUT /sends/<send_id>`
- `PUT /sends/<send_id>/remove-password`

## `src/api/core/two_factor/authenticator.rs`

- `DELETE /two-factor/authenticator`
- `POST /two-factor/authenticator`
- `POST /two-factor/get-authenticator`
- `PUT /two-factor/authenticator`

## `src/api/core/two_factor/duo.rs`

- `POST /two-factor/duo`
- `POST /two-factor/get-duo`
- `PUT /two-factor/duo`

## `src/api/core/two_factor/email.rs`

- `POST /two-factor/get-email`
- `POST /two-factor/send-email`
- `POST /two-factor/send-email-login`
- `PUT /two-factor/email`

## `src/api/core/two_factor/mod.rs`

- `GET /two-factor`
- `GET /two-factor/get-device-verification-settings`
- `POST /two-factor/disable`
- `POST /two-factor/get-recover`
- `POST /two-factor/recover`
- `PUT /two-factor/disable`

## `src/api/core/two_factor/protected_actions.rs`

- `POST /accounts/request-otp`
- `POST /accounts/verify-otp`

## `src/api/core/two_factor/webauthn.rs`

- `DELETE /two-factor/webauthn`
- `POST /two-factor/get-webauthn`
- `POST /two-factor/get-webauthn-challenge`
- `POST /two-factor/webauthn`
- `PUT /two-factor/webauthn`

## `src/api/core/two_factor/yubikey.rs`

- `POST /two-factor/get-yubikey`
- `POST /two-factor/yubikey`
- `PUT /two-factor/yubikey`

## `src/api/icons.rs`

- `GET /<domain>/icon.png`
- `GET /<domain>/icon.png`

## `src/api/identity.rs`

- `GET /connect/authorize?<data..>`
- `GET /connect/oidc-signin?<code>&<state>`
- `GET /connect/oidc-signin?<state>&<error>&<error_description>`
- `GET /sso/prevalidate`
- `POST /accounts/prelogin`
- `POST /accounts/register`
- `POST /accounts/register/finish`
- `POST /accounts/register/send-verification-email`
- `POST /connect/token`

## `src/api/notifications.rs`

- `GET /anonymous-hub?<token..>`
- `GET /hub?<data..>`

## `src/api/web.rs`

- `GET /`
- `GET /<p..>`
- `GET /alive`
- `GET /app-id.json`
- `GET /attachments/<cipher_id>/<file_id>?<token>`
- `GET /css/vaultwarden.css`
- `GET /index.html`
- `GET /vw_static/<filename>`
- `GET /vw_static/<filename>`
- `HEAD /`
- `HEAD /alive`

---

Total endpoints: **311**
