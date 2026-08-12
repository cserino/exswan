# Credential Persistence

Applications implement `ExSwan.Plug.Store`; ExSwan does not depend on Ecto or an
application user schema.

## Registration

`create_credential/3` receives the authorized application user and a verified
`ExSwan.RegistrationResult`. Persist the complete `result.credential`, device type,
backup state, and any application audit fields in one transaction. Enforce a unique
constraint on the unpadded base64url credential ID and return `{:error, :duplicate}`
when that constraint is hit.

## Authentication

`get_credential/2` returns `{:error, :not_found}` when the ID is unknown.
`update_credential/3` must atomically compare and update the stored signature counter
and backup state using the verified `ExSwan.AuthenticationResult`. If another request
changed the row after lookup, return `{:error, :stale_credential}` instead of silently
overwriting it. A database transaction or optimistic lock is appropriate.

The callback context is application-defined and may carry tenant or request policy,
but must not be derived from untrusted browser fields. Store callbacks should return
tagged tuples and must not log public keys, signatures, user handles, or challenges.
