# Core Ceremony Guide

Use the four functions in `ExSwan`. Send each generated `options` map to
`@simplewebauthn/browser` without changing its keys or values. Keep `ceremony` on the
server.

## Registration

```elixir
{:ok, %{options: options_json, ceremony: ceremony}} =
  ExSwan.generate_registration_options(
    rp_name: "Example",
    rp_id: "example.com",
    user_name: "person@example.com",
    user_display_name: "Person",
    user_id: user_handle
  )

{:ok, registration} =
  ExSwan.verify_registration_response(
    response: browser_json,
    expected_challenge: ceremony.challenge,
    expected_origin: "https://example.com",
    expected_rp_id: ceremony.rp_id
  )
```

Persist `registration.credential` without changing its ID or binary public key. Also
persist its device type and backup state. The generator supports `:challenge`,
`:timeout`, `:exclude_credentials`, `:authenticator_selection`, `:attestation`, and
`:extensions`. ES256 and `none` attestation are the supported initial surface.

## Authentication

```elixir
{:ok, %{options: options_json, ceremony: ceremony}} =
  ExSwan.generate_authentication_options(
    rp_id: "example.com",
    allow_credentials: stored_credentials
  )

{:ok, authentication} =
  ExSwan.verify_authentication_response(
    response: browser_json,
    expected_challenge: ceremony.challenge,
    expected_origin: "https://example.com",
    expected_rp_id: ceremony.rp_id,
    expected_user_handle: user_handle,
    credential: stored_credential
  )
```

Persist `authentication.new_sign_count`, `credential_device_type`, and
`credential_backed_up` atomically. The generator also supports `:challenge`,
`:timeout`, `:user_verification`, and `:extensions`.

All four functions return tagged tuples. Browser-input errors are stable atoms or
`{:missing_field, field}` and `{:missing_option, option}` tuples. Treat the specific
error as server diagnostic data. Return a coarse failure to the browser.
See the [public error reference](errors.md) for the complete stable set.
