# ExSwan

[![Hex Version](https://img.shields.io/hexpm/v/exswan.svg)](https://hex.pm/packages/exswan)
[![Docs](https://img.shields.io/badge/hex-docs-green.svg)](https://hexdocs.pm/exswan)

**A security-focused WebAuthn server library for Elixir.**

ExSwan targets WebAuthn Level 2 and direct compatibility with
`@simplewebauthn/browser` JSON. Its current compatibility evidence and intentional
differences are recorded in
[`docs/compatibility.md`](https://github.com/cserino/exswan/blob/main/docs/compatibility.md).

This package lives in the [exswan monorepo](https://github.com/cserino/exswan). Related packages:

- [`exswan`](https://hex.pm/packages/exswan) — core WebAuthn library (this package)
- [`exswan_plug`](https://github.com/cserino/exswan/tree/main/packages/exswan_plug) — Plug integration helpers

## Features

🔐 **Covered WebAuthn Ceremonies**

- Registration and authentication ceremony support
- ES256 credential support with `none` attestation
- Comprehensive security validation

🛡️ **Security First**

- Cryptographic challenge generation
- Origin and RP ID validation
- Strict challenge, origin, RP ID, flags, and counter validation
- Secure credential storage patterns

⚡ **Developer Friendly**

- Clean, documented APIs
- Comprehensive error handling
- Full test coverage

## Installation

Add `exswan` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:exswan, "~> 0.1.0"}
  ]
end
```

## Quick Start

### 1. Registration Flow

```elixir
{:ok, %{options: options_json, ceremony: ceremony}} =
  ExSwan.generate_registration_options(
    rp_name: "Example Corp",
    rp_id: "example.com",
    user_name: "user@example.com",
    user_display_name: "John Doe",
    user_id: user_handle
  )

# Pass options_json directly to startRegistration({optionsJSON: options_json}).
{:ok, registration} =
  ExSwan.verify_registration_response(
    response: browser_response,
    expected_challenge: ceremony.challenge,
    expected_origin: "https://example.com",
    expected_rp_id: ceremony.rp_id
  )
```

### 2. Authentication Flow

```elixir
{:ok, %{options: options_json, ceremony: ceremony}} =
  ExSwan.generate_authentication_options(
    rp_id: "example.com",
    allow_credentials: stored_credentials
  )

# Pass options_json directly to startAuthentication({optionsJSON: options_json}).
{:ok, authentication} =
  ExSwan.verify_authentication_response(
    response: browser_response,
    expected_challenge: ceremony.challenge,
    expected_origin: "https://example.com",
    expected_rp_id: ceremony.rp_id,
    credential: stored_credential
  )
```

## Core Concepts

### Credential Management

```elixir
# Store the complete credential from registration.
credential = registration.credential

# Persist every authentication update atomically.
new_sign_count = authentication.new_sign_count
credential_backed_up = authentication.credential_backed_up
```

## Security Considerations

- Always validate origins against your allowlist
- Use HTTPS in production environments
- Implement proper credential storage with encryption
- Regularly update dependencies for security patches
- Consider implementing rate limiting for registration/authentication endpoints
- Android SafetyNet attestation is intentionally unsupported because Google deprecated the service
  and its trust guarantees cannot be validated without the retired Google infrastructure. Android
  passkeys remain supported through `none` or another supported attestation format.

## Documentation

- [API Documentation](https://hexdocs.pm/exswan)
- [Monorepo README](https://github.com/cserino/exswan/blob/main/README.md)
- [Development Plan](https://github.com/cserino/exswan/blob/main/docs/plan.md)

## License

ExSwan is available under the
[MIT License](https://github.com/cserino/exswan/blob/main/packages/exswan/LICENSE).
