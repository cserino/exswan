# ExSwan

[![Hex Version](https://img.shields.io/hexpm/v/exswan.svg)](https://hex.pm/packages/exswan)
[![Docs](https://img.shields.io/badge/hex-docs-green.svg)](https://hexdocs.pm/exswan)

**A complete Elixir implementation of the WebAuthn (FIDO2) specification for passwordless authentication.**

ExSwan provides a robust, security-focused library for implementing WebAuthn authentication in Elixir applications. Built with compliance to the WebAuthn Level 2 specification, it enables developers to add secure, passwordless authentication using FIDO2-compatible authenticators like security keys, platform authenticators, and biometric devices.

This package lives in the [exswan monorepo](https://github.com/cserino/exswan). Related packages:

- [`exswan`](https://hex.pm/packages/exswan) — core WebAuthn library (this package)
- [`exswan_plug`](https://hex.pm/packages/exswan_plug) — Plug integration helpers (stub / upcoming)

## Features

🔐 **Complete WebAuthn Implementation**

- Full WebAuthn Level 2 specification compliance
- Registration and authentication ceremony support
- Attestation format support for `none`, `packed`, and `fido-u2f`
- Comprehensive security validation

🛡️ **Security First**

- Cryptographic challenge generation
- Origin and RP ID validation
- Replay attack protection
- Certificate chain validation
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
# Generate creation options for a new credential
rp = %ExSwan.Credential.RelyingParty{
  id: "example.com",
  name: "Example Corp"
}

user = %ExSwan.Credential.User{
  id: :crypto.strong_rand_bytes(32),
  name: "user@example.com",
  display_name: "John Doe"
}

{:ok, options} = ExSwan.Registration.generate_creation_options(rp, user)

# Send options to client, receive attestation response
# Then verify the registration response
{:ok, credential} = ExSwan.Registration.verify_creation(response, options)
```

### 2. Authentication Flow

```elixir
# Generate request options for authentication
{:ok, options} = ExSwan.Authentication.generate_request_options("example.com")

# Send options to client, receive assertion response
# Then verify the authentication response
{:ok, result} = ExSwan.Authentication.verify_assertion(response, options, stored_credential)
```

## Core Concepts

### Credential Management

```elixir
# Create credential descriptors for allowlist
descriptor = %ExSwan.Credential.Descriptor{
  type: :public_key,
  id: credential_id,
  transports: ["usb", "nfc", "ble", "internal"]
}
```

### Security Validation

```elixir
# Validate challenges
challenge = ExSwan.generate_challenge()
:ok = ExSwan.validate(challenge)

# Validate origins
:ok = ExSwan.Validator.validate_origin("https://example.com", ["https://example.com"])
```

### CBOR Handling

```elixir
# Decode attestation objects
{:ok, attestation_object} = ExSwan.CBORUtils.decode_attestation_object(cbor_data)

# Decode credential public keys
{:ok, public_key} = ExSwan.CBORUtils.decode_credential_public_key(cbor_data)
```

## Configuration

Configure ExSwan in your `config/config.exs`:

```elixir
config :exswan,
  # Default RP ID (can be overridden per operation)
  rp_id: "example.com",
  # Allowed origins for requests
  origins: ["https://example.com", "https://www.example.com"],
  # Default timeout for operations (milliseconds)
  timeout: 60_000,
  # Challenge size (minimum 16 bytes, default 32)
  challenge_size: 32
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
- [Monorepo README](../../README.md)
- [Development Plan](../../docs/plan.md)

## License

ExSwan is released under the MIT License. See [LICENSE](LICENSE) for details.
