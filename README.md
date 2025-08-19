# ExWebauthn

[![Hex Version](https://img.shields.io/hexpm/v/ex_webauthn.svg)](https://hex.pm/packages/ex_webauthn)
[![Docs](https://img.shields.io/badge/hex-docs-green.svg)](https://hexdocs.pm/ex_webauthn)

**A complete Elixir implementation of the WebAuthn (FIDO2) specification for passwordless authentication.**

ExWebauthn provides a robust, security-focused library for implementing WebAuthn authentication in Elixir applications. Built with compliance to the WebAuthn Level 2 specification, it enables developers to add secure, passwordless authentication using FIDO2-compatible authenticators like security keys, platform authenticators, and biometric devices.

## Features

🔐 **Complete WebAuthn Implementation**

- Full WebAuthn Level 2 specification compliance
- Registration and authentication ceremony support
- Multiple attestation format support (packed, fido-u2f, android-safetynet)
- Comprehensive security validation

🛡️ **Security First**

- Cryptographic challenge generation
- Origin and RP ID validation
- Replay attack protection
- Certificate chain validation
- Secure credential storage patterns

⚡ **Developer Friendly**

- Clean, documented APIs
- Phoenix integration helpers
- Comprehensive error handling
- Full test coverage

## Installation

Add `ex_webauthn` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:ex_webauthn, "~> 0.1.0"}
  ]
end
```

## Quick Start

### 1. Registration Flow

```elixir
# Generate creation options for a new credential
rp = %ExWebauthn.Credential.RelyingParty{
  id: "example.com",
  name: "Example Corp"
}

user = %ExWebauthn.Credential.User{
  id: :crypto.strong_rand_bytes(32),
  name: "user@example.com",
  display_name: "John Doe"
}

{:ok, options} = ExWebauthn.Registration.generate_creation_options(rp, user)

# Send options to client, receive attestation response
# Then verify the registration response
{:ok, credential} = ExWebauthn.Registration.verify_creation(response, options)
```

### 2. Authentication Flow

```elixir
# Generate request options for authentication
{:ok, options} = ExWebauthn.Authentication.generate_request_options("example.com")

# Send options to client, receive assertion response
# Then verify the authentication response
{:ok, result} = ExWebauthn.Authentication.verify_assertion(response, options, stored_credential)
```

## Core Concepts

### Credential Management

```elixir
# Create credential descriptors for allowlist
descriptor = %ExWebauthn.Credential.Descriptor{
  type: :public_key,
  id: credential_id,
  transports: ["usb", "nfc", "ble", "internal"]
}
```

### Security Validation

```elixir
# Validate challenges
challenge = ExWebauthn.generate_challenge()
:ok = ExWebauthn.validate(challenge)

# Validate origins
:ok = ExWebauthn.Validator.validate_origin("https://example.com", ["https://example.com"])
```

### CBOR Handling

```elixir
# Decode attestation objects
{:ok, attestation_object} = ExWebauthn.CBOR.decode_attestation_object(cbor_data)

# Decode credential public keys
{:ok, public_key} = ExWebauthn.CBOR.decode_credential_public_key(cbor_data)
```

## Phoenix Integration

ExWebauthn provides Phoenix-specific helpers for common patterns:

```elixir
# In your controller
defmodule MyAppWeb.AuthController do
  use MyAppWeb, :controller
  alias ExWebauthn.Phoenix.Helpers

  def begin_registration(conn, params) do
    case Helpers.start_registration(conn, params) do
      {:ok, options, conn} ->
        json(conn, options)
      {:error, reason} ->
        put_status(conn, 400) |> json(%{error: reason})
    end
  end
end
```

## Configuration

Configure ExWebauthn in your `config/config.exs`:

```elixir
config :ex_webauthn,
  # Default RP ID (can be overridden per operation)
  rp_id: "example.com",
  # Allowed origins for requests
  origins: ["https://example.com", "https://www.example.com"],
  # Default timeout for operations (milliseconds)
  timeout: 60_000,
  # Challenge size (minimum 16 bytes, default 32)
  challenge_size: 32
```

## Project Status

ExWebauthn is currently under active development following a phased approach:

- ✅ **Phase 1**: Core Infrastructure (Complete)

  - Data structures and validation
  - CBOR encoding/decoding
  - Basic API foundation

- 🚧 **Phase 2**: Registration Flow (In Progress)

  - Credential creation options
  - Attestation processing
  - Registration verification

- 📋 **Phase 3**: Authentication Flow (Planned)
  - Assertion options generation
  - Authentication verification
  - Session management

See [docs/plan.md](docs/plan.md) for the complete development roadmap.

## Security Considerations

- Always validate origins against your allowlist
- Use HTTPS in production environments
- Implement proper credential storage with encryption
- Regularly update dependencies for security patches
- Consider implementing rate limiting for registration/authentication endpoints

## Contributing

We welcome contributions! Please see our [contributing guidelines](CONTRIBUTING.md) for details.

1. Fork the repository
2. Create a feature branch
3. Add tests for your changes
4. Ensure all tests pass with `mix test`
5. Format code with `mix format`
6. Submit a pull request

## Documentation

- [API Documentation](https://hexdocs.pm/ex_webauthn)
- [Development Plan](docs/plan.md)
- [Agent Guidelines](AGENTS.md)

## License

ExWebauthn is released under the MIT License. See [LICENSE](LICENSE) for details.

## Acknowledgments

- Built following the [WebAuthn W3C Specification](https://www.w3.org/TR/webauthn-2/)
- Inspired by the FIDO Alliance's work on passwordless authentication
- Thanks to the Elixir community for excellent libraries and tooling
