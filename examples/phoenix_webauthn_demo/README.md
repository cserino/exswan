# Phoenix WebAuthn Demo

This is a local demonstration of passwordless authentication with `exswan` and
`exswan_plug`. It is not a production deployment template.

## Deployment limits

- Ceremony state uses the single-node in-memory adapter and is lost on restart.
- SQLite and the demo account flow are intended for local evaluation.
- The app does not include rate limiting, abuse controls, operational key management,
  multi-node ceremony storage, or a production account-recovery policy.
- Browser and FIDO conformance results belong to the library release evidence; the
  existence of this demo is not a compliance claim.

## Features

- **Passwordless Registration**: Create accounts using only email, then add passkeys
- **Biometric Authentication**: Sign in using fingerprint, face recognition, or security keys
- **Multiple Credentials**: Support for multiple passkeys per user
- **Usernameless Flow**: Sign in without entering email (using available passkeys)
- **Credential Management**: View and manage registered passkeys

## Prerequisites

- Elixir 1.15+
- Phoenix 1.8+
- A modern browser that supports WebAuthn
- HTTPS connection (required for WebAuthn in production)

## Setup

1. Install dependencies:
```bash
mix deps.get
```

2. Set up the database:
```bash
mix ecto.setup
```

3. Install and build assets:
```bash
mix assets.setup
mix assets.build
```

4. Start the server:
```bash
mix phx.server
```

5. Visit http://localhost:4000

## Usage

### Registration Flow
1. Go to "Get started" from the home page
2. Enter your email and display name
3. Click "Create Account"
4. Follow the passkey creation flow using your device's biometric authentication

### Authentication Flow
1. Go to "Sign in" from the home page
2. Either:
   - Click "Sign In with Passkey" for usernameless authentication
   - Enter your email and click "Sign In with Email + Passkey"
3. Use your registered passkey to authenticate

### Dashboard
- View all registered passkeys
- See last used dates and sign counts
- Add additional passkeys
- Manage account information

## WebAuthn Configuration

The app is configured in `config/config.exs`:

```elixir
config :phoenix_webauthn_demo, :webauthn,
  rp_id: "localhost",
  rp_name: "Phoenix WebAuthn Demo",
  origin: "http://localhost:4000"
```

For production, update:
- `rp_id` to your domain
- `origin` to the exact HTTPS browser origin

## Testing with Different Devices

### Chrome/Edge
- Platform authenticator (Windows Hello, Touch ID, Face ID)
- USB security keys
- Bluetooth security keys

### Safari
- Touch ID on macOS
- Face ID on iOS
- USB security keys on macOS

### Firefox
- USB security keys
- Platform authenticators (with flag enabled)

## Security Features

- **Origin validation**: Ensures requests come from authorized domains
- **Challenge-based authentication**: Prevents replay attacks
- **Cryptographic verification**: Uses public key cryptography
- **Sign counter tracking**: Detects cloned authenticators
- **Backup state tracking**: Monitors credential synchronization

## Related Documentation

- [exswan Documentation](../../README.md)
- [WebAuthn Specification](https://www.w3.org/TR/webauthn-2/)
- [SimpleWebAuthn Documentation](https://simplewebauthn.dev/)
- [Phoenix Framework Guides](https://hexdocs.pm/phoenix/overview.html)
