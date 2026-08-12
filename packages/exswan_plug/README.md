# ExSwan.Plug

[![Hex Version](https://img.shields.io/hexpm/v/exswan_plug.svg)](https://hex.pm/packages/exswan_plug)
[![Docs](https://img.shields.io/badge/hex-docs-green.svg)](https://hexdocs.pm/exswan_plug)

Plug integration helpers for [ExSwan](https://hex.pm/packages/exswan), the Elixir WebAuthn (FIDO2) library.

The package owns expiring one-time ceremony state, calls ExSwan verification, and
hands persistence back to the application through explicit callbacks.

This package lives in the [exswan monorepo](https://github.com/cserino/exswan). Related packages:

- [`exswan`](https://hex.pm/packages/exswan) — core WebAuthn library
- [`exswan_plug`](https://hex.pm/packages/exswan_plug) — Plug integration helpers (this package)

## Installation

```elixir
def deps do
  [
    {:exswan_plug, "~> 0.1.0"}
  ]
end
```

`exswan_plug` depends on `exswan`. Outside this monorepo, Hex resolves that dependency normally.

### Monorepo development

When working on both packages together, set:

```bash
export EXSWAN_MONOREPO=true
```

With that flag set, `exswan_plug` uses a path dependency on `../exswan` instead of the published Hex version. The root `Makefile` exports this for workspace commands.

## Registration

```elixir
{:ok, conn, options_json} =
  ExSwan.Plug.begin_registration(conn,
    user: current_user,
    user_handle: current_user.webauthn_id,
    user_name: current_user.email,
    rp_name: "Example",
    rp_id: "example.com",
    origin: "https://example.com",
    ceremony_store: {MyApp.Ceremonies, :primary},
    context: %{tenant_id: current_user.tenant_id}
  )

# Send options_json to startRegistration({optionsJSON: options_json}).
{:ok, conn, registration, persisted} =
  ExSwan.Plug.finish_registration(conn,
    response: params,
    store: MyApp.Passkeys,
    ceremony_store: {MyApp.Ceremonies, :primary}
  )
```

Registration requires non-nil `:user` and `:user_handle` authorization inputs.

## Authentication

```elixir
{:ok, conn, options_json} =
  ExSwan.Plug.begin_authentication(conn,
    rp_id: "example.com",
    origin: "https://example.com",
    allow_credentials: stored_credentials,
    ceremony_store: {MyApp.Ceremonies, :primary},
    context: %{tenant_id: tenant_id}
  )

{:ok, conn, authentication, persisted} =
  ExSwan.Plug.finish_authentication(conn,
    response: params,
    store: MyApp.Passkeys,
    ceremony_store: {MyApp.Ceremonies, :primary}
  )
```

The Plug session contains only a random lookup token. Challenge, RP, origin, user, and
callback context remain in server-side ceremony storage. Applications must fetch the
Plug session before calling these functions.

See
[Ceremony store adapters](https://github.com/cserino/exswan/blob/main/docs/ceremony-store-adapters.md)
and
[Credential persistence](https://github.com/cserino/exswan/blob/main/docs/credential-persistence.md)
before deploying.

## Documentation

- [API Documentation](https://hexdocs.pm/exswan_plug)
- [Monorepo README](https://github.com/cserino/exswan/blob/main/README.md)
- [Core package](https://github.com/cserino/exswan/tree/main/packages/exswan)

## License

ExSwan.Plug is available under the
[MIT License](https://github.com/cserino/exswan/blob/main/packages/exswan_plug/LICENSE).
