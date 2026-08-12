# ExSwan.Plug

[![Hex Version](https://img.shields.io/hexpm/v/exswan_plug.svg)](https://hex.pm/packages/exswan_plug)
[![Docs](https://img.shields.io/badge/hex-docs-green.svg)](https://hexdocs.pm/exswan_plug)

Plug integration helpers for [ExSwan](https://hex.pm/packages/exswan), the Elixir WebAuthn (FIDO2) library.

> **Status:** stub package. Public APIs beyond version metadata are not implemented yet.

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

## Usage

```elixir
ExSwan.Plug.version()
#=> "0.1.0"
```

Plug middleware and Phoenix helpers will be added in a follow-up.

## Documentation

- [API Documentation](https://hexdocs.pm/exswan_plug)
- [Monorepo README](../../README.md)
- [Core package](../exswan/README.md)

## License

ExSwan.Plug is released under the MIT License. See [LICENSE](LICENSE) for details.
