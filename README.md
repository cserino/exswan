# ExSwan

[![Hex Version](https://img.shields.io/hexpm/v/exswan.svg)](https://hex.pm/packages/exswan)
[![Docs](https://img.shields.io/badge/hex-docs-green.svg)](https://hexdocs.pm/exswan)
[![CI](https://github.com/cserino/exswan/actions/workflows/ci.yml/badge.svg)](https://github.com/cserino/exswan/actions/workflows/ci.yml)

**WebAuthn (FIDO2) for Elixir** — a monorepo of standalone Hex packages for passwordless authentication.

## Packages

| Package | Hex | Description | Version |
| --- | --- | --- | --- |
| [`exswan`](packages/exswan) | [hex.pm/packages/exswan](https://hex.pm/packages/exswan) | Core WebAuthn library | independent |
| [`exswan_plug`](packages/exswan_plug) | [hex.pm/packages/exswan_plug](https://hex.pm/packages/exswan_plug) | Plug integration helpers | independent |

Each package is a **real standalone Hex package** with its own `mix.exs`, version, dependencies, changelog, and release lifecycle. Packages are **not** version-locked to each other.

```text
exswan/
├── packages/
│   ├── exswan/          # :exswan  → ExSwan
│   └── exswan_plug/     # :exswan_plug → ExSwan.Plug
├── examples/
├── docs/
├── Makefile
└── .github/workflows/
```

Module namespaces stay under `ExSwan` for first-party packages:

```elixir
ExSwan
ExSwan.Registration
ExSwan.Authentication

ExSwan.Plug   # from :exswan_plug
```

## Installation

Add the packages you need to your app's `mix.exs`:

```elixir
def deps do
  [
    {:exswan, "~> 0.1.0"},
    # optional Plug helpers (stub / upcoming)
    {:exswan_plug, "~> 0.1.0"}
  ]
end
```

See each package README for full usage:

- [packages/exswan/README.md](packages/exswan/README.md)
- [packages/exswan_plug/README.md](packages/exswan_plug/README.md)

## Quick Start (core)

```elixir
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
{:ok, credential} = ExSwan.Registration.verify_creation(response, options, origin)

{:ok, options} = ExSwan.Authentication.generate_request_options("example.com")
{:ok, result} = ExSwan.Authentication.verify_assertion(response, options, stored_credential)
```

## Development (monorepo)

This is **not** an OTP umbrella. Packages are independent Mix projects under `packages/`. Root tooling is deliberately thin.

### Prerequisites

- Elixir `~> 1.18` and a compatible OTP (see `.tool-versions`)
- GNU Make

### Workspace commands

```bash
make deps          # mix deps.get in every package
make test          # mix test in every package
make compile       # mix compile --warnings-as-errors
make format        # mix format
make format-check  # mix format --check-formatted
make docs          # mix docs
make hex-build     # mix hex.build (validate publishable artifacts)
make clean
```

Or work on a single package:

```bash
cd packages/exswan
mix deps.get
mix test
```

### `EXSWAN_MONOREPO`

Integration packages depend on the core library. Locally they should use a path dependency; when published they should depend on Hex.

```elixir
# packages/exswan_plug/mix.exs
defp exswan_dep do
  if System.get_env("EXSWAN_MONOREPO") == "true" do
    {:exswan, path: "../exswan"}
  else
    {:exswan, "~> 0.1.0"}
  end
end
```

The root `Makefile` exports `EXSWAN_MONOREPO=true` by default so workspace tests use local path deps.

To test against the **published** Hex graph (catches unreleased API usage):

```bash
EXSWAN_MONOREPO=false make test
# or:
cd packages/exswan_plug && EXSWAN_MONOREPO=false mix deps.get && mix test
```

CI runs:

1. **Workspace matrix** — each package with `EXSWAN_MONOREPO=true` (path deps)
2. **Package / Hex matrix** (ready, enabled once `exswan` is published) — integration packages with Hex deps

### Examples

```bash
cd examples/phoenix_webauthn_demo
mix deps.get
mix phx.server
```

The demo depends on the core package via path:

```elixir
{:exswan, path: "../../packages/exswan"}
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Please open PRs against this monorepo — cross-package changes can ship atomically.

## Documentation

- [Core package docs](https://hexdocs.pm/exswan)
- [Development plan](docs/plan.md)
- [Agent guidelines](AGENTS.md)

## License

MIT — see [LICENSE](LICENSE).
