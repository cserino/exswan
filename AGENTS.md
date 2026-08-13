# Agent Guidelines for exswan

## Repository layout

This is a **Hex-package monorepo** (not an OTP umbrella):

```text
packages/exswan/       # :exswan — core WebAuthn library (ExSwan.*)
packages/exswan_plug/  # :exswan_plug — Plug helpers (ExSwan.Plug)
packages/exswan_test/  # :exswan_test — consumer test helpers (ExSwan.Test.*)
examples/              # demo apps
docs/                  # design / plan docs
Makefile               # root orchestration (EXSWAN_MONOREPO=true by default)
```

Each package under `packages/` is an independent Mix project and independent Hex package with its own version.

## Commands

Prefer root Make targets from the repository root:

- **All packages**: `make deps`, `make test`, `make format`, `make compile`, `make docs`
- **Single package**: `cd packages/exswan && mix test` (etc.)
- **Format check**: `make format-check`
- **Hex artifact check**: `make hex-build`

### `EXSWAN_MONOREPO`

- `EXSWAN_MONOREPO=true` (Makefile default): integration packages use `path: "../exswan"`
- unset / not `"true"`: integration packages depend on Hex `{:exswan, "~> x.y"}`

Always set `EXSWAN_MONOREPO=true` when developing across packages so local changes to `exswan` are visible to `exswan_plug`.

## Code Style

- Use `mix format` for consistent formatting (each package has `.formatter.exs`)
- Module names: PascalCase under `ExSwan` (e.g. `ExSwan`, `ExSwan.Registration`, `ExSwan.Plug`)
- Function names: snake_case (e.g. `process_request`)
- Variables/atoms: snake_case (e.g. `user_id`, `:success`)
- Constants: `@module_attribute` format for module-level constants
- Always include `@moduledoc` and `@doc` for public functions
- Include doctests in `@doc` examples using `iex>` format
- Use pattern matching and guards instead of if/else when possible
- Organize functions: public functions first, then private (`defp`)
- Group related functions together
- Use `with` for complex nested operations
- Return `{:ok, result} | {:error, reason}` tuples for operations that can fail
- Write one-off scripts in `.local/scripts`; don't use iex directly for temporary tests

## Naming conventions

| Hex package   | OTP app atom    | Root module   |
| ------------- | --------------- | ------------- |
| `exswan`      | `:exswan`       | `ExSwan`      |
| `exswan_plug` | `:exswan_plug`  | `ExSwan.Plug` |
| `exswan_test` | `:exswan_test`  | `ExSwan.Test` |

First-party extension packages keep the `ExSwan.*` namespace. Independent semantic versions per package.

## Do not

- Convert this repo into an OTP umbrella (`apps/`)
- Synchronize package versions unless there is a hard compatibility reason
- Depend on unpublished monorepo APIs from a package that will be published independently without a coordinated release
