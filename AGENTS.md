# Agent Guidelines for ex_webauthn

## Commands
- **Test**: `mix test` (all tests), `mix test test/filename_test.exs` (single file)
- **Format**: `mix format` (auto-format code)
- **Compile**: `mix compile`
- **Dependencies**: `mix deps.get` (install), `mix deps.update --all` (update)
- **Documentation**: `mix docs` (generate docs)

## Code Style
- Use `mix format` for consistent formatting (configured in .formatter.exs)
- Module names: PascalCase (e.g., `ExWebauthn`, `ExWebauthn.Client`)
- Function names: snake_case (e.g., `hello`, `process_request`)
- Variables/atoms: snake_case (e.g., `user_id`, `:success`)
- Constants: @module_attribute format for module-level constants
- Always include @moduledoc and @doc for public functions
- Include doctests in @doc examples using `iex>` format
- Use pattern matching and guards instead of if/else when possible
- Organize functions: public functions first, then private (defp)
- Group related functions together
- Use `with` for complex nested operations
- Return {:ok, result} | {:error, reason} tuples for operations that can fail
- Import order: standard library, deps, local modules