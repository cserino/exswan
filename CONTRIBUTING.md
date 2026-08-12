# Contributing to ExSwan

Thank you for your interest in contributing to ExSwan! This document provides guidelines for contributing to the monorepo.

## Development Setup

1. Clone the repository:

   ```bash
   git clone https://github.com/cserino/exswan.git
   cd exswan
   ```

2. Install dependencies for all packages:

   ```bash
   make deps
   ```

   This exports `EXSWAN_MONOREPO=true` so integration packages use local path dependencies.

3. Run tests:

   ```bash
   make test
   ```

### Working on a single package

```bash
cd packages/exswan
mix deps.get
mix test
mix format
```

## Monorepo notes

- Packages live under `packages/` and are **independent Hex packages** (not an umbrella).
- Prefer atomic PRs that touch related packages together when changing shared APIs.
- Keep package versions independent; do not bump every package for an unrelated fix.
- Integration packages switch between path and Hex deps via `EXSWAN_MONOREPO`:

  ```bash
  # Workspace (local path deps) — default via Makefile
  make test

  # Published Hex graph for exswan_plug (after exswan is on Hex)
  EXSWAN_MONOREPO=false make test
  ```

## Development Workflow

1. **Fork the repository** and create your branch from `main`
2. **Make your changes** following the coding standards
3. **Add tests** for any new functionality
4. **Ensure all tests pass**: `make test`
5. **Format your code**: `make format`
6. **Update documentation** if needed (package README / CHANGELOG)
7. **Submit a pull request**

## Coding Standards

- Follow the project's coding style (enforced by `mix format`)
- Write comprehensive tests for new features
- Include `@doc` documentation for public functions
- Use descriptive variable and function names
- Follow Elixir conventions for naming and code organization
- Keep first-party modules under the `ExSwan` namespace

## Testing

- All new code must include tests
- Tests should cover both happy path and error cases
- Run the full monorepo suite with `make test`
- Maintain or improve test coverage

## Documentation

- Update `@doc` comments for any changed public APIs
- Include examples in documentation when helpful
- Update the relevant package `README.md` and `CHANGELOG.md`
- Consider adding entries to `docs/plan.md` for major changes

## Security

- Never commit secrets or credentials
- Follow WebAuthn security best practices
- Consider security implications of changes
- Report security issues privately to the maintainers

## Pull Request Process

1. Ensure your PR has a clear description of the changes
2. Reference any related issues
3. Ensure all tests pass and code is formatted
4. Be responsive to feedback and review comments
5. Squash commits if requested

## Code of Conduct

- Be respectful and inclusive in all interactions
- Focus on constructive feedback
- Help maintain a welcoming community

## Questions?

If you have questions about contributing, please open an issue or reach out to the maintainers.

Thank you for contributing to ExSwan!
