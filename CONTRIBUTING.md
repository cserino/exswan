# Contributing to ExWebauthn

Thank you for your interest in contributing to ExWebauthn! This document provides guidelines for contributing to the project.

## Development Setup

1. Clone the repository:

   ```bash
   git clone https://github.com/cserino/ex_webauthn.git
   cd ex_webauthn
   ```

2. Install dependencies:

   ```bash
   mix deps.get
   ```

3. Run tests to ensure everything is working:

   ```bash
   mix test
   ```

## Development Workflow

1. **Fork the repository** and create your branch from `main`
2. **Make your changes** following the coding standards
3. **Add tests** for any new functionality
4. **Ensure all tests pass**: `mix test`
5. **Format your code**: `mix format`
6. **Update documentation** if needed
7. **Submit a pull request**

## Coding Standards

- Follow the project's coding style (enforced by `mix format`)
- Write comprehensive tests for new features
- Include @doc documentation for public functions
- Use descriptive variable and function names
- Follow Elixir conventions for naming and code organization

## Testing

- All new code must include tests
- Tests should cover both happy path and error cases
- Run the full test suite with `mix test`
- Maintain or improve test coverage

## Documentation

- Update @doc comments for any changed public APIs
- Include examples in documentation when helpful
- Update README.md if adding significant features
- Consider adding entries to docs/plan.md for major changes

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

Thank you for contributing to ExWebauthn! 🎉

