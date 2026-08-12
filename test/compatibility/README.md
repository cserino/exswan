# SimpleWebAuthn compatibility fixtures

This project pins the SimpleWebAuthn browser and server packages. The generator creates
deterministic reference options and a complete ES256 `none`
registration-to-authentication ceremony. TypeScript checks the options and response
objects against the JSON types accepted and returned by `@simplewebauthn/browser`.

The ceremony uses a fixed test-only P-256 key. Never use this key outside the fixture
suite.

Run `make compatibility-fixtures` from the repository root to update the committed
fixtures. Run `make compatibility-check` in CI. The check fails when regeneration
changes a committed fixture.

Do not edit files under `fixtures/` by hand.
