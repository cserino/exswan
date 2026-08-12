# SimpleWebAuthn compatibility fixtures

This project pins the SimpleWebAuthn browser and server packages. The generator creates
deterministic reference options. TypeScript also checks those options against the JSON
types accepted by `@simplewebauthn/browser`.

Run `make compatibility-fixtures` from the repository root to update the committed
fixtures. Run `make compatibility-check` in CI. The check fails when regeneration
changes a committed fixture.

Do not edit files under `fixtures/` by hand.
