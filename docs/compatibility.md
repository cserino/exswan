# SimpleWebAuthn Compatibility

ExSwan targets `@simplewebauthn/browser` major version 13. Compatibility fixtures pin
`@simplewebauthn/browser` and `@simplewebauthn/server` to version 13.1.2. The browser
version also matches the version locked by the Phoenix demo.
Fixture generation runs on Bun 1.2.20. The supported runtime matrix is Elixir 1.18.4
on OTP 27.3; additions require the full cryptographic and compatibility suites in CI.
The initial protocol baseline is the Web Authentication Level 2 Recommendation already
tracked in this repository. Later-level browser fields can pass through where they do
not weaken Level 2 verification requirements.

JSON from `@simplewebauthn/browser` should pass directly to ExSwan verification.
Browser-ready option maps from ExSwan should pass directly to
`startRegistration({optionsJSON})` and `startAuthentication({optionsJSON})`.

## Version policy

- The compatibility target is a SimpleWebAuthn major version.
- Fixture generation uses an exact package version and a committed lockfile.
- A fixture-version update must regenerate all fixtures and pass both compatibility
  directions before merge.
- A SimpleWebAuthn major-version update requires a compatibility review and may require
  a new ExSwan major version if the public Elixir interface changes.

Run `make compatibility-fixtures` to regenerate the committed fixtures. Run
`make compatibility-check` to type-check the generated options against the pinned
browser package and fail on fixture drift. Compatibility-sensitive implementation
work follows a red-green loop through the public `ExSwan` interface.

Release evidence is tracked in [the browser validation matrix](browser-validation.md)
and [the private FIDO harness results](../test/conformance/results/README.md). Empty or
failing entries block compatibility and production-readiness claims.

Use [the remaining validation runbook](remaining-validation.md) to prepare manual
browser runs, real authenticator coverage, and official FIDO server conformance.

## Safety policy

WebAuthn compliance and protocol safety govern verification. ExSwan can reject a
response that SimpleWebAuthn accepts when current protocol safety requires rejection.
ExSwan must not accept a response that WebAuthn requires a relying party to reject.

## Intentional differences

- ExSwan returns tagged tuples instead of throwing exceptions.
- Public Elixir structs and keyword options use snake-case names.
- Challenge-verifier functions are synchronous.
- ExSwan can omit deprecated algorithms and attestation formats that it cannot verify
  safely from generation defaults.
- ExSwan can apply stricter validation than legacy SimpleWebAuthn behavior.

## Current implementation status

- Browser-ready registration and authentication option generation is available at the
  top-level `ExSwan` interface.
- ES256 is the only default advertised algorithm.
- Complete registration and authentication browser-response parsing and structured
  verification results are available.
- `none` is the initial attestation target. Other formats are not part of the initial
  compatibility claim.
