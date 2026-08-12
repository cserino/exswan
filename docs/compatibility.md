# SimpleWebAuthn Compatibility

ExSwan targets `@simplewebauthn/browser` major version 13. Compatibility fixtures are
pinned to version 13.1.2, which is also the version locked by the Phoenix demo.
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
