# SimpleWebAuthn Compatibility and Package Design

- Date: 2026-08-12
- Status: Proposed
- Packages: `exswan`, `exswan_plug`

## Decision

ExSwan will be a SimpleWebAuthn-browser-compatible WebAuthn server for Elixir.
JSON emitted by `@simplewebauthn/browser` must pass directly to ExSwan verification.
Options emitted by ExSwan must pass directly to `startRegistration({optionsJSON})` or
`startAuthentication({optionsJSON})`.

SimpleWebAuthn compatibility governs wire shapes, field names, defaults, and returned
ceremony information. WebAuthn compliance and protocol safety govern verification.

> ExSwan may reject responses that SimpleWebAuthn accepts when current protocol safety
> requires rejection. ExSwan must never accept a response that WebAuthn requires a
> relying party to reject.

## Goals

- Accept complete browser response objects without caller-side reshaping.
- Generate browser-ready maps without a separate JSON conversion step.
- Return all information that an application needs to store or update a credential.
- Keep protocol and cryptographic work in `exswan`.
- Keep HTTP and ceremony lifecycle work in `exswan_plug`.
- Make compatibility explicit through generated fixtures and conformance tests.

## Non-goals

- `exswan` will not depend on Plug, Phoenix, Ecto, sessions, controllers, or user schemas.
- `exswan_plug` will not parse CBOR or COSE, validate attestation statements, or verify
  signatures.
- `exswan_plug` will not define account creation, login, user storage, HTML, LiveView,
  or a mandatory route layout.
- Initial releases will not advertise algorithms or attestation formats without a full
  registration-to-authentication test.

## Package seam

```text
@simplewebauthn/browser
          | exact JSON shapes
          v
       ExSwan
  generation + verification
          | structured results
          v
    ExSwan.Plug
session/challenge lifecycle,
routes, persistence callbacks
          |
          v
 Phoenix application
```

This seam creates two deep modules. `ExSwan` hides WebAuthn parsing, validation, and
cryptography behind four ceremony functions. `ExSwan.Plug` hides secure state handling
and HTTP orchestration behind begin and finish functions. The application supplies
identity policy and persistence through explicit inputs and a store adapter.

## Core interface

### Registration options

```elixir
{:ok, %{options: options_json, ceremony: ceremony}} =
  ExSwan.generate_registration_options(
    rp_name: "Example",
    rp_id: "example.com",
    user_name: "person@example.com",
    user_id: user_handle
  )
```

`options_json` uses the camel-case field names and base64url values expected by
`@simplewebauthn/browser`. `ceremony` contains server-only state that verification
needs. The exact ceremony type is an Elixir implementation detail, but it must be safe
to serialize into server-side storage.

### Registration verification

```elixir
ExSwan.verify_registration_response(
  response: browser_json,
  expected_challenge: challenge,
  expected_origin: origin,
  expected_rp_id: rp_id
)
```

The function accepts the complete object returned by `@simplewebauthn/browser`. It
validates `id`, `rawId`, `type`, the nested `response`, credential ID correspondence,
transports, extension outputs, optional fields, and every base64url value before it
performs protocol verification.

Successful verification returns:

```elixir
{:ok,
 %ExSwan.RegistrationResult{
   credential: %ExSwan.Credential{
     id: "base64url-credential-id",
     public_key: <<...>>,
     sign_count: 0,
     transports: []
   },
   aaguid: "aaguid",
   attestation_format: :none,
   user_verified: true,
   credential_device_type: :multi_device,
   credential_backed_up: true,
   authenticator_extension_results: %{},
   origin: "https://example.com",
   rp_id: "example.com"
 }}
```

### Authentication options

```elixir
{:ok, %{options: options_json, ceremony: ceremony}} =
  ExSwan.generate_authentication_options(
    rp_id: "example.com",
    allow_credentials: credentials
  )
```

The result follows the same browser-ready and server-only split as registration.

### Authentication verification

```elixir
ExSwan.verify_authentication_response(
  response: browser_json,
  expected_challenge: challenge,
  expected_origin: origin,
  expected_rp_id: rp_id,
  credential: stored_credential
)
```

Successful verification returns at least:

```elixir
{:ok,
 %ExSwan.AuthenticationResult{
   credential_id: "base64url-credential-id",
   new_sign_count: 42,
   user_verified: true,
   credential_device_type: :multi_device,
   credential_backed_up: true,
   authenticator_extension_results: %{},
   origin: "https://example.com",
   rp_id: "example.com"
 }}
```

Returning `new_sign_count` and backup state makes the required persistence update
explicit. Callers must not reconstruct these values from internal parser output.

## Wire and data rules

- Public option and response maps use SimpleWebAuthn's JSON field names.
- Elixir structs and keyword options use snake-case field names.
- Credential IDs use unpadded base64url strings at the public and persistence seams.
- Raw public keys use the binary representation required for later verification.
- Parsers reject malformed base64url, truncated input, and unconsumed binary data.
- Verification checks user presence, configured user verification, backup eligibility
  and state, signature counters, origin, RP ID, ceremony type, and challenge.
- Registration confirms that outer `id`, outer `rawId`, and attested credential ID
  identify the same credential.
- Authentication confirms that the response credential ID matches the stored
  credential and any applicable allow-list.
- Extension results and transports are preserved in the result when the browser sends
  them. Unsupported security-sensitive extensions cause an explicit error when their
  safe interpretation is required.
- Public functions return tagged tuples. No malformed public input may raise an
  exception or terminate the caller process.

## Algorithms and attestation

The first supported attestation format is `none`. Option generation must advertise
only algorithms that registration can parse and validate and authentication can use
to verify a signature on every supported OTP version.

Add ES256 first. Add Ed25519 and RS256 only after each has a real cryptographic
registration-to-authentication vector. Add packed self-attestation, packed full
attestation, and FIDO U2F only after their trust and certificate rules have full
end-to-end coverage. Until then, option generation must not advertise them and
verification must return an explicit unsupported-format or unsupported-algorithm
error.

## Intentional compatibility differences

Maintain a dedicated compatibility page with the pinned SimpleWebAuthn major version
and every known deviation. Allowed differences are:

- Tagged tuples instead of thrown exceptions.
- Snake-case fields in Elixir structs.
- Synchronous challenge-verifier functions.
- Stronger rejection of unsafe legacy behavior.
- Omission of deprecated attestation formats that cannot be verified safely.

The following differences are not allowed:

- Different wire JSON or credential ID representation.
- Advertising an algorithm that verification cannot use.
- Discarding browser-returned ceremony state without an explicit reason.
- Weaker user-verification, backup-flag, counter, or attestation checks.
- Requiring callers to extract or transform fields from a browser response.

## Plug interface

Applications call ceremony functions from their own controllers or route handlers:

```elixir
ExSwan.Plug.begin_registration(conn,
  user: current_user,
  user_handle: current_user.webauthn_id
)

ExSwan.Plug.finish_registration(conn,
  response: params,
  store: MyApp.Passkeys
)
```

Equivalent begin and finish functions support authentication. Begin functions create
and store expiring ceremony state. Finish functions consume that state once, call the
core verifier, invoke the store adapter, and translate known failures into stable HTTP
errors.

Registration requires an explicit authorization input, such as an authenticated user
or a signed pending-registration token. The package must not infer authorization from
the presence of a session or request parameter.

The persistence seam starts with callbacks rather than an Ecto dependency:

```elixir
defmodule MyApp.Passkeys do
  @behaviour ExSwan.Plug.Store

  def get_credential(credential_id, context), do: ...
  def create_credential(user, registration, context), do: ...
  def update_credential(credential, authentication, context), do: ...
end
```

The callback contract must define duplicate handling, not-found behavior, atomic
counter and backup-state updates, and the context passed from the application.

## Challenge lifecycle

`ExSwan.Plug` owns challenge generation, server-side storage, expiration, and one-time
consumption. It must consume ceremony state atomically before or as part of successful
verification so concurrent retries cannot both succeed. A failed response must not
make an attacker-controlled challenge reusable. The storage interface must support an
in-memory test adapter and at least one production-capable adapter or a clear adapter
implementation guide.

## Errors and telemetry

Core errors use stable, documented atoms or structs and preserve enough context for
tests and server logs without exposing credential material. `ExSwan.Plug` maps them to
coarse HTTP responses and emits telemetry for ceremony start, success, and failure.
Telemetry metadata must not contain challenges, client data, public keys, signatures,
attestation certificates, or user handles.

## Compatibility and conformance tests

A small TypeScript fixture project will pin one SimpleWebAuthn major and exact package
version. A generator, not hand-edited copies, will produce option fixtures, browser
response fixtures, expected verification information, and invalid mutations.

The test layers are:

1. Shared SimpleWebAuthn fixtures in both directions.
2. Real cryptographic registration-to-authentication vectors for every advertised
   algorithm and attestation format.
3. Protocol rejection tests derived by mutating valid fixtures.
4. StreamData properties and fuzz cases for every binary parser and public verifier.
5. FIDO Alliance conformance tests against a private HTTP harness.

The release sequence is:

1. Pass pinned SimpleWebAuthn compatibility fixtures.
2. Pass Chrome, Firefox, and Safari registration and authentication tests.
3. Pass malformed-input and property tests.
4. Pass the applicable WebAuthn and FIDO conformance suite.
5. Restore compliance or production-readiness claims only after the evidence supports
   them.

## Implementation task list

### 0. Establish the baseline

- [ ] Select and record the supported WebAuthn level and pinned
  `@simplewebauthn/browser` major and exact fixture-generator version.
- [ ] Add `docs/compatibility.md` with the version policy and known deviations.
- [ ] Remove unsupported compliance and production-readiness claims from package docs.
- [ ] Record the supported Elixir and OTP matrix for cryptographic behavior.
- [ ] Add architecture tests or dependency checks that prevent Plug/Phoenix/Ecto from
  entering `exswan` and protocol internals from entering `exswan_plug`.

### 1. Define the core interface and types

- [ ] Add `ExSwan.RegistrationResult` and `ExSwan.AuthenticationResult`.
- [ ] Redefine `ExSwan.Credential` as the public stored-credential value, including ID,
  public key, sign count, transports, device type, and backup state.
- [ ] Define private ceremony state for registration and authentication.
- [ ] Implement the four keyword-based functions documented in this design.
- [ ] Return browser-ready maps and ceremony state from both generation functions.
- [ ] Mark old struct-based and `options_to_json/1` interfaces for migration or removal.
- [ ] Document every public function, option, result field, and error.

### 2. Make browser JSON a strict input seam

- [ ] Add total parsers for registration and authentication browser response objects.
- [ ] Accept string-keyed maps from JSON decoders without caller conversion.
- [ ] Validate required outer fields, nested response fields, and `type` values.
- [ ] Implement one strict unpadded-base64url decoder and use it for every binary field.
- [ ] Validate `id`/`rawId` and attested or stored credential ID correspondence.
- [ ] Parse and preserve transports and client extension results.
- [ ] Handle optional authentication `userHandle` and enforce expected-user matching.
- [ ] Ensure arbitrary maps and binaries return documented errors without raising.

### 3. Harden protocol parsing and verification

- [ ] Reject CBOR values with trailing bytes in all security-sensitive parsers.
- [ ] Reject truncated or leftover authenticator data, credential keys, and extensions.
- [ ] Validate COSE key type, algorithm, curve, coordinate sizes, and required fields.
- [ ] Enforce that the credential algorithm was offered during registration.
- [ ] Enforce ceremony type, challenge, origin, RP ID hash, UP, and configured UV.
- [ ] Reject the invalid backup-state combination `BS = 1` and `BE = 0`.
- [ ] Derive and return device type and backup state for both ceremonies.
- [ ] Implement safe signature-counter rules and always return `new_sign_count`.
- [ ] Implement `none` attestation as the initial supported format.
- [ ] Limit generated algorithms to ES256 until other algorithms pass end-to-end tests.
- [ ] Audit rescue/catch clauses so programmer errors are not mislabeled as user input.

### 4. Build generated compatibility fixtures

- [ ] Create a small TypeScript fixture project with lockfile-pinned SimpleWebAuthn
  dependencies.
- [ ] Generate registration and authentication options for comparison with ExSwan.
- [ ] Generate browser response JSON and expected verification information.
- [x] Generate invalid cases by mutating valid fixtures.
- [ ] Add a reproducible root command to regenerate fixtures.
- [ ] Make CI fail when committed fixtures differ from generated fixtures.
- [ ] Test ExSwan options against SimpleWebAuthn browser types and expected shapes.
- [ ] Test unmodified SimpleWebAuthn browser JSON against ExSwan verification.

### 5. Complete cryptographic and rejection coverage

- [ ] Add a full ES256 registration-to-authentication vector.
- [x] Add wrong challenge, origin, RP ID, ceremony type, and credential ID cases.
- [x] Add malformed base64url, JSON, CBOR, COSE, and authenticator-data cases.
- [x] Add algorithm-not-offered, UV/UP, BE/BS, counter rollback, and user-handle cases.
- [ ] Add StreamData properties for base64url and all binary parsers.
- [ ] Assert that no arbitrary public input crashes a verifier process.
- [ ] Add Ed25519 and RS256 only with complete vectors across the supported OTP matrix.
- [ ] Add each attestation format only with trust, certificate-profile, and end-to-end
  rejection coverage.

### 6. Implement `exswan_plug`

- [ ] Define `ExSwan.Plug.Store` callback types and error semantics.
- [ ] Define a ceremony-store seam with atomic expiry and one-time consumption.
- [ ] Provide a deterministic in-memory ceremony-store adapter for tests.
- [ ] Implement registration begin and finish functions.
- [ ] Require explicit registration authorization and test unauthorized attempts.
- [ ] Implement authentication begin and finish functions.
- [ ] Make credential lookup and counter/backup updates explicit store operations.
- [ ] Define stable JSON success and error responses.
- [ ] Add origin and RP configuration validation at application startup.
- [ ] Emit secret-free telemetry for start, success, and failure.
- [ ] Add optional Phoenix router/controller helpers without a Phoenix core dependency.

### 7. Migrate the demo and documentation

- [ ] Move all ceremony state and security logic out of the demo and into
  `exswan_plug`.
- [ ] Keep user lookup, account policy, login policy, and UI in the demo.
- [ ] Use `startRegistration({optionsJSON})` and
  `startAuthentication({optionsJSON})` without transformations.
- [ ] Add framework-neutral core guides and separate Plug/Phoenix guides.
- [ ] Add a credential persistence and atomic-update guide for store adapters.
- [ ] Label the example as a demo and document its deployment limits.

### 8. Validate releases

- [ ] Run `make format-check`, `make compile`, `make test`, and `make hex-build`.
- [ ] Test registration and authentication in current Chrome, Firefox, and Safari.
- [ ] Build the private HTTP harness for FIDO Alliance conformance tooling.
- [ ] Run the applicable conformance suite and track failures as release blockers.
- [ ] Verify that each Hex package contains only its own public files and dependencies.
- [ ] Publish independent package versions and coordinate them only when compatibility
  requires it.

## Definition of done

The design is implemented when browser options and responses cross the JavaScript and
Elixir seam without reshaping, every advertised cryptographic combination has a full
positive and negative test path, public verifiers are total over untrusted input, and
`exswan_plug` owns the security-sensitive ceremony lifecycle without owning application
identity policy.
