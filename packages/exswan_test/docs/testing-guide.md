# Testing applications with ExSwan

`exswan_test` creates valid WebAuthn responses for application tests. Use it when a test must
cross your HTTP, ceremony-store, persistence, or session code without a real browser.

The helpers run the real ExSwan verification code. They do not replace or mock the verifier.

## Install the package

Add `exswan_test` only to the test environment:

```elixir
def deps do
  [
    {:exswan, "~> 0.1.0"},
    {:exswan_test, "~> 0.1.0", only: :test}
  ]
end
```

Do not include this package in a production release. Its default private key is public and
fixed. This makes tests repeatable, but makes the key unsafe for real credentials.

## Test registration

Create an authenticator and keep it for the authentication test. Pass the challenge and RP ID
from the ceremony that your application stored.

```elixir
alias ExSwan.Test.Authenticator

challenge = :binary.copy(<<7>>, 32)
origin = "https://example.com"
rp_id = "example.com"
user_handle = <<1, 2, 3, 4>>

authenticator = Authenticator.new(user_handle: user_handle)

response =
  Authenticator.registration_response(authenticator,
    challenge: challenge,
    origin: origin,
    rp_id: rp_id
  )

assert {:ok, registration} =
         ExSwan.verify_registration_response(
           response: response,
           expected_challenge: challenge,
           expected_origin: origin,
           expected_rp_id: rp_id
         )

credential = registration.credential
```

The returned credential contains a CBOR-encoded public key. Persist it in the same form that
your application uses in production.

## Test authentication

Reuse the authenticator that created the credential. It owns the matching private key.

```elixir
response =
  Authenticator.authentication_response(authenticator,
    challenge: challenge,
    origin: origin,
    rp_id: rp_id,
    sign_count: credential.sign_count + 1
  )

assert {:ok, authentication} =
         ExSwan.verify_authentication_response(
           response: response,
           expected_challenge: challenge,
           expected_origin: origin,
           expected_rp_id: rp_id,
           expected_user_handle: user_handle,
           credential: credential
         )

assert authentication.new_sign_count == credential.sign_count + 1
```

After verification, test that your application persists `new_sign_count` and the returned
backup state. A later request must use the updated stored credential.

## Create a stored credential directly

Some tests start at authentication and do not need registration. Use `credential/2` to create
the stored value that matches an authenticator:

```elixir
authenticator = Authenticator.new(user_handle: user_handle)

credential =
  Authenticator.credential(authenticator,
    sign_count: 10,
    credential_device_type: :single_device,
    credential_backed_up: false
  )
```

Use a second `Authenticator.new/1` value with a different `:credential_id` to test an unknown
credential.

## Test rejection paths

The builders sign the response after they apply their options. This lets you create responses
that are cryptographically valid but fail a specific WebAuthn check.

```elixir
# Wrong challenge
Authenticator.authentication_response(authenticator,
  challenge: :binary.copy(<<9>>, 32),
  origin: origin,
  rp_id: rp_id
)

# Wrong origin
Authenticator.authentication_response(authenticator,
  challenge: challenge,
  origin: "https://evil.example",
  rp_id: rp_id
)

# Wrong RP ID hash
Authenticator.authentication_response(authenticator,
  challenge: challenge,
  origin: origin,
  rp_id: "other.example.com"
)

# Counter rollback: verify this response against a stored count of 10
Authenticator.authentication_response(authenticator,
  challenge: challenge,
  origin: origin,
  rp_id: rp_id,
  sign_count: 9
)

# User presence without user verification
Authenticator.authentication_response(authenticator,
  challenge: challenge,
  origin: origin,
  rp_id: rp_id,
  flags: 0x01
)
```

Use `tamper/2` when the corruption itself is the scenario:

```elixir
invalid_response = Authenticator.tamper(response, :signature)
invalid_json = Authenticator.tamper(response, :client_data)
short_authenticator_data = Authenticator.tamper(response, :authenticator_data)
```

Prefer builder options for semantic failures. Use `tamper/2` for malformed or corrupted input.
This keeps each test clear about the condition it exercises.

## Test HTTP endpoints

For an endpoint test, use the options returned by the begin endpoint to build the completion
response:

1. Call the registration or authentication begin endpoint.
2. Read the challenge from its JSON response, or from the stored ceremony when the response is
   wrapped in an application-specific token.
3. Build a response with the same challenge, origin, and RP ID.
4. Send that response to the completion endpoint.
5. Assert the HTTP result and all application effects.

Test effects that ExSwan cannot own, including:

- ceremony consumption and replay rejection;
- credential uniqueness and ownership rules;
- transaction rollback after persistence failures;
- signature counter and backup-state updates;
- session renewal after authentication;
- behavior for unknown credential IDs.

If a controller test must avoid cryptographic verification, add a small verifier module inside
your application and inject a test adapter there. Keep that seam local to the application. Use
`exswan_test` for endpoint and integration tests that should exercise real verification.

## Authenticator options

`Authenticator.new/1` accepts:

- `:credential_id` — raw binary credential ID;
- `:user_handle` — raw binary user handle;
- `:private_key` — a 32-byte P-256 private key.

The response builders accept these common options:

- `:challenge`, `:origin`, and `:rp_id` — required ceremony values;
- `:credential_id` — overrides the response credential ID;
- `:flags` — raw WebAuthn authenticator flags;
- `:sign_count` — authenticator signature counter;
- `:authenticator_attachment` — defaults to `"platform"`;
- `:client_extensions` — defaults to an empty map.

Registration also accepts `:aaguid` and `:transports`. Authentication also accepts
`:user_handle`.
