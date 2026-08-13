# ExSwan Test

`exswan_test` provides a software WebAuthn authenticator for consumer application tests.
It emits browser-shaped responses with real ES256 signatures and `none` attestation.

Add it only in test:

```elixir
{:exswan_test, "~> 0.1.0", only: :test}
```

```elixir
alias ExSwan.Test.Authenticator

authenticator = Authenticator.new(user_handle: user.id)

response = Authenticator.registration_response(authenticator,
  challenge: ceremony.challenge,
  origin: "https://example.com",
  rp_id: "example.com"
)
```

Reuse the authenticator to build authentication responses. Pass semantic overrides such as
`origin: "https://evil.example"`, `sign_count: 0`, or `flags: 0x01` to test rejection paths.

This package is test infrastructure. Never use its fixed default private key for production
credentials or authentication.

See the [consumer testing guide](docs/testing-guide.md) for complete ceremonies and common
failure scenarios.
