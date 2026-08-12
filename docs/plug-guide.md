# Plug Ceremony Guide

`ExSwan.Plug` stores ceremony state on the server and places a random lookup token in
the Plug session. Call `fetch_session/2` before the ceremony functions.

Start registration only after the application authorizes it. Pass the authorized
user and stable user handle to `begin_registration/2`. Finish with the complete
browser response and an `ExSwan.Plug.Store` implementation.

```elixir
{:ok, conn, options_json} =
  ExSwan.Plug.begin_registration(conn,
    user: current_user,
    user_handle: current_user.webauthn_id,
    user_name: current_user.email,
    rp_name: "Example",
    rp_id: "example.com",
    origin: "https://example.com",
    ceremony_store: {MyApp.Ceremonies, :primary},
    context: %{tenant_id: current_user.tenant_id}
  )
```

Use the matching `begin_authentication/2`, `finish_registration/2`, and
`finish_authentication/2` functions. A finish call consumes ceremony state before it
verifies the response. A failed response cannot be retried with the same challenge.

Add `ExSwan.Plug.Config` to the supervision tree to reject an unsafe RP ID or origin
at startup. Use `ExSwan.Plug.Response` for stable coarse JSON responses. See
[Ceremony store adapters](ceremony-store-adapters.md) and
[Credential persistence](credential-persistence.md).
