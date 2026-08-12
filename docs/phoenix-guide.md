# Phoenix Integration Guide

Phoenix owns controllers, account policy, login state, and response redirects.
`exswan_plug` owns WebAuthn ceremony state and verification orchestration.

Import the optional route macro in a Phoenix router:

```elixir
import ExSwan.Plug.Phoenix

scope "/api", MyAppWeb do
  pipe_through :api
  webauthn_routes PasskeyController, path: "/passkeys"
end
```

The controller implements `begin_registration/2`, `finish_registration/2`,
`begin_authentication/2`, and `finish_authentication/2`. Each action calls the
matching `ExSwan.Plug` function. Registration authorization must come from an
authenticated user or a signed pending-registration token. Do not infer authorization
from an email or user ID in request parameters.

The Phoenix demo shows a complete integration. It uses in-memory ceremony storage for
local use. Replace that adapter with a shared atomic store before a multi-node or
production deployment.
