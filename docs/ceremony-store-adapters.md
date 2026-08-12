# Ceremony Store Adapters

`ExSwan.Plug.CeremonyStore` stores server-only WebAuthn ceremony state. A production
adapter must implement `put/4` and `consume/3` with these guarantees:

- Expiration uses a server-controlled monotonic or database time source.
- `consume/3` removes and returns a live entry in one atomic operation.
- Concurrent consumers cannot both receive the same entry.
- An expired entry is removed and returns `{:error, :expired}`.
- A missing or previously consumed entry returns `{:error, :not_found}`.
- Tokens and stored values are never logged or included in telemetry.
- Stored values are encrypted at rest when the backing service does not already
  provide equivalent protection.

For PostgreSQL, use one transaction containing `DELETE ... WHERE token = $1 AND
expires_at > now() RETURNING ceremony`. If no live row is returned, delete any expired
row separately and return the appropriate stable error. For Redis, use a Lua script
that reads, checks expiry, and deletes the key atomically. Do not implement consume as
separate get and delete calls.

`ExSwan.Plug.CeremonyStore.Memory` is deterministic and suitable for tests or a
single-node process. It is not a multi-node production adapter: state disappears on
restart and another node cannot consume it.
