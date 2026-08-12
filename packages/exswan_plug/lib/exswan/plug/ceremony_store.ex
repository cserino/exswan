defmodule ExSwan.Plug.CeremonyStore do
  @moduledoc """
  Storage contract for expiring, single-use WebAuthn ceremony state.

  `consume/2` must atomically remove and return a live entry. Concurrent consumers
  must never both receive the same ceremony.
  """

  @typedoc "Opaque, caller-visible lookup token."
  @type token :: String.t()
  @typedoc "Serializable server-only ceremony state."
  @type ceremony :: term()
  @typedoc "Adapter-specific process, connection, or namespace."
  @type context :: term()
  @type error :: :not_found | :expired | term()

  @doc "Stores ceremony state until the monotonic deadline in milliseconds."
  @callback put(context(), token(), ceremony(), integer()) :: :ok | {:error, term()}

  @doc "Atomically removes and returns a live ceremony."
  @callback consume(context(), token(), integer()) :: {:ok, ceremony()} | {:error, error()}
end
