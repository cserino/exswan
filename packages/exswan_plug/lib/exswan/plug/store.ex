defmodule ExSwan.Plug.Store do
  @moduledoc """
  Persistence contract used by WebAuthn ceremony finish functions.

  Implementations own application identity and transaction policy. In particular,
  `update_credential/3` must persist the signature counter and backup state atomically.
  """

  alias ExSwan.{AuthenticationResult, Credential, RegistrationResult}

  @typedoc "Application-defined user or registration subject."
  @type user :: term()
  @typedoc "Application-defined callback context."
  @type context :: term()
  @typedoc "Stable failures understood by `ExSwan.Plug`."
  @type error :: :not_found | :duplicate | :stale_credential | term()

  @doc "Fetches a stored credential by its unpadded base64url identifier."
  @callback get_credential(Credential.credential_id(), context()) ::
              {:ok, Credential.t()} | {:error, error()}

  @doc "Persists a newly verified credential, returning `:duplicate` on conflict."
  @callback create_credential(user(), RegistrationResult.t(), context()) ::
              {:ok, term()} | {:error, error()}

  @doc "Atomically persists authentication counter and backup-state changes."
  @callback update_credential(Credential.t(), AuthenticationResult.t(), context()) ::
              {:ok, term()} | {:error, error()}
end
