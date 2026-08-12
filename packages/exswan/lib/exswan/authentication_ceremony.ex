defmodule ExSwan.AuthenticationCeremony do
  @moduledoc """
  Server-only state required to verify an authentication ceremony.

  Store this value on the server. Do not send it to the browser.
  """

  @enforce_keys [:challenge, :rp_id]
  defstruct [:challenge, :rp_id]

  @type t :: %__MODULE__{
          challenge: binary(),
          rp_id: String.t()
        }
end
