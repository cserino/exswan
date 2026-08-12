defmodule ExSwan.RegistrationCeremony do
  @moduledoc """
  Server-only state required to verify a registration ceremony.

  Store this value on the server. Do not send it to the browser.
  """

  @enforce_keys [:challenge, :rp_id, :user_id]
  defstruct [:challenge, :rp_id, :user_id]

  @type t :: %__MODULE__{
          challenge: binary(),
          rp_id: String.t(),
          user_id: binary()
        }
end
