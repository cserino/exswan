defmodule ExSwan.AuthenticationResult do
  @moduledoc """
  Information produced by successful authentication verification.

  Persist `new_sign_count` and backup state after every successful ceremony.
  """

  @enforce_keys [
    :credential_id,
    :new_sign_count,
    :user_verified,
    :credential_device_type,
    :credential_backed_up,
    :authenticator_extension_results,
    :origin,
    :rp_id
  ]
  defstruct @enforce_keys

  @type t :: %__MODULE__{
          credential_id: String.t(),
          new_sign_count: non_neg_integer(),
          user_verified: boolean(),
          credential_device_type: :single_device | :multi_device,
          credential_backed_up: boolean(),
          authenticator_extension_results: map(),
          origin: String.t(),
          rp_id: String.t()
        }
end
