defmodule ExSwan.RegistrationResult do
  @moduledoc """
  Information produced by successful registration verification.
  """

  alias ExSwan.Credential

  @enforce_keys [
    :credential,
    :aaguid,
    :attestation_format,
    :user_verified,
    :credential_device_type,
    :credential_backed_up,
    :authenticator_extension_results,
    :origin,
    :rp_id
  ]
  defstruct @enforce_keys

  @type t :: %__MODULE__{
          credential: Credential.t(),
          aaguid: String.t(),
          attestation_format: atom(),
          user_verified: boolean(),
          credential_device_type: :single_device | :multi_device,
          credential_backed_up: boolean(),
          authenticator_extension_results: map(),
          origin: String.t(),
          rp_id: String.t()
        }
end
