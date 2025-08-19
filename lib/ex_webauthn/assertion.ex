defmodule ExWebauthn.Assertion do
  @moduledoc """
  Defines WebAuthn assertion structures and operations.

  This module contains structures used during the authentication ceremony,
  including assertion responses and request options.
  """

  alias ExWebauthn.Attestation.AuthenticatorData
  alias ExWebauthn.Credential

  defmodule RequestOptions do
    @moduledoc """
    Represents options for requesting an assertion.
    """

    defstruct [
      :challenge,
      :timeout,
      :rp_id,
      :allow_credentials,
      :user_verification,
      :extensions
    ]

    @type t :: %__MODULE__{
            challenge: binary(),
            timeout: pos_integer() | nil,
            rp_id: String.t() | nil,
            allow_credentials: [Credential.Descriptor.t()] | nil,
            user_verification: String.t() | nil,
            extensions: map() | nil
          }

    def to_json(%__MODULE__{} = options) do
      %{
        "challenge" => Base.url_encode64(options.challenge, padding: false),
        "timeout" => options.timeout,
        "rpId" => options.rp_id,
        "allowCredentials" => options.allow_credentials,
        "userVerification" => options.user_verification,
        "extensions" => options.extensions
      }
      |> remove_nil_values()
    end

    defp remove_nil_values(map) when is_map(map) do
      map
      |> Enum.reject(fn {_key, value} -> is_nil(value) end)
      |> Enum.into(%{})
    end
  end

  defmodule Response do
    @moduledoc """
    Represents an authenticator assertion response.
    """

    defstruct [
      :credential_id,
      :authenticator_data,
      :signature,
      :user_handle
    ]

    @type t :: %__MODULE__{
            credential_id: binary(),
            authenticator_data: AuthenticatorData.t(),
            signature: binary(),
            user_handle: binary() | nil
          }
  end

  defmodule ClientData do
    @moduledoc """
    Represents client data JSON for WebAuthn assertions.
    """

    defstruct [
      :type,
      :challenge,
      :origin,
      :cross_origin,
      :token_binding
    ]

    @type t :: %__MODULE__{
            type: String.t(),
            challenge: String.t(),
            origin: String.t(),
            cross_origin: boolean() | nil,
            token_binding: map() | nil
          }
  end

  defmodule Result do
    @moduledoc """
    Represents a complete assertion result.
    """

    defstruct [
      :credential_id,
      :client_data_json,
      :authenticator_data,
      :signature,
      :user_handle
    ]

    @type t :: %__MODULE__{
            credential_id: binary(),
            client_data_json: binary(),
            authenticator_data: binary(),
            signature: binary(),
            user_handle: binary() | nil
          }
  end
end

defimpl Jason.Encoder, for: ExWebauthn.Assertion.RequestOptions do
  alias ExWebauthn.Assertion.RequestOptions

  def encode(value, opts) do
    Jason.Encode.map(
      RequestOptions.to_json(value),
      opts
    )
  end
end
