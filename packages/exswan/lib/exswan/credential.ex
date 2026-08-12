defmodule ExSwan.Credential do
  @moduledoc """
  Defines WebAuthn credential structures and operations.

  This module contains the core data structures used in WebAuthn operations,
  including public key credentials, authenticator data, and credential sources.
  """

  @type credential_id :: String.t()
  @type user_handle :: binary()

  @doc """
  Represents a WebAuthn credential source as stored by the authenticator.
  """
  @derive Jason.Encoder
  defstruct [
    :type,
    :id,
    :private_key,
    :public_key,
    :rp_id,
    :user_handle,
    :user_display_name,
    :cred_protect,
    :creation_time,
    :sign_count
  ]

  @type t :: %__MODULE__{
          type: :public_key,
          id: credential_id(),
          private_key: binary() | nil,
          public_key: map(),
          rp_id: String.t(),
          user_handle: user_handle(),
          user_display_name: String.t(),
          cred_protect: atom() | nil,
          creation_time: DateTime.t(),
          sign_count: non_neg_integer()
        }

  defmodule Descriptor do
    @moduledoc """
    Represents a public key credential descriptor.
    """

    defstruct [
      :type,
      :id,
      :transports
    ]

    @type t :: %__MODULE__{
            type: :public_key,
            id: String.t(),
            transports: [String.t()]
          }

    def to_json(%__MODULE__{} = desc) do
      %{
        "type" => "public-key",
        "id" => desc.id,
        "transports" => desc.transports
      }
    end
  end

  defmodule User do
    @moduledoc """
    Represents user entity information in WebAuthn operations.
    """

    @derive Jason.Encoder
    defstruct [
      :id,
      :name,
      :display_name
    ]

    @type t :: %__MODULE__{
            id: binary(),
            name: String.t(),
            display_name: String.t()
          }
  end

  defmodule RelyingParty do
    @moduledoc """
    Represents relying party entity information.
    """

    @derive Jason.Encoder
    defstruct [
      :id,
      :name,
      :icon
    ]

    @type t :: %__MODULE__{
            id: String.t(),
            name: String.t(),
            icon: String.t() | nil
          }
  end

  defmodule Parameters do
    @moduledoc """
    Represents public key credential parameters.
    """

    defstruct [
      :type,
      :alg
    ]

    @type t :: %__MODULE__{
            type: :public_key,
            alg: integer()
          }

    def to_json(%__MODULE__{} = param) do
      %{
        "type" => type_to_json(param.type),
        "alg" => param.alg
      }
    end

    defp type_to_json(:public_key), do: "public-key"
    defp type_to_json(other), do: other
  end
end

defimpl Jason.Encoder, for: ExSwan.Credential.Descriptor do
  alias ExSwan.Credential.Descriptor

  def encode(value, opts) do
    Jason.Encode.map(
      Descriptor.to_json(value),
      opts
    )
  end
end

defimpl Jason.Encoder, for: ExSwan.Credential.Parameters do
  alias ExSwan.Credential.Parameters

  def encode(value, opts) do
    Jason.Encode.map(
      Parameters.to_json(value),
      opts
    )
  end
end
