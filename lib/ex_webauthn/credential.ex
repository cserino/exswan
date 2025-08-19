defmodule ExWebauthn.Credential do
  @moduledoc """
  Defines WebAuthn credential structures and operations.

  This module contains the core data structures used in WebAuthn operations,
  including public key credentials, authenticator data, and credential sources.
  """

  @type credential_id :: binary()
  @type user_handle :: binary()

  @doc """
  Represents a WebAuthn credential source as stored by the authenticator.
  """
  defstruct [
    :type,
    :id,
    :private_key,
    :rp_id,
    :user_handle,
    :user_display_name,
    :cred_protect,
    :creation_time
  ]

  @type t :: %__MODULE__{
          type: :public_key,
          id: credential_id(),
          private_key: binary(),
          rp_id: String.t(),
          user_handle: user_handle(),
          user_display_name: String.t(),
          cred_protect: atom(),
          creation_time: DateTime.t()
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
            id: binary(),
            transports: [String.t()]
          }
  end

  defmodule User do
    @moduledoc """
    Represents user entity information in WebAuthn operations.
    """

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
  end
end
