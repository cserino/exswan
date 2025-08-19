defmodule ExWebauthn.Attestation do
  @moduledoc """
  Defines WebAuthn attestation structures and operations.

  This module contains structures used during the registration ceremony,
  including attestation objects, authenticator data, and attestation statements.
  """

  alias ExWebauthn.Credential

  @doc """
  Attestation object returned by authenticator during registration.
  """
  defstruct [
    :fmt,
    :auth_data,
    :att_stmt
  ]

  @type t :: %__MODULE__{
          fmt: String.t(),
          auth_data: AuthenticatorData.t(),
          att_stmt: map()
        }

  @doc """
  Authenticator data structure.
  """
  defmodule AuthenticatorData do
    @moduledoc """
    Represents authenticator data returned during WebAuthn operations.
    """

    defstruct [
      :rp_id_hash,
      :flags,
      :sign_count,
      :attested_credential_data,
      :extensions
    ]

    @type t :: %__MODULE__{
            rp_id_hash: binary(),
            flags: Flags.t(),
            sign_count: non_neg_integer(),
            attested_credential_data: AttestedCredentialData.t() | nil,
            extensions: map() | nil
          }
  end

  @doc """
  Flags within authenticator data.
  """
  defmodule Flags do
    @moduledoc """
    Represents flags in authenticator data.
    """

    defstruct [
      :user_present,
      :user_verified,
      :attested_credential_data_included,
      :extension_data_included
    ]

    @type t :: %__MODULE__{
            user_present: boolean(),
            user_verified: boolean(),
            attested_credential_data_included: boolean(),
            extension_data_included: boolean()
          }
  end

  @doc """
  Attested credential data included in authenticator data during registration.
  """
  defmodule AttestedCredentialData do
    @moduledoc """
    Represents attested credential data.
    """

    defstruct [
      :aaguid,
      :credential_id_length,
      :credential_id,
      :credential_public_key
    ]

    @type t :: %__MODULE__{
            aaguid: binary(),
            credential_id_length: non_neg_integer(),
            credential_id: binary(),
            credential_public_key: map()
          }
  end

  @doc """
  Public key credential creation options sent to authenticator.
  """
  defmodule CreationOptions do
    @moduledoc """
    Represents options for creating a new credential.
    """

    defstruct [
      :rp,
      :user,
      :challenge,
      :pub_key_cred_params,
      :timeout,
      :exclude_credentials,
      :authenticator_selection,
      :attestation,
      :extensions
    ]

    @type t :: %__MODULE__{
            rp: Credential.RelyingParty.t(),
            user: Credential.User.t(),
            challenge: binary(),
            pub_key_cred_params: [Credential.Parameters.t()],
            timeout: pos_integer() | nil,
            exclude_credentials: [Credential.Descriptor.t()] | nil,
            authenticator_selection: AuthenticatorSelection.t() | nil,
            attestation: String.t() | nil,
            extensions: map() | nil
          }
  end

  @doc """
  Authenticator selection criteria.
  """
  defmodule AuthenticatorSelection do
    @moduledoc """
    Represents authenticator selection criteria.
    """

    defstruct [
      :authenticator_attachment,
      :resident_key,
      :require_resident_key,
      :user_verification
    ]

    @type t :: %__MODULE__{
            authenticator_attachment: String.t() | nil,
            resident_key: String.t() | nil,
            require_resident_key: boolean() | nil,
            user_verification: String.t() | nil
          }
  end
end
