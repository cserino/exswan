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

  defmodule Flags do
    @moduledoc """
    Represents flags in authenticator data.

    Reference: vendor/SimpleWebAuthn/packages/server/src/helpers/parseAuthenticatorData.ts:28-38
    Bit positions can be referenced here: https://www.w3.org/TR/webauthn-2/#flags
    """

    defstruct [
      # UP (bit 0) - User Presence
      :user_present,
      # UV (bit 2) - User Verified
      :user_verified,
      # BE (bit 3) - Backup Eligibility
      :backup_eligible,
      # BS (bit 4) - Backup State
      :backup_state,
      # AT (bit 6) - Attested Credential Data Present
      :attested_credential_data_included,
      # ED (bit 7) - Extension Data Present
      :extension_data_included
    ]

    @type t :: %__MODULE__{
            user_present: boolean(),
            user_verified: boolean(),
            backup_eligible: boolean(),
            backup_state: boolean(),
            attested_credential_data_included: boolean(),
            extension_data_included: boolean()
          }
  end

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

  defmodule CreationOptions do
    @moduledoc """
    Public key credential creation options sent to authenticator.
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
      :extensions,
      :hints
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
            extensions: map() | nil,
            hints: [String.t()] | nil
          }

    @doc """
    Converts creation options to JSON-serializable format for client.

    Encodes binary data as base64url strings and formats the options
    according to WebAuthn specification requirements.
    """
    @spec to_json(__MODULE__.t()) :: map()
    def to_json(%__MODULE__{} = options) do
      %{
        "rp" => %{
          "id" => options.rp.id,
          "name" => options.rp.name,
          "icon" => options.rp.icon
        },
        "user" => %{
          "id" => Base.url_encode64(options.user.id, padding: false),
          "name" => options.user.name,
          "displayName" => options.user.display_name
        },
        "challenge" => Base.url_encode64(options.challenge, padding: false),
        "pubKeyCredParams" =>
          Enum.map(options.pub_key_cred_params, fn param ->
            %{
              "type" => "public-key",
              "alg" => param.alg
            }
          end),
        "timeout" => options.timeout,
        "excludeCredentials" => options.exclude_credentials,
        "authenticatorSelection" => options.authenticator_selection,
        "attestation" => options.attestation,
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

    def to_json(%__MODULE__{} = selection) do
      %{
        "authenticatorAttachment" => selection.authenticator_attachment,
        "residentKey" => selection.resident_key,
        "requireResidentKey" => selection.require_resident_key,
        "userVerification" => selection.user_verification
      }
      |> remove_nil_values()
    end

    defp remove_nil_values(map) when is_map(map) do
      map
      |> Enum.reject(fn {_key, value} -> is_nil(value) end)
      |> Enum.into(%{})
    end
  end
end

defimpl Jason.Encoder, for: ExWebauthn.Attestation.CreationOptions do
  alias ExWebauthn.Attestation.CreationOptions

  def encode(value, opts) do
    Jason.Encode.map(
      CreationOptions.to_json(value),
      opts
    )
  end
end

defimpl Jason.Encoder, for: ExWebauthn.Attestation.AuthenticatorSelection do
  alias ExWebauthn.Attestation.AuthenticatorSelection

  def encode(value, opts) do
    Jason.Encode.map(
      AuthenticatorSelection.to_json(value),
      opts
    )
  end
end
