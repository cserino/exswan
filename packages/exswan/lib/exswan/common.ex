defmodule ExSwan.Common do
  @moduledoc """
  Common WebAuthn functionality shared between registration and authentication flows.

  This module contains functions that are used by both registration and authentication
  ceremonies, including client data parsing, authenticator data parsing, and common
  verification functions.
  """

  import Bitwise

  alias ExSwan.Attestation

  @doc """
  Parses and verifies client data JSON from base64 encoding.

  Decodes the base64 client data, parses the JSON, and validates the structure.
  This is used by both registration and authentication flows.

  ## Parameters

  - `client_data_base64` - Base64url encoded client data JSON
  - `expected_type` - Expected client data type ("webauthn.create" or "webauthn.get")

  ## Returns

  - `{:ok, {client_data, client_data_json}}` - Successfully parsed client data
  - `{:error, reason}` - Parsing or validation failure
  """
  @spec parse_client_data(String.t(), String.t()) ::
          {:ok, {map(), String.t()}} | {:error, atom()}
  def parse_client_data(client_data_base64, expected_type) when is_binary(client_data_base64) do
    with {:ok, client_data_json} <- Base.url_decode64(client_data_base64, padding: false),
         {:ok, client_data} <- Jason.decode(client_data_json),
         :ok <- verify_client_data_type(client_data["type"], expected_type) do
      {:ok, {client_data, client_data_json}}
    else
      :error -> {:error, :invalid_client_data_encoding}
      {:error, %Jason.DecodeError{}} -> {:error, :invalid_client_data_json}
      error -> error
    end
  end

  @doc """
  Verifies client data challenge against expected challenge.

  Supports both binary challenges and custom challenge verification functions
  for compatibility with SimpleWebAuthn patterns.

  ## Parameters

  - `received_challenge` - Challenge from client data (base64url encoded)
  - `expected_challenge` - Expected challenge (binary or verification function)

  ## Returns

  - `:ok` - Challenge verification successful
  - `{:error, reason}` - Challenge verification failed
  """
  @spec verify_challenge(String.t(), binary() | function()) :: :ok | {:error, atom()}
  def verify_challenge(received_challenge, expected_challenge)
      when is_binary(received_challenge) and is_function(expected_challenge) do
    case Base.url_decode64(received_challenge, padding: false) do
      {:ok, decoded_challenge} ->
        case expected_challenge.(decoded_challenge) do
          true -> :ok
          false -> {:error, {:custom_challenge_verification_failed, received_challenge}}
          {:ok, true} -> :ok
          {:ok, false} -> {:error, {:custom_challenge_verification_failed, received_challenge}}
          {:error, reason} -> {:error, reason}
        end

      _ ->
        {:error, :invalid_challenge_encoding}
    end
  end

  def verify_challenge(received_challenge, expected_challenge)
      when is_binary(received_challenge) and is_binary(expected_challenge) do
    case Base.url_decode64(received_challenge, padding: false) do
      {:ok, decoded_challenge} ->
        if decoded_challenge == expected_challenge do
          :ok
        else
          {:error, :challenge_mismatch}
        end

      _ ->
        {:error, :invalid_challenge_encoding}
    end
  end

  @doc """
  Verifies client data origin against expected origin(s).

  ## Parameters

  - `received_origin` - Origin from client data
  - `expected_origins` - Expected origin(s) (string or list of strings)

  ## Returns

  - `:ok` - Origin verification successful
  - `{:error, :origin_mismatch}` - Origin verification failed
  """
  @spec verify_origin(String.t(), String.t() | [String.t()]) :: :ok | {:error, :origin_mismatch}
  def verify_origin(received_origin, expected_origins) when is_list(expected_origins) do
    if received_origin in expected_origins do
      :ok
    else
      {:error, :origin_mismatch}
    end
  end

  def verify_origin(received_origin, expected_origin) when is_binary(expected_origin) do
    if received_origin == expected_origin do
      :ok
    else
      {:error, :origin_mismatch}
    end
  end

  @doc """
  Parses authenticator data from binary format.

  Extracts RP ID hash, flags, signature counter, and other fields from the
  binary authenticator data according to the WebAuthn specification.

  ## Parameters

  - `auth_data_bytes` - Binary authenticator data

  ## Returns

  - `{:ok, authenticator_data}` - Successfully parsed authenticator data
  - `{:error, reason}` - Parsing failure
  """
  @spec parse_authenticator_data(binary()) ::
          {:ok, Attestation.AuthenticatorData.t()} | {:error, atom()}
  def parse_authenticator_data(auth_data_bytes) when is_binary(auth_data_bytes) do
    if byte_size(auth_data_bytes) < 37 do
      {:error, :invalid_authenticator_data_length}
    else
      <<
        rp_id_hash::binary-size(32),
        flags::8,
        sign_count::32-big,
        _remaining::binary
      >> = auth_data_bytes

      # Reference: vendor/SimpleWebAuthn/packages/server/src/helpers/parseAuthenticatorData.ts:28-38
      # Bit positions can be referenced here: https://www.w3.org/TR/webauthn-2/#flags
      # UP (bit 0) - User Presence
      user_present = (flags &&& 0x01) != 0
      # UV (bit 2) - User Verified
      user_verified = (flags &&& 0x04) != 0
      # BE (bit 3) - Backup Eligibility
      backup_eligible = (flags &&& 0x08) != 0
      # BS (bit 4) - Backup State
      backup_state = (flags &&& 0x10) != 0
      # ED (bit 7) - Extension Data Present
      extension_data_included = (flags &&& 0x80) != 0

      flags_struct = %Attestation.Flags{
        user_present: user_present,
        user_verified: user_verified,
        backup_eligible: backup_eligible,
        backup_state: backup_state,
        attested_credential_data_included: false,
        extension_data_included: extension_data_included
      }

      authenticator_data = %Attestation.AuthenticatorData{
        rp_id_hash: rp_id_hash,
        flags: flags_struct,
        sign_count: sign_count,
        attested_credential_data: nil,
        extensions: nil
      }

      {:ok, authenticator_data}
    end
  end

  @doc """
  Verifies RP ID hash against expected relying party ID.

  ## Parameters

  - `received_hash` - RP ID hash from authenticator data
  - `rp_id` - Expected relying party ID

  ## Returns

  - `:ok` - Hash verification successful
  - `{:error, :rp_id_hash_mismatch}` - Hash verification failed
  """
  @spec verify_rp_id_hash(binary(), String.t()) :: :ok | {:error, :rp_id_hash_mismatch}
  def verify_rp_id_hash(received_hash, rp_id) when is_binary(received_hash) do
    expected_hash = :crypto.hash(:sha256, rp_id)

    if received_hash == expected_hash do
      :ok
    else
      {:error, :rp_id_hash_mismatch}
    end
  end

  @doc """
  Verifies user presence flag in authenticator data.

  ## Parameters

  - `authenticator_data` - Parsed authenticator data

  ## Returns

  - `:ok` - User presence verified
  - `{:error, :user_not_present}` - User presence verification failed
  """
  @spec verify_user_presence(Attestation.AuthenticatorData.t()) ::
          :ok | {:error, :user_not_present}
  def verify_user_presence(%Attestation.AuthenticatorData{flags: flags}) do
    if flags.user_present do
      :ok
    else
      {:error, :user_not_present}
    end
  end

  @doc """
  Computes SHA256 hash of client data JSON.

  ## Parameters

  - `client_data_json` - Client data JSON string

  ## Returns

  - `{:ok, hash}` - Successfully computed hash
  """
  @spec compute_client_data_hash(String.t()) :: {:ok, binary()}
  def compute_client_data_hash(client_data_json) do
    hash = :crypto.hash(:sha256, client_data_json)
    {:ok, hash}
  end

  @doc """
  Removes nil values from a map recursively.

  ## Parameters

  - `map` - Map to clean

  ## Returns

  - Cleaned map with nil values removed
  """
  @spec remove_nil_values(map()) :: map()
  def remove_nil_values(map) when is_map(map) do
    map
    |> Enum.reject(fn {_key, value} -> is_nil(value) end)
    |> Enum.map(fn {key, value} ->
      if is_map(value) do
        {key, remove_nil_values(value)}
      else
        {key, value}
      end
    end)
    |> Enum.into(%{})
  end

  # Private functions

  defp verify_client_data_type("webauthn.create", "webauthn.create"), do: :ok
  defp verify_client_data_type("webauthn.get", "webauthn.get"), do: :ok
  defp verify_client_data_type(_received, _expected), do: {:error, :invalid_client_data_type}
end
