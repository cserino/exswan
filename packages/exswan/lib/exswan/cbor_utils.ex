defmodule ExSwan.CBORUtils do
  @moduledoc """
  CBOR encoding and decoding utilities for WebAuthn objects.

  This module provides functions to encode and decode CBOR data structures
  used in WebAuthn operations, particularly for attestation objects and
  credential public keys.
  """

  @doc """
  Decodes a CBOR-encoded attestation object.

  ## Examples

      iex> ExSwan.CBORUtils.decode_attestation_object(cbor_data)
      {:ok, %{
        "fmt" => "packed",
        "authData" => <<...>>,
        "attStmt" => %{...}
      }}
  """
  @spec decode_attestation_object(binary()) :: {:ok, map()} | {:error, term()}
  def decode_attestation_object(cbor_data) do
    case CBOR.decode(cbor_data) do
      {:ok, decoded, _remaining} -> {:ok, decoded}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Decodes a base64url-encoded CBOR attestation object.

  This function is used when the attestation object comes from client as base64url.
  """
  @spec decode_attestation_object_from_base64(binary()) :: {:ok, map()} | {:error, term()}
  def decode_attestation_object_from_base64(base64_data) do
    with {:ok, cbor_decoded} <- Base.url_decode64(base64_data, padding: false),
         {:ok, decoded, _remaining} <- CBOR.decode(cbor_decoded) do
      {:ok, decoded}
    else
      :error -> {:error, :invalid_attestation_object}
      {:error, _reason} -> {:error, :invalid_attestation_object}
    end
  rescue
    _error -> {:error, :invalid_attestation_object}
  catch
    _kind, _reason -> {:error, :invalid_attestation_object}
  end

  @doc """
  Encodes an attestation object map to CBOR format.
  """
  @spec encode_attestation_object(map()) :: {:ok, binary()} | {:error, term()}
  def encode_attestation_object(attestation_map) do
    encoded = CBOR.encode(attestation_map)
    {:ok, encoded}
  rescue
    error -> {:error, error}
  end

  @doc """
  Decodes a CBOR-encoded credential public key.

  Returns a map containing the public key parameters according to
  RFC 8152 (CBOR Object Signing and Encryption).

  Includes workaround for Firefox 117 EdDSA CBOR encoding bug.

  ## Examples

      iex> ExSwan.CBORUtils.decode_credential_public_key(cbor_data)
      {:ok, %{
        1 => 2,    # kty (Key Type): EC2
        3 => -7,   # alg (Algorithm): ES256
        -1 => 1,   # crv (Curve): P-256
        -2 => x_coordinate,
        -3 => y_coordinate
      }}
  """
  @spec decode_credential_public_key(binary()) :: {:ok, map()} | {:error, term()}
  def decode_credential_public_key(cbor_data) do
    # First try to decode the original CBOR
    case CBOR.decode(cbor_data) do
      {:ok, decoded, _remaining} ->
        # Check if this needs Firefox string value fixing
        fixed_decoded = fix_firefox_cbor_keys(decoded)
        {:ok, fixed_decoded}

      {:error, _reason} ->
        # If that fails, try the Firefox 117 byte-level workaround
        cbor_data_fixed = apply_firefox_117_eddsa_workaround(cbor_data)

        case CBOR.decode(cbor_data_fixed) do
          {:ok, decoded, _remaining} ->
            fixed_decoded = fix_firefox_cbor_keys(decoded)
            {:ok, fixed_decoded}

          {:error, _reason} ->
            {:error, :cbor_function_clause_error}
        end
    end
  rescue
    _ -> {:error, :cbor_function_clause_error}
  end

  @doc """
  Encodes a credential public key map to CBOR format.
  """
  @spec encode_credential_public_key(map()) :: {:ok, binary()} | {:error, term()}
  def encode_credential_public_key(public_key_map) do
    encoded = CBOR.encode(public_key_map)
    {:ok, encoded}
  rescue
    error -> {:error, error}
  end

  @doc """
  Decodes CBOR-encoded authenticator data extensions.
  """
  @spec decode_extensions(binary()) :: {:ok, map()} | {:error, term()}
  def decode_extensions(cbor_data) do
    case CBOR.decode(cbor_data) do
      {:ok, decoded, _remaining} -> {:ok, decoded}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Encodes extensions map to CBOR format.
  """
  @spec encode_extensions(map()) :: {:ok, binary()} | {:error, term()}
  def encode_extensions(extensions_map) do
    encoded = CBOR.encode(extensions_map)
    {:ok, encoded}
  rescue
    error -> {:error, error}
  end

  @doc """
  Validates that a decoded CBOR map contains expected WebAuthn fields.

  ## Examples

      iex> ExSwan.CBORUtils.validate_attestation_object(%{"fmt" => "packed", "authData" => <<...>>})
      :ok

      iex> ExSwan.CBORUtils.validate_attestation_object(%{"invalid" => "data"})
      {:error, :missing_required_fields}
  """
  @spec validate_attestation_object(map()) :: :ok | {:error, atom()}
  def validate_attestation_object(decoded_map) do
    required_fields = ["fmt", "authData", "attStmt"]

    case Enum.all?(required_fields, &Map.has_key?(decoded_map, &1)) do
      true -> :ok
      false -> {:error, :missing_required_fields}
    end
  end

  @doc """
  Validates that a decoded public key contains expected COSE key fields.
  """
  @spec validate_public_key(map()) :: :ok | {:error, atom()}
  def validate_public_key(decoded_map) when is_map(decoded_map) do
    # Check for required COSE key parameters
    # 1 = kty (Key Type), 3 = alg (Algorithm)
    required_params = [1, 3]

    case Enum.all?(required_params, &Map.has_key?(decoded_map, &1)) do
      true -> :ok
      false -> {:error, :missing_required_key_params}
    end
  end

  def validate_public_key(_), do: {:error, :invalid_key_format}

  def untag_decoded_cbor_data(%CBOR.Tag{value: data}), do: data

  def untag_decoded_cbor_data(%{} = data),
    do: Map.new(data, fn {k, v} -> {k, untag_decoded_cbor_data(v)} end)

  def untag_decoded_cbor_data(data) when is_list(data),
    do: Enum.map(data, &untag_decoded_cbor_data/1)

  def untag_decoded_cbor_data(data), do: data

  # Helper to fix Firefox CBOR key issues
  defp fix_firefox_cbor_keys(decoded) when is_map(decoded) do
    decoded
    |> Enum.map(fn
      # Convert string to integer
      {1, "OKP"} -> {1, 1}
      # Keep algorithm as-is
      {3, val} -> {3, val}
      # Convert curve name to number
      {-1, "Ed25519"} -> {-1, 6}
      # Handle the specific Firefox 117 case
      {k, v} when k in [1, -1] and is_binary(v) -> {k, convert_firefox_value(v)}
      {k, v} -> {k, v}
    end)
    |> Enum.into(%{})
  end

  defp fix_firefox_cbor_keys(decoded), do: decoded

  # Convert Firefox string values to proper COSE values
  defp convert_firefox_value("OKP"), do: 1
  defp convert_firefox_value("EC2"), do: 2
  defp convert_firefox_value("RSA"), do: 3
  defp convert_firefox_value("Ed25519"), do: 6
  defp convert_firefox_value("P-256"), do: 1
  defp convert_firefox_value("P-384"), do: 2
  defp convert_firefox_value("P-521"), do: 3
  defp convert_firefox_value(v), do: v

  # Reference: vendor/SimpleWebAuthn/packages/server/src/helpers/parseAuthenticatorData.ts:57-95
  # Firefox 117 EdDSA CBOR encoding bug workaround
  defp apply_firefox_117_eddsa_workaround(cbor_data) do
    # Firefox 117 incorrectly CBOR-encodes authData when EdDSA (-8) is used for the public key.
    # A CBOR "Map of 3 items" (0xa3) should be "Map of 4 items" (0xa4), and if we manually adjust
    # the single byte there's a good chance the authData can be correctly parsed.

    # Bytes decode to `{ 1: "OKP", 3: -8, -1: "Ed25519" }` (it's missing key -2 a.k.a. COSEKEYS.x)
    bad_eddsa_cbor =
      <<0xA3, 0x01, 0x63, 0x4F, 0x4B, 0x50, 0x03, 0x27, 0x20, 0x67, 0x45, 0x64, 0x32, 0x35, 0x35,
        0x31, 0x39>>

    if byte_size(cbor_data) >= byte_size(bad_eddsa_cbor) and
         binary_part(cbor_data, 0, byte_size(bad_eddsa_cbor)) == bad_eddsa_cbor do
      # Change the bad CBOR 0xa3 to 0xa4 so that the credential public key can be recognized
      <<_first_byte, rest::binary>> = cbor_data
      # Return the fixed CBOR data, but note: this is temporary for parsing only
      # The original authData must be restored for signature verification
      <<0xA4, rest::binary>>
    else
      cbor_data
    end
  end
end
