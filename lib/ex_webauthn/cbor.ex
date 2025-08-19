defmodule ExWebauthn.CBOR do
  @moduledoc """
  CBOR encoding and decoding utilities for WebAuthn objects.

  This module provides functions to encode and decode CBOR data structures
  used in WebAuthn operations, particularly for attestation objects and
  credential public keys.
  """

  @doc """
  Decodes a CBOR-encoded attestation object.

  ## Examples

      iex> ExWebauthn.CBOR.decode_attestation_object(cbor_data)
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

  ## Examples

      iex> ExWebauthn.CBOR.decode_credential_public_key(cbor_data)
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
    case CBOR.decode(cbor_data) do
      {:ok, decoded, _remaining} -> {:ok, decoded}
      {:error, reason} -> {:error, reason}
    end
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

      iex> ExWebauthn.CBOR.validate_attestation_object(%{"fmt" => "packed", "authData" => <<...>>})
      :ok
      
      iex> ExWebauthn.CBOR.validate_attestation_object(%{"invalid" => "data"})
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
end
