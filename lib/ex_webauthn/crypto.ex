defmodule ExWebauthn.Crypto do
  @moduledoc """
  Cryptographic utilities for WebAuthn operations.

  This module provides functions for signature verification, public key handling,
  and other cryptographic operations required by the WebAuthn specification.
  """

  @doc """
  Verifies a digital signature using the provided public key and data.

  ## Parameters

  - `signature` - The signature bytes to verify
  - `signed_data` - The data that was signed
  - `public_key_map` - COSE public key map from credential
  - `algorithm` - Signature algorithm identifier

  ## Returns

  - `:ok` if signature is valid
  - `{:error, reason}` if verification fails

  ## Examples

      public_key = %{1 => 2, 3 => -7, -1 => 1, -2 => x_coord, -3 => y_coord}
      {:ok} = ExWebauthn.Crypto.verify_signature(signature, data, public_key, -7)
  """
  @spec verify_signature(binary(), binary(), map(), integer()) :: :ok | {:error, atom()}
  def verify_signature(signature, signed_data, public_key_map, algorithm) do
    case extract_public_key(public_key_map, algorithm) do
      {:ok, public_key} ->
        verify_with_algorithm(signature, signed_data, public_key, algorithm)

      error ->
        error
    end
  end

  @doc """
  Extracts the public key from a COSE public key map.

  Converts COSE key parameters to Erlang's :public_key format.
  """
  @spec extract_public_key(map(), integer()) :: {:ok, term()} | {:error, atom()}
  def extract_public_key(public_key_map, algorithm) do
    case algorithm do
      # ES256 (ECDSA w/ SHA-256)
      -7 ->
        extract_ec_public_key(public_key_map, :secp256r1)

      # ES384 (ECDSA w/ SHA-384)
      -35 ->
        extract_ec_public_key(public_key_map, :secp384r1)

      # ES512 (ECDSA w/ SHA-512)
      -36 ->
        extract_ec_public_key(public_key_map, :secp521r1)

      # RS256 (RSA PKCS#1 v1.5 w/ SHA-256)
      -257 ->
        extract_rsa_public_key(public_key_map)

      # RS384 (RSA PKCS#1 v1.5 w/ SHA-384)
      -258 ->
        extract_rsa_public_key(public_key_map)

      # RS512 (RSA PKCS#1 v1.5 w/ SHA-512)
      -259 ->
        extract_rsa_public_key(public_key_map)

      _ ->
        {:error, :unsupported_algorithm}
    end
  end

  @doc """
  Computes the signed data for WebAuthn assertion verification.

  Concatenates authenticator data and client data hash as per WebAuthn spec.
  """
  @spec compute_signed_data(binary(), binary()) :: binary()
  def compute_signed_data(authenticator_data, client_data_hash) do
    authenticator_data <> client_data_hash
  end

  # Private functions

  defp extract_ec_public_key(public_key_map, curve) do
    with {:ok, x} <- get_coordinate(public_key_map, -2),
         {:ok, y} <- get_coordinate(public_key_map, -3) do
      # Create ECPoint in uncompressed format (0x04 || x || y)
      point = <<0x04>> <> x <> y

      # Create public key tuple for :public_key module
      public_key = {
        {:ECPoint, point},
        {:namedCurve, curve}
      }

      {:ok, public_key}
    else
      _ -> {:error, :invalid_ec_public_key}
    end
  end

  defp extract_rsa_public_key(public_key_map) do
    with {:ok, n} <- get_rsa_param(public_key_map, -1),
         {:ok, e} <- get_rsa_param(public_key_map, -2) do
      # Convert binary to integer
      n_int = :binary.decode_unsigned(n, :big)
      e_int = :binary.decode_unsigned(e, :big)

      # Create RSA public key tuple
      public_key = {:RSAPublicKey, n_int, e_int}

      {:ok, public_key}
    else
      _ -> {:error, :invalid_rsa_public_key}
    end
  end

  defp get_coordinate(key_map, param) do
    case Map.get(key_map, param) do
      coord when is_binary(coord) -> {:ok, coord}
      _ -> :error
    end
  end

  defp get_rsa_param(key_map, param) do
    case Map.get(key_map, param) do
      value when is_binary(value) -> {:ok, value}
      _ -> :error
    end
  end

  defp verify_with_algorithm(signature, signed_data, public_key, algorithm) do
    hash_algorithm = get_hash_algorithm(algorithm)

    try do
      case algorithm do
        alg when alg in [-7, -35, -36] ->
          # ECDSA algorithms
          verify_ecdsa(signature, signed_data, public_key, hash_algorithm)

        alg when alg in [-257, -258, -259] ->
          # RSA algorithms
          verify_rsa(signature, signed_data, public_key, hash_algorithm)

        _ ->
          {:error, :unsupported_signature_algorithm}
      end
    rescue
      _ -> {:error, :signature_verification_failed}
    end
  end

  defp verify_ecdsa(signature, signed_data, public_key, hash_algorithm) do
    # Hash the signed data
    hashed_data = :crypto.hash(hash_algorithm, signed_data)

    # Verify ECDSA signature
    case :public_key.verify(hashed_data, :ecdsa, signature, public_key) do
      true -> :ok
      false -> {:error, :invalid_signature}
    end
  end

  defp verify_rsa(signature, signed_data, public_key, hash_algorithm) do
    # Hash the signed data
    hashed_data = :crypto.hash(hash_algorithm, signed_data)

    # Verify RSA signature with PKCS#1 v1.5 padding
    case :public_key.verify(hashed_data, hash_algorithm, signature, public_key) do
      true -> :ok
      false -> {:error, :invalid_signature}
    end
  end

  # ES256
  defp get_hash_algorithm(-7), do: :sha256
  # ES384
  defp get_hash_algorithm(-35), do: :sha384
  # ES512
  defp get_hash_algorithm(-36), do: :sha512
  # RS256
  defp get_hash_algorithm(-257), do: :sha256
  # RS384
  defp get_hash_algorithm(-258), do: :sha384
  # RS512
  defp get_hash_algorithm(-259), do: :sha512
end
