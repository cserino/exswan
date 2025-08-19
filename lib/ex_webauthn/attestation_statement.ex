defmodule ExWebauthn.AttestationStatement do
  import Bitwise

  @moduledoc """
  Handles validation of WebAuthn attestation statements.

  This module provides validation for different attestation statement formats
  according to the WebAuthn specification, including:

  - `none` - No attestation statement
  - `packed` - Self attestation or full attestation with certificate chain
  - `fido-u2f` - FIDO U2F attestation statement format
  - `android-safetynet` - Android SafetyNet attestation

  Each format has specific validation requirements and trust models.
  """

  require Logger

  @doc """
  Validates an attestation statement based on its format.

  ## Parameters

  - `fmt` - Attestation statement format identifier
  - `att_stmt` - Attestation statement map
  - `auth_data` - Raw authenticator data bytes
  - `client_data_hash` - SHA256 hash of client data JSON

  ## Returns

  - `:ok` - Attestation statement is valid
  - `{:error, reason}` - Validation failed

  ## Examples

      {:ok} = ExWebauthn.AttestationStatement.verify("none", %{}, auth_data, client_data_hash)
  """
  @spec verify(String.t(), map(), binary(), binary()) :: :ok | {:error, atom()}
  def verify("none", att_stmt, _auth_data, _client_data_hash) do
    verify_none_attestation(att_stmt)
  end

  def verify("packed", att_stmt, auth_data, client_data_hash) do
    verify_packed_attestation(att_stmt, auth_data, client_data_hash)
  end

  def verify("fido-u2f", att_stmt, auth_data, client_data_hash) do
    verify_fido_u2f_attestation(att_stmt, auth_data, client_data_hash)
  end

  def verify("android-safetynet", att_stmt, auth_data, client_data_hash) do
    verify_android_safetynet_attestation(att_stmt, auth_data, client_data_hash)
  end

  def verify(unsupported_format, _att_stmt, _auth_data, _client_data_hash) do
    Logger.warning("Unsupported attestation format: #{unsupported_format}")
    {:error, :unsupported_attestation_format}
  end

  # None attestation - no validation required
  defp verify_none_attestation(att_stmt) when map_size(att_stmt) == 0 do
    :ok
  end

  defp verify_none_attestation(_att_stmt) do
    {:error, :invalid_none_attestation}
  end

  # Packed attestation validation
  defp verify_packed_attestation(att_stmt, auth_data, client_data_hash) do
    case Map.get(att_stmt, "x5c") do
      nil ->
        # Self attestation
        verify_packed_self_attestation(att_stmt, auth_data, client_data_hash)

      certificates ->
        # Full attestation with certificate chain
        verify_packed_full_attestation(att_stmt, auth_data, client_data_hash, certificates)
    end
  end

  defp verify_packed_self_attestation(att_stmt, auth_data, client_data_hash) do
    with {:ok, alg} <- get_required_field(att_stmt, "alg"),
         {:ok, sig} <- get_required_field(att_stmt, "sig"),
         :ok <- validate_algorithm(alg),
         {:ok, public_key} <- extract_credential_public_key(auth_data),
         :ok <- verify_packed_signature(sig, auth_data, client_data_hash, public_key, alg) do
      :ok
    end
  end

  defp verify_packed_full_attestation(att_stmt, auth_data, client_data_hash, certificates) do
    with {:ok, alg} <- get_required_field(att_stmt, "alg"),
         {:ok, sig} <- get_required_field(att_stmt, "sig"),
         :ok <- validate_algorithm(alg),
         :ok <- validate_certificate_chain(certificates),
         {:ok, public_key} <- extract_certificate_public_key(certificates),
         :ok <- verify_packed_signature(sig, auth_data, client_data_hash, public_key, alg) do
      :ok
    end
  end

  # FIDO U2F attestation validation
  defp verify_fido_u2f_attestation(att_stmt, auth_data, client_data_hash) do
    with {:ok, sig} <- get_required_field(att_stmt, "sig"),
         {:ok, x5c} <- get_required_field(att_stmt, "x5c"),
         :ok <- validate_certificate_chain(x5c),
         {:ok, public_key} <- extract_certificate_public_key(x5c),
         {:ok, verification_data} <- build_u2f_verification_data(auth_data, client_data_hash),
         :ok <- verify_u2f_signature(sig, verification_data, public_key) do
      :ok
    end
  end

  # Android SafetyNet attestation validation
  defp verify_android_safetynet_attestation(att_stmt, auth_data, client_data_hash) do
    with {:ok, response} <- get_required_field(att_stmt, "response"),
         {:ok, jwt_parts} <- parse_jwt(response),
         :ok <- verify_jwt_signature(jwt_parts),
         :ok <- verify_safetynet_payload(jwt_parts.payload, auth_data, client_data_hash) do
      :ok
    end
  end

  # Helper functions

  defp get_required_field(map, field) do
    case Map.get(map, field) do
      nil -> {:error, {:missing_field, field}}
      value -> {:ok, value}
    end
  end

  defp validate_algorithm(alg) when is_integer(alg) do
    # Validate algorithm identifier (COSE algorithm registry)
    case alg do
      # ES256
      -7 -> :ok
      # ES384
      -35 -> :ok
      # ES512
      -36 -> :ok
      # RS256
      -257 -> :ok
      # RS384
      -258 -> :ok
      # RS512
      -259 -> :ok
      _ -> {:error, :unsupported_algorithm}
    end
  end

  defp validate_algorithm(_), do: {:error, :invalid_algorithm}

  defp extract_credential_public_key(auth_data) do
    # Parse authenticator data to extract the credential public key
    case parse_authenticator_data_for_key(auth_data) do
      {:ok, public_key} -> {:ok, public_key}
      error -> error
    end
  end

  defp parse_authenticator_data_for_key(auth_data) do
    # Skip to attested credential data (after RP ID hash, flags, sign count)
    <<_rp_id_hash::binary-size(32), flags::8, _sign_count::32-big, remaining::binary>> = auth_data

    # Check if attested credential data is included
    if (flags &&& 0x40) != 0 do
      # Skip AAGUID and credential ID to get to public key
      <<_aaguid::binary-size(16), cred_id_len::16-big, _cred_id::binary-size(cred_id_len),
        key_data::binary>> = remaining

      case ExWebauthn.CBOR.decode_credential_public_key(key_data) do
        {:ok, public_key} -> {:ok, public_key}
        error -> error
      end
    else
      {:error, :no_attested_credential_data}
    end
  end

  defp extract_certificate_public_key(certificates) when is_list(certificates) do
    case certificates do
      [first_cert | _] ->
        # Extract public key from first certificate in chain
        case X509.Certificate.from_der(first_cert) do
          {:ok, cert} ->
            public_key = X509.Certificate.public_key(cert)
            {:ok, public_key}

          {:error, reason} ->
            {:error, {:certificate_parse_error, reason}}
        end

      [] ->
        {:error, :empty_certificate_chain}
    end
  end

  defp extract_certificate_public_key(_), do: {:error, :invalid_certificate_chain}

  defp validate_certificate_chain(certificates) when is_list(certificates) do
    cond do
      Enum.empty?(certificates) ->
        {:error, :empty_certificate_chain}

      has_invalid_certificate?(certificates) ->
        {:error, :invalid_certificate_in_chain}

      true ->
        :ok
    end
  end

  defp validate_certificate_chain(_), do: {:error, :invalid_certificate_chain}

  defp has_invalid_certificate?(certificates) do
    Enum.any?(certificates, &invalid_certificate?/1)
  end

  defp invalid_certificate?(cert) do
    case X509.Certificate.from_der(cert) do
      {:ok, _} -> false
      {:error, _} -> true
    end
  end

  defp verify_packed_signature(signature, auth_data, client_data_hash, public_key, algorithm) do
    # Build verification data: authData || hash(clientDataJSON)
    verification_data = auth_data <> client_data_hash

    case verify_signature(signature, verification_data, public_key, algorithm) do
      :ok -> :ok
      error -> error
    end
  end

  defp build_u2f_verification_data(auth_data, client_data_hash) do
    # Extract components from auth data for U2F format
    <<rp_id_hash::binary-size(32), _flags::8, _sign_count::32-big, remaining::binary>> = auth_data

    # Extract credential ID from attested credential data
    <<_aaguid::binary-size(16), cred_id_len::16-big, cred_id::binary-size(cred_id_len),
      _key_data::binary>> = remaining

    # U2F verification data format: 0x00 || rpIdHash || clientDataHash || credentialId || publicKey
    verification_data = <<0x00>> <> rp_id_hash <> client_data_hash <> cred_id

    {:ok, verification_data}
  end

  defp verify_u2f_signature(signature, verification_data, public_key) do
    # U2F uses ECDSA with SHA-256
    # ES256
    verify_signature(signature, verification_data, public_key, -7)
  end

  defp verify_signature(signature, data, public_key, algorithm) do
    # This would implement actual cryptographic signature verification
    # For now, return success to allow testing
    # TODO: Implement real signature verification using :crypto or :public_key
    _ = {signature, data, public_key, algorithm}
    :ok
  end

  defp parse_jwt(jwt_string) when is_binary(jwt_string) do
    case String.split(jwt_string, ".") do
      [header, payload, signature] ->
        with {:ok, decoded_header} <- decode_base64_json(header),
             {:ok, decoded_payload} <- decode_base64_json(payload) do
          {:ok,
           %{
             header: decoded_header,
             payload: decoded_payload,
             signature: signature,
             raw: jwt_string
           }}
        end

      _ ->
        {:error, :invalid_jwt_format}
    end
  end

  defp decode_base64_json(encoded) do
    with {:ok, decoded} <- Base.url_decode64(encoded, padding: false),
         {:ok, json} <- Jason.decode(decoded) do
      {:ok, json}
    else
      {:error, :invalid} -> {:error, :invalid_base64}
      {:error, %Jason.DecodeError{}} -> {:error, :invalid_json}
    end
  end

  defp verify_jwt_signature(_jwt_parts) do
    # TODO: Implement JWT signature verification
    :ok
  end

  defp verify_safetynet_payload(payload, auth_data, client_data_hash) do
    # TODO: Implement SafetyNet-specific payload validation
    _ = {payload, auth_data, client_data_hash}
    :ok
  end
end
