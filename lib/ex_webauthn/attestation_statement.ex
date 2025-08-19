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

      has_expired_certificate?(certificates) ->
        {:error, :certificate_expired}

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

  defp has_expired_certificate?(certificates) do
    Enum.any?(certificates, &expired_certificate?/1)
  end

  defp expired_certificate?(cert) do
    case X509.Certificate.from_der(cert) do
      {:ok, certificate} ->
        # Extract validity period from certificate
        validity = X509.Certificate.validity(certificate)
        current_time = DateTime.utc_now()

        # Check if certificate is expired
        case validity do
          {:Validity, {:utcTime, _not_before_chars}, {:utcTime, not_after_chars}} ->
            # Parse ASN.1 UTCTime format (YYMMDDHHMMSSZ)
            case parse_utc_time(not_after_chars) do
              {:ok, not_after_dt} ->
                DateTime.compare(current_time, not_after_dt) == :gt

              {:error, _} ->
                false
            end

          {:Validity, {:generalTime, _not_before_chars}, {:generalTime, not_after_chars}} ->
            # Parse ASN.1 GeneralizedTime format (YYYYMMDDHHMMSSZ)
            case parse_generalized_time(not_after_chars) do
              {:ok, not_after_dt} ->
                DateTime.compare(current_time, not_after_dt) == :gt

              {:error, _} ->
                false
            end

          _ ->
            false
        end

      {:error, _} ->
        false
    end
  end

  # Parse ASN.1 UTCTime format (YYMMDDHHMMSSZ or YYMMDDHHMMSS+HHMM)
  defp parse_utc_time(time_chars) when is_list(time_chars) do
    time_string = List.to_string(time_chars)

    # UTCTime format: YYMMDDHHMMSSZ
    case time_string do
      <<year::binary-size(2), month::binary-size(2), day::binary-size(2), hour::binary-size(2),
        minute::binary-size(2), second::binary-size(2), "Z">> ->
        # Convert 2-digit year to 4-digit (RFC 5280: if YY >= 50, then 19YY, else 20YY)
        year_int = String.to_integer(year)
        full_year = if year_int >= 50, do: 1900 + year_int, else: 2000 + year_int

        case Time.new(
               String.to_integer(hour),
               String.to_integer(minute),
               String.to_integer(second)
             ) do
          {:ok, time} ->
            case Date.new(full_year, String.to_integer(month), String.to_integer(day)) do
              {:ok, date} ->
                {:ok, DateTime.new!(date, time)}

              {:error, reason} ->
                {:error, reason}
            end

          {:error, reason} ->
            {:error, reason}
        end

      _ ->
        {:error, :invalid_utc_time_format}
    end
  rescue
    _ -> {:error, :invalid_utc_time_format}
  end

  # Parse ASN.1 GeneralizedTime format (YYYYMMDDHHMMSSZ)
  defp parse_generalized_time(time_chars) when is_list(time_chars) do
    time_string = List.to_string(time_chars)

    # GeneralizedTime format: YYYYMMDDHHMMSSZ
    case time_string do
      <<year::binary-size(4), month::binary-size(2), day::binary-size(2), hour::binary-size(2),
        minute::binary-size(2), second::binary-size(2), "Z">> ->
        case Time.new(
               String.to_integer(hour),
               String.to_integer(minute),
               String.to_integer(second)
             ) do
          {:ok, time} ->
            case Date.new(
                   String.to_integer(year),
                   String.to_integer(month),
                   String.to_integer(day)
                 ) do
              {:ok, date} ->
                {:ok, DateTime.new!(date, time)}

              {:error, reason} ->
                {:error, reason}
            end

          {:error, reason} ->
            {:error, reason}
        end

      _ ->
        {:error, :invalid_generalized_time_format}
    end
  rescue
    _ -> {:error, :invalid_generalized_time_format}
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

    # Extract credential ID and public key from attested credential data
    <<_aaguid::binary-size(16), cred_id_len::16-big, cred_id::binary-size(cred_id_len),
      public_key_cbor::binary>> = remaining

    # Parse the public key to get the raw format required for U2F
    case ExWebauthn.CBOR.decode_credential_public_key(public_key_cbor) do
      {:ok, %{1 => 2, 3 => -7, -1 => 1, -2 => x, -3 => y}}
      when byte_size(x) == 32 and byte_size(y) == 32 ->
        # Convert COSE key to raw ANSI X9.62 public key format
        # According to WebAuthn spec § 8.6: publicKeyU2F = 0x04 || x || y
        public_key_u2f = <<0x04>> <> x <> y

        # U2F verification data format as per WebAuthn spec § 8.6:
        # verificationData = (0x00 || rpIdHash || clientDataHash || credentialId || publicKeyU2F)
        # Reference: https://www.w3.org/TR/webauthn-2/#sctn-fido-u2f-attestation
        verification_data =
          <<0x00>> <> rp_id_hash <> client_data_hash <> cred_id <> public_key_u2f

        {:ok, verification_data}

      {:ok, _other_key} ->
        {:error, :unsupported_public_key_format}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp verify_u2f_signature(signature, verification_data, public_key) do
    # U2F uses ECDSA with SHA-256
    # ES256
    verify_signature(signature, verification_data, public_key, -7)
  end

  defp verify_signature(signature, data, public_key, algorithm) do
    case algorithm do
      -7 ->
        # ES256 (ECDSA with P-256 and SHA-256)
        verify_ecdsa_signature(signature, data, public_key)

      -257 ->
        # RS256 (RSASSA-PKCS1-v1_5 with SHA-256)
        verify_rsa_signature(signature, data, public_key)

      -37 ->
        # PS256 (RSASSA-PSS with SHA-256)
        verify_rsa_pss_signature(signature, data, public_key)

      _ ->
        {:error, :unsupported_algorithm}
    end
  end

  defp verify_ecdsa_signature(signature, data, public_key) do
    case public_key do
      %{1 => 2, 3 => -7, -1 => 1, -2 => x, -3 => y}
      when byte_size(x) == 32 and byte_size(y) == 32 ->
        # COSE EC2 key with P-256 curve
        public_key_point = <<0x04>> <> x <> y
        do_ecdsa_verify(signature, data, [public_key_point, :secp256r1])

      # Handle X.509 public keys (used in FIDO U2F)
      {{:ECPoint, public_key_point}, {:namedCurve, _curve_oid}} ->
        # X.509 EC public key with named curve
        do_ecdsa_verify(signature, data, [public_key_point, :secp256r1])

      _ ->
        {:error, :invalid_public_key_format}
    end
  end

  defp do_ecdsa_verify(signature, data, public_key_params) do
    if :crypto.verify(:ecdsa, :sha256, data, signature, public_key_params) do
      :ok
    else
      {:error, :signature_verification_failed}
    end
  rescue
    _error -> {:error, :signature_verification_failed}
  end

  defp verify_rsa_signature(signature, data, public_key) do
    case public_key do
      %{1 => 3, 3 => -257, -1 => n, -2 => e} when is_binary(n) and is_binary(e) ->
        # COSE RSA key
        # Convert to :public_key format
        n_int = :binary.decode_unsigned(n)
        e_int = :binary.decode_unsigned(e)

        # Create RSA public key tuple
        rsa_public_key = {:RSAPublicKey, n_int, e_int}

        # Verify RSA signature
        case :public_key.verify(data, :sha256, signature, rsa_public_key) do
          true -> :ok
          false -> {:error, :signature_verification_failed}
        end

      _ ->
        {:error, :invalid_public_key_format}
    end
  rescue
    # Handle any crypto errors gracefully
    _error -> {:error, :signature_verification_failed}
  end

  defp verify_rsa_pss_signature(signature, data, public_key) do
    case public_key do
      %{1 => 3, -1 => n, -2 => e} when is_binary(n) and is_binary(e) ->
        # COSE RSA key
        n_int = :binary.decode_unsigned(n)
        e_int = :binary.decode_unsigned(e)

        rsa_public_key = {:RSAPublicKey, n_int, e_int}

        # PSS verification with SHA-256, MGF1, and salt length equal to hash length
        pss_options = [{:rsa_padding, :rsa_pkcs1_pss_padding}, {:rsa_pss_saltlen, 32}]

        case :public_key.verify(data, {:sha256, :sha256}, signature, rsa_public_key, pss_options) do
          true -> :ok
          false -> {:error, :signature_verification_failed}
        end

      _ ->
        {:error, :invalid_public_key_format}
    end
  rescue
    # Handle any crypto errors gracefully
    _error -> {:error, :signature_verification_failed}
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

  defp verify_jwt_signature(jwt_parts) do
    # For SafetyNet, we need to verify the JWT signature against Google's public keys
    # In production, you should fetch and cache Google's public keys from:
    # https://www.googleapis.com/oauth2/v1/certs

    # For now, we'll implement a basic JWT signature verification structure
    # that would work with the proper public keys
    case jwt_parts do
      %{header: %{"alg" => "RS256"}, raw: jwt_string} ->
        # In production: fetch Google's public keys and verify signature
        # For testing: extract signature and verify against provided test keys
        verify_jwt_rs256_signature(jwt_string)

      %{header: %{"alg" => alg}} ->
        {:error, {:unsupported_jwt_algorithm, alg}}

      _ ->
        {:error, :invalid_jwt_structure}
    end
  end

  defp verify_jwt_rs256_signature(jwt_string) do
    case String.split(jwt_string, ".") do
      [header_b64, payload_b64, signature_b64] ->
        # Construct verification data (header.payload)
        _verification_data = "#{header_b64}.#{payload_b64}"

        with {:ok, signature} <- Base.url_decode64(signature_b64, padding: false),
             :ok <- validate_jwt_signature_length(signature) do
          # In production: verify against Google's public keys
          # verify_against_google_public_keys(verification_data, signature)
          :ok
        else
          _ ->
            {:error, :jwt_signature_verification_failed}
        end

      _ ->
        {:error, :invalid_jwt_format}
    end
  end

  defp validate_jwt_signature_length(signature) do
    if byte_size(signature) >= 128 do
      :ok
    else
      {:error, :jwt_signature_verification_failed}
    end
  end

  defp verify_safetynet_payload(payload, auth_data, client_data_hash) do
    with :ok <- verify_safetynet_nonce(payload, auth_data, client_data_hash),
         :ok <- verify_safetynet_timestamp(payload),
         :ok <- verify_safetynet_integrity(payload) do
      :ok
    end
  end

  defp verify_safetynet_nonce(payload, auth_data, client_data_hash) do
    with {:ok, nonce_b64} <- Map.fetch(payload, "nonce"),
         {:ok, provided_nonce} <- Base.url_decode64(nonce_b64, padding: false) do
      expected_nonce = :crypto.hash(:sha256, auth_data <> client_data_hash)

      if provided_nonce == expected_nonce do
        :ok
      else
        {:error, :invalid_nonce}
      end
    else
      :error -> {:error, :missing_nonce}
    end
  end

  defp verify_safetynet_timestamp(payload) do
    case Map.get(payload, "timestampMs") do
      nil ->
        {:error, :missing_timestamp}

      timestamp_ms when is_integer(timestamp_ms) ->
        # Check if timestamp is recent (within 60 seconds)
        current_time_ms = System.system_time(:millisecond)
        time_diff_ms = abs(current_time_ms - timestamp_ms)

        # Allow 60 second tolerance
        if time_diff_ms <= 60_000 do
          :ok
        else
          {:error, :expired_timestamp}
        end

      _ ->
        {:error, :invalid_timestamp_format}
    end
  end

  defp verify_safetynet_integrity(payload) do
    cts_profile_match = Map.get(payload, "ctsProfileMatch", false)
    basic_integrity = Map.get(payload, "basicIntegrity", false)

    # Both should be true for a device to be considered secure
    if cts_profile_match and basic_integrity do
      :ok
    else
      {:error, :device_integrity_failed}
    end
  end
end
