defmodule ExSwan.AttestationStatement do
  import Bitwise

  @moduledoc """
  Handles validation of WebAuthn attestation statements.

  This module provides validation for different attestation statement formats
  according to the WebAuthn specification, including:

  - `none` - No attestation statement
  - `packed` - Self attestation or full attestation with certificate chain
  - `fido-u2f` - FIDO U2F attestation statement format

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

      {:ok} = ExSwan.AttestationStatement.verify("none", %{}, auth_data, client_data_hash)
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

      case ExSwan.CBORUtils.decode_credential_public_key(key_data) do
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
    with {:ok, certificate} <- parse_certificate(cert),
         {:ok, not_after} <- extract_expiry_date(certificate) do
      certificate_expired?(not_after)
    else
      _ -> false
    end
  end

  defp parse_certificate(cert) do
    X509.Certificate.from_der(cert)
  end

  defp extract_expiry_date(certificate) do
    validity = X509.Certificate.validity(certificate)

    case validity do
      {:Validity, _not_before, {:utcTime, not_after_chars}} ->
        parse_utc_time(not_after_chars)

      {:Validity, _not_before, {:generalTime, not_after_chars}} ->
        parse_generalized_time(not_after_chars)

      _ ->
        {:error, :invalid_validity_format}
    end
  end

  defp certificate_expired?(not_after_dt) do
    current_time = DateTime.utc_now()
    DateTime.compare(current_time, not_after_dt) == :gt
  end

  # Parse ASN.1 UTCTime format (YYMMDDHHMMSSZ or YYMMDDHHMMSS+HHMM)
  defp parse_utc_time(time_chars) when is_list(time_chars) do
    time_string = List.to_string(time_chars)

    with {:ok, components} <- extract_utc_time_components(time_string),
         {:ok, full_year} <- convert_two_digit_year(components.year),
         {:ok, time} <- build_time(components.hour, components.minute, components.second),
         {:ok, date} <- build_date(full_year, components.month, components.day) do
      {:ok, DateTime.new!(date, time)}
    else
      _ -> {:error, :invalid_utc_time_format}
    end
  rescue
    _ -> {:error, :invalid_utc_time_format}
  end

  defp extract_utc_time_components(time_string) do
    case time_string do
      <<year::binary-size(2), month::binary-size(2), day::binary-size(2), hour::binary-size(2),
        minute::binary-size(2), second::binary-size(2), "Z">> ->
        {:ok,
         %{
           year: String.to_integer(year),
           month: String.to_integer(month),
           day: String.to_integer(day),
           hour: String.to_integer(hour),
           minute: String.to_integer(minute),
           second: String.to_integer(second)
         }}

      _ ->
        {:error, :invalid_format}
    end
  end

  defp convert_two_digit_year(year_int) do
    # RFC 5280: if YY >= 50, then 19YY, else 20YY
    full_year = if year_int >= 50, do: 1900 + year_int, else: 2000 + year_int
    {:ok, full_year}
  end

  defp build_time(hour, minute, second) do
    Time.new(hour, minute, second)
  end

  defp build_date(year, month, day) do
    Date.new(year, month, day)
  end

  # Parse ASN.1 GeneralizedTime format (YYYYMMDDHHMMSSZ)
  defp parse_generalized_time(time_chars) when is_list(time_chars) do
    time_string = List.to_string(time_chars)

    with {:ok, components} <- extract_generalized_time_components(time_string),
         {:ok, time} <- build_time(components.hour, components.minute, components.second),
         {:ok, date} <- build_date(components.year, components.month, components.day) do
      {:ok, DateTime.new!(date, time)}
    else
      _ -> {:error, :invalid_generalized_time_format}
    end
  rescue
    _ -> {:error, :invalid_generalized_time_format}
  end

  defp extract_generalized_time_components(time_string) do
    case time_string do
      <<year::binary-size(4), month::binary-size(2), day::binary-size(2), hour::binary-size(2),
        minute::binary-size(2), second::binary-size(2), "Z">> ->
        {:ok,
         %{
           year: String.to_integer(year),
           month: String.to_integer(month),
           day: String.to_integer(day),
           hour: String.to_integer(hour),
           minute: String.to_integer(minute),
           second: String.to_integer(second)
         }}

      _ ->
        {:error, :invalid_format}
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

    # Extract credential ID and public key from attested credential data
    <<_aaguid::binary-size(16), cred_id_len::16-big, cred_id::binary-size(cred_id_len),
      public_key_cbor::binary>> = remaining

    # Parse the public key to get the raw format required for U2F
    case ExSwan.CBORUtils.decode_credential_public_key(public_key_cbor) do
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
end
