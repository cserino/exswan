defmodule ExWebauthn.AttestationStatementTest do
  use ExUnit.Case
  alias ExWebauthn.AttestationStatement

  describe "verify/4" do
    test "accepts none attestation with empty statement" do
      att_stmt = %{}
      auth_data = create_test_auth_data()
      client_data_hash = :crypto.hash(:sha256, "test")

      assert AttestationStatement.verify("none", att_stmt, auth_data, client_data_hash) == :ok
    end

    test "rejects none attestation with non-empty statement" do
      att_stmt = %{"invalid" => "field"}
      auth_data = create_test_auth_data()
      client_data_hash = :crypto.hash(:sha256, "test")

      assert AttestationStatement.verify("none", att_stmt, auth_data, client_data_hash) ==
               {:error, :invalid_none_attestation}
    end

    test "handles packed self-attestation format" do
      {auth_data, private_key} = create_test_auth_data_with_key()
      client_data_hash = :crypto.hash(:sha256, "test")

      # Create verification data for signature
      verification_data = auth_data <> client_data_hash

      # Sign with the private key that corresponds to the public key in auth_data
      signature = :public_key.sign(verification_data, :sha256, private_key)

      att_stmt = %{
        "alg" => -7,
        "sig" => signature
      }

      assert AttestationStatement.verify("packed", att_stmt, auth_data, client_data_hash) == :ok
    end

    test "handles packed full attestation format" do
      auth_data = create_test_auth_data()
      client_data_hash = :crypto.hash(:sha256, "test")

      # Create verification data for signature
      verification_data = auth_data <> client_data_hash

      # Create certificate and sign with its private key
      {certificate, private_key} = create_test_certificate_with_key()
      signature = :public_key.sign(verification_data, :sha256, private_key)

      att_stmt = %{
        "alg" => -7,
        "sig" => signature,
        "x5c" => [certificate]
      }

      assert AttestationStatement.verify("packed", att_stmt, auth_data, client_data_hash) == :ok
    end

    test "rejects packed attestation with missing required fields" do
      att_stmt = %{
        "sig" => :crypto.strong_rand_bytes(64)
      }

      auth_data = create_test_auth_data()
      client_data_hash = :crypto.hash(:sha256, "test")

      assert AttestationStatement.verify("packed", att_stmt, auth_data, client_data_hash) ==
               {:error, {:missing_field, "alg"}}
    end

    test "rejects packed attestation with invalid algorithm" do
      att_stmt = %{
        "alg" => 999,
        "sig" => :crypto.strong_rand_bytes(64)
      }

      auth_data = create_test_auth_data()
      client_data_hash = :crypto.hash(:sha256, "test")

      assert AttestationStatement.verify("packed", att_stmt, auth_data, client_data_hash) ==
               {:error, :unsupported_algorithm}
    end

    test "handles fido-u2f attestation format" do
      auth_data = create_test_auth_data()
      client_data_hash = :crypto.hash(:sha256, "test")

      # Extract components for U2F verification data
      <<rp_id_hash::binary-size(32), _flags::8, _sign_count::32-big, remaining::binary>> =
        auth_data

      <<_aaguid::binary-size(16), cred_id_len::16-big, cred_id::binary-size(cred_id_len),
        key_data::binary>> = remaining

      # Parse the COSE public key to get the coordinates for U2F format
      {:ok, %{-2 => x, -3 => y}} = ExWebauthn.CBORUtils.decode_credential_public_key(key_data)
      # Convert to raw ANSI X9.62 public key format as per WebAuthn spec § 8.6
      public_key_u2f = <<0x04>> <> x <> y

      # Create U2F verification data format as per WebAuthn spec § 8.6:
      # verificationData = (0x00 || rpIdHash || clientDataHash || credentialId || publicKeyU2F)
      # Reference: https://www.w3.org/TR/webauthn-2/#sctn-fido-u2f-attestation
      verification_data = <<0x00>> <> rp_id_hash <> client_data_hash <> cred_id <> public_key_u2f

      # Create certificate and sign with its private key
      {certificate, private_key} = create_test_certificate_with_key()
      signature = :public_key.sign(verification_data, :sha256, private_key)

      att_stmt = %{
        "sig" => signature,
        "x5c" => [certificate]
      }

      assert AttestationStatement.verify("fido-u2f", att_stmt, auth_data, client_data_hash) == :ok
    end

    test "rejects fido-u2f attestation with missing certificate" do
      att_stmt = %{
        "sig" => :crypto.strong_rand_bytes(64)
      }

      auth_data = create_test_auth_data()
      client_data_hash = :crypto.hash(:sha256, "test")

      assert AttestationStatement.verify("fido-u2f", att_stmt, auth_data, client_data_hash) ==
               {:error, {:missing_field, "x5c"}}
    end

    test "handles android-safetynet attestation format" do
      auth_data = create_test_auth_data()
      client_data_hash = :crypto.hash(:sha256, "test")

      # Create proper SafetyNet JWT with correct nonce
      jwt_response = create_valid_safetynet_jwt(auth_data, client_data_hash)

      att_stmt = %{
        "response" => jwt_response
      }

      assert AttestationStatement.verify(
               "android-safetynet",
               att_stmt,
               auth_data,
               client_data_hash
             ) == :ok
    end

    @tag capture_log: true
    test "rejects unsupported attestation format" do
      att_stmt = %{}
      auth_data = create_test_auth_data()
      client_data_hash = :crypto.hash(:sha256, "test")

      assert AttestationStatement.verify("unknown-format", att_stmt, auth_data, client_data_hash) ==
               {:error, :unsupported_attestation_format}
    end
  end

  defp create_test_auth_data do
    rp_id_hash = :crypto.hash(:sha256, "example.com")
    flags = 0x41
    sign_count = 0
    aaguid = :crypto.strong_rand_bytes(16)
    cred_id = :crypto.strong_rand_bytes(16)
    cred_id_len = byte_size(cred_id)

    public_key = %{
      1 => 2,
      3 => -7,
      -1 => 1,
      -2 => :crypto.strong_rand_bytes(32),
      -3 => :crypto.strong_rand_bytes(32)
    }

    {:ok, encoded_key} = ExWebauthn.CBORUtils.encode_credential_public_key(public_key)

    rp_id_hash <>
      <<flags>> <>
      <<sign_count::32-big>> <>
      aaguid <>
      <<cred_id_len::16-big>> <>
      cred_id <>
      encoded_key
  end

  defp create_test_auth_data_with_key do
    # Generate a known EC private key for testing using X509
    private_key = X509.PrivateKey.new_ec(:secp256r1)
    public_key_point = X509.PublicKey.derive(private_key)

    # Extract x and y coordinates from the ECPoint
    {{:ECPoint, point_binary}, {:namedCurve, _curve_oid}} = public_key_point

    # Extract x and y coordinates from uncompressed point (0x04 + x + y)
    <<0x04, x::binary-size(32), y::binary-size(32)>> = point_binary

    rp_id_hash = :crypto.hash(:sha256, "example.com")
    flags = 0x41
    sign_count = 0
    aaguid = :crypto.strong_rand_bytes(16)
    cred_id = :crypto.strong_rand_bytes(16)
    cred_id_len = byte_size(cred_id)

    # Create COSE public key with the generated coordinates
    public_key = %{
      1 => 2,
      3 => -7,
      -1 => 1,
      -2 => x,
      -3 => y
    }

    {:ok, encoded_key} = ExWebauthn.CBORUtils.encode_credential_public_key(public_key)

    auth_data =
      rp_id_hash <>
        <<flags>> <>
        <<sign_count::32-big>> <>
        aaguid <>
        <<cred_id_len::16-big>> <>
        cred_id <>
        encoded_key

    {auth_data, private_key}
  end

  defp create_test_certificate_with_key do
    private_key = X509.PrivateKey.new_ec(:secp256r1)

    certificate =
      X509.Certificate.self_signed(
        private_key,
        "/CN=Test Certificate",
        template: :server
      )
      |> X509.Certificate.to_der()

    {certificate, private_key}
  end

  defp create_valid_safetynet_jwt(auth_data, client_data_hash) do
    header = %{"alg" => "RS256", "typ" => "JWT"}

    # Create correct nonce: SHA256(authData || clientDataHash)
    expected_nonce = :crypto.hash(:sha256, auth_data <> client_data_hash)
    nonce_b64 = Base.url_encode64(expected_nonce, padding: false)

    payload = %{
      "nonce" => nonce_b64,
      "timestampMs" => System.system_time(:millisecond),
      "apkPackageName" => "com.example.app",
      "ctsProfileMatch" => true,
      "basicIntegrity" => true
    }

    encoded_header = Base.url_encode64(Jason.encode!(header), padding: false)
    encoded_payload = Base.url_encode64(Jason.encode!(payload), padding: false)
    signature = Base.url_encode64(:crypto.strong_rand_bytes(256), padding: false)

    "#{encoded_header}.#{encoded_payload}.#{signature}"
  end
end
