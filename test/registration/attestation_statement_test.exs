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
      att_stmt = %{
        # ES256
        "alg" => -7,
        "sig" => :crypto.strong_rand_bytes(64)
      }

      auth_data = create_test_auth_data()
      client_data_hash = :crypto.hash(:sha256, "test")

      # Should return ok since we're not doing real signature verification yet
      assert AttestationStatement.verify("packed", att_stmt, auth_data, client_data_hash) == :ok
    end

    test "handles packed full attestation format" do
      att_stmt = %{
        # ES256
        "alg" => -7,
        "sig" => :crypto.strong_rand_bytes(64),
        "x5c" => [create_test_certificate()]
      }

      auth_data = create_test_auth_data()
      client_data_hash = :crypto.hash(:sha256, "test")

      # Should return ok since we're not doing real signature verification yet
      assert AttestationStatement.verify("packed", att_stmt, auth_data, client_data_hash) == :ok
    end

    test "rejects packed attestation with missing required fields" do
      att_stmt = %{
        "sig" => :crypto.strong_rand_bytes(64)
        # missing "alg" field
      }

      auth_data = create_test_auth_data()
      client_data_hash = :crypto.hash(:sha256, "test")

      assert AttestationStatement.verify("packed", att_stmt, auth_data, client_data_hash) ==
               {:error, {:missing_field, "alg"}}
    end

    test "rejects packed attestation with invalid algorithm" do
      att_stmt = %{
        # Invalid algorithm
        "alg" => 999,
        "sig" => :crypto.strong_rand_bytes(64)
      }

      auth_data = create_test_auth_data()
      client_data_hash = :crypto.hash(:sha256, "test")

      assert AttestationStatement.verify("packed", att_stmt, auth_data, client_data_hash) ==
               {:error, :unsupported_algorithm}
    end

    test "handles fido-u2f attestation format" do
      att_stmt = %{
        "sig" => :crypto.strong_rand_bytes(64),
        "x5c" => [create_test_certificate()]
      }

      auth_data = create_test_auth_data()
      client_data_hash = :crypto.hash(:sha256, "test")

      # Should return ok since we're not doing real signature verification yet
      assert AttestationStatement.verify("fido-u2f", att_stmt, auth_data, client_data_hash) == :ok
    end

    test "rejects fido-u2f attestation with missing certificate" do
      att_stmt = %{
        "sig" => :crypto.strong_rand_bytes(64)
        # missing "x5c" field
      }

      auth_data = create_test_auth_data()
      client_data_hash = :crypto.hash(:sha256, "test")

      assert AttestationStatement.verify("fido-u2f", att_stmt, auth_data, client_data_hash) ==
               {:error, {:missing_field, "x5c"}}
    end

    test "handles android-safetynet attestation format" do
      # Create a mock JWT response
      jwt_response = create_mock_jwt()

      att_stmt = %{
        "response" => jwt_response
      }

      auth_data = create_test_auth_data()
      client_data_hash = :crypto.hash(:sha256, "test")

      # Should return ok since we're not doing real JWT verification yet
      assert AttestationStatement.verify(
               "android-safetynet",
               att_stmt,
               auth_data,
               client_data_hash
             ) == :ok
    end

    test "rejects unsupported attestation format" do
      att_stmt = %{}
      auth_data = create_test_auth_data()
      client_data_hash = :crypto.hash(:sha256, "test")

      assert AttestationStatement.verify("unknown-format", att_stmt, auth_data, client_data_hash) ==
               {:error, :unsupported_attestation_format}
    end
  end

  # Helper functions

  defp create_test_auth_data do
    # Create minimal authenticator data with attested credential data
    rp_id_hash = :crypto.hash(:sha256, "example.com")
    # UP and AT flags set
    flags = 0x41
    sign_count = 0
    aaguid = :crypto.strong_rand_bytes(16)
    cred_id = :crypto.strong_rand_bytes(16)
    cred_id_len = byte_size(cred_id)

    # Minimal COSE public key (ES256)
    public_key = %{
      # kty: EC2
      1 => 2,
      # alg: ES256
      3 => -7,
      # crv: P-256
      -1 => 1,
      # x coordinate
      -2 => :crypto.strong_rand_bytes(32),
      # y coordinate
      -3 => :crypto.strong_rand_bytes(32)
    }

    {:ok, encoded_key} = ExWebauthn.CBOR.encode_credential_public_key(public_key)

    rp_id_hash <>
      <<flags>> <>
      <<sign_count::32-big>> <>
      aaguid <>
      <<cred_id_len::16-big>> <>
      cred_id <>
      encoded_key
  end

  defp create_test_certificate do
    # Create a minimal self-signed certificate for testing
    private_key = X509.PrivateKey.new_ec(:secp256r1)

    X509.Certificate.self_signed(
      private_key,
      "/CN=Test Certificate",
      template: :server
    )
    |> X509.Certificate.to_der()
  end

  defp create_mock_jwt do
    # Create a mock JWT for SafetyNet testing
    header = %{"alg" => "RS256", "typ" => "JWT"}

    payload = %{
      "nonce" => Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false),
      "timestampMs" => System.system_time(:millisecond),
      "apkPackageName" => "com.example.app"
    }

    encoded_header = Base.url_encode64(Jason.encode!(header), padding: false)
    encoded_payload = Base.url_encode64(Jason.encode!(payload), padding: false)
    signature = Base.url_encode64(:crypto.strong_rand_bytes(256), padding: false)

    "#{encoded_header}.#{encoded_payload}.#{signature}"
  end
end
