defmodule ExWebauthn.AttestationCryptoTest do
  use ExUnit.Case
  alias ExWebauthn.AttestationStatement
  alias X509.Certificate

  @moduledoc """
  Comprehensive cryptographic tests for attestation statement verification.
  These tests ensure the security-critical signature verification functions work correctly.
  """

  describe "ES256 (ECDSA with P-256 and SHA-256) signature verification" do
    setup do
      # Generate a real P-256 key pair for testing
      {public_key_bin, private_key_bin} = :crypto.generate_key(:ecdh, :secp256r1)

      # Create COSE public key format for ES256
      # The public key is in uncompressed format (0x04 || x || y)
      case public_key_bin do
        <<0x04, x::binary-size(32), y::binary-size(32)>> ->
          cose_public_key = %{
            # kty: EC2
            1 => 2,
            # alg: ES256
            3 => -7,
            # crv: P-256
            -1 => 1,
            # x coordinate
            -2 => x,
            # y coordinate
            -3 => y
          }

          {:ok,
           private_key: [private_key_bin, :secp256r1],
           public_key_bin: public_key_bin,
           cose_public_key: cose_public_key,
           x: x,
           y: y}

        _ ->
          # Handle compressed or other formats
          {:error, :invalid_public_key_format}
      end
    end

    test "verifies valid ES256 signature", %{private_key: private_key, cose_public_key: cose_key} do
      # Create test data
      auth_data = create_test_auth_data_with_key(cose_key)
      client_data_hash = :crypto.hash(:sha256, "test client data")

      # Create signature over correct data
      verification_data = auth_data <> client_data_hash
      signature = :crypto.sign(:ecdsa, :sha256, verification_data, private_key)

      # Create attestation statement
      att_stmt = %{
        # ES256
        "alg" => -7,
        "sig" => signature
      }

      # This should verify successfully once implemented
      assert AttestationStatement.verify("packed", att_stmt, auth_data, client_data_hash) == :ok
    end

    test "rejects ES256 signature with wrong data", %{
      private_key: private_key,
      cose_public_key: cose_key
    } do
      auth_data = create_test_auth_data_with_key(cose_key)
      client_data_hash = :crypto.hash(:sha256, "test client data")

      # Sign different data than what will be verified
      wrong_data = "wrong data"
      signature = :crypto.sign(:ecdsa, :sha256, wrong_data, private_key)

      att_stmt = %{
        "alg" => -7,
        "sig" => signature
      }

      # This should fail verification
      assert {:error, :signature_verification_failed} =
               AttestationStatement.verify("packed", att_stmt, auth_data, client_data_hash)
    end

    test "rejects ES256 signature with wrong key", %{cose_public_key: cose_key} do
      auth_data = create_test_auth_data_with_key(cose_key)
      client_data_hash = :crypto.hash(:sha256, "test client data")

      # Create signature with different key
      {_pub, priv} = :crypto.generate_key(:ecdh, :secp256r1)
      different_key = [priv, :secp256r1]
      verification_data = auth_data <> client_data_hash
      signature = :crypto.sign(:ecdsa, :sha256, verification_data, different_key)

      att_stmt = %{
        "alg" => -7,
        "sig" => signature
      }

      assert {:error, :signature_verification_failed} =
               AttestationStatement.verify("packed", att_stmt, auth_data, client_data_hash)
    end

    test "rejects malformed ES256 signature", %{cose_public_key: cose_key} do
      auth_data = create_test_auth_data_with_key(cose_key)
      client_data_hash = :crypto.hash(:sha256, "test client data")

      # Create invalid signature (wrong size)
      # Too short for ECDSA
      invalid_signature = :crypto.strong_rand_bytes(32)

      att_stmt = %{
        "alg" => -7,
        "sig" => invalid_signature
      }

      assert {:error, _} =
               AttestationStatement.verify("packed", att_stmt, auth_data, client_data_hash)
    end
  end

  describe "RS256 (RSA with SHA-256) signature verification" do
    setup do
      # Generate RSA key pair using :public_key directly for simpler testing
      rsa_private_key = :public_key.generate_key({:rsa, 2048, 65_537})

      # Extract public key components
      {:RSAPrivateKey, _, modulus, exponent, _, _, _, _, _, _, _} = rsa_private_key

      # Convert to binary format for COSE
      modulus_bin = :binary.encode_unsigned(modulus)
      exponent_bin = :binary.encode_unsigned(exponent)

      # Create COSE public key format for RS256
      cose_public_key = %{
        # kty: RSA
        1 => 3,
        # alg: RS256
        3 => -257,
        # n: modulus
        -1 => modulus_bin,
        # e: exponent
        -2 => exponent_bin
      }

      {:ok, private_key: rsa_private_key, cose_public_key: cose_public_key}
    end

    test "verifies valid RS256 signature", %{private_key: private_key, cose_public_key: cose_key} do
      auth_data = create_test_auth_data_with_key(cose_key)
      client_data_hash = :crypto.hash(:sha256, "test client data")

      verification_data = auth_data <> client_data_hash
      # Sign using :public_key directly
      signature = :public_key.sign(verification_data, :sha256, private_key)

      att_stmt = %{
        # RS256
        "alg" => -257,
        "sig" => signature
      }

      assert AttestationStatement.verify("packed", att_stmt, auth_data, client_data_hash) == :ok
    end

    test "rejects RS256 signature with wrong data", %{
      private_key: private_key,
      cose_public_key: cose_key
    } do
      auth_data = create_test_auth_data_with_key(cose_key)
      client_data_hash = :crypto.hash(:sha256, "test client data")

      wrong_data = "wrong data"
      # Sign using :public_key directly
      signature = :public_key.sign(wrong_data, :sha256, private_key)

      att_stmt = %{
        "alg" => -257,
        "sig" => signature
      }

      assert {:error, :signature_verification_failed} =
               AttestationStatement.verify("packed", att_stmt, auth_data, client_data_hash)
    end
  end

  describe "JWT signature verification for Android SafetyNet" do
    setup do
      # Create RSA key for JWT signing (Google uses RS256)
      rsa_key = JOSE.JWK.generate_key({:rsa, 2048})
      {:ok, rsa_key: rsa_key}
    end

    test "verifies valid SafetyNet JWT", %{rsa_key: rsa_key} do
      auth_data = create_test_auth_data()
      client_data_hash = :crypto.hash(:sha256, "test client data")

      # Create nonce from auth_data and client_data_hash (as per spec)
      nonce = :crypto.hash(:sha256, auth_data <> client_data_hash)
      nonce_b64 = Base.url_encode64(nonce, padding: false)

      # Create valid SafetyNet payload
      payload = %{
        "nonce" => nonce_b64,
        "timestampMs" => System.system_time(:millisecond),
        "apkPackageName" => "com.example.app",
        "apkCertificateDigestSha256" => [Base.encode64(:crypto.hash(:sha256, "test_cert"))],
        "ctsProfileMatch" => true,
        "basicIntegrity" => true
      }

      # Sign JWT with our test key using RS256
      jws = %{"alg" => "RS256"}
      {_, jwt} = JOSE.JWT.sign(rsa_key, jws, payload) |> JOSE.JWS.compact()

      att_stmt = %{
        "response" => jwt,
        # SafetyNet version
        "ver" => "15701436"
      }

      # Note: In real implementation, we'd need to verify against Google's public keys
      # For testing, we'll need to mock or inject the public key
      assert AttestationStatement.verify(
               "android-safetynet",
               att_stmt,
               auth_data,
               client_data_hash
             ) == :ok
    end

    test "rejects SafetyNet JWT with wrong nonce", %{rsa_key: rsa_key} do
      auth_data = create_test_auth_data()
      client_data_hash = :crypto.hash(:sha256, "test client data")

      # Use wrong nonce
      wrong_nonce = :crypto.hash(:sha256, "wrong data")
      nonce_b64 = Base.url_encode64(wrong_nonce, padding: false)

      payload = %{
        "nonce" => nonce_b64,
        "timestampMs" => System.system_time(:millisecond),
        "apkPackageName" => "com.example.app",
        "ctsProfileMatch" => true,
        "basicIntegrity" => true
      }

      jws = %{"alg" => "RS256"}
      {_, jwt} = JOSE.JWT.sign(rsa_key, jws, payload) |> JOSE.JWS.compact()

      att_stmt = %{
        "response" => jwt
      }

      assert {:error, :invalid_nonce} =
               AttestationStatement.verify(
                 "android-safetynet",
                 att_stmt,
                 auth_data,
                 client_data_hash
               )
    end

    test "rejects SafetyNet JWT with expired timestamp", %{rsa_key: rsa_key} do
      auth_data = create_test_auth_data()
      client_data_hash = :crypto.hash(:sha256, "test client data")

      nonce = :crypto.hash(:sha256, auth_data <> client_data_hash)
      nonce_b64 = Base.url_encode64(nonce, padding: false)

      # Use old timestamp (more than 1 minute ago)
      old_timestamp = System.system_time(:millisecond) - 120_000

      payload = %{
        "nonce" => nonce_b64,
        "timestampMs" => old_timestamp,
        "apkPackageName" => "com.example.app",
        "ctsProfileMatch" => true,
        "basicIntegrity" => true
      }

      jws = %{"alg" => "RS256"}
      {_, jwt} = JOSE.JWT.sign(rsa_key, jws, payload) |> JOSE.JWS.compact()

      att_stmt = %{
        "response" => jwt
      }

      assert {:error, :expired_timestamp} =
               AttestationStatement.verify(
                 "android-safetynet",
                 att_stmt,
                 auth_data,
                 client_data_hash
               )
    end

    test "rejects SafetyNet JWT when device integrity check fails", %{rsa_key: rsa_key} do
      auth_data = create_test_auth_data()
      client_data_hash = :crypto.hash(:sha256, "test client data")

      nonce = :crypto.hash(:sha256, auth_data <> client_data_hash)
      nonce_b64 = Base.url_encode64(nonce, padding: false)

      payload = %{
        "nonce" => nonce_b64,
        "timestampMs" => System.system_time(:millisecond),
        "apkPackageName" => "com.example.app",
        # Device fails CTS
        "ctsProfileMatch" => false,
        # Device is compromised
        "basicIntegrity" => false
      }

      jws = %{"alg" => "RS256"}
      {_, jwt} = JOSE.JWT.sign(rsa_key, jws, payload) |> JOSE.JWS.compact()

      att_stmt = %{
        "response" => jwt
      }

      assert {:error, :device_integrity_failed} =
               AttestationStatement.verify(
                 "android-safetynet",
                 att_stmt,
                 auth_data,
                 client_data_hash
               )
    end

    test "rejects malformed JWT", %{} do
      auth_data = create_test_auth_data()
      client_data_hash = :crypto.hash(:sha256, "test client data")

      att_stmt = %{
        "response" => "not.a.valid.jwt"
      }

      assert {:error, :invalid_jwt_format} =
               AttestationStatement.verify(
                 "android-safetynet",
                 att_stmt,
                 auth_data,
                 client_data_hash
               )
    end

    test "rejects JWT with invalid signature", %{rsa_key: rsa_key} do
      auth_data = create_test_auth_data()
      client_data_hash = :crypto.hash(:sha256, "test client data")

      nonce = :crypto.hash(:sha256, auth_data <> client_data_hash)
      nonce_b64 = Base.url_encode64(nonce, padding: false)

      payload = %{
        "nonce" => nonce_b64,
        "timestampMs" => System.system_time(:millisecond),
        "apkPackageName" => "com.example.app",
        "ctsProfileMatch" => true,
        "basicIntegrity" => true
      }

      jws = %{"alg" => "RS256"}
      {_, jwt} = JOSE.JWT.sign(rsa_key, jws, payload) |> JOSE.JWS.compact()

      # Corrupt the signature part of JWT
      [header, payload_part, _signature] = String.split(jwt, ".")
      corrupted_jwt = "#{header}.#{payload_part}.corrupted_signature"

      att_stmt = %{
        "response" => corrupted_jwt
      }

      assert {:error, :jwt_signature_verification_failed} =
               AttestationStatement.verify(
                 "android-safetynet",
                 att_stmt,
                 auth_data,
                 client_data_hash
               )
    end
  end

  describe "FIDO U2F signature verification" do
    setup do
      # Generate EC key for U2F (uses P-256)
      {public_key_bin, _private_key_bin} = :crypto.generate_key(:ecdh, :secp256r1)

      # Create a test certificate with the public key
      cert_private_key = X509.PrivateKey.new_ec(:secp256r1)

      certificate =
        X509.Certificate.self_signed(
          cert_private_key,
          "/CN=U2F Test Certificate",
          template: :server,
          extensions: [
            subject_alt_name: Certificate.Extension.subject_alt_name(["test.example.com"])
          ]
        )

      cert_der = X509.Certificate.to_der(certificate)

      {:ok,
       private_key: cert_private_key, certificate_der: cert_der, public_key_bin: public_key_bin}
    end

    test "verifies valid FIDO U2F signature", %{
      private_key: private_key,
      certificate_der: cert_der
    } do
      auth_data = create_test_auth_data()
      client_data_hash = :crypto.hash(:sha256, "test client data")

      # Extract public key and credential ID from auth_data for U2F
      # U2F signature is over different data than packed
      rp_id_hash = binary_part(auth_data, 0, 32)

      # For U2F, the signature is over:
      # 0x00 || rpIdHash || clientDataHash || credentialId || publicKeyU2F
      # We need to extract credentialId and publicKey from auth_data

      # Skip RP ID hash (32), flags (1), counter (4), AAGUID (16)
      <<_::binary-size(53), cred_id_len::16-big, rest::binary>> = auth_data
      <<cred_id::binary-size(cred_id_len), public_key_cbor::binary>> = rest

      # Parse the COSE public key to get the coordinates for U2F format
      {:ok, %{-2 => x, -3 => y}} = ExWebauthn.CBOR.decode_credential_public_key(public_key_cbor)
      # Convert to raw ANSI X9.62 public key format as per WebAuthn spec § 8.6
      public_key_u2f = <<0x04>> <> x <> y

      # Construct U2F verification data as per WebAuthn spec § 8.6
      verification_data = <<0x00>> <> rp_id_hash <> client_data_hash <> cred_id <> public_key_u2f

      # Use :public_key.sign for signing with X509 private key
      signature = :public_key.sign(verification_data, :sha256, private_key)

      att_stmt = %{
        "sig" => signature,
        "x5c" => [cert_der]
      }

      assert AttestationStatement.verify("fido-u2f", att_stmt, auth_data, client_data_hash) == :ok
    end

    test "rejects FIDO U2F signature with wrong data", %{
      private_key: private_key,
      certificate_der: cert_der
    } do
      auth_data = create_test_auth_data()
      client_data_hash = :crypto.hash(:sha256, "test client data")

      # Sign wrong data
      wrong_data = "wrong verification data"
      signature = :public_key.sign(wrong_data, :sha256, private_key)

      att_stmt = %{
        "sig" => signature,
        "x5c" => [cert_der]
      }

      assert {:error, :signature_verification_failed} =
               AttestationStatement.verify("fido-u2f", att_stmt, auth_data, client_data_hash)
    end
  end

  describe "Certificate chain validation" do
    test "validates proper certificate chain" do
      # Create a certificate chain: root -> intermediate -> leaf
      root_key = X509.PrivateKey.new_ec(:secp256r1)

      root_cert =
        X509.Certificate.self_signed(
          root_key,
          "/CN=Test Root CA",
          template: :root_ca
        )

      intermediate_key = X509.PrivateKey.new_ec(:secp256r1)

      intermediate_cert =
        X509.Certificate.new(
          X509.PublicKey.derive(intermediate_key),
          "/CN=Test Intermediate CA",
          root_cert,
          root_key,
          template: :ca
        )

      leaf_key = X509.PrivateKey.new_ec(:secp256r1)

      leaf_cert =
        X509.Certificate.new(
          X509.PublicKey.derive(leaf_key),
          "/CN=Test Attestation Certificate",
          intermediate_cert,
          intermediate_key,
          template: :server
        )

      # Certificate chain should be leaf -> intermediate -> root
      cert_chain = [
        X509.Certificate.to_der(leaf_cert),
        X509.Certificate.to_der(intermediate_cert),
        X509.Certificate.to_der(root_cert)
      ]

      auth_data = create_test_auth_data()
      client_data_hash = :crypto.hash(:sha256, "test client data")

      # Sign with leaf certificate's private key
      verification_data = auth_data <> client_data_hash
      signature = :public_key.sign(verification_data, :sha256, leaf_key)

      att_stmt = %{
        # ES256
        "alg" => -7,
        "sig" => signature,
        "x5c" => cert_chain
      }

      assert AttestationStatement.verify("packed", att_stmt, auth_data, client_data_hash) == :ok
    end

    test "rejects expired certificate" do
      # Create an expired certificate
      private_key = X509.PrivateKey.new_ec(:secp256r1)

      # Create certificate that expired yesterday
      # Use -1 to create an expired certificate (expired 1 day ago)
      expired_cert =
        X509.Certificate.self_signed(
          private_key,
          "/CN=Expired Certificate",
          template: :server,
          validity: -1
        )

      cert_der = X509.Certificate.to_der(expired_cert)

      auth_data = create_test_auth_data()
      client_data_hash = :crypto.hash(:sha256, "test client data")
      verification_data = auth_data <> client_data_hash
      signature = :public_key.sign(verification_data, :sha256, private_key)

      att_stmt = %{
        "alg" => -7,
        "sig" => signature,
        "x5c" => [cert_der]
      }

      assert {:error, :certificate_expired} =
               AttestationStatement.verify("packed", att_stmt, auth_data, client_data_hash)
    end
  end

  describe "Edge cases and security boundaries" do
    test "handles empty signature gracefully" do
      auth_data = create_test_auth_data()
      client_data_hash = :crypto.hash(:sha256, "test client data")

      att_stmt = %{
        "alg" => -7,
        # Empty signature
        "sig" => <<>>
      }

      assert {:error, _} =
               AttestationStatement.verify("packed", att_stmt, auth_data, client_data_hash)
    end

    test "handles very large signatures gracefully" do
      auth_data = create_test_auth_data()
      client_data_hash = :crypto.hash(:sha256, "test client data")

      # Create unreasonably large signature (10KB)
      huge_signature = :crypto.strong_rand_bytes(10_240)

      att_stmt = %{
        "alg" => -7,
        "sig" => huge_signature
      }

      assert {:error, _} =
               AttestationStatement.verify("packed", att_stmt, auth_data, client_data_hash)
    end

    test "prevents algorithm confusion attacks" do
      # Try to use RS256 signature with ES256 algorithm identifier
      rsa_key = :public_key.generate_key({:rsa, 2048, 65_537})

      auth_data = create_test_auth_data()
      client_data_hash = :crypto.hash(:sha256, "test client data")

      verification_data = auth_data <> client_data_hash
      rsa_signature = :public_key.sign(verification_data, :sha256, rsa_key)

      att_stmt = %{
        # Claims ES256 but signature is RSA
        "alg" => -7,
        "sig" => rsa_signature
      }

      assert {:error, _} =
               AttestationStatement.verify("packed", att_stmt, auth_data, client_data_hash)
    end

    test "validates signature padding and encoding" do
      auth_data = create_test_auth_data()
      client_data_hash = :crypto.hash(:sha256, "test client data")

      # Create signature with incorrect padding
      malformed_sig = <<0, 0, 0, 0>> <> :crypto.strong_rand_bytes(60)

      att_stmt = %{
        "alg" => -7,
        "sig" => malformed_sig
      }

      assert {:error, _} =
               AttestationStatement.verify("packed", att_stmt, auth_data, client_data_hash)
    end
  end

  # Helper functions

  defp create_test_auth_data do
    rp_id_hash = :crypto.hash(:sha256, "example.com")
    # UP, UV, AT flags
    flags = 0x45
    sign_count = 1
    aaguid = :crypto.strong_rand_bytes(16)
    cred_id = :crypto.strong_rand_bytes(16)
    cred_id_len = byte_size(cred_id)

    # Default ES256 public key
    public_key = %{
      # kty: EC2
      1 => 2,
      # alg: ES256
      3 => -7,
      # crv: P-256
      -1 => 1,
      # x
      -2 => :crypto.strong_rand_bytes(32),
      # y
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

  defp create_test_auth_data_with_key(cose_public_key) do
    rp_id_hash = :crypto.hash(:sha256, "example.com")
    # UP, UV, AT flags
    flags = 0x45
    sign_count = 1
    aaguid = :crypto.strong_rand_bytes(16)
    cred_id = :crypto.strong_rand_bytes(16)
    cred_id_len = byte_size(cred_id)

    {:ok, encoded_key} = ExWebauthn.CBOR.encode_credential_public_key(cose_public_key)

    rp_id_hash <>
      <<flags>> <>
      <<sign_count::32-big>> <>
      aaguid <>
      <<cred_id_len::16-big>> <>
      cred_id <>
      encoded_key
  end
end
