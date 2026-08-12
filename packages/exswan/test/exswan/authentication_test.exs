defmodule ExSwan.AuthenticationTest do
  use ExUnit.Case
  doctest ExSwan.Authentication

  alias ExSwan.{Assertion, Authentication, Credential}

  describe "generate_request_options/2" do
    test "generates valid request options with defaults" do
      rp_id = "example.com"

      {:ok, options} = Authentication.generate_request_options(rp_id)

      assert %Assertion.RequestOptions{} = options
      assert options.rp_id == rp_id
      assert byte_size(options.challenge) == 32
      assert options.timeout == 60_000
      assert options.user_verification == "preferred"
      assert is_nil(options.allow_credentials)
      assert is_nil(options.extensions)
    end

    test "generates request options with custom parameters" do
      rp_id = "example.com"
      challenge = :crypto.strong_rand_bytes(16)

      credential_desc = %Credential.Descriptor{
        id: :crypto.strong_rand_bytes(32),
        transports: ["usb", "nfc"]
      }

      opts = [
        challenge: challenge,
        timeout: 30_000,
        allow_credentials: [credential_desc],
        user_verification: "required",
        extensions: %{"txAuthSimple" => "Please confirm"}
      ]

      {:ok, options} = Authentication.generate_request_options(rp_id, opts)

      assert options.challenge == challenge
      assert options.timeout == 30_000
      assert options.allow_credentials == [credential_desc]
      assert options.user_verification == "required"
      assert options.extensions == %{"txAuthSimple" => "Please confirm"}
    end

    test "accepts public stored credentials at the allow-list seam" do
      credential = %Credential{id: "CQgHBg", transports: ["usb"]}

      assert {:ok, options} =
               Authentication.generate_request_options("example.com",
                 allow_credentials: [credential]
               )

      assert options.allow_credentials == [
               %Credential.Descriptor{type: :public_key, id: "CQgHBg", transports: ["usb"]}
             ]
    end

    test "rejects malformed allow-list values without raising" do
      assert {:error, :invalid_allow_credentials} =
               Authentication.generate_request_options("example.com",
                 allow_credentials: [%{}]
               )
    end

    test "validates request options" do
      # Invalid RP ID should fail validation
      {:error, :invalid_rp_id_format} = Authentication.generate_request_options("")
      {:error, :invalid_rp_id_format} = Authentication.generate_request_options("invalid..domain")
    end
  end

  describe "options_to_json/1" do
    test "converts request options to JSON format" do
      challenge = :crypto.strong_rand_bytes(32)

      raw_id = :crypto.strong_rand_bytes(16)

      credential_desc = %Credential.Descriptor{
        type: :public_key,
        id: Base.url_encode64(raw_id, padding: false),
        transports: ["usb"]
      }

      options = %Assertion.RequestOptions{
        challenge: challenge,
        timeout: 30_000,
        rp_id: "example.com",
        allow_credentials: [credential_desc],
        user_verification: "required",
        extensions: %{"txAuthSimple" => "test"}
      }

      json = Authentication.options_to_json(options)

      assert json["challenge"] == Base.url_encode64(challenge, padding: false)
      assert json["timeout"] == 30_000
      assert json["rpId"] == "example.com"
      assert json["userVerification"] == "required"
      assert json["extensions"] == %{"txAuthSimple" => "test"}

      [allow_cred] = json["allowCredentials"]
      assert allow_cred["type"] == "public-key"
      assert allow_cred["id"] == credential_desc.id
      assert allow_cred["transports"] == ["usb"]
    end

    test "omits nil values from JSON" do
      options = %Assertion.RequestOptions{
        challenge: :crypto.strong_rand_bytes(32),
        rp_id: "example.com",
        timeout: nil,
        allow_credentials: nil,
        user_verification: nil,
        extensions: nil
      }

      json = Authentication.options_to_json(options)

      refute Map.has_key?(json, "timeout")
      refute Map.has_key?(json, "allowCredentials")
      refute Map.has_key?(json, "userVerification")
      refute Map.has_key?(json, "extensions")
    end
  end

  describe "verify_assertion/4" do
    setup do
      # Create a mock credential with public key
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

      credential = %Credential{
        id: :crypto.strong_rand_bytes(32),
        public_key: public_key,
        user_handle: :crypto.strong_rand_bytes(32),
        sign_count: 1
      }

      challenge = :crypto.strong_rand_bytes(32)

      options = %Assertion.RequestOptions{
        challenge: challenge,
        timeout: 60_000,
        rp_id: "example.com",
        allow_credentials: nil,
        user_verification: "preferred",
        extensions: nil
      }

      %{credential: credential, options: options, challenge: challenge}
    end

    test "validates assertion response structure", %{options: options, credential: credential} do
      # Missing required fields
      invalid_response = %{"clientDataJSON" => "test"}

      {:error, :missing_required_assertion_fields} =
        Authentication.verify_assertion(
          invalid_response,
          options,
          credential,
          "https://example.com"
        )
    end

    test "validates client data JSON structure", %{options: options, credential: credential} do
      # Invalid JSON
      invalid_response = %{
        "clientDataJSON" => "invalid-json",
        "authenticatorData" => Base.url_encode64(<<0::296>>, padding: false),
        "signature" => Base.url_encode64(<<1, 2, 3, 4>>, padding: false)
      }

      {:error, :invalid_client_data_json} =
        Authentication.verify_assertion(
          invalid_response,
          options,
          credential,
          "https://example.com"
        )
    end

    test "validates client data type", %{options: options, credential: credential} do
      client_data = %{
        # Wrong type
        "type" => "webauthn.create",
        "challenge" => Base.url_encode64(options.challenge, padding: false),
        "origin" => "https://example.com"
      }

      response = %{
        "clientDataJSON" => Base.url_encode64(Jason.encode!(client_data), padding: false),
        "authenticatorData" => Base.url_encode64(<<0::296>>, padding: false),
        "signature" => Base.url_encode64(<<1, 2, 3, 4>>, padding: false)
      }

      {:error, :invalid_client_data_type} =
        Authentication.verify_assertion(response, options, credential, "https://example.com")
    end

    test "validates challenge mismatch", %{options: options, credential: credential} do
      wrong_challenge = :crypto.strong_rand_bytes(32)

      client_data = %{
        "type" => "webauthn.get",
        "challenge" => Base.url_encode64(wrong_challenge, padding: false),
        "origin" => "https://example.com"
      }

      response = %{
        "clientDataJSON" => Base.url_encode64(Jason.encode!(client_data), padding: false),
        "authenticatorData" => Base.url_encode64(<<0::296>>, padding: false),
        "signature" => Base.url_encode64(<<1, 2, 3, 4>>, padding: false)
      }

      {:error, :challenge_mismatch} =
        Authentication.verify_assertion(response, options, credential, "https://example.com")
    end

    test "validates origin mismatch", %{options: options, credential: credential} do
      client_data = %{
        "type" => "webauthn.get",
        "challenge" => Base.url_encode64(options.challenge, padding: false),
        "origin" => "https://evil.com"
      }

      response = %{
        "clientDataJSON" => Base.url_encode64(Jason.encode!(client_data), padding: false),
        "authenticatorData" => Base.url_encode64(<<0::296>>, padding: false),
        "signature" => Base.url_encode64(<<1, 2, 3, 4>>, padding: false)
      }

      {:error, :origin_mismatch} =
        Authentication.verify_assertion(response, options, credential, "https://example.com")
    end

    test "validates authenticator data length", %{options: options, credential: credential} do
      client_data = %{
        "type" => "webauthn.get",
        "challenge" => Base.url_encode64(options.challenge, padding: false),
        "origin" => "https://example.com"
      }

      # Authenticator data too short (less than 37 bytes)
      short_auth_data = <<0::200>>

      response = %{
        "clientDataJSON" => Base.url_encode64(Jason.encode!(client_data), padding: false),
        "authenticatorData" => Base.url_encode64(short_auth_data, padding: false),
        "signature" => Base.url_encode64(<<1, 2, 3, 4>>, padding: false)
      }

      {:error, :invalid_authenticator_data_length} =
        Authentication.verify_assertion(response, options, credential, "https://example.com")
    end

    test "validates RP ID hash", %{options: options, credential: credential} do
      client_data = %{
        "type" => "webauthn.get",
        "challenge" => Base.url_encode64(options.challenge, padding: false),
        "origin" => "https://example.com"
      }

      # Create authenticator data with wrong RP ID hash
      wrong_rp_hash = :crypto.strong_rand_bytes(32)
      # User Present
      flags = 0x01
      sign_count = 2
      auth_data = wrong_rp_hash <> <<flags>> <> <<sign_count::32-big>>

      response = %{
        "clientDataJSON" => Base.url_encode64(Jason.encode!(client_data), padding: false),
        "authenticatorData" => Base.url_encode64(auth_data, padding: false),
        "signature" => Base.url_encode64(<<1, 2, 3, 4>>, padding: false),
        "credentialId" => Base.url_encode64(credential.id, padding: false)
      }

      {:error, :rp_id_hash_mismatch} =
        Authentication.verify_assertion(response, options, credential, "https://example.com")
    end

    test "validates user presence flag", %{options: options, credential: credential} do
      client_data = %{
        "type" => "webauthn.get",
        "challenge" => Base.url_encode64(options.challenge, padding: false),
        "origin" => "https://example.com"
      }

      # Create authenticator data without user present flag
      rp_hash = :crypto.hash(:sha256, options.rp_id)
      # No flags set
      flags = 0x00
      sign_count = 2
      auth_data = rp_hash <> <<flags>> <> <<sign_count::32-big>>

      response = %{
        "clientDataJSON" => Base.url_encode64(Jason.encode!(client_data), padding: false),
        "authenticatorData" => Base.url_encode64(auth_data, padding: false),
        "signature" => Base.url_encode64(<<1, 2, 3, 4>>, padding: false),
        "credentialId" => Base.url_encode64(credential.id, padding: false)
      }

      {:error, :user_not_present} =
        Authentication.verify_assertion(response, options, credential, "https://example.com")
    end

    test "validates credential ID mismatch", %{options: options, credential: credential} do
      client_data = %{
        "type" => "webauthn.get",
        "challenge" => Base.url_encode64(options.challenge, padding: false),
        "origin" => "https://example.com"
      }

      rp_hash = :crypto.hash(:sha256, options.rp_id)
      # User Present
      flags = 0x01
      sign_count = 2
      auth_data = rp_hash <> <<flags>> <> <<sign_count::32-big>>

      wrong_credential_id = :crypto.strong_rand_bytes(32)

      response = %{
        "clientDataJSON" => Base.url_encode64(Jason.encode!(client_data), padding: false),
        "authenticatorData" => Base.url_encode64(auth_data, padding: false),
        "signature" => Base.url_encode64(<<1, 2, 3, 4>>, padding: false),
        "credentialId" => Base.url_encode64(wrong_credential_id, padding: false)
      }

      {:error, :signature_verification_failed} =
        Authentication.verify_assertion(response, options, credential, "https://example.com")
    end
  end
end
