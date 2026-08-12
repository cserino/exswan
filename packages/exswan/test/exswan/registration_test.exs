defmodule ExSwan.RegistrationTest do
  use ExUnit.Case
  alias ExSwan.{Attestation, Credential, Registration}

  describe "generate_creation_options/3" do
    test "generates valid creation options with required fields" do
      rp = %Credential.RelyingParty{
        id: "example.com",
        name: "Example Corp"
      }

      user = %Credential.User{
        id: :crypto.strong_rand_bytes(32),
        name: "john@example.com",
        display_name: "John Doe"
      }

      {:ok, options} = Registration.generate_creation_options(rp, user)

      assert options.rp == rp
      assert options.user == user
      assert byte_size(options.challenge) == 32
      assert length(options.pub_key_cred_params) > 0
      assert options.timeout == 60_000
      assert options.attestation == "none"
    end

    test "accepts custom challenge" do
      rp = %Credential.RelyingParty{id: "example.com", name: "Example"}
      user = %Credential.User{id: <<1, 2, 3, 4>>, name: "test", display_name: "Test"}
      custom_challenge = :crypto.strong_rand_bytes(64)

      {:ok, options} =
        Registration.generate_creation_options(rp, user, challenge: custom_challenge)

      assert options.challenge == custom_challenge
    end

    test "accepts custom timeout" do
      rp = %Credential.RelyingParty{id: "example.com", name: "Example"}
      user = %Credential.User{id: <<1, 2, 3, 4>>, name: "test", display_name: "Test"}

      {:ok, options} = Registration.generate_creation_options(rp, user, timeout: 120_000)

      assert options.timeout == 120_000
    end

    test "accepts exclude credentials list" do
      rp = %Credential.RelyingParty{id: "example.com", name: "Example"}
      user = %Credential.User{id: <<1, 2, 3, 4>>, name: "test", display_name: "Test"}

      exclude_creds = [
        %Credential.Descriptor{
          type: :public_key,
          id: <<1, 2, 3, 4>>,
          transports: ["usb"]
        }
      ]

      {:ok, options} =
        Registration.generate_creation_options(rp, user, exclude_credentials: exclude_creds)

      assert options.exclude_credentials == exclude_creds
    end

    test "accepts authenticator selection criteria" do
      rp = %Credential.RelyingParty{id: "example.com", name: "Example"}
      user = %Credential.User{id: <<1, 2, 3, 4>>, name: "test", display_name: "Test"}

      auth_selection = %Attestation.AuthenticatorSelection{
        authenticator_attachment: "platform",
        user_verification: "required"
      }

      {:ok, options} =
        Registration.generate_creation_options(rp, user, authenticator_selection: auth_selection)

      assert options.authenticator_selection == auth_selection
    end

    test "validates creation options" do
      invalid_rp = %Credential.RelyingParty{id: "invalid..domain", name: "Test"}
      user = %Credential.User{id: <<1, 2, 3, 4>>, name: "test", display_name: "Test"}

      {:error, reason} = Registration.generate_creation_options(invalid_rp, user)

      assert reason == :invalid_rp_id_format
    end
  end

  describe "options_to_json/1" do
    test "converts options to JSON-serializable format" do
      options = %Attestation.CreationOptions{
        rp: %Credential.RelyingParty{id: "example.com", name: "Example Corp", icon: nil},
        user: %Credential.User{id: <<1, 2, 3, 4>>, name: "john@example.com", display_name: "John"},
        challenge: <<1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16>>,
        pub_key_cred_params: [%Credential.Parameters{type: :public_key, alg: -7}],
        timeout: 60_000,
        exclude_credentials: nil,
        authenticator_selection: nil,
        attestation: "none",
        extensions: nil
      }

      json = Registration.options_to_json(options)

      assert json["rp"]["id"] == "example.com"
      assert json["rp"]["name"] == "Example Corp"
      assert json["user"]["name"] == "john@example.com"
      assert json["user"]["displayName"] == "John"
      assert is_binary(json["user"]["id"])
      assert is_binary(json["challenge"])
      assert length(json["pubKeyCredParams"]) == 1
      assert hd(json["pubKeyCredParams"])["type"] == "public-key"
      assert hd(json["pubKeyCredParams"])["alg"] == -7
      assert json["timeout"] == 60_000
      assert json["attestation"] == "none"
      refute Map.has_key?(json, "excludeCredentials")
    end

    test "includes exclude credentials when present" do
      exclude_creds = [
        %Credential.Descriptor{
          type: :public_key,
          id: <<1, 2, 3, 4>>,
          transports: ["usb", "nfc"]
        }
      ]

      options = %Attestation.CreationOptions{
        rp: %Credential.RelyingParty{id: "example.com", name: "Example"},
        user: %Credential.User{id: <<1, 2, 3, 4>>, name: "test", display_name: "Test"},
        challenge: :crypto.strong_rand_bytes(32),
        pub_key_cred_params: [%Credential.Parameters{type: :public_key, alg: -7}],
        exclude_credentials: exclude_creds,
        timeout: nil,
        authenticator_selection: nil,
        attestation: nil,
        extensions: nil
      }

      json = Registration.options_to_json(options)

      assert length(json["excludeCredentials"]) == 1
      cred = hd(json["excludeCredentials"])
      assert cred["type"] == "public-key"
      assert is_binary(cred["id"])
      assert cred["transports"] == ["usb", "nfc"]
    end

    test "includes authenticator selection when present" do
      auth_selection = %Attestation.AuthenticatorSelection{
        authenticator_attachment: "platform",
        user_verification: "required",
        resident_key: "required",
        require_resident_key: true
      }

      options = %Attestation.CreationOptions{
        rp: %Credential.RelyingParty{id: "example.com", name: "Example"},
        user: %Credential.User{id: <<1, 2, 3, 4>>, name: "test", display_name: "Test"},
        challenge: :crypto.strong_rand_bytes(32),
        pub_key_cred_params: [%Credential.Parameters{type: :public_key, alg: -7}],
        exclude_credentials: nil,
        timeout: nil,
        authenticator_selection: auth_selection,
        attestation: nil,
        extensions: nil
      }

      json = Registration.options_to_json(options)

      assert json["authenticatorSelection"]["authenticatorAttachment"] == "platform"
      assert json["authenticatorSelection"]["userVerification"] == "required"
      assert json["authenticatorSelection"]["residentKey"] == "required"
      assert json["authenticatorSelection"]["requireResidentKey"] == true
    end
  end

  describe "verify_creation/3" do
    test "validates response structure" do
      options = create_test_options()

      invalid_response = %{"clientDataJSON" => "test"}

      {:error, reason} =
        Registration.verify_creation(invalid_response, options, "https://example.com")

      assert reason == :missing_required_fields
    end

    test "rejects invalid response format" do
      options = create_test_options()

      {:error, reason} = Registration.verify_creation("not a map", options, "https://example.com")

      assert reason == :invalid_response_format
    end

    test "validates client data JSON structure" do
      options = create_test_options()

      # Invalid JSON (base64url encoded)
      response = %{
        "clientDataJSON" => Base.url_encode64("invalid json", padding: false),
        "attestationObject" => create_test_attestation_object()
      }

      {:error, reason} = Registration.verify_creation(response, options, "https://example.com")

      assert reason == :invalid_client_data_json
    end

    test "validates client data type" do
      options = create_test_options()

      client_data = create_test_client_data(%{"type" => "webauthn.get"})

      response = %{
        "clientDataJSON" => Base.url_encode64(Jason.encode!(client_data), padding: false),
        "attestationObject" => create_test_attestation_object()
      }

      {:error, reason} = Registration.verify_creation(response, options, "https://example.com")

      assert reason == :invalid_client_data_type
    end

    test "validates challenge match" do
      options = create_test_options()

      # Wrong challenge
      client_data =
        create_test_client_data(%{
          "challenge" => Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false),
          "origin" => "https://example.com"
        })

      response = %{
        "clientDataJSON" => Base.url_encode64(Jason.encode!(client_data), padding: false),
        "attestationObject" => create_test_attestation_object()
      }

      {:error, reason} = Registration.verify_creation(response, options, "https://example.com")

      assert reason == :challenge_mismatch
    end

    test "validates origin match" do
      options = create_test_options()

      client_data =
        create_test_client_data(%{
          "origin" => "https://evil.com",
          "challenge" => Base.url_encode64(options.challenge, padding: false)
        })

      response = %{
        "clientDataJSON" => Base.url_encode64(Jason.encode!(client_data), padding: false),
        "attestationObject" => create_test_attestation_object()
      }

      {:error, reason} = Registration.verify_creation(response, options, "https://example.com")

      assert reason == :origin_mismatch
    end
  end

  # Helper functions

  defp create_test_options do
    rp = %Credential.RelyingParty{id: "example.com", name: "Example"}
    user = %Credential.User{id: <<1, 2, 3, 4>>, name: "test", display_name: "Test"}

    {:ok, options} = Registration.generate_creation_options(rp, user)
    options
  end

  defp create_test_client_data(overrides) do
    base_challenge = Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false)

    %{
      "type" => "webauthn.create",
      "challenge" => base_challenge,
      "origin" => "https://example.com",
      "crossOrigin" => false
    }
    |> Map.merge(overrides)
  end

  defp create_test_attestation_object do
    # Create a minimal valid CBOR-encoded attestation object
    attestation_map = %{
      "fmt" => "none",
      "authData" => create_test_auth_data(),
      "attStmt" => %{}
    }

    {:ok, encoded} = ExSwan.CBORUtils.encode_attestation_object(attestation_map)
    Base.url_encode64(encoded, padding: false)
  end

  defp create_test_auth_data do
    # Create minimal authenticator data
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

    {:ok, encoded_key} = ExSwan.CBORUtils.encode_credential_public_key(public_key)

    rp_id_hash <>
      <<flags>> <>
      <<sign_count::32-big>> <>
      aaguid <>
      <<cred_id_len::16-big>> <>
      cred_id <>
      encoded_key
  end
end
