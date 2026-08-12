defmodule ExSwanTest do
  use ExUnit.Case
  doctest ExSwan

  alias ExSwan.{Attestation, Credential}

  describe "generate_challenge/0" do
    test "generates challenge of correct length" do
      challenge = ExSwan.generate_challenge()
      assert byte_size(challenge) == 32
    end

    test "generates different challenges each time" do
      challenge1 = ExSwan.generate_challenge()
      challenge2 = ExSwan.generate_challenge()

      assert challenge1 != challenge2
    end
  end

  describe "validate/1" do
    test "validates challenge" do
      valid_challenge = :crypto.strong_rand_bytes(32)
      invalid_challenge = :crypto.strong_rand_bytes(10)

      assert ExSwan.validate(valid_challenge) == :ok
      assert ExSwan.validate(invalid_challenge) == {:error, :unsupported_validation_type}
    end

    test "validates creation options" do
      valid_options = %Attestation.CreationOptions{
        rp: %Credential.RelyingParty{id: "example.com", name: "Example"},
        user: %Credential.User{id: <<1, 2, 3, 4>>, name: "test", display_name: "Test"},
        challenge: :crypto.strong_rand_bytes(32),
        pub_key_cred_params: [%Credential.Parameters{type: :public_key, alg: -7}]
      }

      assert ExSwan.validate(valid_options) == :ok
    end

    test "rejects unsupported validation types" do
      assert ExSwan.validate("unsupported") == {:error, :unsupported_validation_type}
      assert ExSwan.validate(123) == {:error, :unsupported_validation_type}
    end
  end

  describe "registration convenience functions" do
    test "generates browser-ready registration options and server ceremony state" do
      challenge = :binary.copy(<<1>>, 32)

      assert {:ok, %{options: options, ceremony: ceremony}} =
               ExSwan.generate_registration_options(
                 rp_name: "Example",
                 rp_id: "example.com",
                 user_name: "person@example.com",
                 user_id: <<1, 2, 3, 4>>,
                 challenge: challenge
               )

      assert options["rp"] == %{"id" => "example.com", "name" => "Example"}
      assert options["user"]["id"] == "AQIDBA"
      assert options["pubKeyCredParams"] == [%{"alg" => -7, "type" => "public-key"}]
      assert ceremony.challenge == challenge
      assert ceremony.rp_id == "example.com"
      assert ceremony.user_id == <<1, 2, 3, 4>>
    end

    test "reports a missing required registration option" do
      assert ExSwan.generate_registration_options(rp_name: "Example") ==
               {:error, {:missing_option, :rp_id}}
    end

    test "generate_registration_options/2 creates valid options" do
      rp = %Credential.RelyingParty{id: "example.com", name: "Example"}
      user = %Credential.User{id: <<1, 2, 3, 4>>, name: "test", display_name: "Test"}

      {:ok, options} = ExSwan.generate_registration_options(rp, user)

      assert %Attestation.CreationOptions{} = options
      assert options.rp == rp
      assert options.user == user
    end

    test "options_to_json/1 converts options to JSON format" do
      options = %Attestation.CreationOptions{
        rp: %Credential.RelyingParty{id: "example.com", name: "Example", icon: nil},
        user: %Credential.User{id: <<1, 2, 3, 4>>, name: "test", display_name: "Test"},
        challenge: :crypto.strong_rand_bytes(32),
        pub_key_cred_params: [%Credential.Parameters{type: :public_key, alg: -7}],
        timeout: 60_000,
        exclude_credentials: nil,
        authenticator_selection: nil,
        attestation: "none",
        extensions: nil
      }

      json = ExSwan.options_to_json(options)

      assert is_map(json)
      assert json["rp"]["id"] == "example.com"
      assert json["user"]["name"] == "test"
      assert is_binary(json["challenge"])
    end
  end

  describe "authentication convenience functions" do
    test "generates browser-ready authentication options and server ceremony state" do
      challenge = :binary.copy(<<2>>, 32)

      assert {:ok, %{options: options, ceremony: ceremony}} =
               ExSwan.generate_authentication_options(
                 rp_id: "example.com",
                 challenge: challenge
               )

      assert options["challenge"] == Base.url_encode64(challenge, padding: false)
      assert options["rpId"] == "example.com"
      assert ceremony.challenge == challenge
      assert ceremony.rp_id == "example.com"
    end

    test "reports a missing RP ID" do
      assert ExSwan.generate_authentication_options([]) ==
               {:error, {:missing_option, :rp_id}}
    end
  end

  describe "version/0" do
    test "returns version string" do
      version = ExSwan.version()
      assert is_binary(version)
      assert String.match?(version, ~r/^\d+\.\d+\.\d+/)
    end
  end
end
