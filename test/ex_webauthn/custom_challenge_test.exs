defmodule ExWebauthn.CustomChallengeTest do
  use ExUnit.Case, async: true

  alias ExWebauthn.{Authentication, Credential, Registration}

  setup do
    rp = %Credential.RelyingParty{id: "example.com", name: "Example Corp"}

    user = %Credential.User{
      id: :crypto.strong_rand_bytes(32),
      name: "user@example.com",
      display_name: "User"
    }

    # Mock credential for authentication tests
    credential = %Credential{
      type: :public_key,
      id: "test-credential-id",
      public_key: %{
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
      },
      rp_id: "example.com",
      sign_count: 0
    }

    %{rp: rp, user: user, credential: credential}
  end

  describe "custom challenge validation in registration" do
    # Reference: vendor/SimpleWebAuthn/packages/server/src/registration/verifyRegistrationResponse.test.ts

    test "should pass verification if custom challenge verifier returns true", %{
      rp: rp,
      user: user
    } do
      # Create a challenge that contains structured data
      challenge_data = %{
        actual_challenge: Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false),
        arbitrary_data: "some additional context"
      }

      encoded_challenge = Jason.encode!(challenge_data)
      challenge_bytes = Base.decode64!(Base.encode64(encoded_challenge))

      {:ok, options} =
        Registration.generate_creation_options(rp, user, challenge: challenge_bytes)

      client_data = %{
        "type" => "webauthn.create",
        "challenge" => Base.url_encode64(challenge_bytes, padding: false),
        "origin" => "https://example.com"
      }

      client_data_json = Jason.encode!(client_data)
      client_data_b64 = Base.url_encode64(client_data_json, padding: false)

      response = %{
        "clientDataJSON" => client_data_b64,
        "attestationObject" => "mock_attestation_object"
      }

      # Custom challenge verifier that parses the structured challenge
      challenge_verifier = fn received_challenge ->
        case Jason.decode(received_challenge) do
          {:ok, parsed} ->
            # Verify it has the expected structure
            Map.has_key?(parsed, "actual_challenge") and Map.has_key?(parsed, "arbitrary_data")

          {:error, _} ->
            false
        end
      end

      # Test with custom challenge verifier
      result =
        Registration.verify_creation(
          response,
          %{options | challenge: challenge_verifier},
          "https://example.com"
        )

      # Should not fail with challenge verification (may fail for other reasons)
      case result do
        {:error, {:custom_challenge_verification_failed, _}} ->
          flunk("Should not fail custom challenge verification")

        {:error, :challenge_mismatch} ->
          flunk("Should not fail with challenge mismatch")

        {:error, _other_reason} ->
          # Expected - would fail for other reasons like invalid attestation object
          :ok

        {:ok, _} ->
          # Unexpected success but acceptable
          :ok
      end
    end

    test "should fail verification if custom challenge verifier returns false", %{
      rp: rp,
      user: user
    } do
      challenge_bytes = :crypto.strong_rand_bytes(32)

      {:ok, options} =
        Registration.generate_creation_options(rp, user, challenge: challenge_bytes)

      client_data = %{
        "type" => "webauthn.create",
        "challenge" => Base.url_encode64(challenge_bytes, padding: false),
        "origin" => "https://example.com"
      }

      client_data_json = Jason.encode!(client_data)
      client_data_b64 = Base.url_encode64(client_data_json, padding: false)

      response = %{
        "clientDataJSON" => client_data_b64,
        "attestationObject" => "mock_attestation_object"
      }

      # Challenge verifier that always returns false
      challenge_verifier = fn _challenge -> false end

      # Should fail with custom challenge verification error
      assert {:error, {:custom_challenge_verification_failed, _}} =
               Registration.verify_creation(
                 response,
                 %{options | challenge: challenge_verifier},
                 "https://example.com"
               )
    end

    test "should handle custom challenge verifier that returns {:ok, boolean()}", %{
      rp: rp,
      user: user
    } do
      challenge_bytes = :crypto.strong_rand_bytes(32)

      {:ok, options} =
        Registration.generate_creation_options(rp, user, challenge: challenge_bytes)

      client_data = %{
        "type" => "webauthn.create",
        "challenge" => Base.url_encode64(challenge_bytes, padding: false),
        "origin" => "https://example.com"
      }

      client_data_json = Jason.encode!(client_data)
      client_data_b64 = Base.url_encode64(client_data_json, padding: false)

      response = %{
        "clientDataJSON" => client_data_b64,
        "attestationObject" => "mock_attestation_object"
      }

      # Challenge verifier that returns {:ok, true}
      challenge_verifier = fn _challenge -> {:ok, true} end

      result =
        Registration.verify_creation(
          response,
          %{options | challenge: challenge_verifier},
          "https://example.com"
        )

      # Should not fail with challenge verification
      case result do
        {:error, {:custom_challenge_verification_failed, _}} ->
          flunk("Should not fail custom challenge verification")

        {:error, :challenge_mismatch} ->
          flunk("Should not fail with challenge mismatch")

        {:error, _other_reason} ->
          # Expected - would fail for other reasons
          :ok

        {:ok, _} ->
          :ok
      end
    end

    test "should handle custom challenge verifier errors", %{rp: rp, user: user} do
      challenge_bytes = :crypto.strong_rand_bytes(32)

      {:ok, options} =
        Registration.generate_creation_options(rp, user, challenge: challenge_bytes)

      client_data = %{
        "type" => "webauthn.create",
        "challenge" => Base.url_encode64(challenge_bytes, padding: false),
        "origin" => "https://example.com"
      }

      client_data_json = Jason.encode!(client_data)
      client_data_b64 = Base.url_encode64(client_data_json, padding: false)

      response = %{
        "clientDataJSON" => client_data_b64,
        "attestationObject" => "mock_attestation_object"
      }

      # Challenge verifier that returns an error
      challenge_verifier = fn _challenge -> {:error, :custom_validation_failed} end

      # Should propagate the custom error
      assert {:error, :custom_validation_failed} =
               Registration.verify_creation(
                 response,
                 %{options | challenge: challenge_verifier},
                 "https://example.com"
               )
    end
  end

  describe "custom challenge validation in authentication" do
    # Reference: vendor/SimpleWebAuthn/packages/server/src/authentication/verifyAuthenticationResponse.test.ts

    test "should pass verification if custom challenge verifier returns true", %{
      credential: credential
    } do
      # Create structured challenge
      challenge_data = %{
        actual_challenge: Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false),
        arbitrary_data: "authentication context"
      }

      encoded_challenge = Jason.encode!(challenge_data)
      challenge_bytes = Base.decode64!(Base.encode64(encoded_challenge))

      {:ok, auth_options} =
        Authentication.generate_request_options("example.com",
          challenge: challenge_bytes
        )

      client_data = %{
        "type" => "webauthn.get",
        "challenge" => Base.url_encode64(challenge_bytes, padding: false),
        "origin" => "https://example.com"
      }

      client_data_json = Jason.encode!(client_data)

      response = %{
        "clientDataJSON" => Base.url_encode64(client_data_json, padding: false),
        "authenticatorData" => Base.url_encode64(<<0::296>>, padding: false),
        "signature" => Base.url_encode64(<<1, 2, 3, 4>>, padding: false),
        "credentialId" => credential.id
      }

      # Custom challenge verifier
      challenge_verifier = fn received_challenge ->
        case Jason.decode(received_challenge) do
          {:ok, parsed} ->
            Map.has_key?(parsed, "actual_challenge") and Map.has_key?(parsed, "arbitrary_data")

          {:error, _} ->
            false
        end
      end

      # Update auth options to use custom verifier
      custom_auth_options = %{auth_options | challenge: challenge_verifier}

      result =
        Authentication.verify_assertion(
          response,
          custom_auth_options,
          credential,
          "https://example.com"
        )

      # Should not fail with challenge verification
      case result do
        {:error, {:custom_challenge_verification_failed, _}} ->
          flunk("Should not fail custom challenge verification")

        {:error, :challenge_mismatch} ->
          flunk("Should not fail with challenge mismatch")

        {:error, _other_reason} ->
          # Expected - would fail for other reasons like signature verification
          :ok

        {:ok, _} ->
          :ok
      end
    end

    test "should fail verification if custom challenge verifier returns false", %{
      credential: credential
    } do
      challenge_bytes = :crypto.strong_rand_bytes(32)

      {:ok, auth_options} =
        Authentication.generate_request_options("example.com",
          challenge: challenge_bytes
        )

      client_data = %{
        "type" => "webauthn.get",
        "challenge" => Base.url_encode64(challenge_bytes, padding: false),
        "origin" => "https://example.com"
      }

      client_data_json = Jason.encode!(client_data)

      response = %{
        "clientDataJSON" => Base.url_encode64(client_data_json, padding: false),
        "authenticatorData" => Base.url_encode64(<<0::296>>, padding: false),
        "signature" => Base.url_encode64(<<1, 2, 3, 4>>, padding: false),
        "credentialId" => credential.id
      }

      # Challenge verifier that always returns false
      challenge_verifier = fn _challenge -> false end

      # Update auth options to use custom verifier
      custom_auth_options = %{auth_options | challenge: challenge_verifier}

      # Should fail with custom challenge verification error
      assert {:error, {:custom_challenge_verification_failed, _}} =
               Authentication.verify_assertion(
                 response,
                 custom_auth_options,
                 credential,
                 "https://example.com"
               )
    end
  end
end
