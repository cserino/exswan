defmodule ExWebauthn.MultipleOriginTest do
  use ExUnit.Case, async: true

  alias ExWebauthn.{Authentication, Credential, Registration}

  setup do
    rp = %Credential.RelyingParty{id: "example.com", name: "Example Corp"}

    user = %Credential.User{
      id: :crypto.strong_rand_bytes(32),
      name: "user@example.com",
      display_name: "User"
    }

    challenge = :crypto.strong_rand_bytes(32)

    {:ok, options} = Registration.generate_creation_options(rp, user, challenge: challenge)

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

    %{
      rp: rp,
      user: user,
      challenge: challenge,
      options: options,
      credential: credential
    }
  end

  describe "multiple origins in registration" do
    # Reference: vendor/SimpleWebAuthn/packages/server/src/registration/verifyRegistrationResponse.test.ts

    test "should support multiple possible origins", %{options: options, challenge: challenge} do
      # Create a mock response with specific origin
      client_data = %{
        "type" => "webauthn.create",
        "challenge" => Base.url_encode64(challenge, padding: false),
        "origin" => "https://example.com"
      }

      client_data_json = Jason.encode!(client_data)
      client_data_b64 = Base.url_encode64(client_data_json, padding: false)

      response = %{
        "clientDataJSON" => client_data_b64,
        "attestationObject" => "mock_attestation_object"
      }

      # Should work with single origin
      origins = ["https://example.com", "https://different.address"]

      # This would normally fail in full verification due to mock attestation object,
      # but we can test the origin parsing part by checking the error
      result = Registration.verify_creation(response, options, origins)

      # Should not fail with origin mismatch (would fail later for other reasons)
      case result do
        {:error, :origin_mismatch} ->
          flunk("Should not fail with origin mismatch for valid origin in list")

        {:error, _other_reason} ->
          # Expected - would fail for other reasons like invalid attestation object
          :ok

        {:ok, _} ->
          # Unexpected success but acceptable
          :ok
      end
    end

    test "should reject origin not in list", %{options: options, challenge: challenge} do
      client_data = %{
        "type" => "webauthn.create",
        "challenge" => Base.url_encode64(challenge, padding: false),
        "origin" => "https://evil.com"
      }

      client_data_json = Jason.encode!(client_data)
      client_data_b64 = Base.url_encode64(client_data_json, padding: false)

      response = %{
        "clientDataJSON" => client_data_b64,
        "attestationObject" => "mock_attestation_object"
      }

      # Should reject origin not in allowed list
      origins = ["https://example.com", "https://different.address"]

      # Should fail with origin mismatch
      assert {:error, :origin_mismatch} =
               Registration.verify_creation(response, options, origins)
    end
  end

  describe "multiple origins in authentication" do
    # Reference: vendor/SimpleWebAuthn/packages/server/src/authentication/verifyAuthenticationResponse.test.ts

    test "should support multiple possible origins", %{credential: credential} do
      challenge = :crypto.strong_rand_bytes(32)

      {:ok, auth_options} =
        Authentication.generate_request_options("example.com",
          challenge: challenge
        )

      client_data = %{
        "type" => "webauthn.get",
        "challenge" => Base.url_encode64(challenge, padding: false),
        "origin" => "https://example.com"
      }

      client_data_json = Jason.encode!(client_data)

      response = %{
        "clientDataJSON" => Base.url_encode64(client_data_json, padding: false),
        "authenticatorData" => Base.url_encode64(<<0::296>>, padding: false),
        "signature" => Base.url_encode64(<<1, 2, 3, 4>>, padding: false),
        "credentialId" => credential.id
      }

      # Should work with multiple origins
      origins = ["https://example.com", "https://different.address"]

      result = Authentication.verify_assertion(response, auth_options, credential, origins)

      # Should not fail with origin mismatch (may fail for other reasons like signature)
      case result do
        {:error, :origin_mismatch} ->
          flunk("Should not fail with origin mismatch for valid origin in list")

        {:error, _other_reason} ->
          # Expected - would fail for other reasons like invalid signature
          :ok

        {:ok, _} ->
          # Unexpected success but acceptable
          :ok
      end
    end

    test "should reject origin not in list during authentication", %{credential: credential} do
      challenge = :crypto.strong_rand_bytes(32)

      {:ok, auth_options} =
        Authentication.generate_request_options("example.com",
          challenge: challenge
        )

      client_data = %{
        "type" => "webauthn.get",
        "challenge" => Base.url_encode64(challenge, padding: false),
        "origin" => "https://evil.com"
      }

      client_data_json = Jason.encode!(client_data)

      response = %{
        "clientDataJSON" => Base.url_encode64(client_data_json, padding: false),
        "authenticatorData" => Base.url_encode64(<<0::296>>, padding: false),
        "signature" => Base.url_encode64(<<1, 2, 3, 4>>, padding: false),
        "credentialId" => credential.id
      }

      # Should reject origin not in allowed list
      origins = ["https://example.com", "https://different.address"]

      assert {:error, :origin_mismatch} =
               Authentication.verify_assertion(response, auth_options, credential, origins)
    end
  end
end
