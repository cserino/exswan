defmodule ExSwan.RegistrationResponseTest do
  use ExUnit.Case, async: true

  alias ExSwan.RegistrationResult

  @challenge :binary.copy(<<7>>, 32)
  @credential_id <<0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15>>
  @aaguid <<0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15>>

  describe "verify_registration_response/1" do
    test "accepts a complete browser response and returns ceremony information" do
      response = browser_response()

      assert {:ok, %RegistrationResult{} = result} = verify(response)

      assert result.credential.id == Base.url_encode64(@credential_id, padding: false)
      assert result.credential.transports == ["internal", "hybrid"]
      assert result.credential.credential_device_type == :multi_device
      assert result.credential.credential_backed_up
      assert result.aaguid == "00010203-0405-0607-0809-0a0b0c0d0e0f"
      assert result.attestation_format == :none
      assert result.user_verified
      assert result.credential_device_type == :multi_device
      assert result.credential_backed_up
      assert result.authenticator_extension_results == %{}
      assert result.client_extension_results == %{"credProps" => %{"rk" => true}}
      assert result.authenticator_attachment == "platform"
      assert result.origin == "https://example.com"
      assert result.rp_id == "example.com"
    end

    test "requires the complete outer credential object" do
      assert verify(%{"response" => %{}}) == {:error, {:missing_field, "id"}}
    end

    test "rejects the wrong outer credential type" do
      response = Map.put(browser_response(), "type", "password")
      assert verify(response) == {:error, :invalid_credential_type}
    end

    test "rejects malformed base64url in every binary browser field" do
      for path <- [
            ["id"],
            ["rawId"],
            ["response", "clientDataJSON"],
            ["response", "attestationObject"],
            ["response", "publicKey"]
          ] do
        response = put_in(browser_response(), path, "not+base64")
        assert {:error, _reason} = verify(response)
      end
    end

    test "rejects padded base64url" do
      response = Map.put(browser_response(), "id", "AA==")
      assert verify(response) == {:error, :invalid_credential_id}
    end

    test "rejects an id and rawId mismatch" do
      response = Map.put(browser_response(), "id", Base.url_encode64(<<99>>, padding: false))
      assert verify(response) == {:error, :credential_id_mismatch}
    end

    test "rejects an outer ID that differs from the attested credential ID" do
      other_id = Base.url_encode64(:binary.copy(<<42>>, 16), padding: false)

      response =
        browser_response()
        |> Map.put("id", other_id)
        |> Map.put("rawId", other_id)

      assert verify(response) == {:error, :credential_id_mismatch}
    end

    test "rejects unknown or duplicate transports" do
      response = put_in(browser_response(), ["response", "transports"], ["internal", "magic"])
      assert verify(response) == {:error, :invalid_transports}

      response =
        put_in(browser_response(), ["response", "transports"], ["internal", "internal"])

      assert verify(response) == {:error, :invalid_transports}
    end

    test "rejects backup state without backup eligibility" do
      # UP + UV + BS + AT
      response = browser_response(0x55)
      assert verify(response) == {:error, :invalid_backup_flags}
    end

    test "requires user verification by default" do
      # UP + AT
      response = browser_response(0x41)
      assert verify(response) == {:error, :user_verification_required}

      assert {:ok, %RegistrationResult{user_verified: false}} =
               ExSwan.verify_registration_response(
                 response: response,
                 expected_challenge: @challenge,
                 expected_origin: "https://example.com",
                 expected_rp_id: "example.com",
                 require_user_verification: false
               )
    end

    test "rejects an algorithm that was not advertised" do
      response = put_in(browser_response(), ["response", "publicKeyAlgorithm"], -257)
      assert verify(response) == {:error, :unsupported_credential_algorithm}
    end

    test "returns errors instead of raising for arbitrary public input" do
      for input <- [nil, "response", [], %{}, %{"id" => 1}] do
        assert {:error, _reason} =
                 ExSwan.verify_registration_response(
                   response: input,
                   expected_challenge: @challenge,
                   expected_origin: "https://example.com",
                   expected_rp_id: "example.com"
                 )
      end
    end
  end

  defp verify(response) do
    ExSwan.verify_registration_response(
      response: response,
      expected_challenge: @challenge,
      expected_origin: "https://example.com",
      expected_rp_id: "example.com"
    )
  end

  defp browser_response(flags \\ 0x5D) do
    credential_id = Base.url_encode64(@credential_id, padding: false)
    client_data_json = Jason.encode!(client_data())

    %{
      "id" => credential_id,
      "rawId" => credential_id,
      "type" => "public-key",
      "authenticatorAttachment" => "platform",
      "clientExtensionResults" => %{"credProps" => %{"rk" => true}},
      "response" => %{
        "attestationObject" => encode_attestation_object(flags),
        "clientDataJSON" => Base.url_encode64(client_data_json, padding: false),
        "publicKey" => Base.url_encode64(<<1, 2, 3>>, padding: false),
        "publicKeyAlgorithm" => -7,
        "transports" => ["internal", "hybrid"]
      }
    }
  end

  defp client_data do
    %{
      "type" => "webauthn.create",
      "challenge" => Base.url_encode64(@challenge, padding: false),
      "origin" => "https://example.com",
      "crossOrigin" => false
    }
  end

  defp encode_attestation_object(flags) do
    attestation_object = %{
      "fmt" => "none",
      "authData" => authenticator_data(flags),
      "attStmt" => %{}
    }

    attestation_object
    |> CBOR.encode()
    |> Base.url_encode64(padding: false)
  end

  defp authenticator_data(flags) do
    public_key = %{
      1 => 2,
      3 => -7,
      -1 => 1,
      -2 => :binary.copy(<<11>>, 32),
      -3 => :binary.copy(<<12>>, 32)
    }

    :crypto.hash(:sha256, "example.com") <>
      <<flags, 0::32-big>> <>
      @aaguid <>
      <<byte_size(@credential_id)::16-big>> <>
      @credential_id <>
      CBOR.encode(public_key)
  end
end
