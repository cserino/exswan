defmodule ExSwan.AuthenticationResponseTest do
  use ExUnit.Case, async: true

  alias ExSwan.{AuthenticationResult, Credential}

  @challenge :binary.copy(<<8>>, 32)
  @credential_id <<16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31>>
  @user_handle :binary.copy(<<9>>, 32)

  setup do
    {public_key, private_key} = :crypto.generate_key(:ecdh, :secp256r1)
    <<4, x::binary-size(32), y::binary-size(32)>> = public_key

    credential = %Credential{
      type: :public_key,
      id: Base.url_encode64(@credential_id, padding: false),
      public_key: %{1 => 2, 3 => -7, -1 => 1, -2 => x, -3 => y},
      rp_id: "example.com",
      user_handle: @user_handle,
      sign_count: 41,
      credential_device_type: :multi_device,
      credential_backed_up: false
    }

    %{credential: credential, private_key: private_key}
  end

  describe "verify_authentication_response/1" do
    test "accepts a complete browser response and returns update information", context do
      response = browser_response(context.private_key)

      assert {:ok, %AuthenticationResult{} = result} = verify(response, context.credential)

      assert result.credential_id == context.credential.id
      assert result.new_sign_count == 42
      assert result.user_verified
      assert result.credential_device_type == :multi_device
      assert result.credential_backed_up
      assert result.authenticator_extension_results == %{}
      assert result.client_extension_results == %{"appid" => false}
      assert result.authenticator_attachment == "platform"
      assert result.user_handle == @user_handle
      assert result.origin == "https://example.com"
      assert result.rp_id == "example.com"
    end

    test "requires the complete outer credential object", context do
      assert verify(%{"response" => %{}}, context.credential) ==
               {:error, {:missing_field, "id"}}
    end

    test "rejects malformed base64url in every binary browser field", context do
      for path <- [
            ["id"],
            ["rawId"],
            ["response", "clientDataJSON"],
            ["response", "authenticatorData"],
            ["response", "signature"],
            ["response", "userHandle"]
          ] do
        response = put_in(browser_response(context.private_key), path, "not+base64")
        assert {:error, _reason} = verify(response, context.credential)
      end
    end

    test "rejects credential ID mismatches", context do
      other_id = Base.url_encode64(:binary.copy(<<99>>, 16), padding: false)

      response =
        context.private_key
        |> browser_response()
        |> Map.put("id", other_id)
        |> Map.put("rawId", other_id)

      assert verify(response, context.credential) == {:error, :credential_id_mismatch}
    end

    test "rejects a user handle mismatch", context do
      response =
        put_in(
          browser_response(context.private_key),
          ["response", "userHandle"],
          Base.url_encode64(<<1>>, padding: false)
        )

      assert verify(response, context.credential) == {:error, :user_handle_mismatch}
    end

    test "accepts a null user handle for a non-discoverable assertion", context do
      response = put_in(browser_response(context.private_key), ["response", "userHandle"], nil)
      assert {:ok, %AuthenticationResult{user_handle: nil}} = verify(response, context.credential)
    end

    test "rejects backup state without backup eligibility", context do
      response = browser_response(context.private_key, 0x15)
      assert verify(response, context.credential) == {:error, :invalid_backup_flags}
    end

    test "rejects a credential device-type change", context do
      response = browser_response(context.private_key, 0x05)

      assert verify(response, context.credential) ==
               {:error, :credential_device_type_mismatch}
    end

    test "rejects counter rollback", context do
      credential = %{context.credential | sign_count: 42}
      response = browser_response(context.private_key)
      assert verify(response, credential) == {:error, :invalid_signature_counter}
    end

    test "requires user verification by default", context do
      response = browser_response(context.private_key, 0x19)
      assert verify(response, context.credential) == {:error, :user_verification_required}
    end

    test "rejects trailing authenticator bytes without the extension flag", context do
      response = browser_response(context.private_key, 0x1D, <<0>>)
      assert verify(response, context.credential) == {:error, :unexpected_authenticator_data}
    end

    test "returns errors instead of raising for arbitrary public input", context do
      for input <- [nil, "response", [], %{}, %{"id" => 1}] do
        assert {:error, _reason} =
                 ExSwan.verify_authentication_response(
                   response: input,
                   expected_challenge: @challenge,
                   expected_origin: "https://example.com",
                   expected_rp_id: "example.com",
                   credential: context.credential
                 )
      end
    end
  end

  defp verify(response, credential) do
    ExSwan.verify_authentication_response(
      response: response,
      expected_challenge: @challenge,
      expected_origin: "https://example.com",
      expected_rp_id: "example.com",
      credential: credential
    )
  end

  defp browser_response(private_key, flags \\ 0x1D, trailing \\ <<>>) do
    id = Base.url_encode64(@credential_id, padding: false)
    client_data_json = Jason.encode!(client_data())
    authenticator_data = authenticator_data(flags, trailing)
    signed_data = authenticator_data <> :crypto.hash(:sha256, client_data_json)
    signature = :crypto.sign(:ecdsa, :sha256, signed_data, [private_key, :secp256r1])

    %{
      "id" => id,
      "rawId" => id,
      "type" => "public-key",
      "authenticatorAttachment" => "platform",
      "clientExtensionResults" => %{"appid" => false},
      "response" => %{
        "clientDataJSON" => Base.url_encode64(client_data_json, padding: false),
        "authenticatorData" => Base.url_encode64(authenticator_data, padding: false),
        "signature" => Base.url_encode64(signature, padding: false),
        "userHandle" => Base.url_encode64(@user_handle, padding: false)
      }
    }
  end

  defp client_data do
    %{
      "type" => "webauthn.get",
      "challenge" => Base.url_encode64(@challenge, padding: false),
      "origin" => "https://example.com",
      "crossOrigin" => false
    }
  end

  defp authenticator_data(flags, trailing) do
    :crypto.hash(:sha256, "example.com") <> <<flags, 42::32-big>> <> trailing
  end
end
