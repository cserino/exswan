defmodule ExSwan.Test.AuthenticatorTest do
  use ExUnit.Case, async: true
  doctest ExSwan.Test.Authenticator

  alias ExSwan.{AuthenticationResult, RegistrationResult}
  alias ExSwan.Test.Authenticator

  @challenge :binary.copy(<<7>>, 32)
  @origin "https://example.com"
  @rp_id "example.com"
  @user_handle :binary.copy(<<8>>, 32)

  test "one authenticator completes registration and authentication" do
    authenticator = Authenticator.new(user_handle: @user_handle)

    registration_response =
      Authenticator.registration_response(authenticator,
        challenge: @challenge,
        origin: @origin,
        rp_id: @rp_id
      )

    assert {:ok, %RegistrationResult{credential: credential}} =
             ExSwan.verify_registration_response(
               response: registration_response,
               expected_challenge: @challenge,
               expected_origin: @origin,
               expected_rp_id: @rp_id
             )

    authentication_response =
      Authenticator.authentication_response(authenticator,
        challenge: @challenge,
        origin: @origin,
        rp_id: @rp_id,
        user_handle: @user_handle
      )

    assert {:ok, %AuthenticationResult{new_sign_count: 1}} =
             ExSwan.verify_authentication_response(
               response: authentication_response,
               expected_challenge: @challenge,
               expected_origin: @origin,
               expected_rp_id: @rp_id,
               expected_user_handle: @user_handle,
               credential: credential
             )
  end

  test "semantic overrides and tampering exercise failures" do
    authenticator = Authenticator.new()
    credential = Authenticator.credential(authenticator)

    wrong_origin =
      Authenticator.authentication_response(authenticator,
        challenge: @challenge,
        origin: "https://evil.example",
        rp_id: @rp_id
      )

    assert {:error, :origin_mismatch} = verify(wrong_origin, credential)

    valid =
      Authenticator.authentication_response(authenticator,
        challenge: @challenge,
        origin: @origin,
        rp_id: @rp_id
      )

    assert {:error, :signature_verification_failed} =
             valid |> Authenticator.tamper(:signature) |> verify(credential)
  end

  test "credential is deterministic and ready for persistence" do
    assert Authenticator.credential(Authenticator.new()) ==
             Authenticator.credential(Authenticator.new())
  end

  defp verify(response, credential) do
    ExSwan.verify_authentication_response(
      response: response,
      expected_challenge: @challenge,
      expected_origin: @origin,
      expected_rp_id: @rp_id,
      credential: credential
    )
  end
end
