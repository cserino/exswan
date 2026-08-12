defmodule ExSwan.CompatibilityCeremonyTest do
  use ExUnit.Case, async: true

  alias ExSwan.{AuthenticationResult, RegistrationResult}

  @fixture_path Path.expand(
                  "../../../../test/compatibility/fixtures/options.json",
                  __DIR__
                )

  test "pinned ES256 none fixture completes registration and authentication" do
    fixture = load_fixture()
    ceremony = fixture["ceremony"]
    expected = ceremony["expected"]
    user_id = Base.url_decode64!(ceremony["userID"], padding: false)

    registration_challenge =
      Base.url_decode64!(fixture["registration"]["challenge"], padding: false)

    assert {:ok, %RegistrationResult{} = registration} =
             ExSwan.verify_registration_response(
               response: ceremony["registrationResponse"],
               expected_challenge: registration_challenge,
               expected_origin: ceremony["origin"],
               expected_rp_id: ceremony["rpID"]
             )

    assert registration.credential.id == expected["credentialID"]
    assert registration.credential.sign_count == expected["registrationSignCount"]
    assert registration.attestation_format == :none
    assert registration.credential_device_type == :single_device
    refute registration.credential_backed_up

    authentication_challenge =
      Base.url_decode64!(fixture["authentication"]["challenge"], padding: false)

    assert {:ok, %AuthenticationResult{} = authentication} =
             ExSwan.verify_authentication_response(
               response: ceremony["authenticationResponse"],
               expected_challenge: authentication_challenge,
               expected_origin: ceremony["origin"],
               expected_rp_id: ceremony["rpID"],
               expected_user_handle: user_id,
               credential: registration.credential
             )

    assert authentication.credential_id == expected["credentialID"]
    assert authentication.new_sign_count == expected["authenticationSignCount"]
    assert authentication.credential_device_type == :single_device
    refute authentication.credential_backed_up
  end

  defp load_fixture do
    @fixture_path
    |> File.read!()
    |> Jason.decode!()
  end
end
