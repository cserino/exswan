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

  test "generated registration mutations return their documented errors" do
    fixture = load_fixture()
    ceremony = fixture["ceremony"]
    challenge = Base.url_decode64!(fixture["registration"]["challenge"], padding: false)

    for {name, invalid_case} <- fixture["invalid"]["registration"] do
      assert ExSwan.verify_registration_response(
               response: invalid_case["response"],
               expected_challenge: challenge,
               expected_origin: ceremony["origin"],
               expected_rp_id: Map.get(invalid_case, "expectedRpID", ceremony["rpID"])
             ) == {:error, expected_error(invalid_case["expectedError"])},
             "registration mutation #{name} returned an unexpected result"
    end
  end

  test "generated authentication mutations return their documented errors" do
    fixture = load_fixture()
    ceremony = fixture["ceremony"]
    credential = register_credential(fixture)
    challenge = Base.url_decode64!(fixture["authentication"]["challenge"], padding: false)
    user_id = Base.url_decode64!(ceremony["userID"], padding: false)

    for {name, invalid_case} <- fixture["invalid"]["authentication"] do
      assert ExSwan.verify_authentication_response(
               response: invalid_case["response"],
               expected_challenge: challenge,
               expected_origin: ceremony["origin"],
               expected_rp_id: Map.get(invalid_case, "expectedRpID", ceremony["rpID"]),
               expected_user_handle: user_id,
               credential: credential
             ) == {:error, expected_error(invalid_case["expectedError"])},
             "authentication mutation #{name} returned an unexpected result"
    end
  end

  defp register_credential(fixture) do
    ceremony = fixture["ceremony"]
    challenge = Base.url_decode64!(fixture["registration"]["challenge"], padding: false)

    {:ok, registration} =
      ExSwan.verify_registration_response(
        response: ceremony["registrationResponse"],
        expected_challenge: challenge,
        expected_origin: ceremony["origin"],
        expected_rp_id: ceremony["rpID"]
      )

    registration.credential
  end

  defp expected_error("challenge_mismatch"), do: :challenge_mismatch
  defp expected_error("origin_mismatch"), do: :origin_mismatch
  defp expected_error("invalid_client_data_type"), do: :invalid_client_data_type
  defp expected_error("rp_id_hash_mismatch"), do: :rp_id_hash_mismatch
  defp expected_error("credential_id_mismatch"), do: :credential_id_mismatch

  defp load_fixture do
    @fixture_path
    |> File.read!()
    |> Jason.decode!()
  end
end
