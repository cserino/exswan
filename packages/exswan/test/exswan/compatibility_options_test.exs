defmodule ExSwan.CompatibilityOptionsTest do
  use ExUnit.Case, async: true

  alias ExSwan.Credential

  @fixture_path Path.expand(
                  "../../../../test/compatibility/fixtures/options.json",
                  __DIR__
                )

  test "registration options use the pinned SimpleWebAuthn browser wire shape" do
    fixture = load_fixture()
    reference = fixture["registration"]
    challenge = Base.url_decode64!(reference["challenge"], padding: false)

    assert {:ok, %{options: options}} =
             ExSwan.generate_registration_options(
               rp_name: reference["rp"]["name"],
               rp_id: reference["rp"]["id"],
               user_name: reference["user"]["name"],
               user_display_name: reference["user"]["displayName"],
               user_id: Base.url_decode64!(reference["user"]["id"], padding: false),
               challenge: challenge,
               timeout: reference["timeout"],
               attestation: reference["attestation"]
             )

    for field <- ~w(challenge rp user pubKeyCredParams timeout attestation) do
      assert options[field] == reference[field]
    end
  end

  test "authentication options match the pinned SimpleWebAuthn reference" do
    fixture = load_fixture()
    reference = fixture["authentication"]
    [reference_credential] = reference["allowCredentials"]

    credential = %Credential.Descriptor{
      type: :public_key,
      id: reference_credential["id"],
      transports: reference_credential["transports"]
    }

    assert {:ok, %{options: options}} =
             ExSwan.generate_authentication_options(
               rp_id: reference["rpId"],
               challenge: Base.url_decode64!(reference["challenge"], padding: false),
               timeout: reference["timeout"],
               user_verification: reference["userVerification"],
               allow_credentials: [credential]
             )

    assert options == reference
  end

  defp load_fixture do
    @fixture_path
    |> File.read!()
    |> Jason.decode!()
  end
end
