defmodule ExSwan.PublicVerifierPropertyTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  property "registration verification returns an error for arbitrary public input" do
    check all(response <- hostile_term(), max_runs: 250) do
      assert {:error, _reason} =
               ExSwan.verify_registration_response(
                 response: response,
                 expected_challenge: <<0::256>>,
                 expected_origin: "https://example.com",
                 expected_rp_id: "example.com"
               )
    end
  end

  property "authentication verification returns an error for arbitrary public input" do
    check all(
            response <- hostile_term(),
            credential <- hostile_term(),
            max_runs: 250
          ) do
      assert {:error, _reason} =
               ExSwan.verify_authentication_response(
                 response: response,
                 expected_challenge: <<0::256>>,
                 expected_origin: "https://example.com",
                 expected_rp_id: "example.com",
                 credential: credential
               )
    end
  end

  defp hostile_term do
    term()
  end
end
