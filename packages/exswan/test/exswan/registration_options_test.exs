defmodule ExSwan.RegistrationOptionsTest do
  use ExUnit.Case, async: true

  alias ExSwan.{Credential, Registration}

  setup do
    rp = %Credential.RelyingParty{id: "example.com", name: "Example Corp"}

    user = %Credential.User{
      id: :crypto.strong_rand_bytes(32),
      name: "user@example.com",
      display_name: "User"
    }

    %{rp: rp, user: user}
  end

  describe "authenticator preference hints" do
    # Reference: vendor/SimpleWebAuthn/packages/server/src/registration/generateRegistrationOptions.test.ts

    test "should generate empty hints when no preference is specified", %{rp: rp, user: user} do
      {:ok, options} =
        Registration.generate_creation_options(rp, user, preferred_authenticator_type: nil)

      assert options.hints == nil
    end

    test "should map 'securityKey' authenticator preference to hint and attachment", %{
      rp: rp,
      user: user
    } do
      {:ok, options} =
        Registration.generate_creation_options(rp, user,
          preferred_authenticator_type: "securityKey"
        )

      assert options.hints == ["security-key"]
      # Should also set authenticator attachment for backwards compatibility
      assert Map.get(options.authenticator_selection || %{}, :authenticator_attachment) ==
               "cross-platform"
    end

    test "should map 'localDevice' authenticator preference to hint and attachment", %{
      rp: rp,
      user: user
    } do
      {:ok, options} =
        Registration.generate_creation_options(rp, user,
          preferred_authenticator_type: "localDevice"
        )

      assert options.hints == ["client-device"]

      assert Map.get(options.authenticator_selection || %{}, :authenticator_attachment) ==
               "platform"
    end

    test "should map 'remoteDevice' authenticator preference to hint and attachment", %{
      rp: rp,
      user: user
    } do
      {:ok, options} =
        Registration.generate_creation_options(rp, user,
          preferred_authenticator_type: "remoteDevice"
        )

      assert options.hints == ["hybrid"]

      assert Map.get(options.authenticator_selection || %{}, :authenticator_attachment) ==
               "cross-platform"
    end

    test "should preserve existing authenticator selection when adding hints", %{
      rp: rp,
      user: user
    } do
      existing_selection = %{
        user_verification: "required",
        resident_key: "preferred"
      }

      {:ok, options} =
        Registration.generate_creation_options(rp, user,
          preferred_authenticator_type: "securityKey",
          authenticator_selection: existing_selection
        )

      assert options.hints == ["security-key"]
      # Should preserve existing settings
      assert options.authenticator_selection.user_verification == "required"
      assert options.authenticator_selection.resident_key == "preferred"
      # Should add attachment
      assert options.authenticator_selection.authenticator_attachment == "cross-platform"
    end
  end

  describe "options_to_json/1 with hints" do
    test "should include hints in JSON output", %{rp: rp, user: user} do
      {:ok, options} =
        Registration.generate_creation_options(rp, user,
          preferred_authenticator_type: "securityKey"
        )

      json = Registration.options_to_json(options)

      assert json["hints"] == ["security-key"]
    end

    test "should omit hints when nil", %{rp: rp, user: user} do
      {:ok, options} = Registration.generate_creation_options(rp, user)

      json = Registration.options_to_json(options)

      refute Map.has_key?(json, "hints")
    end
  end

  describe "advertised algorithms" do
    test "advertises only ES256 by default", %{rp: rp, user: user} do
      {:ok, options} = Registration.generate_creation_options(rp, user)

      algorithms = Enum.map(options.pub_key_cred_params, & &1.alg)
      assert algorithms == [-7]
    end
  end
end
