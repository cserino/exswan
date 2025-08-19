defmodule ExWebauthn.CredentialTest do
  use ExUnit.Case
  alias ExWebauthn.Credential

  describe "Credential structs" do
    test "creates valid credential descriptor" do
      descriptor = %Credential.Descriptor{
        type: :public_key,
        id: <<1, 2, 3, 4>>,
        transports: ["usb", "nfc"]
      }

      assert descriptor.type == :public_key
      assert descriptor.id == <<1, 2, 3, 4>>
      assert descriptor.transports == ["usb", "nfc"]
    end

    test "creates valid user entity" do
      user = %Credential.User{
        id: <<1, 2, 3, 4>>,
        name: "testuser",
        display_name: "Test User"
      }

      assert user.id == <<1, 2, 3, 4>>
      assert user.name == "testuser"
      assert user.display_name == "Test User"
    end

    test "creates valid relying party entity" do
      rp = %Credential.RelyingParty{
        id: "example.com",
        name: "Example Corp",
        icon: "https://example.com/icon.png"
      }

      assert rp.id == "example.com"
      assert rp.name == "Example Corp"
      assert rp.icon == "https://example.com/icon.png"
    end

    test "creates valid credential parameters" do
      params = %Credential.Parameters{
        type: :public_key,
        alg: -7
      }

      assert params.type == :public_key
      assert params.alg == -7
    end
  end
end
