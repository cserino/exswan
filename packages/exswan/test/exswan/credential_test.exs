defmodule ExSwan.CredentialTest do
  use ExUnit.Case
  alias ExSwan.Credential

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

  describe "Credential.Descriptor.normalize_list/1" do
    test "preserves descriptors and converts stored credentials in order" do
      descriptor = %Credential.Descriptor{type: :public_key, id: "first", transports: []}
      credential = %Credential{id: "second", transports: ["internal"]}

      assert {:ok, [^descriptor, normalized]} =
               Credential.Descriptor.normalize_list([descriptor, credential])

      assert normalized == %Credential.Descriptor{
               type: :public_key,
               id: "second",
               transports: ["internal"]
             }
    end

    test "rejects values that cannot become descriptors" do
      assert Credential.Descriptor.normalize_list([%{}]) ==
               {:error, :invalid_credential_descriptor}
    end
  end
end
