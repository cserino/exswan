defmodule ExSwanTest do
  use ExUnit.Case
  doctest ExSwan

  describe "registration convenience functions" do
    test "generates browser-ready registration options and server ceremony state" do
      challenge = :binary.copy(<<1>>, 32)

      assert {:ok, %{options: options, ceremony: ceremony}} =
               ExSwan.generate_registration_options(
                 rp_name: "Example",
                 rp_id: "example.com",
                 user_name: "person@example.com",
                 user_id: <<1, 2, 3, 4>>,
                 challenge: challenge
               )

      assert options["rp"] == %{"id" => "example.com", "name" => "Example"}
      assert options["user"]["id"] == "AQIDBA"
      assert options["pubKeyCredParams"] == [%{"alg" => -7, "type" => "public-key"}]
      assert ceremony.challenge == challenge
      assert ceremony.rp_id == "example.com"
      assert ceremony.user_id == <<1, 2, 3, 4>>
    end

    test "reports a missing required registration option" do
      assert ExSwan.generate_registration_options(rp_name: "Example") ==
               {:error, {:missing_option, :rp_id}}
    end
  end

  describe "authentication convenience functions" do
    test "generates browser-ready authentication options and server ceremony state" do
      challenge = :binary.copy(<<2>>, 32)

      assert {:ok, %{options: options, ceremony: ceremony}} =
               ExSwan.generate_authentication_options(
                 rp_id: "example.com",
                 challenge: challenge
               )

      assert options["challenge"] == Base.url_encode64(challenge, padding: false)
      assert options["rpId"] == "example.com"
      assert ceremony.challenge == challenge
      assert ceremony.rp_id == "example.com"
    end

    test "reports a missing RP ID" do
      assert ExSwan.generate_authentication_options([]) ==
               {:error, {:missing_option, :rp_id}}
    end
  end

  describe "version/0" do
    test "returns version string" do
      version = ExSwan.version()
      assert is_binary(version)
      assert String.match?(version, ~r/^\d+\.\d+\.\d+/)
    end
  end
end
