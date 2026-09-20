defmodule ExSwan.CommonTest do
  use ExUnit.Case, async: true

  alias ExSwan.Common

  test "decoded and encoded client data return the same values and errors" do
    for json <- [
          ~s({"type":"webauthn.get","challenge":"AQ","origin":"https://example.com"}),
          ~s({"type":"webauthn.create"}),
          ~s({}),
          "null",
          "true",
          "1",
          ~s("text"),
          "[]",
          "{"
        ] do
      assert Common.parse_client_data_json(json, "webauthn.get") ==
               Common.parse_client_data(Base.url_encode64(json, padding: false), "webauthn.get")
    end

    for json <- ["null", "true", "1", ~s("text"), "[]", "{"] do
      assert Common.parse_client_data_json(json, "webauthn.get") ==
               {:error, :invalid_client_data_json}
    end
  end

  describe "parse_client_data/2" do
    test "rejects JSON values that are not objects" do
      encoded = Base.url_encode64("true", padding: false)

      assert Common.parse_client_data(encoded, "webauthn.get") ==
               {:error, :invalid_client_data_json}
    end

    test "rejects a missing challenge without raising" do
      client_data = Jason.encode!(%{"type" => "webauthn.get"})
      encoded = Base.url_encode64(client_data, padding: false)

      assert Common.parse_client_data(encoded, "webauthn.get") ==
               {:ok, {%{"type" => "webauthn.get"}, client_data}}

      assert Common.verify_challenge(nil, <<0::256>>) ==
               {:error, :invalid_challenge_encoding}
    end
  end
end
