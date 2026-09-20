defmodule ExSwan.CommonTest do
  use ExUnit.Case, async: true

  alias ExSwan.Common

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
