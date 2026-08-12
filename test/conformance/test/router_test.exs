defmodule ExSwan.Conformance.RouterTest do
  use ExUnit.Case, async: false

  import Plug.Test
  import Plug.Conn, only: [put_req_header: 3]

  alias ExSwan.Conformance.Router

  test "registration options use the official success envelope" do
    conn =
      :post
      |> conn(
        "/attestation/options",
        Jason.encode!(%{"username" => "test-user", "displayName" => "Test User"})
      )
      |> put_req_header("content-type", "application/json")
      |> Router.call([])

    body = Jason.decode!(conn.resp_body)
    assert conn.status == 200
    assert body["status"] == "ok"
    assert body["errorMessage"] == ""
    assert body["pubKeyCredParams"] == [%{"alg" => -7, "type" => "public-key"}]
    assert is_binary(body["challenge"])
  end

  test "unsupported attestation fails without advertising it" do
    conn =
      :post
      |> conn(
        "/attestation/options",
        Jason.encode!(%{
          "username" => "test-user",
          "displayName" => "Test User",
          "attestation" => "direct"
        })
      )
      |> put_req_header("content-type", "application/json")
      |> Router.call([])

    assert conn.status == 400

    assert Jason.decode!(conn.resp_body) == %{
             "status" => "failed",
             "errorMessage" => "Verification failed"
           }
  end

  test "authentication options use the official success envelope" do
    conn =
      :post
      |> conn(
        "/assertion/options",
        Jason.encode!(%{"username" => "unknown-user", "userVerification" => "required"})
      )
      |> put_req_header("content-type", "application/json")
      |> Router.call([])

    body = Jason.decode!(conn.resp_body)
    assert conn.status == 200
    assert body["status"] == "ok"
    assert body["errorMessage"] == ""
    assert body["userVerification"] == "required"
    assert body["rpId"] == "localhost"
  end
end
