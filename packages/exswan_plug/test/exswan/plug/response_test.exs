defmodule ExSwan.Plug.ResponseTest do
  use ExUnit.Case, async: true

  import Plug.Test
  import Plug.Conn, only: [get_resp_header: 2]

  alias ExSwan.Plug.Response

  test "success responses have stable status and JSON" do
    conn = Response.send_success(conn(:post, "/"), :registration)

    assert conn.status == 201
    assert Jason.decode!(conn.resp_body) == %{"verified" => true}
    assert ["application/json; charset=utf-8"] = get_resp_header(conn, "content-type")
  end

  test "detailed verifier failures collapse to a coarse response" do
    challenge = Response.send_error(conn(:post, "/"), :challenge_mismatch)
    signature = Response.send_error(conn(:post, "/"), :invalid_signature)

    assert challenge.status == signature.status
    assert challenge.resp_body == signature.resp_body
    assert Jason.decode!(challenge.resp_body) == %{"error" => "verification_failed"}
  end

  test "authorization, duplicate, and consumed ceremony errors remain stable" do
    assert response(:registration_not_authorized) ==
             {403, %{"error" => "registration_not_authorized"}}

    assert response(:duplicate) == {409, %{"error" => "credential_already_registered"}}
    assert response(:expired) == {400, %{"error" => "ceremony_unavailable"}}
    assert response(:not_found) == {400, %{"error" => "ceremony_unavailable"}}
  end

  defp response(reason) do
    conn = Response.send_error(conn(:post, "/"), reason)
    {conn.status, Jason.decode!(conn.resp_body)}
  end
end
