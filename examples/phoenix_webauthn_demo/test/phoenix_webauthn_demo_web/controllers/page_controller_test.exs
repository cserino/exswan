defmodule PhoenixWebauthnDemoWeb.PageControllerTest do
  use PhoenixWebauthnDemoWeb.ConnCase

  test "GET /", %{conn: conn} do
    conn = get(conn, ~p"/")
    assert html_response(conn, 200) =~ "Phoenix WebAuthn Demo"
  end
end
