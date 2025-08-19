defmodule PhoenixWebauthnDemoWeb.DashboardController do
  use PhoenixWebauthnDemoWeb, :controller

  alias PhoenixWebauthnDemo.Accounts
  alias PhoenixWebauthnDemo.WebAuthn

  plug(:require_authenticated_user)

  def index(conn, _params) do
    user = conn.assigns.current_user
    credentials = WebAuthn.list_user_credentials(user)
    render(conn, :index, user: user, credentials: credentials)
  end

  defp require_authenticated_user(conn, _opts) do
    case get_session(conn, :current_user_id) do
      nil ->
        conn
        |> put_flash(:error, "You must be signed in to access this page.")
        |> redirect(to: ~p"/signin")
        |> halt()

      user_id ->
        user = Accounts.get_user!(user_id)
        assign(conn, :current_user, user)
    end
  end
end
