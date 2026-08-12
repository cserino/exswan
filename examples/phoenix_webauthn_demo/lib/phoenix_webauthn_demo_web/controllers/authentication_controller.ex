defmodule PhoenixWebauthnDemoWeb.AuthenticationController do
  use PhoenixWebauthnDemoWeb, :controller

  alias ExSwan.Plug.Response
  alias PhoenixWebauthnDemo.{Accounts, Repo, WebAuthn}
  alias PhoenixWebauthnDemo.Accounts.User

  @ceremony_store {ExSwan.Plug.CeremonyStore.Memory, PhoenixWebauthnDemo.CeremonyStore}

  def new(conn, _params), do: render(conn, :new)

  def begin_authentication(conn, params) do
    user = user_from_params(params)

    opts = [
      rp_id: WebAuthn.rp_id(),
      origin: WebAuthn.origin(),
      allow_credentials: WebAuthn.allowed_credentials(user),
      ceremony_store: @ceremony_store
    ]

    opts = if user, do: Keyword.put(opts, :expected_user_handle, user.user_handle), else: opts

    case ExSwan.Plug.begin_authentication(conn, opts) do
      {:ok, conn, options_json} -> json(conn, options_json)
      {:error, reason} -> Response.send_error(conn, reason)
    end
  end

  def complete_authentication(conn, browser_response) do
    case ExSwan.Plug.finish_authentication(conn,
           response: browser_response,
           store: WebAuthn,
           ceremony_store: @ceremony_store
         ) do
      {:ok, conn, _authentication, credential} ->
        user = Repo.get!(User, credential.user_id)

        conn
        |> clear_session()
        |> put_session(:current_user_id, user.id)
        |> json(%{success: true, redirect: ~p"/dashboard"})

      {:error, reason} ->
        Response.send_error(conn, reason)
    end
  end

  def delete(conn, _params) do
    conn
    |> clear_session()
    |> redirect(to: ~p"/")
  end

  defp user_from_params(%{"email" => email}) when is_binary(email) and email != "",
    do: Accounts.get_user_by_email(email)

  defp user_from_params(_params), do: nil
end
