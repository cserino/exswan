defmodule PhoenixWebauthnDemoWeb.AuthenticationController do
  use PhoenixWebauthnDemoWeb, :controller

  alias PhoenixWebauthnDemo.Accounts
  alias PhoenixWebauthnDemo.WebAuthn

  def new(conn, _params) do
    render(conn, :new)
  end

  def begin_authentication(conn, params) do
    # Support both usernameless and user-specific authentication
    user =
      case params["email"] do
        email when is_binary(email) and email != "" ->
          Accounts.get_user_by_email(email)

        _ ->
          nil
      end

    case WebAuthn.generate_authentication_options(user) do
      {:ok, options} ->
        # Store challenge in session for verification
        conn
        |> put_session(:webauthn_challenge, options.challenge)
        |> json(options)

      {:error, reason} ->
        conn
        |> put_status(:internal_server_error)
        |> json(%{error: to_string(reason)})
    end
  end

  def complete_authentication(conn, params) do
    challenge = get_session(conn, :webauthn_challenge)

    if challenge do
      # Reconstruct options for verification
      options = %{challenge: challenge}

      case WebAuthn.verify_authentication(params, options) do
        {:ok, user} ->
          conn
          |> clear_session()
          |> put_session(:current_user_id, user.id)
          |> json(%{success: true, redirect: ~p"/dashboard"})

        {:error, reason} ->
          conn
          |> put_status(:bad_request)
          |> json(%{error: to_string(reason)})
      end
    else
      conn
      |> put_status(:bad_request)
      |> json(%{error: "Invalid session"})
    end
  end

  def delete(conn, _params) do
    conn
    |> clear_session()
    |> redirect(to: ~p"/")
  end
end
