defmodule PhoenixWebauthnDemoWeb.RegistrationController do
  use PhoenixWebauthnDemoWeb, :controller

  alias ExSwan.Plug.Response
  alias PhoenixWebauthnDemo.Accounts
  alias PhoenixWebauthnDemo.WebAuthn

  @ceremony_store {ExSwan.Plug.CeremonyStore.Memory, PhoenixWebauthnDemo.CeremonyStore}

  def new(conn, _params) do
    changeset = Accounts.change_user(%Accounts.User{})
    render(conn, :new, changeset: changeset)
  end

  def create(conn, %{"user" => user_params}) do
    case Accounts.create_user(user_params) do
      {:ok, user} ->
        conn
        |> put_session(:pending_registration_user_id, user.id)
        |> put_flash(:info, "Account created successfully! Now add a passkey.")
        |> redirect(to: ~p"/register/passkey?email=#{user.email}")

      {:error, %Ecto.Changeset{} = changeset} ->
        render(conn, :new, changeset: changeset)
    end
  end

  def passkey(conn, %{"email" => email}) do
    case authorized_user(conn, email) do
      nil ->
        conn
        |> put_flash(:error, "Registration authorization is missing or expired")
        |> redirect(to: ~p"/register")

      user ->
        render(conn, :passkey, user: user)
    end
  end

  def begin_passkey_registration(conn, %{"email" => email}) do
    case authorized_user(conn, email) do
      nil ->
        Response.send_error(conn, :registration_not_authorized)

      user ->
        case ExSwan.Plug.begin_registration(conn,
               user: user,
               user_handle: user.user_handle,
               user_name: user.email,
               user_display_name: user.display_name || user.email,
               rp_name: "Phoenix WebAuthn Demo",
               rp_id: WebAuthn.rp_id(),
               origin: WebAuthn.origin(),
               exclude_credentials: WebAuthn.allowed_credentials(user),
               ceremony_store: @ceremony_store
             ) do
          {:ok, conn, options_json} -> json(conn, options_json)
          {:error, reason} -> Response.send_error(conn, reason)
        end
    end
  end

  def complete_passkey_registration(conn, browser_response) do
    case ExSwan.Plug.finish_registration(conn,
           response: browser_response,
           store: WebAuthn,
           ceremony_store: @ceremony_store
         ) do
      {:ok, conn, _registration, credential} ->
        conn
        |> clear_session()
        |> put_session(:current_user_id, credential.user_id)
        |> json(%{success: true, redirect: ~p"/dashboard"})

      {:error, reason} ->
        Response.send_error(conn, reason)
    end
  end

  defp authorized_user(conn, email) do
    requested_user = Accounts.get_user_by_email(email)

    authorized_id =
      get_session(conn, :current_user_id) || get_session(conn, :pending_registration_user_id)

    case requested_user do
      %{id: ^authorized_id} = user -> user
      _other -> nil
    end
  end
end
