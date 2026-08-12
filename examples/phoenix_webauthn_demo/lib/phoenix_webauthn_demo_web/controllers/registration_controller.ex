defmodule PhoenixWebauthnDemoWeb.RegistrationController do
  use PhoenixWebauthnDemoWeb, :controller

  alias PhoenixWebauthnDemo.Accounts
  alias PhoenixWebauthnDemo.WebAuthn

  def new(conn, _params) do
    changeset = Accounts.change_user(%Accounts.User{})
    render(conn, :new, changeset: changeset)
  end

  def create(conn, %{"user" => user_params}) do
    case Accounts.create_user(user_params) do
      {:ok, user} ->
        conn
        |> put_flash(:info, "Account created successfully! Now add a passkey.")
        |> redirect(to: ~p"/register/passkey?email=#{user.email}")

      {:error, %Ecto.Changeset{} = changeset} ->
        render(conn, :new, changeset: changeset)
    end
  end

  def passkey(conn, %{"email" => email}) do
    case Accounts.get_user_by_email(email) do
      nil ->
        conn
        |> put_flash(:error, "User not found")
        |> redirect(to: ~p"/register")

      user ->
        render(conn, :passkey, user: user)
    end
  end

  def begin_passkey_registration(conn, %{"email" => email}) do
    case Accounts.get_user_by_email(email) do
      nil ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "User not found"})

      user ->
        case WebAuthn.generate_registration_options(user) do
          {:ok, options} ->
            # Store challenge in session for verification
            conn
            |> put_session(:webauthn_challenge, options.challenge)
            |> put_session(:webauthn_user_id, user.id)
            |> json(options)

          {:error, reason} ->
            conn
            |> put_status(:internal_server_error)
            |> json(%{error: to_string(reason)})
        end
    end
  end

  def complete_passkey_registration(conn, %{"response" => response}) do
    with user_id when not is_nil(user_id) <- get_session(conn, :webauthn_user_id),
         challenge when not is_nil(challenge) <- get_session(conn, :webauthn_challenge),
         user <- Accounts.get_user!(user_id) do
      # Reconstruct options for verification - need to create proper options struct
      rp = %ExSwan.Credential.RelyingParty{
        id: Application.get_env(:phoenix_webauthn_demo, :webauthn)[:rp_id] || "localhost",
        name: "Phoenix WebAuthn Demo"
      }

      webauthn_user = %ExSwan.Credential.User{
        id: user.user_handle,
        name: user.email,
        display_name: user.display_name || user.email
      }

      options = %ExSwan.Attestation.CreationOptions{
        challenge: challenge,
        rp: rp,
        user: webauthn_user,
        pub_key_cred_params: [
          # ES256
          %ExSwan.Credential.Parameters{type: :public_key, alg: -7},
          # RS256
          %ExSwan.Credential.Parameters{type: :public_key, alg: -257}
        ],
        timeout: 60_000,
        exclude_credentials: [],
        authenticator_selection: %ExSwan.Attestation.AuthenticatorSelection{
          authenticator_attachment: nil,
          require_resident_key: false,
          resident_key: "preferred",
          user_verification: "preferred"
        },
        attestation: "none"
      }

      case WebAuthn.verify_registration(response, options, user) do
        {:ok, _credential} ->
          conn
          |> clear_session()
          |> put_session(:current_user_id, user.id)
          |> json(%{success: true, redirect: ~p"/dashboard"})

        {:error, %Ecto.Changeset{} = changeset} ->
          conn
            |> put_status(:bad_request)
            |> json(%{error: Ecto.Changeset.traverse_errors(changeset, &format_error/1)})

        {:error, reason} ->
          conn
          |> put_status(:bad_request)
          |> json(%{error: to_string(reason)})
      end
    else
      nil ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "Invalid session"})
    end
  end

  defp format_error({msg, opts}) do
  Regex.replace(~r"%{(\w+)}", msg, fn _, key ->
    opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
  end)
end
end
