defmodule PhoenixWebauthnDemo.WebAuthn do
  @moduledoc """
  Application-owned passkey persistence and identity policy for the demo.

  Protocol verification and ceremony lifecycle are owned by ExSwan and ExSwan.Plug.
  """

  @behaviour ExSwan.Plug.Store

  import Ecto.Query, warn: false

  alias ExSwan.{AuthenticationResult, RegistrationResult}
  alias PhoenixWebauthnDemo.Accounts.User
  alias PhoenixWebauthnDemo.Repo
  alias PhoenixWebauthnDemo.WebAuthn.Credential, as: StoredCredential

  @doc "Returns credentials belonging to a user."
  def list_user_credentials(%User{id: user_id}) do
    StoredCredential
    |> where([credential], credential.user_id == ^user_id)
    |> order_by([credential], desc: credential.last_used_at)
    |> Repo.all()
  end

  @doc "Returns a credential by its unpadded base64url identifier."
  def get_credential_by_id(credential_id) when is_binary(credential_id) do
    Repo.get_by(StoredCredential, credential_id: credential_id)
  end

  @doc "Deletes an application credential."
  def delete_credential(%StoredCredential{} = credential), do: Repo.delete(credential)

  @impl ExSwan.Plug.Store
  def get_credential(credential_id, _context) do
    case get_credential_by_id(credential_id) do
      nil -> {:error, :not_found}
      credential -> {:ok, to_exswan_credential(credential)}
    end
  end

  @impl ExSwan.Plug.Store
  def create_credential(%User{} = user, %RegistrationResult{} = registration, _context) do
    credential = registration.credential

    %StoredCredential{}
    |> StoredCredential.changeset(%{
      user_id: user.id,
      credential_id: credential.id,
      public_key: credential.public_key,
      sign_count: credential.sign_count,
      backup_eligible: registration.credential_device_type == :multi_device,
      backup_state: registration.credential_backed_up,
      transports: credential.transports || []
    })
    |> Repo.insert()
    |> normalize_insert_error()
  end

  @impl ExSwan.Plug.Store
  def update_credential(
        %ExSwan.Credential{} = credential,
        %AuthenticationResult{} = authentication,
        _context
      ) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    {updated, _rows} =
      StoredCredential
      |> where(
        [stored],
        stored.credential_id == ^credential.id and stored.sign_count == ^credential.sign_count
      )
      |> Repo.update_all(
        set: [
          sign_count: authentication.new_sign_count,
          backup_eligible: authentication.credential_device_type == :multi_device,
          backup_state: authentication.credential_backed_up,
          last_used_at: now
        ]
      )

    case updated do
      1 -> {:ok, get_credential_by_id(credential.id)}
      0 -> {:error, :stale_credential}
    end
  end

  @doc "Returns stored credentials in the core public value format."
  def allowed_credentials(nil), do: []

  def allowed_credentials(%User{} = user) do
    Enum.map(list_user_credentials(user), &to_exswan_credential/1)
  end

  @doc "Returns the configured relying-party ID."
  def rp_id do
    Application.get_env(:phoenix_webauthn_demo, :webauthn)[:rp_id] || "localhost"
  end

  @doc "Returns the configured browser origin."
  def origin do
    Application.get_env(:phoenix_webauthn_demo, :webauthn)[:origin] ||
      "http://localhost:4000"
  end

  defp to_exswan_credential(%StoredCredential{} = credential) do
    user = Repo.get!(User, credential.user_id)

    %ExSwan.Credential{
      id: credential.credential_id,
      public_key: credential.public_key,
      user_handle: user.user_handle,
      sign_count: credential.sign_count,
      transports: credential.transports || [],
      credential_device_type:
        if(credential.backup_eligible, do: :multi_device, else: :single_device),
      credential_backed_up: credential.backup_state || false
    }
  end

  defp normalize_insert_error({:ok, credential}), do: {:ok, credential}

  defp normalize_insert_error({:error, %Ecto.Changeset{} = changeset}) do
    case changeset.errors[:credential_id] do
      {_message, options} when is_list(options) ->
        if options[:constraint] == :unique, do: {:error, :duplicate}, else: {:error, changeset}

      _other ->
        {:error, changeset}
    end
  end
end
