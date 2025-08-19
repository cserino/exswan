defmodule PhoenixWebauthnDemo.Accounts.User do
  use Ecto.Schema
  import Ecto.Changeset

  schema "users" do
    field(:email, :string)
    field(:display_name, :string)
    field(:user_handle, :binary)

    has_many(:webauthn_credentials, PhoenixWebauthnDemo.WebAuthn.Credential)

    timestamps()
  end

  @doc false
  def changeset(user, attrs) do
    user
    |> cast(attrs, [:email, :display_name, :user_handle])
    |> validate_required([:email])
    |> validate_format(:email, ~r/^[^\s]+@[^\s]+$/, message: "must have the @ sign and no spaces")
    |> validate_length(:email, max: 160)
    |> unsafe_validate_unique(:email, PhoenixWebauthnDemo.Repo)
    |> unique_constraint(:email)
    |> put_user_handle()
    |> unique_constraint(:user_handle)
  end

  defp put_user_handle(changeset) do
    case get_field(changeset, :user_handle) do
      nil -> put_change(changeset, :user_handle, :crypto.strong_rand_bytes(32))
      _ -> changeset
    end
  end
end
