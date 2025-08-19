defmodule PhoenixWebauthnDemo.WebAuthn.Credential do
  use Ecto.Schema
  import Ecto.Changeset

  schema "webauthn_credentials" do
    field(:credential_id, :string)
    field(:public_key, :binary)
    field(:sign_count, :integer, default: 0)
    field(:name, :string)
    field(:transports, {:array, :string}, default: [])
    field(:backup_eligible, :boolean)
    field(:backup_state, :boolean)
    field(:last_used_at, :utc_datetime)

    belongs_to(:user, PhoenixWebauthnDemo.Accounts.User)

    timestamps()
  end

  @doc false
  def changeset(credential, attrs) do
    credential
    |> cast(attrs, [
      :user_id,
      :credential_id,
      :public_key,
      :sign_count,
      :name,
      :transports,
      :backup_eligible,
      :backup_state,
      :last_used_at
    ])
    |> validate_required([:user_id, :credential_id, :public_key])
    |> foreign_key_constraint(:user_id)
    |> unique_constraint(:credential_id)
    |> validate_number(:sign_count, greater_than_or_equal_to: 0)
  end
end
