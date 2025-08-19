defmodule PhoenixWebauthnDemo.Repo.Migrations.CreateWebauthnCredentials do
  use Ecto.Migration

  def change do
    create table(:webauthn_credentials) do
      add(:user_id, references(:users, on_delete: :delete_all), null: false)
      add(:credential_id, :string, null: false)
      add(:public_key, :binary, null: false)
      add(:sign_count, :integer, default: 0)
      add(:name, :string)
      add(:transports, {:array, :string}, default: [])
      add(:backup_eligible, :boolean)
      add(:backup_state, :boolean)
      add(:last_used_at, :utc_datetime)

      timestamps()
    end

    create(unique_index(:webauthn_credentials, [:credential_id]))
    create(index(:webauthn_credentials, [:user_id]))
  end
end
