defmodule PhoenixWebauthnDemo.Repo.Migrations.CreateUsers do
  use Ecto.Migration

  def change do
    create table(:users) do
      add(:email, :string, null: false)
      add(:display_name, :string)
      add(:user_handle, :binary, null: false)

      timestamps()
    end

    create(unique_index(:users, [:email]))
    create(unique_index(:users, [:user_handle]))
  end
end
