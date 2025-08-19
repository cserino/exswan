defmodule PhoenixWebauthnDemo.Accounts do
  @moduledoc """
  The Accounts context.
  """

  import Ecto.Query, warn: false
  alias PhoenixWebauthnDemo.Repo
  alias PhoenixWebauthnDemo.Accounts.User

  @doc """
  Returns the list of users.
  """
  def list_users do
    Repo.all(User)
  end

  @doc """
  Gets a single user by id.
  """
  def get_user!(id), do: Repo.get!(User, id)

  @doc """
  Gets a user by email.
  """
  def get_user_by_email(email) when is_binary(email) do
    Repo.get_by(User, email: email)
  end

  @doc """
  Gets a user by user handle (WebAuthn user ID).
  """
  def get_user_by_handle(user_handle) when is_binary(user_handle) do
    Repo.get_by(User, user_handle: user_handle)
  end

  @doc """
  Creates a user.
  """
  def create_user(attrs \\ %{}) do
    attrs_with_handle =
      Map.put_new_lazy(attrs, "user_handle", fn ->
        :crypto.strong_rand_bytes(32)
      end)

    %User{}
    |> User.changeset(attrs_with_handle)
    |> Repo.insert()
  end

  @doc """
  Updates a user.
  """
  def update_user(%User{} = user, attrs) do
    user
    |> User.changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Deletes a user.
  """
  def delete_user(%User{} = user) do
    Repo.delete(user)
  end

  @doc """
  Returns an `%Ecto.Changeset{}` for tracking user changes.
  """
  def change_user(%User{} = user, attrs \\ %{}) do
    User.changeset(user, attrs)
  end
end
