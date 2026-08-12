defmodule ExSwan.Conformance.Store do
  @moduledoc false

  use Agent

  @behaviour ExSwan.Plug.Store

  def start_link(_opts), do: Agent.start_link(fn -> %{credentials: %{}} end, name: __MODULE__)

  def credentials(username) do
    Agent.get(__MODULE__, fn state ->
      state.credentials
      |> Map.values()
      |> Enum.filter(&(&1.username == username))
      |> Enum.map(& &1.credential)
    end)
  end

  @impl true
  def get_credential(id, _context) do
    Agent.get(__MODULE__, fn state ->
      case state.credentials[id] do
        nil -> {:error, :not_found}
        stored -> {:ok, stored.credential}
      end
    end)
  end

  @impl true
  def create_credential(username, registration, _context) do
    Agent.get_and_update(__MODULE__, fn state ->
      id = registration.credential.id

      if Map.has_key?(state.credentials, id) do
        {{:error, :duplicate}, state}
      else
        stored = %{username: username, credential: registration.credential}
        {{:ok, stored}, put_in(state, [:credentials, id], stored)}
      end
    end)
  end

  @impl true
  def update_credential(credential, authentication, _context) do
    Agent.get_and_update(__MODULE__, fn state ->
      case state.credentials[credential.id] do
        %{credential: %{sign_count: sign_count}} = stored
        when sign_count == credential.sign_count ->
          updated_credential = %{
            credential
            | sign_count: authentication.new_sign_count,
              credential_device_type: authentication.credential_device_type,
              credential_backed_up: authentication.credential_backed_up
          }

          updated = %{stored | credential: updated_credential}
          {{:ok, updated}, put_in(state, [:credentials, credential.id], updated)}

        _other ->
          {{:error, :stale_credential}, state}
      end
    end)
  end
end
