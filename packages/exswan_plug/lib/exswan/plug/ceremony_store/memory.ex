defmodule ExSwan.Plug.CeremonyStore.Memory do
  @moduledoc """
  Deterministic in-memory ceremony store intended for tests and single-node use.

  The caller supplies monotonic timestamps to make expiration tests deterministic.
  Use a shared transactional store when ceremonies can finish on multiple nodes.
  """

  use GenServer

  @behaviour ExSwan.Plug.CeremonyStore

  @doc "Starts an isolated ceremony store."
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, %{}, Keyword.take(opts, [:name]))
  end

  @doc "Stores an entry in the named store or server process."
  @spec put(GenServer.server(), String.t(), term(), integer()) :: :ok
  @impl ExSwan.Plug.CeremonyStore
  def put(server, token, ceremony, expires_at)
      when is_binary(token) and is_integer(expires_at) do
    GenServer.call(server, {:put, token, ceremony, expires_at})
  end

  @doc "Atomically consumes an entry from the named store or server process."
  @spec consume(GenServer.server(), String.t(), integer()) ::
          {:ok, term()} | {:error, :not_found | :expired}
  @impl ExSwan.Plug.CeremonyStore
  def consume(server, token, now) when is_binary(token) and is_integer(now) do
    GenServer.call(server, {:consume, token, now})
  end

  @impl GenServer
  def init(entries), do: {:ok, entries}

  @impl GenServer
  def handle_call({:put, token, ceremony, expires_at}, _from, entries) do
    {:reply, :ok, Map.put(entries, token, {ceremony, expires_at})}
  end

  def handle_call({:consume, token, now}, _from, entries) do
    case Map.pop(entries, token) do
      {nil, remaining} ->
        {:reply, {:error, :not_found}, remaining}

      {{_ceremony, expires_at}, remaining} when expires_at <= now ->
        {:reply, {:error, :expired}, remaining}

      {{ceremony, _expires_at}, remaining} ->
        {:reply, {:ok, ceremony}, remaining}
    end
  end
end
