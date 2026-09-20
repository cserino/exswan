defmodule ExSwan.Plug.CeremonyStore.Memory do
  @moduledoc """
  Deterministic in-memory ceremony store intended for tests and single-node use.

  The caller supplies monotonic timestamps to make expiration tests deterministic.
  Use a shared transactional store when ceremonies can finish on multiple nodes.
  """

  use GenServer

  @behaviour ExSwan.Plug.CeremonyStore

  @default_cleanup_interval 60_000

  @doc """
  Starts an isolated ceremony store.

  The `:cleanup_interval` option controls how often expired entries are removed. A
  zero interval disables periodic cleanup. The `:clock` option accepts a zero-arity
  function returning the current monotonic time and is useful in deterministic tests.
  """
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, Keyword.take(opts, [:name]))
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
  def init(opts) do
    state = %{
      entries: %{},
      clock: Keyword.get(opts, :clock, fn -> System.monotonic_time(:millisecond) end),
      cleanup_interval: Keyword.get(opts, :cleanup_interval, @default_cleanup_interval)
    }

    schedule_cleanup(state.cleanup_interval)
    {:ok, state}
  end

  @impl GenServer
  def handle_call({:put, token, ceremony, expires_at}, _from, state) do
    {:reply, :ok, put_in(state.entries[token], {ceremony, expires_at})}
  end

  def handle_call({:consume, token, now}, _from, state) do
    case Map.pop(state.entries, token) do
      {nil, remaining} ->
        {:reply, {:error, :not_found}, %{state | entries: remove_expired(remaining, now)}}

      {{_ceremony, expires_at}, remaining} when expires_at <= now ->
        {:reply, {:error, :expired}, %{state | entries: remove_expired(remaining, now)}}

      {{ceremony, _expires_at}, remaining} ->
        {:reply, {:ok, ceremony}, %{state | entries: remove_expired(remaining, now)}}
    end
  end

  @impl GenServer
  def handle_info(:cleanup, state) do
    now = state.clock.()
    schedule_cleanup(state.cleanup_interval)
    {:noreply, %{state | entries: remove_expired(state.entries, now)}}
  end

  defp remove_expired(entries, now) do
    Map.reject(entries, fn {_token, {_ceremony, expires_at}} -> expires_at <= now end)
  end

  defp schedule_cleanup(0), do: :ok
  defp schedule_cleanup(interval), do: Process.send_after(self(), :cleanup, interval)
end
