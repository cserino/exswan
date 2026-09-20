defmodule ExSwan.Plug.CeremonyStore.MemoryTest do
  use ExUnit.Case, async: true

  alias ExSwan.Plug.CeremonyStore.Memory

  setup do
    %{store: start_supervised!({Memory, []})}
  end

  test "a ceremony can be consumed exactly once", %{store: store} do
    assert :ok = Memory.put(store, "token", %{challenge: "secret"}, 101)
    assert {:ok, %{challenge: "secret"}} = Memory.consume(store, "token", 100)
    assert {:error, :not_found} = Memory.consume(store, "token", 100)
  end

  test "an expired ceremony is removed and cannot be retried", %{store: store} do
    assert :ok = Memory.put(store, "token", :ceremony, 100)
    assert {:error, :expired} = Memory.consume(store, "token", 100)
    assert {:error, :not_found} = Memory.consume(store, "token", 99)
  end

  test "concurrent consumers cannot both succeed", %{store: store} do
    assert :ok = Memory.put(store, "token", :ceremony, 101)

    results =
      1..2
      |> Task.async_stream(fn _ -> Memory.consume(store, "token", 100) end,
        ordered: false
      )
      |> Enum.map(fn {:ok, result} -> result end)

    assert Enum.sort(results) == [{:error, :not_found}, {:ok, :ceremony}]
  end

  test "periodic cleanup runs and reschedules without a consume call" do
    test_pid = self()

    clock = fn ->
      send(test_pid, :cleanup_tick)
      100
    end

    store = start_supervised!({Memory, cleanup_interval: 10, clock: clock}, id: :periodic)
    assert :ok = Memory.put(store, "expired", :expired, 100)
    assert :ok = Memory.put(store, "live", :live, 101)
    assert_receive :cleanup_tick, 1_000
    assert :sys.get_state(store).entries == %{"live" => {:live, 101}}
    assert_receive :cleanup_tick, 1_000
  end

  test "consuming any token prunes unrelated expired entries", %{store: store} do
    for token <- ["live", "expired", "missing"] do
      assert :ok = Memory.put(store, "unrelated", :stale, 100)
      assert :ok = Memory.put(store, "live", :live, 101)
      assert :ok = Memory.put(store, "expired", :expired, 100)
      Memory.consume(store, token, 100)
      refute Map.has_key?(:sys.get_state(store).entries, "unrelated")
    end
  end

  test "cleanup removes abandoned expired ceremonies" do
    store =
      start_supervised!({Memory, cleanup_interval: 0, clock: fn -> 100 end},
        id: :cleanup_store
      )

    assert :ok = Memory.put(store, "expired", :ceremony, 100)
    assert :ok = Memory.put(store, "live", :ceremony, 101)

    send(store, :cleanup)

    assert {:error, :not_found} = Memory.consume(store, "expired", 99)
    assert {:ok, :ceremony} = Memory.consume(store, "live", 100)
  end
end
