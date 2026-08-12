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
end
