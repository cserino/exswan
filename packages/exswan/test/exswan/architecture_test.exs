defmodule ExSwan.ArchitectureTest do
  use ExUnit.Case, async: true

  test "core has no HTTP, Phoenix, or persistence framework dependency" do
    applications = Application.spec(:exswan, :applications)

    refute Enum.any?([:plug, :phoenix, :ecto], &(&1 in applications))

    source = read_library_source()
    refute source =~ "Plug."
    refute source =~ "Phoenix."
    refute source =~ "Ecto."
  end

  defp read_library_source do
    __DIR__
    |> Path.join("../../lib/**/*.ex")
    |> Path.wildcard()
    |> Enum.map_join("\n", &File.read!/1)
  end
end
