defmodule ExSwan.Plug.ArchitectureTest do
  use ExUnit.Case, async: true

  test "integration package uses the four-function core seam, not protocol internals" do
    source = read_library_source()

    for internal <- [
          "ExSwan.Attestation",
          "ExSwan.Authentication.",
          "ExSwan.CBOR",
          "ExSwan.Crypto",
          "ExSwan.Registration.",
          "ExSwan.Validator"
        ] do
      refute source =~ internal
    end
  end

  defp read_library_source do
    __DIR__
    |> Path.join("../../../lib/**/*.ex")
    |> Path.wildcard()
    |> Enum.map_join("\n", &File.read!/1)
  end
end
