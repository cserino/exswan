defmodule ExSwan.PlugTest do
  use ExUnit.Case, async: true

  doctest ExSwan.Plug

  test "version/0 returns a non-empty version string" do
    version = ExSwan.Plug.version()
    assert is_binary(version)
    assert version != ""
  end
end
