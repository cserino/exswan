defmodule ExSwan.Plug.ConfigTest do
  use ExUnit.Case, async: true

  alias ExSwan.Plug.Config

  test "validates relying-party configuration while starting" do
    assert {:ok, pid} = Config.start_link(rp_id: "example.com", origin: "https://example.com")
    assert Process.alive?(pid)
    GenServer.stop(pid)
  end

  test "refuses to start with an unsafe origin" do
    Process.flag(:trap_exit, true)

    assert {:error, {:invalid_webauthn_config, :invalid_origin}} =
             Config.start_link(rp_id: "example.com", origin: "http://example.com")
  end
end
