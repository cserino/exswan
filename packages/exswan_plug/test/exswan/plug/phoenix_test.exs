defmodule ExSwan.Plug.PhoenixTest do
  use ExUnit.Case, async: true

  defmodule RouterFixture do
    import ExSwan.Plug.Phoenix

    defmacro post(path, controller, action) do
      quote do
        {unquote(path), unquote(controller), unquote(action)}
      end
    end

    def routes do
      webauthn_routes(MyApp.PasskeyController, path: "/passkeys")
    end
  end

  test "expands conventional routes without a Phoenix dependency" do
    assert RouterFixture.routes() ==
             {"/passkeys/authentication/result", MyApp.PasskeyController, :finish_authentication}

    refute :phoenix in Application.spec(:exswan_plug, :applications)
  end
end
