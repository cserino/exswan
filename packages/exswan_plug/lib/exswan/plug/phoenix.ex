defmodule ExSwan.Plug.Phoenix do
  @moduledoc """
  Optional route macros for Phoenix applications.

  This module does not depend on Phoenix. The generated calls are expanded in the
  application's router, where Phoenix is already available.
  """

  @doc """
  Adds the four conventional WebAuthn ceremony routes to the current Phoenix scope.

  The controller must implement `begin_registration/2`, `finish_registration/2`,
  `begin_authentication/2`, and `finish_authentication/2`.
  """
  defmacro webauthn_routes(controller, opts \\ []) do
    path = Keyword.get(opts, :path, "/webauthn")

    quote do
      post(unquote(path) <> "/registration/options", unquote(controller), :begin_registration)
      post(unquote(path) <> "/registration/result", unquote(controller), :finish_registration)

      post(
        unquote(path) <> "/authentication/options",
        unquote(controller),
        :begin_authentication
      )

      post(
        unquote(path) <> "/authentication/result",
        unquote(controller),
        :finish_authentication
      )
    end
  end
end
