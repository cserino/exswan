defmodule ExSwan.Plug do
  @moduledoc """
  Plug integration helpers for [ExSwan](https://hex.pm/packages/exswan).

  This package is a stub. Full Plug/Phoenix helpers for WebAuthn registration
  and authentication ceremonies will be added in a follow-up release.

  ## Installation

      def deps do
        [
          {:exswan_plug, "~> 0.1.0"}
        ]
      end

  When developing inside the exswan monorepo, depend on the path package and set
  `EXSWAN_MONOREPO=true` so `:exswan` resolves from `packages/exswan`.
  """

  @doc """
  Returns the library version.
  """
  @spec version() :: String.t()
  def version do
    Application.spec(:exswan_plug, :vsn) |> to_string()
  end
end
