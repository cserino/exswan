defmodule ExSwan.Plug.Config do
  @moduledoc """
  Startup validation for relying-party configuration.

  Add this module to an application's supervision tree so an unsafe RP ID or origin
  prevents the endpoint from starting.
  """

  use GenServer

  @doc "Starts a validator process after checking the RP ID and origin."
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts) do
    {server_opts, config} = Keyword.split(opts, [:name])
    GenServer.start_link(__MODULE__, config, server_opts)
  end

  @impl GenServer
  def init(config) do
    case ExSwan.Plug.validate_config(config) do
      :ok -> {:ok, config}
      {:error, reason} -> {:stop, {:invalid_webauthn_config, reason}}
    end
  end
end
