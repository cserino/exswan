defmodule ExSwan.Conformance.Application do
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    port = String.to_integer(System.get_env("PORT", "4005"))

    children = [
      {ExSwan.Plug.Config,
       rp_id: ExSwan.Conformance.Config.rp_id(), origin: ExSwan.Conformance.Config.origin()},
      {ExSwan.Plug.CeremonyStore.Memory, name: ExSwan.Conformance.CeremonyStore},
      ExSwan.Conformance.Store,
      {Bandit, plug: ExSwan.Conformance.Router, port: port}
    ]

    Supervisor.start_link(children, strategy: :one_for_one, name: __MODULE__.Supervisor)
  end
end
