defmodule ExSwan.Conformance.Config do
  @moduledoc false

  def rp_id, do: System.get_env("WEBAUTHN_RP_ID", "localhost")
  def origin, do: System.get_env("WEBAUTHN_ORIGIN", "http://localhost:4005")
end
