defmodule ExSwan.Plug.Response do
  @moduledoc """
  Stable, deliberately coarse JSON responses for ceremony endpoints.

  Detailed verifier errors belong in secret-free server telemetry. Browser responses
  group them so callers cannot use an endpoint as a credential or policy oracle.
  """

  import Plug.Conn, only: [put_resp_content_type: 2, send_resp: 3]

  @type ceremony :: :registration | :authentication

  @doc "Sends a stable successful ceremony response."
  @spec send_success(Plug.Conn.t(), ceremony()) :: Plug.Conn.t()
  def send_success(conn, :registration), do: send(conn, 201, %{"verified" => true})
  def send_success(conn, :authentication), do: send(conn, 200, %{"verified" => true})

  @doc "Sends a stable coarse response for a known ceremony failure."
  @spec send_error(Plug.Conn.t(), term()) :: Plug.Conn.t()
  def send_error(conn, :registration_not_authorized),
    do: send(conn, 403, %{"error" => "registration_not_authorized"})

  def send_error(conn, :duplicate),
    do: send(conn, 409, %{"error" => "credential_already_registered"})

  def send_error(conn, reason) when reason in [:not_found, :expired, :ceremony_not_found],
    do: send(conn, 400, %{"error" => "ceremony_unavailable"})

  def send_error(conn, _reason),
    do: send(conn, 400, %{"error" => "verification_failed"})

  defp send(conn, status, body) do
    conn
    |> put_resp_content_type("application/json")
    |> send_resp(status, Jason.encode!(body))
  end
end
