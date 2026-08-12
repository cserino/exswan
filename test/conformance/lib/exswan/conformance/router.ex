defmodule ExSwan.Conformance.Router do
  @moduledoc false

  use Plug.Router

  alias ExSwan.Conformance.{Config, Store}

  @ceremony_store {ExSwan.Plug.CeremonyStore.Memory, ExSwan.Conformance.CeremonyStore}
  @session_options [
    store: :cookie,
    key: "_exswan_conformance",
    signing_salt: "exswan-conformance-session",
    same_site: "Lax"
  ]

  plug(Plug.Logger)
  plug(:put_secret_key_base)
  plug(Plug.Session, @session_options)
  plug(:fetch_session)
  plug(Plug.Parsers, parsers: [:json], json_decoder: Jason)
  plug(:match)
  plug(:dispatch)

  post "/attestation/options" do
    with %{"username" => username, "displayName" => display_name} <- conn.body_params,
         :ok <- supported_attestation(conn.body_params["attestation"]),
         user_handle = :crypto.hash(:sha256, username),
         {:ok, conn, options} <-
           ExSwan.Plug.begin_registration(conn,
             user: username,
             user_handle: user_handle,
             user_name: username,
             user_display_name: display_name,
             rp_name: "ExSwan Conformance",
             rp_id: Config.rp_id(),
             origin: Config.origin(),
             exclude_credentials: Store.credentials(username),
             authenticator_selection: conn.body_params["authenticatorSelection"],
             attestation: "none",
             ceremony_store: @ceremony_store
           ) do
      respond(conn, 200, Map.merge(options, ok()))
    else
      error -> failed(conn, error)
    end
  end

  post "/attestation/result" do
    case ExSwan.Plug.finish_registration(conn,
           response: normalize_credential(conn.body_params),
           store: Store,
           ceremony_store: @ceremony_store
         ) do
      {:ok, conn, _registration, _stored} -> respond(conn, 200, ok())
      error -> failed(conn, error)
    end
  end

  post "/assertion/options" do
    with %{"username" => username} <- conn.body_params,
         {:ok, conn, options} <-
           ExSwan.Plug.begin_authentication(conn,
             rp_id: Config.rp_id(),
             origin: Config.origin(),
             allow_credentials: Store.credentials(username),
             expected_user_handle: :crypto.hash(:sha256, username),
             user_verification: Map.get(conn.body_params, "userVerification", "preferred"),
             ceremony_store: @ceremony_store
           ) do
      respond(conn, 200, Map.merge(options, ok()))
    else
      error -> failed(conn, error)
    end
  end

  post "/assertion/result" do
    case ExSwan.Plug.finish_authentication(conn,
           response: normalize_credential(conn.body_params),
           store: Store,
           ceremony_store: @ceremony_store
         ) do
      {:ok, conn, _authentication, _stored} -> respond(conn, 200, ok())
      error -> failed(conn, error)
    end
  end

  match _ do
    respond(conn, 404, %{"status" => "failed", "errorMessage" => "Not found"})
  end

  defp normalize_credential(response) do
    response
    |> Map.put_new("rawId", response["id"])
    |> Map.put_new("clientExtensionResults", response["getClientExtensionResults"] || %{})
  end

  defp supported_attestation(value) when value in [nil, "none"], do: :ok
  defp supported_attestation(_value), do: {:error, :unsupported_attestation_format}

  defp ok, do: %{"status" => "ok", "errorMessage" => ""}

  defp failed(conn, _error) do
    respond(conn, 400, %{"status" => "failed", "errorMessage" => "Verification failed"})
  end

  defp respond(conn, status, body) do
    conn
    |> put_resp_content_type("application/json")
    |> send_resp(status, Jason.encode!(body))
  end

  defp put_secret_key_base(conn, _opts) do
    %{conn | secret_key_base: String.duplicate("exswan-conformance-secret-", 4)}
  end
end
