defmodule ExSwan.Plug do
  @moduledoc """
  Plug integration helpers for [ExSwan](https://hex.pm/packages/exswan).

  Ceremony helpers keep challenges in server-side storage and put only opaque lookup
  tokens in the Plug session. Applications retain identity and persistence policy
  through the `ExSwan.Plug.Store` callbacks.

  ## Installation

      def deps do
        [
          {:exswan_plug, "~> 0.1.0"}
        ]
      end

  When developing inside the exswan monorepo, depend on the path package and set
  `EXSWAN_MONOREPO=true` so `:exswan` resolves from `packages/exswan`.
  """

  import Plug.Conn, only: [delete_session: 2, get_session: 2, put_session: 3]

  @registration_session_key "exswan_registration"
  @authentication_session_key "exswan_authentication"
  @default_timeout 300_000

  @typedoc "A ceremony-store module and its adapter-specific context."
  @type ceremony_store :: {module(), term()}

  @doc """
  Begins an authorized registration ceremony.

  Required options are `:user`, `:user_handle`, `:user_name`, `:rp_name`, `:rp_id`,
  `:origin`, and `:ceremony_store`. The returned options are browser-ready.
  """
  @spec begin_registration(Plug.Conn.t(), keyword()) ::
          {:ok, Plug.Conn.t(), map()} | {:error, term()}
  def begin_registration(conn, opts) when is_list(opts) do
    started_at = monotonic_time(opts)

    with {:ok, config} <- registration_config(opts),
         {:ok, generated} <- ExSwan.generate_registration_options(config.generation_opts),
         token = token(),
         state = %{
           type: :registration,
           ceremony: generated.ceremony,
           origin: config.origin,
           user: config.user,
           context: config.context
         },
         :ok <- store_put(config.ceremony_store, token, state, started_at + config.timeout) do
      conn = put_session(conn, @registration_session_key, token)
      emit([:registration, :start], %{system_time: System.system_time()}, %{})
      {:ok, conn, generated.options}
    end
  end

  def begin_registration(_conn, _opts), do: {:error, :invalid_options}

  @doc """
  Consumes and verifies a registration ceremony, then invokes `create_credential/3`.

  Ceremony state is consumed before verification, so failed and concurrent retries
  cannot reuse an attacker-controlled response.
  """
  @spec finish_registration(Plug.Conn.t(), keyword()) ::
          {:ok, Plug.Conn.t(), ExSwan.RegistrationResult.t(), term()} | {:error, term()}
  def finish_registration(conn, opts) when is_list(opts) do
    finish(:registration, conn, opts)
  end

  def finish_registration(_conn, _opts), do: {:error, :invalid_options}

  @doc """
  Begins an authentication ceremony.

  Required options are `:rp_id`, `:origin`, and `:ceremony_store`. Pass stored
  credentials with `:allow_credentials` when the account is known in advance.
  """
  @spec begin_authentication(Plug.Conn.t(), keyword()) ::
          {:ok, Plug.Conn.t(), map()} | {:error, term()}
  def begin_authentication(conn, opts) when is_list(opts) do
    started_at = monotonic_time(opts)

    with {:ok, config} <- authentication_config(opts),
         {:ok, generated} <- ExSwan.generate_authentication_options(config.generation_opts),
         token = token(),
         state = %{
           type: :authentication,
           ceremony: generated.ceremony,
           origin: config.origin,
           expected_user_handle: config.expected_user_handle,
           context: config.context
         },
         :ok <- store_put(config.ceremony_store, token, state, started_at + config.timeout) do
      conn = put_session(conn, @authentication_session_key, token)
      emit([:authentication, :start], %{system_time: System.system_time()}, %{})
      {:ok, conn, generated.options}
    end
  end

  def begin_authentication(_conn, _opts), do: {:error, :invalid_options}

  @doc """
  Consumes and verifies an authentication ceremony, then atomically persists its
  counter and backup-state result through `update_credential/3`.
  """
  @spec finish_authentication(Plug.Conn.t(), keyword()) ::
          {:ok, Plug.Conn.t(), ExSwan.AuthenticationResult.t(), term()} | {:error, term()}
  def finish_authentication(conn, opts) when is_list(opts) do
    finish(:authentication, conn, opts)
  end

  def finish_authentication(_conn, _opts), do: {:error, :invalid_options}

  @doc """
  Validates relying-party configuration.

  Origins must be absolute HTTPS URLs without userinfo, query, or fragment. HTTP is
  accepted only for localhost development.
  """
  @spec validate_config(keyword()) :: :ok | {:error, term()}
  def validate_config(opts) when is_list(opts) do
    with {:ok, rp_id} <- fetch(opts, :rp_id),
         {:ok, origin} <- fetch(opts, :origin),
         :ok <- validate_rp_id(rp_id) do
      validate_origin(origin)
    end
  end

  def validate_config(_opts), do: {:error, :invalid_config}

  @doc """
  Returns the library version.
  """
  @spec version() :: String.t()
  def version do
    Application.spec(:exswan_plug, :vsn) |> to_string()
  end

  defp registration_config(opts) do
    with {:ok, user} <- fetch_non_nil(opts, :user, :registration_not_authorized),
         {:ok, user_handle} <- fetch_non_nil(opts, :user_handle, :registration_not_authorized),
         {:ok, user_name} <- fetch(opts, :user_name),
         {:ok, rp_name} <- fetch(opts, :rp_name),
         {:ok, rp_id} <- fetch(opts, :rp_id),
         {:ok, origin} <- fetch(opts, :origin),
         {:ok, ceremony_store} <- fetch_store(opts),
         :ok <- validate_config(rp_id: rp_id, origin: origin) do
      generation_opts =
        [
          rp_name: rp_name,
          rp_id: rp_id,
          user_name: user_name,
          user_id: user_handle,
          user_display_name: Keyword.get(opts, :user_display_name, user_name)
        ] ++ generation_overrides(opts)

      {:ok,
       %{
         user: user,
         origin: origin,
         context: Keyword.get(opts, :context),
         ceremony_store: ceremony_store,
         timeout: timeout(opts),
         generation_opts: generation_opts
       }}
    end
  end

  defp authentication_config(opts) do
    with {:ok, rp_id} <- fetch(opts, :rp_id),
         {:ok, origin} <- fetch(opts, :origin),
         {:ok, ceremony_store} <- fetch_store(opts),
         :ok <- validate_config(rp_id: rp_id, origin: origin) do
      generation_opts =
        [rp_id: rp_id] ++
          Keyword.take(opts, [:allow_credentials, :challenge, :timeout, :user_verification])

      {:ok,
       %{
         origin: origin,
         expected_user_handle: Keyword.get(opts, :expected_user_handle),
         context: Keyword.get(opts, :context),
         ceremony_store: ceremony_store,
         timeout: timeout(opts),
         generation_opts: generation_opts
       }}
    end
  end

  defp finish(type, conn, opts) do
    started_at = System.monotonic_time()
    session_key = session_key(type)

    with {:ok, response} <- fetch(opts, :response),
         {:ok, store} <- fetch(opts, :store),
         {:ok, ceremony_store} <- fetch_store(opts),
         {:ok, token} <- session_token(conn, session_key),
         {:ok, state} <- store_consume(ceremony_store, token, monotonic_time(opts)),
         :ok <- verify_state_type(state, type),
         result <- finish_consumed(type, response, state, store, opts) do
      conn = delete_session(conn, session_key)
      finish_result(result, type, conn, started_at)
    else
      {:error, reason} = error ->
        emit(
          [type, :failure],
          %{duration: System.monotonic_time() - started_at},
          %{
            reason: telemetry_reason(reason)
          }
          |> Map.merge(telemetry_detail(reason))
        )

        error
    end
  end

  defp finish_consumed(:registration, response, state, store, opts) do
    with {:ok, result} <-
           ExSwan.verify_registration_response(
             response: response,
             expected_challenge: state.ceremony.challenge,
             expected_origin: state.origin,
             expected_rp_id: state.ceremony.rp_id
           ),
         {:ok, persisted} <-
           store.create_credential(state.user, result, callback_context(state, opts)) do
      {:ok, result, persisted}
    end
  end

  defp finish_consumed(:authentication, %{"id" => credential_id} = response, state, store, opts) do
    context = callback_context(state, opts)

    with {:ok, credential} <- store.get_credential(credential_id, context),
         verification_opts <- authentication_verification_opts(response, credential, state),
         {:ok, result} <- ExSwan.verify_authentication_response(verification_opts),
         {:ok, persisted} <- store.update_credential(credential, result, context) do
      {:ok, result, persisted}
    end
  end

  defp finish_consumed(:authentication, _response, _state, _store, _opts),
    do: {:error, :invalid_authentication_response}

  defp authentication_verification_opts(response, credential, state) do
    [
      response: response,
      expected_challenge: state.ceremony.challenge,
      expected_origin: state.origin,
      expected_rp_id: state.ceremony.rp_id,
      credential: credential
    ]
    |> maybe_put(:expected_user_handle, state.expected_user_handle)
  end

  defp finish_result({:ok, result, persisted}, type, conn, started_at) do
    emit([type, :success], %{duration: System.monotonic_time() - started_at}, %{})
    {:ok, conn, result, persisted}
  end

  defp finish_result({:error, reason} = error, type, _conn, started_at) do
    emit(
      [type, :failure],
      %{duration: System.monotonic_time() - started_at},
      %{
        reason: telemetry_reason(reason)
      }
      |> Map.merge(telemetry_detail(reason))
    )

    error
  end

  defp generation_overrides(opts) do
    Keyword.take(opts, [
      :attestation,
      :authenticator_selection,
      :challenge,
      :exclude_credentials,
      :extensions,
      :timeout
    ])
  end

  defp fetch_store(opts) do
    case Keyword.fetch(opts, :ceremony_store) do
      {:ok, {module, context}} when is_atom(module) -> {:ok, {module, context}}
      _other -> {:error, {:missing_option, :ceremony_store}}
    end
  end

  defp store_put({module, context}, token, state, expires_at),
    do: module.put(context, token, state, expires_at)

  defp store_consume({module, context}, token, now), do: module.consume(context, token, now)

  defp callback_context(state, opts), do: Keyword.get(opts, :context, state.context)

  defp session_token(conn, key) do
    case get_session(conn, key) do
      token when is_binary(token) -> {:ok, token}
      _other -> {:error, :ceremony_not_found}
    end
  end

  defp verify_state_type(%{type: type}, type), do: :ok
  defp verify_state_type(_state, _type), do: {:error, :ceremony_type_mismatch}

  defp session_key(:registration), do: @registration_session_key
  defp session_key(:authentication), do: @authentication_session_key

  defp timeout(opts) do
    case Keyword.get(opts, :ceremony_timeout, @default_timeout) do
      timeout when is_integer(timeout) and timeout > 0 -> timeout
      _other -> @default_timeout
    end
  end

  defp monotonic_time(opts) do
    case Keyword.get(opts, :now) do
      now when is_integer(now) -> now
      _other -> System.monotonic_time(:millisecond)
    end
  end

  defp token, do: Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false)

  defp fetch(opts, key) do
    case Keyword.fetch(opts, key) do
      {:ok, value} -> {:ok, value}
      :error -> {:error, {:missing_option, key}}
    end
  end

  defp fetch_non_nil(opts, key, error) do
    case Keyword.fetch(opts, key) do
      {:ok, value} when not is_nil(value) -> {:ok, value}
      _other -> {:error, error}
    end
  end

  defp validate_rp_id(rp_id) when is_binary(rp_id) and byte_size(rp_id) > 0 do
    if String.contains?(rp_id, [":", "/", " "]), do: {:error, :invalid_rp_id}, else: :ok
  end

  defp validate_rp_id(_rp_id), do: {:error, :invalid_rp_id}

  defp validate_origin(origin) when is_binary(origin) do
    case URI.parse(origin) do
      %URI{scheme: scheme, host: host, userinfo: nil, query: nil, fragment: nil, path: path}
      when is_binary(host) and path in [nil, ""] ->
        validate_origin_scheme(scheme, host)

      _other ->
        {:error, :invalid_origin}
    end
  end

  defp validate_origin(_origin), do: {:error, :invalid_origin}

  defp validate_origin_scheme("https", _host), do: :ok

  defp validate_origin_scheme("http", host) when host in ["localhost", "127.0.0.1", "::1"],
    do: :ok

  defp validate_origin_scheme(_scheme, _host), do: {:error, :invalid_origin}

  defp maybe_put(opts, _key, nil), do: opts
  defp maybe_put(opts, key, value), do: Keyword.put(opts, key, value)

  defp telemetry_reason(reason) when is_atom(reason), do: reason
  defp telemetry_reason({reason, _detail}) when is_atom(reason), do: reason
  defp telemetry_reason(_reason), do: :operation_failed

  defp telemetry_detail({kind, field})
       when kind in [:missing_field, :invalid_field, :missing_option] and
              (is_atom(field) or is_binary(field)),
       do: %{field: field}

  defp telemetry_detail(_reason), do: %{}

  defp emit(suffix, measurements, metadata) do
    :telemetry.execute([:exswan, :plug] ++ suffix, measurements, metadata)
  end
end
