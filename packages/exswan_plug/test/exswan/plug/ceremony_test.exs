defmodule ExSwan.Plug.CeremonyTest do
  use ExUnit.Case, async: true

  import Plug.Test

  alias ExSwan.Plug.CeremonyStore.Memory

  @fixture_path Path.expand(
                  "../../../../../test/compatibility/fixtures/options.json",
                  __DIR__
                )

  defmodule Store do
    @behaviour ExSwan.Plug.Store

    @impl true
    def get_credential(id, %{credential: %{id: id} = credential} = context) do
      send(context.test_pid, {:get_credential, id})
      {:ok, credential}
    end

    def get_credential(_id, _context), do: {:error, :not_found}

    @impl true
    def create_credential(user, registration, context) do
      send(context.test_pid, {:create_credential, user, registration})
      {:ok, :created}
    end

    @impl true
    def update_credential(credential, authentication, context) do
      send(context.test_pid, {:update_credential, credential, authentication})
      {:ok, :updated}
    end
  end

  def handle_telemetry(event, measurements, metadata, test_pid) do
    send(test_pid, {:telemetry, event, measurements, metadata})
  end

  setup do
    fixture = @fixture_path |> File.read!() |> Jason.decode!()
    store = start_supervised!({Memory, []})
    %{fixture: fixture, ceremony_store: {Memory, store}}
  end

  test "registration crosses the browser seam, persists, and cannot be replayed", context do
    fixture = context.fixture
    ceremony = fixture["ceremony"]
    callback_context = %{test_pid: self()}

    assert {:ok, conn, options} =
             ExSwan.Plug.begin_registration(conn(),
               user: :authorized_user,
               user_handle: Base.url_decode64!(ceremony["userID"], padding: false),
               user_name: "person@example.com",
               rp_name: "Example",
               rp_id: ceremony["rpID"],
               origin: ceremony["origin"],
               challenge: fixture["inputs"]["challenge"],
               ceremony_store: context.ceremony_store,
               context: callback_context,
               now: 100
             )

    assert options["challenge"] == fixture["registration"]["challenge"]

    assert {:ok, _conn, registration, :created} =
             ExSwan.Plug.finish_registration(conn,
               response: ceremony["registrationResponse"],
               store: Store,
               ceremony_store: context.ceremony_store,
               now: 101
             )

    assert_receive {:create_credential, :authorized_user, ^registration}

    assert {:error, :not_found} =
             ExSwan.Plug.finish_registration(conn,
               response: ceremony["registrationResponse"],
               store: Store,
               ceremony_store: context.ceremony_store,
               now: 101
             )
  end

  test "registration authorization is explicit", context do
    assert {:error, :registration_not_authorized} =
             ExSwan.Plug.begin_registration(conn(),
               user: nil,
               user_handle: <<1>>,
               user_name: "person@example.com",
               rp_name: "Example",
               rp_id: "example.com",
               origin: "https://example.com",
               ceremony_store: context.ceremony_store
             )
  end

  test "an invalid response consumes its ceremony", context do
    fixture = context.fixture
    ceremony = fixture["ceremony"]

    {:ok, conn, _options} = begin_registration(context)
    invalid = fixture["invalid"]["registration"]["wrongChallenge"]["response"]

    finish_opts = [
      response: invalid,
      store: Store,
      ceremony_store: context.ceremony_store,
      now: 101
    ]

    assert {:error, :challenge_mismatch} = ExSwan.Plug.finish_registration(conn, finish_opts)

    assert {:error, :not_found} =
             ExSwan.Plug.finish_registration(conn,
               response: ceremony["registrationResponse"],
               store: Store,
               ceremony_store: context.ceremony_store,
               now: 101
             )
  end

  test "expired ceremonies fail closed", context do
    {:ok, conn, _options} = begin_registration(context, ceremony_timeout: 1)

    assert {:error, :expired} =
             ExSwan.Plug.finish_registration(conn,
               response: context.fixture["ceremony"]["registrationResponse"],
               store: Store,
               ceremony_store: context.ceremony_store,
               now: 101
             )
  end

  test "authentication looks up and atomically updates the stored credential", context do
    fixture = context.fixture
    ceremony = fixture["ceremony"]
    user_handle = Base.url_decode64!(ceremony["userID"], padding: false)
    credential = register_fixture(fixture)
    callback_context = %{test_pid: self(), credential: credential}

    assert {:ok, conn, options} =
             ExSwan.Plug.begin_authentication(conn(),
               rp_id: ceremony["rpID"],
               origin: ceremony["origin"],
               challenge: fixture["inputs"]["challenge"],
               allow_credentials: [credential],
               expected_user_handle: user_handle,
               ceremony_store: context.ceremony_store,
               context: callback_context,
               now: 100
             )

    assert options["challenge"] == fixture["authentication"]["challenge"]

    assert {:ok, _conn, authentication, :updated} =
             ExSwan.Plug.finish_authentication(conn,
               response: ceremony["authenticationResponse"],
               store: Store,
               ceremony_store: context.ceremony_store,
               now: 101
             )

    assert_receive {:get_credential, "CQgHBg"}
    assert_receive {:update_credential, ^credential, ^authentication}
    assert authentication.new_sign_count == 1
  end

  test "configuration rejects unsafe origins and malformed RP IDs" do
    assert {:error, :invalid_origin} =
             ExSwan.Plug.validate_config(rp_id: "example.com", origin: "http://example.com")

    assert {:error, :invalid_rp_id} =
             ExSwan.Plug.validate_config(
               rp_id: "https://example.com",
               origin: "https://example.com"
             )

    assert :ok =
             ExSwan.Plug.validate_config(rp_id: "localhost", origin: "http://localhost")
  end

  test "telemetry reports lifecycle outcomes without ceremony secrets", context do
    handler = "exswan-plug-test-#{System.unique_integer([:positive])}"
    test_pid = self()

    :ok =
      :telemetry.attach_many(
        handler,
        [
          [:exswan, :plug, :registration, :start],
          [:exswan, :plug, :registration, :failure]
        ],
        &__MODULE__.handle_telemetry/4,
        test_pid
      )

    on_exit(fn -> :telemetry.detach(handler) end)

    {:ok, conn, _options} = begin_registration(context)
    invalid = context.fixture["invalid"]["registration"]["wrongChallenge"]["response"]

    assert {:error, :challenge_mismatch} =
             ExSwan.Plug.finish_registration(conn,
               response: invalid,
               store: Store,
               ceremony_store: context.ceremony_store,
               now: 101
             )

    assert_receive {:telemetry, [:exswan, :plug, :registration, :start], _, %{}}

    assert_receive {:telemetry, [:exswan, :plug, :registration, :failure], _,
                    %{reason: :challenge_mismatch}}
  end

  defp begin_registration(context, extra \\ []) do
    fixture = context.fixture
    ceremony = fixture["ceremony"]

    ExSwan.Plug.begin_registration(
      conn(),
      [
        user: :authorized_user,
        user_handle: Base.url_decode64!(ceremony["userID"], padding: false),
        user_name: "person@example.com",
        rp_name: "Example",
        rp_id: ceremony["rpID"],
        origin: ceremony["origin"],
        challenge: fixture["inputs"]["challenge"],
        ceremony_store: context.ceremony_store,
        context: %{test_pid: self()},
        now: 100
      ] ++ extra
    )
  end

  defp conn do
    :post
    |> conn("/")
    |> init_test_session(%{})
  end

  defp register_fixture(fixture) do
    ceremony = fixture["ceremony"]

    {:ok, result} =
      ExSwan.verify_registration_response(
        response: ceremony["registrationResponse"],
        expected_challenge: fixture["inputs"]["challenge"],
        expected_origin: ceremony["origin"],
        expected_rp_id: ceremony["rpID"]
      )

    result.credential
  end
end
