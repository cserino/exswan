defmodule ExSwan.BrowserTestTelemetry do
  def handle(event, _measurements, metadata, _config) do
    IO.puts("#{Enum.join(event, ".")}: #{inspect(metadata)}")
  end
end

:ok =
  :telemetry.attach_many(
    "exswan-browser-test",
    [
      [:exswan, :plug, :registration, :failure],
      [:exswan, :plug, :authentication, :failure]
    ],
    &ExSwan.BrowserTestTelemetry.handle/4,
    nil
  )

{:ok, _server} =
  Bandit.start_link(
    plug: PhoenixWebauthnDemoWeb.Endpoint,
    port: 4002,
    ip: {127, 0, 0, 1}
  )

IO.puts("Browser test server listening on http://localhost:4002")
Process.sleep(:infinity)
