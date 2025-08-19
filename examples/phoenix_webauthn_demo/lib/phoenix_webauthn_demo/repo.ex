defmodule PhoenixWebauthnDemo.Repo do
  use Ecto.Repo,
    otp_app: :phoenix_webauthn_demo,
    adapter: Ecto.Adapters.SQLite3
end
