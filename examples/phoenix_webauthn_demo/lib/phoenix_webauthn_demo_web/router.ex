defmodule PhoenixWebauthnDemoWeb.Router do
  use PhoenixWebauthnDemoWeb, :router

  pipeline :browser do
    plug(:accepts, ["html"])
    plug(:fetch_session)
    plug(:fetch_live_flash)
    plug(:put_root_layout, html: {PhoenixWebauthnDemoWeb.Layouts, :root})
    plug(:protect_from_forgery)
    plug(:put_secure_browser_headers)
  end

  pipeline :api do
    plug(:accepts, ["json"])
    plug(:fetch_session)
    plug(:protect_from_forgery)
  end

  scope "/", PhoenixWebauthnDemoWeb do
    pipe_through(:browser)

    get("/", PageController, :home)

    # Registration routes
    get("/register", RegistrationController, :new)
    post("/register", RegistrationController, :create)
    get("/register/passkey", RegistrationController, :passkey)

    # Authentication routes
    get("/signin", AuthenticationController, :new)
    get("/signout", AuthenticationController, :delete)

    # Dashboard (protected)
    get("/dashboard", DashboardController, :index)
  end

  scope "/api", PhoenixWebauthnDemoWeb do
    pipe_through(:api)

    # WebAuthn API endpoints
    post("/webauthn/register/begin", RegistrationController, :begin_passkey_registration)
    post("/webauthn/register/complete", RegistrationController, :complete_passkey_registration)
    post("/webauthn/authenticate/begin", AuthenticationController, :begin_authentication)
    post("/webauthn/authenticate/complete", AuthenticationController, :complete_authentication)
  end

  # Other scopes may use custom stacks.
  # scope "/api", PhoenixWebauthnDemoWeb do
  #   pipe_through :api
  # end

  # Enable LiveDashboard and Swoosh mailbox preview in development
  if Application.compile_env(:phoenix_webauthn_demo, :dev_routes) do
    # If you want to use the LiveDashboard in production, you should put
    # it behind authentication and allow only admins to access it.
    # If your application does not have an admins-only section yet,
    # you can use Plug.BasicAuth to set up some basic authentication
    # as long as you are also using SSL (which you should anyway).
    import Phoenix.LiveDashboard.Router

    scope "/dev" do
      pipe_through(:browser)

      live_dashboard("/dashboard", metrics: PhoenixWebauthnDemoWeb.Telemetry)
      forward("/mailbox", Plug.Swoosh.MailboxPreview)
    end
  end
end
