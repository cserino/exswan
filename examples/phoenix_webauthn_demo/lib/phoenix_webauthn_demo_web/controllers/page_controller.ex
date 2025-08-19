defmodule PhoenixWebauthnDemoWeb.PageController do
  use PhoenixWebauthnDemoWeb, :controller

  def home(conn, _params) do
    render(conn, :home)
  end
end
