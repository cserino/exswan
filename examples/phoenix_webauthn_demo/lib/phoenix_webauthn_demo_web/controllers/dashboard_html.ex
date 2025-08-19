defmodule PhoenixWebauthnDemoWeb.DashboardHTML do
  @moduledoc """
  This module contains pages rendered by DashboardController.
  """
  use PhoenixWebauthnDemoWeb, :html

  embed_templates("dashboard_html/*")
end
