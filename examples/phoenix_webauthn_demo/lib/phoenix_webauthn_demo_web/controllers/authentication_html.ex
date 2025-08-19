defmodule PhoenixWebauthnDemoWeb.AuthenticationHTML do
  @moduledoc """
  This module contains pages rendered by AuthenticationController.
  """
  use PhoenixWebauthnDemoWeb, :html

  embed_templates("authentication_html/*")
end
