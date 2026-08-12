defmodule ExSwan.Conformance.MixProject do
  use Mix.Project

  def project do
    [
      app: :exswan_conformance,
      version: "0.1.0",
      elixir: "~> 1.18",
      elixirc_paths: ["lib"],
      deps: deps()
    ]
  end

  def application do
    [
      mod: {ExSwan.Conformance.Application, []},
      extra_applications: [:logger]
    ]
  end

  defp deps do
    [
      {:bandit, "~> 1.8"},
      {:exswan_plug, path: "../../packages/exswan_plug"},
      {:jason, "~> 1.4"}
    ]
  end
end
