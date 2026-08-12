defmodule ExSwan.Plug.MixProject do
  use Mix.Project

  @version "0.1.0"
  @source_url "https://github.com/cserino/exswan"

  def project do
    [
      app: :exswan_plug,
      version: @version,
      elixir: "~> 1.18",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description: description(),
      package: package(),
      docs: docs(),
      source_url: @source_url,
      homepage_url: @source_url
    ]
  end

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp deps do
    [
      exswan_dep(),
      {:plug, "~> 1.16"},
      {:ex_doc, "~> 0.31", only: :dev, runtime: false},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false}
    ]
  end

  # Path dep when developing in the monorepo; Hex dep when published / external.
  # Set EXSWAN_MONOREPO=true for local path resolution (Makefile does this by default).
  # Leave unset to resolve :exswan from Hex (catches unreleased API usage).
  defp exswan_dep do
    if System.get_env("EXSWAN_MONOREPO") == "true" do
      {:exswan, path: "../exswan"}
    else
      {:exswan, "~> 0.1.0"}
    end
  end

  defp description do
    "Plug integration helpers for ExSwan (WebAuthn / FIDO2)"
  end

  defp package do
    [
      name: "exswan_plug",
      licenses: ["MIT"],
      links: %{
        "GitHub" => @source_url,
        "Changelog" => "#{@source_url}/blob/main/packages/exswan_plug/CHANGELOG.md"
      },
      maintainers: ["cserino"],
      files: ~w(lib mix.exs README.md LICENSE CHANGELOG.md)
    ]
  end

  defp docs do
    [
      main: "ExSwan.Plug",
      source_ref: "v#{@version}",
      source_url_pattern: "#{@source_url}/blob/main/packages/exswan_plug/%{path}#L%{line}",
      extras: ["README.md", "CHANGELOG.md"]
    ]
  end
end
