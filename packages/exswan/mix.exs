defmodule ExSwan.MixProject do
  use Mix.Project

  @version "0.1.0"
  @source_url "https://github.com/cserino/exswan"

  def project do
    [
      app: :exswan,
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
      {:jason, "~> 1.4"},
      {:cbor, "~> 1.0"},
      {:x509, "~> 0.8"},
      {:ex_doc, "~> 0.31", only: :dev, runtime: false},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:stream_data, "~> 1.1", only: :test}
    ]
  end

  defp description do
    "An Elixir library for WebAuthn (FIDO2) authentication"
  end

  defp package do
    [
      name: "exswan",
      licenses: ["MIT"],
      links: %{
        "GitHub" => @source_url,
        "Changelog" => "#{@source_url}/blob/main/packages/exswan/CHANGELOG.md"
      },
      maintainers: ["cserino"],
      files: ~w(lib mix.exs README.md LICENSE CHANGELOG.md)
    ]
  end

  defp docs do
    [
      main: "ExSwan",
      source_ref: "v#{@version}",
      source_url_pattern: "#{@source_url}/blob/main/packages/exswan/%{path}#L%{line}",
      extras: ["README.md", "CHANGELOG.md"]
    ]
  end
end
