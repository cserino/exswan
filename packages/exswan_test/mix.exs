defmodule ExSwan.Test.MixProject do
  use Mix.Project

  @version "0.1.0"
  @source_url "https://github.com/cserino/exswan"

  def project do
    [
      app: :exswan_test,
      version: @version,
      elixir: "~> 1.18",
      deps: deps(),
      description: "Consumer test helpers for ExSwan WebAuthn applications",
      package: package(),
      docs: docs(),
      source_url: @source_url
    ]
  end

  def application, do: [extra_applications: [:crypto]]

  defp deps do
    [
      exswan_dep(),
      {:jason, "~> 1.4"},
      {:cbor, "~> 1.0"},
      {:ex_doc, "~> 0.31", only: :dev, runtime: false},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false}
    ]
  end

  defp exswan_dep do
    if System.get_env("EXSWAN_MONOREPO") == "true" do
      {:exswan, path: "../exswan"}
    else
      {:exswan, "~> 0.1.0"}
    end
  end

  defp package do
    [
      name: "exswan_test",
      licenses: ["MIT"],
      links: %{"GitHub" => @source_url},
      maintainers: ["cserino"],
      files: ~w(lib docs mix.exs README.md LICENSE CHANGELOG.md)
    ]
  end

  defp docs do
    [
      main: "ExSwan.Test.Authenticator",
      source_ref: "exswan_test-v#{@version}",
      extras: [
        "README.md",
        "docs/testing-guide.md",
        "CHANGELOG.md"
      ],
      groups_for_extras: [Guides: ["docs/testing-guide.md"]]
    ]
  end
end
