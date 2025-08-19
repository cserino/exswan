defmodule ExWebauthn.MixProject do
  use Mix.Project

  def project do
    [
      app: :ex_webauthn,
      version: "0.1.0",
      elixir: "~> 1.18",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description: description(),
      package: package(),
      docs: docs(),
      source_url: "https://github.com/cserino/ex_webauthn"
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:jason, "~> 1.4"},
      {:cbor, "~> 1.0"},
      {:x509, "~> 0.8"},
      {:ex_doc, "~> 0.31", only: :dev, runtime: false}
    ]
  end

  defp description do
    "An Elixir library for WebAuthn (FIDO2) authentication"
  end

  defp package do
    [
      name: "ex_webauthn",
      licenses: ["MIT"],
      links: %{"GitHub" => "https://github.com/cserino/ex_webauthn"},
      maintainers: ["cserino"]
    ]
  end

  defp docs do
    [
      main: "ExWebauthn",
      extras: ["README.md", "docs/plan.md"]
    ]
  end
end
