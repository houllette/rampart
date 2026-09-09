defmodule Portico.MixProject do
  use Mix.Project

  def project do
    [
      app: :portico,
      version: "0.1.0",
      elixir: "~> 1.20",
      description:
        "Backpressured discovery and enrichment orchestration for authorized port scanning",
      source_url: "https://github.com/houllette/rampart",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      package: package(),
      docs: docs()
    ]
  end

  def application do
    [
      extra_applications: [:logger],
      mod: {Portico.Application, []}
    ]
  end

  defp deps do
    [
      {:security_core, "~> 0.1", in_umbrella: true, hex: :security_core},
      {:broadway, "~> 1.3"},
      {:jason, "~> 1.4"},
      {:nimble_options, "~> 1.1"},
      {:saxy, "~> 1.6"}
    ]
  end

  defp package do
    [
      licenses: ["MIT"],
      links: %{"GitHub" => "https://github.com/houllette/rampart"},
      files: ~w(lib mix.exs README.md ARCHITECTURE.md SECURITY.md TELEMETRY.md LICENSE)
    ]
  end

  defp docs do
    [
      main: "readme",
      source_url_pattern:
        "https://github.com/houllette/rampart/blob/main/apps/portico/%{path}#L%{line}",
      extras: ["README.md", "ARCHITECTURE.md", "SECURITY.md", "TELEMETRY.md"],
      groups_for_extras: [
        Architecture: ["ARCHITECTURE.md"],
        Operations: ["SECURITY.md", "TELEMETRY.md"]
      ]
    ]
  end
end
