defmodule Foray.MixProject do
  use Mix.Project

  def project do
    [
      app: :foray,
      version: "0.1.0",
      elixir: "~> 1.20",
      description: "Backpressured, scope-safe orchestration of ffuf web-fuzzing jobs",
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
      mod: {Foray.Application, []}
    ]
  end

  defp deps do
    [
      {:security_core, "~> 0.1", in_umbrella: true, hex: :security_core},
      {:broadway, "~> 1.3"},
      {:jason, "~> 1.4"},
      {:nimble_options, "~> 1.1"}
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
        "https://github.com/houllette/rampart/blob/main/apps/foray/%{path}#L%{line}",
      extras: ["README.md", "ARCHITECTURE.md", "SECURITY.md", "TELEMETRY.md"],
      groups_for_extras: [
        Architecture: ["ARCHITECTURE.md"],
        Operations: ["SECURITY.md", "TELEMETRY.md"]
      ]
    ]
  end
end
