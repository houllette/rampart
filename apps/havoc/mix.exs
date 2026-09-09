defmodule Havoc.MixProject do
  use Mix.Project

  def project do
    [
      app: :havoc,
      version: "0.2.0",
      elixir: "~> 1.20",
      elixirc_paths: elixirc_paths(Mix.env()),
      description:
        "ExUnit adversarial generators, security oracles, durable regressions, and derived targets",
      source_url: "https://github.com/houllette/rampart",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      package: package(),
      docs: docs()
    ]
  end

  def cli do
    [preferred_envs: ["havoc.replay": :test]]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_env), do: ["lib"]

  def application do
    [extra_applications: []]
  end

  defp deps do
    [
      {:security_core, "~> 0.1", in_umbrella: true, hex: :security_core},
      {:jason, "~> 1.4"},
      {:nimble_options, "~> 1.1"},
      {:stream_data, "~> 1.4"}
    ]
  end

  defp package do
    [
      licenses: ["MIT"],
      links: %{"GitHub" => "https://github.com/houllette/rampart"},
      files: ~w(lib mix.exs README.md ARCHITECTURE.md CORPUS.md ORACLES.md TARGETS.md LICENSE)
    ]
  end

  defp docs do
    [
      main: "readme",
      source_url_pattern:
        "https://github.com/houllette/rampart/blob/main/apps/havoc/%{path}#L%{line}",
      extras: ["README.md", "ARCHITECTURE.md", "CORPUS.md", "ORACLES.md", "TARGETS.md"],
      groups_for_extras: [
        Design: ["ARCHITECTURE.md", "ORACLES.md", "CORPUS.md", "TARGETS.md"]
      ]
    ]
  end
end
