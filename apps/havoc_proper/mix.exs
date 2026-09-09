defmodule HavocProper.MixProject do
  use Mix.Project

  def project do
    [
      app: :havoc_proper,
      version: "0.1.0",
      elixir: "~> 1.20",
      description: "Optional PropEr targeted-PBT and coverage-guided backend for Havoc",
      source_url: "https://github.com/houllette/rampart",
      start_permanent: Mix.env() == :prod,
      elixirc_paths: elixirc_paths(Mix.env()),
      deps: deps(),
      package: package(),
      docs: docs()
    ]
  end

  def application do
    [extra_applications: [:tools]]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_env), do: ["lib"]

  defp deps do
    [
      {:havoc, "~> 0.2", in_umbrella: true, hex: :havoc},
      {:nimble_options, "~> 1.1"},
      {:propcheck, "~> 1.5"}
    ]
  end

  defp package do
    [
      licenses: ["MIT"],
      links: %{"GitHub" => "https://github.com/houllette/rampart"},
      files: ~w(lib mix.exs README.md RESEARCH.md LICENSE)
    ]
  end

  defp docs do
    [
      main: "readme",
      source_url_pattern:
        "https://github.com/houllette/rampart/blob/main/apps/havoc_proper/%{path}#L%{line}",
      extras: ["README.md", "RESEARCH.md"]
    ]
  end
end
