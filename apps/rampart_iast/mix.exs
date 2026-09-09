defmodule RampartIAST.MixProject do
  use Mix.Project

  def project do
    [
      app: :rampart_iast,
      version: "0.1.0-dev",
      elixir: "~> 1.20",
      elixirc_paths: elixirc_paths(Mix.env()),
      description: "Experimental bounded BEAM trace sensor for exact-marker IAST validation",
      source_url: "https://github.com/houllette/rampart",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      package: package(),
      docs: docs()
    ]
  end

  def application do
    [extra_applications: [:crypto]]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_env), do: ["lib"]

  defp deps do
    [
      {:security_core, "~> 0.1", in_umbrella: true, hex: :security_core}
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
        "https://github.com/houllette/rampart/blob/main/apps/rampart_iast/%{path}#L%{line}",
      extras: ["README.md", "RESEARCH.md"]
    ]
  end
end
