defmodule MuexSecurity.MixProject do
  use Mix.Project

  def project do
    [
      app: :muex_security,
      version: "0.1.0",
      elixir: "~> 1.20",
      description: "Focused security mutation operators for Muex",
      source_url: "https://github.com/houllette/rampart",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      package: package(),
      docs: docs()
    ]
  end

  def application do
    [extra_applications: []]
  end

  defp deps do
    [{:muex, "~> 0.9", runtime: false}]
  end

  defp package do
    [
      licenses: ["MIT"],
      links: %{"GitHub" => "https://github.com/houllette/rampart"},
      files: ~w(lib mix.exs README.md OPERATORS.md LICENSE)
    ]
  end

  defp docs do
    [
      main: "readme",
      source_url_pattern:
        "https://github.com/houllette/rampart/blob/main/apps/muex_security/%{path}#L%{line}",
      extras: ["README.md", "OPERATORS.md"]
    ]
  end
end
