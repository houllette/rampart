defmodule SecurityCore.MixProject do
  use Mix.Project

  def project do
    [
      app: :security_core,
      version: "0.1.0",
      elixir: "~> 1.20",
      description: "Findings, proof memory, validation, scope, telemetry, and process contracts",
      source_url: "https://github.com/houllette/rampart",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      package: package(),
      docs: docs()
    ]
  end

  def application do
    [
      extra_applications: [:crypto],
      mod: {Core.Application, []}
    ]
  end

  defp deps do
    [
      {:exile, "~> 0.14.0"},
      {:telemetry, "~> 1.4"}
    ]
  end

  defp package do
    [
      name: "security_core",
      licenses: ["MIT"],
      links: %{"GitHub" => "https://github.com/houllette/rampart"},
      files: ~w(lib mix.exs README.md LICENSE)
    ]
  end

  defp docs do
    [
      main: "readme",
      source_url_pattern:
        "https://github.com/houllette/rampart/blob/main/apps/security_core/%{path}#L%{line}",
      extras: ["README.md"]
    ]
  end
end
