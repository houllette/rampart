defmodule Rampart.MixProject do
  use Mix.Project

  def project do
    [
      apps_path: "apps",
      name: "Rampart",
      version: "0.1.0",
      elixir: "~> 1.20",
      source_url: "https://github.com/houllette/rampart",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      aliases: aliases(),
      docs: docs(),
      dialyzer: [
        plt_file: {:no_warn, "priv/plts/dialyzer.plt"},
        plt_add_apps: [:ex_unit, :mix, :muex],
        paths: [
          "_build/#{Mix.env()}/lib/security_core/ebin",
          "_build/#{Mix.env()}/lib/portico/ebin",
          "_build/#{Mix.env()}/lib/foray/ebin",
          "_build/#{Mix.env()}/lib/havoc/ebin",
          "_build/#{Mix.env()}/lib/havoc_proper/ebin",
          "_build/#{Mix.env()}/lib/muex_security/ebin",
          "_build/#{Mix.env()}/lib/rampart_iast/ebin",
          "_build/#{Mix.env()}/lib/rampart_sast/ebin"
        ]
      ],
      usage_rules: [file: "AGENTS.md", usage_rules: :all]
    ]
  end

  def cli do
    [preferred_envs: [precommit: :test, "havoc.replay": :test]]
  end

  defp deps do
    [
      {:tidewave, "~> 0.8", only: :dev},
      {:bandit, "~> 1.0", only: :dev},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false},
      {:mix_audit, "~> 2.1", only: [:dev, :test], runtime: false},
      {:ex_doc, "~> 0.40", only: [:dev, :test], runtime: false},
      {:usage_rules, "~> 1.2", only: [:dev, :test], runtime: false}
    ]
  end

  defp docs do
    [
      main: "readme",
      extras: ["README.md", "NORTH_STAR.md", "IAST_RESEARCH.md", "LEMIEUX_INTEGRATION.md"],
      groups_for_extras: [
        Architecture: ["NORTH_STAR.md", "IAST_RESEARCH.md", "LEMIEUX_INTEGRATION.md"]
      ],
      groups_for_modules: [
        "Shared spine": [~r/^Core(?:\.|$)/],
        Portico: [~r/^Portico(?:\.|$)/],
        Foray: [~r/^Foray(?:\.|$)/],
        Havoc: [~r/^Havoc(?:\.|$)/],
        "Havoc PropEr adapter": [~r/^HavocProper(?:\.|$)/],
        "Muex security operators": [~r/^MuexSecurity(?:\.|$)/],
        "Experimental IAST sensor": [~r/^RampartIAST(?:\.|$)/],
        "Static security analysis": [~r/^RampartSAST(?:\.|$)/]
      ]
    ]
  end

  defp aliases do
    [
      tidewave:
        "run --no-halt -e 'Agent.start(fn -> Bandit.start_link(plug: Tidewave, port: 4000) end)'",
      precommit: [
        "deps.unlock --check-unused",
        "hex.audit",
        "deps.audit",
        "compile --warnings-as-errors",
        "format",
        "credo --strict",
        "rampart.sast --exit",
        "usage_rules.sync --yes",
        "xref graph --label compile-connected --fail-above 0",
        "docs --warnings-as-errors",
        "test --warnings-as-errors"
      ]
    ]
  end
end
