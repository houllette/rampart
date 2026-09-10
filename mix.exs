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
    [
      preferred_envs: [
        precommit: :test,
        "havoc.replay": :test,
        "rampart.eval": :test,
        "rampart.eval.compare": :test,
        "rampart.perf": :test,
        "rampart.perf.compare": :test,
        "rampart.integration": :test
      ]
    ]
  end

  defp deps do
    [
      {:tidewave, "~> 0.8", only: :dev},
      {:bandit, "~> 1.0", only: :dev},
      {:plug, "~> 1.18", only: [:dev, :test]},
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
      extras: [
        "README.md",
        "NORTH_STAR.md",
        "IAST_RESEARCH.md",
        "LEMIEUX_INTEGRATION.md",
        "EVALUATION.md",
        "PERFORMANCE.md",
        "RESOURCE_LIMITS.md",
        "evaluation/HISTORICAL_CVE_FRONTIER.md",
        "evaluation/CVE_CAPABILITY_CATALOG.md"
      ],
      groups_for_extras: [
        Architecture: ["NORTH_STAR.md", "IAST_RESEARCH.md", "LEMIEUX_INTEGRATION.md"],
        Evaluation: [
          "EVALUATION.md",
          "PERFORMANCE.md",
          "RESOURCE_LIMITS.md",
          "evaluation/HISTORICAL_CVE_FRONTIER.md",
          "evaluation/CVE_CAPABILITY_CATALOG.md"
        ]
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
      "rampart.eval": &run_evaluation/1,
      "rampart.eval.compare": &compare_evaluations/1,
      "rampart.perf": &run_performance/1,
      "rampart.perf.compare": &compare_performance/1,
      "rampart.integration": &run_integration/1,
      precommit: [
        "deps.unlock --check-unused",
        "hex.audit",
        "deps.audit",
        "compile --warnings-as-errors",
        "format",
        "credo --strict",
        "rampart.sast --exit",
        "rampart.eval",
        "usage_rules.sync --yes",
        "xref graph --label compile-connected --fail-above 0",
        "docs --warnings-as-errors",
        "test --warnings-as-errors"
      ]
    ]
  end

  defp run_evaluation(arguments) do
    Mix.Task.run("compile", ["--warnings-as-errors"])

    for application <- [:security_core, :havoc, :rampart_sast, :rampart_iast, :plug] do
      {:ok, _started} = Application.ensure_all_started(application)
    end

    files = [
      "evaluation/fixtures/composed/dependency.ex",
      "evaluation/fixtures/composed/handler.ex",
      "evaluation/fixtures/composed/target.ex",
      "evaluation/fixtures/otp/server.ex",
      "evaluation/fixtures/otp/target.ex",
      "evaluation/fixtures/plug/target.ex",
      "evaluation/fixtures/overhead/target.ex",
      "evaluation/fixtures/historical/plug_static_null_byte/vulnerable.ex",
      "evaluation/fixtures/historical/plug_static_null_byte/fixed.ex",
      "evaluation/fixtures/historical/terminal_control/fixture.ex",
      "evaluation/fixtures/historical/ulid_canonical/fixture.ex",
      "evaluation/fixtures/historical/http_quoted_parameter/fixture.ex",
      "evaluation/fixtures/historical/cache_tenancy/fixture.ex",
      "evaluation/fixtures/historical/ash_field_policy/fixture.ex",
      "evaluation/support/provider.exs",
      "evaluation/support/cross_process_adversarial_probe.exs",
      "evaluation/support/cross_process_frontier_probe.exs",
      "evaluation/support/cross_process_probe.exs",
      "evaluation/corpus.exs",
      "evaluation/runner.exs"
    ]

    Enum.each(files, &Code.require_file/1)
    RampartEvaluation.Runner.run!(arguments)
  end

  defp compare_evaluations(arguments) do
    Code.require_file("evaluation/runtime_comparator.exs")
    RampartEvaluation.RuntimeComparator.run!(arguments)
  end

  defp run_performance(arguments) do
    Mix.Task.run("app.start")
    Code.require_file("evaluation/performance.exs")
    RampartPerformance.run!(arguments)
  end

  defp compare_performance(arguments) do
    Mix.Task.run("compile", ["--warnings-as-errors"])
    Code.require_file("evaluation/performance.exs")
    RampartPerformance.compare!(arguments)
  end

  defp run_integration(arguments) do
    {_output, status} =
      System.cmd("python3", ["evaluation/integration/run.py" | arguments],
        into: IO.stream(:stdio, :line)
      )

    if status != 0,
      do: Mix.raise("Rampart integration gate failed; inspect the retained report and logs")
  end
end
