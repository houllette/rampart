defmodule RampartSAST do
  @moduledoc """
  Deterministic, extensible static security reconnaissance for Elixir and Erlang.

  RampartSAST parses bounded Elixir and Erlang source snapshots once, builds a
  high-recall inventory of definitions, calls, callbacks, directives,
  dependencies, typed behaviors, and provenance-backed package use, then runs
  optional host-selected signal rules and context providers. Inventory facts
  and rule matches are reconnaissance. They
  do not prove attacker control, reachability, abuse, or exploitability.
  """

  alias RampartSAST.{Discovery, Limits, Result, Rule, Scanner}

  @default_rules [
    RampartSAST.Rules.UnsafeAtom,
    RampartSAST.Rules.UnsafeExec,
    RampartSAST.Rules.UnsafeDeserialization,
    RampartSAST.Rules.DynamicCode
  ]

  @doc "Returns the small built-in sink-signal starter pack, not a vulnerability policy."
  @spec default_rules() :: [module()]
  def default_rules, do: @default_rules

  @doc "Builds a broad inventory for an authorized project root without signal rules."
  @spec inventory(root :: Path.t(), options :: keyword()) :: Result.t()
  def inventory(root, options \\ []) when is_binary(root) and is_list(options) do
    scan(root, [], options)
  end

  @doc "Builds a broad inventory from in-memory source snapshots without signal rules."
  @spec inventory_sources(entries :: [{Path.t(), String.t()}], options :: keyword()) :: Result.t()
  def inventory_sources(entries, options \\ []) when is_list(entries) and is_list(options) do
    scan_sources(entries, [], options)
  end

  @doc "Scans an authorized project root with explicit optional static rules."
  @spec scan(root :: Path.t(), rules :: [Rule.specification()], options :: keyword()) ::
          Result.t()
  def scan(root, rules, options \\ []) when is_binary(root) and is_list(options) do
    {discovery_options, scanner_options} = Keyword.split(options, [:include, :exclude])
    limits = scanner_options |> Keyword.get(:limits, Limits.new!([])) |> Limits.new!()

    {entries, diagnostics, discovery_metrics} =
      Discovery.read(root, discovery_options, limits)

    scanner_options =
      scanner_options
      |> Keyword.put(:limits, limits)
      |> Keyword.put(:diagnostics, diagnostics)
      |> Keyword.put(:metrics, discovery_metrics)

    Scanner.scan_sources(entries, rules, scanner_options)
  end

  @doc "Scans in-memory repository-relative source snapshots with explicit rules."
  @spec scan_sources(
          entries :: [{Path.t(), String.t()}],
          rules :: [Rule.specification()],
          options :: keyword()
        ) :: Result.t()
  def scan_sources(entries, rules, options \\ []) do
    Scanner.scan_sources(entries, rules, options)
  end

  @doc "Queries deterministic inventory facts from a completed or partial scan."
  @spec query(Result.t(), filters :: keyword()) :: [RampartSAST.Fact.t()]
  def query(%Result{} = result, filters \\ []) do
    RampartSAST.Inventory.query(result.inventory, filters)
  end

  @doc "Returns the versioned static validation actions."
  @spec validation_actions() :: [Core.Validation.Action.t()]
  def validation_actions, do: Core.Validation.actions(RampartSAST.Validator)

  @doc "Re-runs one finding's exact static rule against host-supplied source snapshots."
  @spec validate(finding :: Core.Finding.t(), options :: keyword()) :: Core.Validation.Result.t()
  def validate(%Core.Finding{} = finding, options) when is_list(options) do
    request = Core.Validation.request(RampartSAST.Validator.action(), finding)
    Core.Validation.run(RampartSAST.Validator, request, options)
  end
end
