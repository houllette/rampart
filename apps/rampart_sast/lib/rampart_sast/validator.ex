defmodule RampartSAST.Validator do
  @moduledoc "Re-runs one exact static rule against host-supplied source snapshots."

  @behaviour Core.Validator

  alias Core.Validation
  alias Core.Validation.{Action, Evidence, Request}
  alias RampartSAST.{Diagnostic, Result, Rule, Scanner}

  @action_id "sast.rule-matches-source.v1"

  @impl true
  @spec actions() :: [Action.t()]
  def actions, do: [action()]

  @doc false
  @spec action() :: Action.t()
  def action do
    %Action{
      id: @action_id,
      tool: :sast,
      name: :rule_matches_source,
      description:
        "re-run one host-selected static rule and test whether the same metadata-free AST anchor remains",
      accepts: [:finding],
      side_effects: :none,
      meta: %{
        proof_level: :syntactic_match,
        source_authority: :host,
        attacker_control: :not_proven,
        exploitability: :not_proven
      }
    }
  end

  @impl true
  @spec validate(Request.t(), keyword()) :: Core.Validation.Result.t()
  def validate(%Request{subject: %Core.Finding{} = finding} = request, options) do
    options =
      Keyword.validate!(options, [
        :rules,
        :source,
        :sources,
        :limits,
        context_providers: [RampartSAST.Context.Elixir]
      ])

    details = finding!(finding)
    rules = options |> Keyword.fetch!(:rules) |> Rule.resolve!()
    rule = Rule.fetch!(rules, details.rule_id)
    ensure_scope!(details, rule.descriptor.scope)

    case source_entries(finding, details, rule, options) do
      {:ok, entries} -> validate_entries(request, finding, details, rule, entries, options)
      {:error, reason} -> inconclusive(request, finding.seed, details, reason, nil)
    end
  end

  defp validate_entries(request, finding, details, rule, entries, options) do
    scan =
      Scanner.scan_sources(entries, [{rule.module, rule.options}],
        limits: Keyword.get(options, :limits, RampartSAST.Limits.new!([])),
        context_providers: options[:context_providers],
        apply_suppressions: false
      )

    cond do
      scan.status == :incomplete ->
        inconclusive(
          request,
          current_seed(entries, details, finding.seed),
          details,
          :scan_incomplete,
          scan
        )

      observation = find_observation(scan, details) ->
        confirmed_finding = Enum.find(scan.findings, &(&1.id == observation.id))

        Validation.confirmed(
          request,
          [confirmed_finding],
          confirmed_finding.seed,
          evidence(details, scan, "the same static rule and AST anchor were reproduced"),
          result_meta(details)
        )

      true ->
        Validation.refuted(
          request,
          current_seed(entries, details, finding.seed),
          evidence(
            details,
            scan,
            "the selected static rule no longer produced the same AST anchor"
          ),
          result_meta(details)
        )
    end
  end

  defp find_observation(%Result{} = scan, details) do
    Enum.find(scan.observations, fn observation ->
      observation.rule.id == details.rule_id and
        observation.span.file == details.file and
        observation.anchor == details.anchor and
        observation.occurrence == details.occurrence
    end)
  end

  defp source_entries(_finding, details, %{descriptor: %{scope: :project}}, options) do
    case Keyword.fetch(options, :sources) do
      {:ok, entries} when is_list(entries) -> ensure_target_source(entries, details.file)
      _other -> {:error, :project_sources_required}
    end
  end

  defp source_entries(finding, details, _rule, options) do
    source = Keyword.get(options, :source)
    sources = Keyword.get(options, :sources)

    case {source, sources} do
      {nil, nil} -> seed_entries(finding.seed, details.file)
      {content, nil} when is_binary(content) -> {:ok, [{details.file, content}]}
      {nil, entries} when is_list(entries) -> ensure_target_source(entries, details.file)
      {_source, _sources} -> {:error, :choose_source_or_sources}
    end
  end

  defp seed_entries(%Core.Seed{value: %{path: path, content: content}}, path)
       when is_binary(content),
       do: {:ok, [{path, content}]}

  defp seed_entries(_seed, _path), do: {:error, :source_snapshot_required}

  defp ensure_target_source(entries, target_path) do
    if Enum.any?(entries, fn
         {^target_path, content} when is_binary(content) -> true
         _entry -> false
       end) do
      {:ok, entries}
    else
      {:error, :target_source_missing}
    end
  end

  defp finding!(%Core.Finding{
         source: :sast,
         locus: locus,
         seed: %Core.Seed{value: %{path: seed_path, content: content}}
       })
       when is_map(locus) and is_binary(seed_path) and is_binary(content) do
    details = %{
      rule_id: Map.get(locus, :rule_id),
      file: Map.get(locus, :file),
      anchor: Map.get(locus, :anchor),
      occurrence: Map.get(locus, :occurrence),
      scope: Map.get(locus, :scope)
    }

    valid? =
      seed_path == details.file and nonempty_string?(details.rule_id) and
        RampartSAST.Span.valid_file?(details.file) and digest?(details.anchor) and
        positive_integer?(details.occurrence) and details.scope in [:source, :project]

    if valid?, do: details, else: raise(ArgumentError, "invalid SAST finding contract")
  end

  defp finding!(_finding), do: raise(ArgumentError, "SAST validation requires a SAST finding")

  defp ensure_scope!(details, scope) do
    unless details.scope == scope,
      do: raise(ArgumentError, "SAST finding scope does not match the host-selected rule")
  end

  defp current_seed(entries, details, fallback) do
    case Enum.find(entries, fn
           {path, content} -> path == details.file and is_binary(content)
           _entry -> false
         end) do
      {path, content} -> source_seed(path, content, details.rule_id)
      nil -> fallback
    end
  end

  defp source_seed(path, content, rule_id) do
    hash = digest(content)

    %Core.Seed{
      id: Core.Finding.dedupe_id(:sast, ["source_snapshot", path, hash]),
      value: %{path: path, content: content},
      classes: [:source_snapshot, :static_analysis],
      provenance: :generated,
      meta: %{source_hash: hash, rule_id: rule_id}
    }
  end

  defp inconclusive(request, seed, details, reason, scan) do
    diagnostics = if scan, do: Enum.map(scan.diagnostics, &Diagnostic.to_map/1), else: []

    Validation.inconclusive(
      request,
      seed,
      %Evidence{
        summary: "the static rule could not be safely re-run",
        facts: %{
          reason: reason,
          rule_id: details.rule_id,
          file: details.file,
          diagnostics: diagnostics,
          proof_level: :syntactic_match
        },
        raw: scan
      },
      result_meta(details)
    )
  end

  defp evidence(details, scan, summary) do
    %Evidence{
      summary: summary,
      facts: %{
        rule_id: details.rule_id,
        file: details.file,
        anchor: details.anchor,
        occurrence: details.occurrence,
        scan_status: scan.status,
        diagnostic_count: length(scan.diagnostics),
        proof_level: :syntactic_match,
        attacker_control: :not_evaluated,
        exploitability: :not_evaluated
      },
      raw: scan
    }
  end

  defp result_meta(details) do
    %{
      rule_id: details.rule_id,
      proof_level: :syntactic_match,
      attacker_control: :not_proven,
      exploitability: :not_proven
    }
  end

  defp digest?(value), do: is_binary(value) and byte_size(value) == 64
  defp positive_integer?(value), do: is_integer(value) and value > 0
  defp nonempty_string?(value), do: is_binary(value) and String.trim(value) != ""

  defp digest(content) do
    :sha256
    |> :crypto.hash(content)
    |> Base.encode16(case: :lower)
  end
end
