defmodule RampartSAST.Scanner do
  @moduledoc false

  alias RampartSAST.{
    Context,
    ContextProvider,
    Diagnostic,
    Inventory,
    Limits,
    Match,
    Observation,
    Result,
    Rule,
    Source,
    Suppressed,
    Suppression
  }

  @type source_entry :: {Path.t(), String.t()}

  @spec scan_sources([source_entry()], [Rule.specification()], keyword()) :: Result.t()
  def scan_sources(entries, rule_specifications, options \\ [])
      when is_list(entries) and is_list(options) do
    options =
      Keyword.validate!(options,
        limits: Limits.new!([]),
        context_providers: [RampartSAST.Context.Elixir],
        module_owners: %{},
        source_origins: %{},
        behavior_classifiers: [RampartSAST.Behavior.BEAM],
        apply_suppressions: true,
        diagnostics: [],
        metrics: %{}
      )

    limits = Limits.new!(options[:limits])
    rules = Rule.resolve!(rule_specifications)
    entries = validate_entries!(entries)
    diagnostics = validate_diagnostics!(options[:diagnostics])
    metrics = validate_metrics!(options[:metrics])
    validate_source_origins!(options[:source_origins], entries)

    case entry_limit_diagnostics(entries, limits) do
      [] -> run(entries, rules, options, limits, diagnostics, metrics)
      limit_diagnostics -> empty_result(diagnostics ++ limit_diagnostics, rules, entries, metrics)
    end
  end

  defp run(entries, rules, options, limits, initial_diagnostics, initial_metrics) do
    {sources, parse_diagnostics} =
      parse_sources(entries, limits, options[:source_origins])

    inventory =
      Inventory.build(sources,
        module_owners: options[:module_owners],
        behavior_classifiers: options[:behavior_classifiers],
        behavior_timeout_ms: limits.behavior_timeout_ms
      )

    {context, context_diagnostics} =
      ContextProvider.build(
        sources,
        options[:context_providers],
        limits.context_timeout_ms
      )

    {rule_matches, rule_diagnostics} = run_rules(rules, sources, context, limits)
    observations = normalize_matches(rule_matches, sources)

    {active, suppressed} =
      apply_suppressions(observations, sources, options[:apply_suppressions])

    observed_at = DateTime.utc_now()
    source_by_path = Map.new(sources, &{&1.path, &1})

    findings =
      Enum.map(active, fn observation ->
        Observation.to_finding(
          observation,
          Map.fetch!(source_by_path, observation.span.file),
          observed_at
        )
      end)

    diagnostics =
      sort_diagnostics(
        initial_diagnostics ++
          parse_diagnostics ++
          inventory.diagnostics ++
          context_diagnostics ++ rule_diagnostics
      )

    metrics =
      Map.merge(initial_metrics, %{
        source_count: length(sources),
        source_bytes: Enum.reduce(sources, 0, &(&1.bytes + &2)),
        rule_count: length(rules),
        fact_count: length(inventory.facts),
        observation_count: length(active),
        suppressed_count: length(suppressed),
        diagnostic_count: length(diagnostics)
      })

    %Result{
      status: status(diagnostics),
      observations: active,
      findings: findings,
      inventory: inventory,
      suppressed: suppressed,
      diagnostics: diagnostics,
      metrics: metrics
    }
  end

  defp parse_sources(entries, limits, source_origins) do
    entries
    |> Task.async_stream(
      fn {path, content} -> Source.parse(path, content, limits.max_file_bytes) end,
      max_concurrency: limits.max_concurrency,
      ordered: true,
      on_timeout: :kill_task,
      timeout: limits.parse_timeout_ms
    )
    |> Stream.zip(entries)
    |> Enum.reduce({[], []}, fn
      {{:ok, {:ok, source, diagnostics}}, _entry}, {sources, all_diagnostics} ->
        source = attach_origin(source, source_origins)
        {[source | sources], diagnostics ++ all_diagnostics}

      {{:ok, {:error, diagnostic}}, _entry}, {sources, diagnostics} ->
        {sources, [diagnostic | diagnostics]}

      {{:exit, :timeout}, {path, _content}}, {sources, diagnostics} ->
        diagnostic =
          Diagnostic.new!(
            level: :error,
            phase: :parse,
            code: :parse_timeout,
            file: path,
            message: "source parsing exceeded #{limits.parse_timeout_ms} ms"
          )

        {sources, [diagnostic | diagnostics]}

      {{:exit, reason}, {path, _content}}, {sources, diagnostics} ->
        diagnostic =
          Diagnostic.new!(
            level: :error,
            phase: :parse,
            code: :parse_failed,
            file: path,
            message: "source parser exited: #{inspect(reason, limit: 20)}"
          )

        {sources, [diagnostic | diagnostics]}
    end)
    |> then(fn {sources, diagnostics} ->
      {Enum.sort_by(sources, & &1.path), diagnostics}
    end)
  end

  defp run_rules(rules, sources, %Context{} = context, limits) do
    jobs = rule_jobs(rules, sources)
    known_paths = MapSet.new(sources, & &1.path)

    jobs
    |> Task.async_stream(
      &safe_run_rule(&1, sources, context, known_paths),
      max_concurrency: limits.max_concurrency,
      ordered: true,
      on_timeout: :kill_task,
      timeout: limits.rule_timeout_ms
    )
    |> Stream.zip(jobs)
    |> Enum.reduce({[], []}, fn
      {{:ok, {:ok, matches}}, _job}, {all_matches, diagnostics} ->
        {matches ++ all_matches, diagnostics}

      {{:ok, {:error, diagnostic}}, _job}, {matches, diagnostics} ->
        {matches, [diagnostic | diagnostics]}

      {{:exit, :timeout}, job}, {matches, diagnostics} ->
        {matches, [rule_timeout_diagnostic(job, limits) | diagnostics]}

      {{:exit, reason}, job}, {matches, diagnostics} ->
        {matches, [rule_exit_diagnostic(job, reason) | diagnostics]}
    end)
  end

  defp rule_jobs(rules, sources) do
    Enum.flat_map(rules, fn
      %{descriptor: %{scope: :source}} = rule ->
        Enum.map(sources, &{:source, rule, &1})

      %{descriptor: %{scope: :project}} = rule ->
        [{:project, rule}]
    end)
  end

  defp safe_run_rule({:source, rule, source}, _sources, context, known_paths) do
    rule.module.run_source(source, context, rule.options)
    |> validate_matches(rule, known_paths, source.path)
  rescue
    error -> {:error, rule_failed_diagnostic(rule, source.path, Exception.message(error))}
  catch
    kind, reason ->
      {:error,
       rule_failed_diagnostic(rule, source.path, "#{kind}: #{inspect(reason, limit: 20)}")}
  end

  defp safe_run_rule({:project, rule}, sources, context, known_paths) do
    rule.module.run_project(sources, context, rule.options)
    |> validate_matches(rule, known_paths, nil)
  rescue
    error -> {:error, rule_failed_diagnostic(rule, nil, Exception.message(error))}
  catch
    kind, reason ->
      {:error, rule_failed_diagnostic(rule, nil, "#{kind}: #{inspect(reason, limit: 20)}")}
  end

  defp validate_matches(matches, rule, known_paths, required_path) when is_list(matches) do
    matches = Enum.map(matches, &Match.validate!/1)

    valid_paths? =
      Enum.all?(matches, fn match ->
        MapSet.member?(known_paths, match.span.file) and
          (is_nil(required_path) or match.span.file == required_path)
      end)

    if valid_paths? do
      {:ok, Enum.map(matches, &{rule.descriptor, &1})}
    else
      {:error,
       rule_failed_diagnostic(rule, required_path, "rule returned a match for an unknown source")}
    end
  rescue
    error in ArgumentError ->
      {:error, rule_failed_diagnostic(rule, required_path, Exception.message(error))}
  end

  defp validate_matches(_matches, rule, _known_paths, required_path) do
    {:error, rule_failed_diagnostic(rule, required_path, "rule must return a list of matches")}
  end

  defp normalize_matches(rule_matches, sources) do
    source_hashes = Map.new(sources, &{&1.path, &1.hash})

    rule_matches
    |> Enum.sort_by(fn {descriptor, match} ->
      {
        descriptor.id,
        match.span.file,
        match.span.start_line,
        match.span.start_column || 0,
        match.anchor,
        match.message
      }
    end)
    |> Enum.map_reduce(%{}, fn {descriptor, match}, occurrences ->
      key = {descriptor.id, match.span.file, match.anchor}
      occurrence = Map.get(occurrences, key, 0) + 1

      observation =
        Observation.build(
          descriptor,
          match,
          Map.fetch!(source_hashes, match.span.file),
          occurrence
        )

      {observation, Map.put(occurrences, key, occurrence)}
    end)
    |> elem(0)
  end

  defp apply_suppressions(observations, _sources, false), do: {observations, []}

  defp apply_suppressions(observations, sources, true) do
    suppressions = Map.new(sources, &{&1.path, &1.suppressions})

    {active, suppressed} =
      Enum.reduce(observations, {[], []}, fn observation, {active, suppressed} ->
        source_suppressions = Map.get(suppressions, observation.span.file, [])

        case Enum.find(
               source_suppressions,
               &Suppression.applies?(&1, observation.rule.id, observation.span.start_line)
             ) do
          nil ->
            {[observation | active], suppressed}

          suppression ->
            {active,
             [%Suppressed{observation: observation, suppression: suppression} | suppressed]}
        end
      end)

    {Enum.reverse(active), Enum.reverse(suppressed)}
  end

  defp entry_limit_diagnostics(entries, limits) do
    file_count = length(entries)

    total_bytes =
      Enum.reduce(entries, 0, fn {_path, content}, sum -> sum + byte_size(content) end)

    []
    |> maybe_add_limit(
      file_count > limits.max_files,
      :file_count_limit,
      "received #{file_count} files; limit is #{limits.max_files}"
    )
    |> maybe_add_limit(
      total_bytes > limits.max_total_bytes,
      :total_size_limit,
      "received #{total_bytes} source bytes; limit is #{limits.max_total_bytes}"
    )
  end

  defp maybe_add_limit(diagnostics, false, _code, _message), do: diagnostics

  defp maybe_add_limit(diagnostics, true, code, message) do
    [
      Diagnostic.new!(level: :error, phase: :limits, code: code, message: message)
      | diagnostics
    ]
  end

  defp empty_result(diagnostics, rules, entries, initial_metrics) do
    diagnostics = sort_diagnostics(diagnostics)

    %Result{
      status: :incomplete,
      observations: [],
      findings: [],
      inventory: Inventory.build([]),
      suppressed: [],
      diagnostics: diagnostics,
      metrics:
        Map.merge(initial_metrics, %{
          source_count: 0,
          source_bytes:
            Enum.reduce(entries, 0, fn {_path, content}, sum -> sum + byte_size(content) end),
          rule_count: length(rules),
          fact_count: 0,
          observation_count: 0,
          suppressed_count: 0,
          diagnostic_count: length(diagnostics)
        })
    }
  end

  defp rule_failed_diagnostic(rule, file, message) do
    Diagnostic.new!(
      level: :error,
      phase: :rule,
      code: :rule_failed,
      file: file,
      rule_id: rule.descriptor.id,
      message: "static rule failed: #{message}"
    )
  end

  defp rule_timeout_diagnostic(job, limits) do
    {rule, file} = job_identity(job)

    Diagnostic.new!(
      level: :error,
      phase: :rule,
      code: :rule_timeout,
      file: file,
      rule_id: rule.descriptor.id,
      message: "static rule exceeded #{limits.rule_timeout_ms} ms"
    )
  end

  defp rule_exit_diagnostic(job, reason) do
    {rule, file} = job_identity(job)
    rule_failed_diagnostic(rule, file, "rule process exited: #{inspect(reason, limit: 20)}")
  end

  defp job_identity({:source, rule, source}), do: {rule, source.path}
  defp job_identity({:project, rule}), do: {rule, nil}

  defp validate_entries!(entries) do
    unless Enum.all?(
             entries,
             &match?({path, content} when is_binary(path) and is_binary(content), &1)
           ) do
      raise ArgumentError, "SAST source entries must be {relative_path, source} string pairs"
    end

    paths = Enum.map(entries, &elem(&1, 0))

    if length(Enum.uniq(paths)) == length(paths) do
      Enum.sort_by(entries, &elem(&1, 0))
    else
      raise ArgumentError, "SAST source entries must have unique paths"
    end
  end

  defp validate_diagnostics!(diagnostics) when is_list(diagnostics) do
    Enum.map(diagnostics, &Diagnostic.validate!/1)
  end

  defp validate_diagnostics!(diagnostics) do
    raise ArgumentError, "SAST initial diagnostics must be a list, got: #{inspect(diagnostics)}"
  end

  defp validate_source_origins!(source_origins, entries) when is_map(source_origins) do
    known_paths = MapSet.new(entries, &elem(&1, 0))

    unless Enum.all?(source_origins, fn {path, origin} ->
             is_binary(path) and MapSet.member?(known_paths, path) and is_map(origin)
           end) do
      raise ArgumentError, "SAST source origins must map known source paths to origin maps"
    end
  end

  defp validate_source_origins!(_source_origins, _entries) do
    raise ArgumentError, "SAST source origins must be a map"
  end

  defp attach_origin(source, source_origins) do
    case Map.fetch(source_origins, source.path) do
      {:ok, origin} -> Source.with_origin(source, origin)
      :error -> source
    end
  end

  defp validate_metrics!(metrics) when is_map(metrics), do: metrics

  defp validate_metrics!(metrics) do
    raise ArgumentError, "SAST initial metrics must be a map, got: #{inspect(metrics)}"
  end

  defp status(diagnostics) do
    if Enum.any?(diagnostics, &(&1.level == :error)), do: :incomplete, else: :complete
  end

  defp sort_diagnostics(diagnostics) do
    Enum.sort_by(diagnostics, &{&1.level, &1.phase, &1.file || "", &1.rule_id || "", &1.code})
  end
end
