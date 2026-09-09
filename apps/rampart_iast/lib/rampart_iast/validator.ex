defmodule RampartIAST.Validator do
  @moduledoc """
  Validates one exact-marker, single-process sink-reachability hypothesis.

  The provider, execution callback, trace backend, and limits are host-owned
  options. The hypothesis carries only inert declaration IDs and a concrete
  replay seed.
  """

  @behaviour Core.Validator

  alias Core.Validation
  alias Core.Validation.{Action, Evidence, Request}
  alias RampartIAST.{ContextProvider, Limits, Source, StaticCandidate, TraceSession}
  alias RampartIAST.TraceSession.Result, as: TraceResult

  @action_id "iast.exact-marker-reaches-sink.v1"

  @impl true
  def actions, do: [action()]

  @doc false
  @spec action() :: Action.t()
  def action do
    %Action{
      id: @action_id,
      tool: :iast,
      name: :exact_marker_reaches_sink,
      description:
        "run one controlled process and test whether unchanged marker bytes reach a reviewed sink argument",
      accepts: [:hypothesis],
      side_effects: :test_execution,
      meta: %{
        observation_level: :exact_marker,
        process_scope: :single_process,
        transformed_values: :unsupported,
        exploitability: :not_proven
      }
    }
  end

  @impl true
  def validate(%Request{subject: %Core.Hypothesis{} = hypothesis} = request, opts) do
    opts =
      Keyword.validate!(opts, [
        :provider,
        :execute,
        :limits,
        :trace_backend
      ])

    provider = Keyword.fetch!(opts, :provider)
    execute = Keyword.fetch!(opts, :execute)

    unless is_atom(provider) and is_function(execute, 1) do
      raise ArgumentError,
            "IAST validation requires a provider module and one-argument execute function"
    end

    details = hypothesis!(hypothesis)
    {static_candidate, source, sink} = resolve_bindings!(provider, details)

    ensure_supported_source!(source)
    limits = opts |> Keyword.get(:limits, Limits.new!([])) |> Limits.new!()
    replay_seed = replay_seed(hypothesis.seed, hypothesis, request)
    session_id = Core.Finding.dedupe_id(:iast, ["trace_session", request.id])

    trace_result =
      TraceSession.run(
        session_id,
        source,
        sink,
        replay_seed.value,
        execute,
        limits,
        trace_backend: Keyword.get(opts, :trace_backend, RampartIAST.TraceBackend.OTP)
      )

    verdict(request, hypothesis, replay_seed, static_candidate, source, sink, trace_result)
  end

  defp verdict(
         request,
         hypothesis,
         seed,
         static_candidate,
         source,
         sink,
         %TraceResult{} = trace_result
       ) do
    facts = facts(static_candidate, source, sink, trace_result)
    matched = Enum.filter(trace_result.observations, &(&1.matched_positions != []))

    cond do
      trace_result.envelope == :intact and matched != [] ->
        finding =
          finding(hypothesis, seed, static_candidate, source, sink, matched, trace_result)

        Validation.confirmed(
          request,
          [finding],
          seed,
          %Evidence{
            summary:
              "unchanged marker bytes reached #{sink.id} in #{length(matched)} captured sink call(s); this proves reachability, not exploitability",
            facts: facts,
            raw: trace_result
          },
          validation_meta(static_candidate)
        )

      trace_result.envelope == :intact and trace_result.execution == :completed ->
        Validation.refuted(
          request,
          seed,
          %Evidence{
            summary:
              "the controlled execution completed with an intact trace envelope and did not expose unchanged marker bytes at #{sink.id}",
            facts: facts,
            raw: trace_result
          },
          validation_meta(static_candidate)
        )

      true ->
        Validation.inconclusive(
          request,
          seed,
          %Evidence{
            summary:
              "the IAST sensor could not decide the exact-marker hypothesis because the execution or trace envelope was incomplete",
            facts: Map.put(facts, :reason, reason_code(trace_result)),
            raw: trace_result
          },
          validation_meta(static_candidate)
        )
    end
  end

  defp finding(hypothesis, seed, static_candidate, source, sink, matched, trace_result) do
    observed_at = DateTime.utc_now()

    %Core.Finding{
      id:
        Core.Finding.dedupe_id(:iast, [
          "exact_marker_reachability",
          hypothesis.id,
          source.id,
          sink.id
        ]),
      source: :iast,
      category: sink.category,
      locus: finding_locus(static_candidate, source, sink),
      severity: sink.severity,
      confidence: :high,
      evidence:
        "unchanged marker bytes reached #{sink.id} at positions #{inspect(matched_positions(matched))}; exploitability was not evaluated",
      raw: %{hypothesis: hypothesis, trace: trace_result},
      seed: seed,
      observed_at: observed_at
    }
  end

  defp finding_locus(static_candidate, source, sink) do
    %{
      context: sink.context,
      source_id: source.id,
      sink_id: sink.id,
      sink_mfa: sink.mfa,
      argument_positions: sink.argument_positions,
      observation_level: :exact_marker,
      process_scope: :single_process
    }
    |> maybe_add_static_localization(static_candidate)
  end

  defp maybe_add_static_localization(locus, nil), do: locus

  defp maybe_add_static_localization(locus, %StaticCandidate{} = candidate) do
    locus =
      Map.merge(locus, %{
        static_candidate_id: candidate.id,
        static_flow_basis: candidate.flow_basis,
        static_sanitizer_status: candidate.sanitizer_status,
        sink_localization_basis: candidate.localization,
        static_sink_candidate_count: length(candidate.sink_sites)
      })

    case StaticCandidate.localized_sink_span(candidate) do
      nil -> locus
      span -> Map.put(locus, :sink_source_span, span)
    end
  end

  defp facts(static_candidate, source, sink, trace_result) do
    matched = Enum.filter(trace_result.observations, &(&1.matched_positions != []))

    %{
      session_id: trace_result.session_id,
      source_id: source.id,
      source_schema_version: source.schema_version,
      source_provenance: source.provenance,
      sink_id: sink.id,
      sink_schema_version: sink.schema_version,
      sink_provenance: sink.provenance,
      sink_mfa: sink.mfa,
      sink_category: sink.category,
      argument_positions: sink.argument_positions,
      observation_level: :exact_marker,
      process_scope: :single_process,
      execution: trace_result.execution,
      trace_envelope: trace_result.envelope,
      teardown: trace_result.teardown,
      event_count: trace_result.event_count,
      matched_event_count: length(matched),
      matched_positions: matched_positions(matched),
      limit_failures: trace_result.limit_failures,
      exploitability: :not_evaluated
    }
    |> maybe_add_static_candidate(static_candidate)
  end

  defp maybe_add_static_candidate(facts, nil), do: facts

  defp maybe_add_static_candidate(facts, %StaticCandidate{} = candidate) do
    Map.put(facts, :static_candidate, StaticCandidate.to_map(candidate))
  end

  defp hypothesis!(%Core.Hypothesis{
         kind: :taint_reaches_sink,
         seed: %Core.Seed{value: marker},
         locus: locus,
         meta: %{observation_level: :exact_marker}
       })
       when is_binary(marker) and byte_size(marker) > 0 and is_map(locus) do
    context = Map.get(locus, :context)
    source_id = Map.get(locus, :source_id)
    sink_id = Map.get(locus, :sink_id)
    static_candidate_id = Map.get(locus, :static_candidate_id)

    valid_candidate_id? = is_nil(static_candidate_id) or nonempty_string?(static_candidate_id)

    if named_atom?(context) and nonempty_string?(source_id) and nonempty_string?(sink_id) and
         valid_candidate_id? do
      %{
        context: context,
        source_id: source_id,
        sink_id: sink_id,
        static_candidate_id: static_candidate_id
      }
    else
      raise ArgumentError,
            "IAST hypotheses require context, source_id, sink_id, and an optional non-empty static_candidate_id in their locus"
    end
  end

  defp hypothesis!(%Core.Hypothesis{kind: :taint_reaches_sink}) do
    raise ArgumentError,
          "IAST validation requires a non-empty binary seed and the exact-marker observation level"
  end

  defp hypothesis!(hypothesis) do
    raise ArgumentError,
          "IAST validation requires a taint_reaches_sink hypothesis, got: #{inspect(hypothesis.kind)}"
  end

  defp resolve_bindings!(provider, %{static_candidate_id: nil} = details) do
    {source, sink} =
      ContextProvider.resolve!(
        provider,
        details.context,
        details.source_id,
        details.sink_id
      )

    {nil, source, sink}
  end

  defp resolve_bindings!(provider, details) do
    {candidate, source, sink} =
      ContextProvider.resolve_candidate!(
        provider,
        details.context,
        details.static_candidate_id
      )

    unless candidate.source_id == details.source_id and candidate.sink_id == details.sink_id do
      raise ArgumentError,
            "IAST static candidate #{inspect(candidate.id)} does not match the hypothesis declarations"
    end

    {candidate, source, sink}
  end

  defp validation_meta(nil) do
    %{observation_level: :exact_marker, process_scope: :single_process}
  end

  defp validation_meta(%StaticCandidate{} = candidate) do
    Map.merge(validation_meta(nil), %{
      static_candidate_id: candidate.id,
      static_localization: candidate.localization,
      static_flow_basis: candidate.flow_basis,
      static_sanitizer_status: candidate.sanitizer_status
    })
  end

  defp ensure_supported_source!(%Source{
         boundary: :in_process,
         extraction: %{type: :callback_argument, position: 1}
       }),
       do: :ok

  defp ensure_supported_source!(source) do
    raise ArgumentError,
          "exact-marker validation only supports an in-process first callback argument source, got: #{inspect(source)}"
  end

  defp replay_seed(%Core.Seed{} = seed, hypothesis, request) do
    id =
      seed.id ||
        Core.Finding.dedupe_id(:iast, [
          "exact_marker_input",
          request.id,
          marker_digest(seed.value)
        ])

    %{
      seed
      | id: id,
        classes: Enum.uniq([:validation, :iast, :exact_marker | seed.classes]),
        provenance: seed.provenance || :generated,
        origin: seed.origin || {hypothesis.source, hypothesis.id},
        meta:
          Map.merge(seed.meta, %{
            action: @action_id,
            observation_level: :exact_marker
          })
    }
  end

  defp matched_positions(observations) do
    observations
    |> Enum.flat_map(& &1.matched_positions)
    |> Enum.uniq()
    |> Enum.sort()
  end

  defp marker_digest(marker) do
    :sha256
    |> :crypto.hash(marker)
    |> Base.encode16(case: :lower)
  end

  defp reason_code(%TraceResult{execution: :completed, reason: nil}), do: nil
  defp reason_code(%TraceResult{execution: execution}) when execution != :completed, do: execution
  defp reason_code(%TraceResult{teardown: :failed}), do: :teardown_failed
  defp reason_code(%TraceResult{reason: _reason}), do: :trace_capture_failed

  defp nonempty_string?(value), do: is_binary(value) and String.trim(value) != ""
  defp named_atom?(value), do: is_atom(value) and value not in [nil, true, false]
end
