defmodule Core.Validation do
  @moduledoc """
  Stable observe-to-validate boundary for Rampart tools and their consumers.

  A client discovers versioned actions through a `Core.Validator`, creates a
  request around a finding, concrete seed, or taint hypothesis, and dispatches
  it through `run/3`. The dispatcher enforces result invariants, emits the
  conventional validation telemetry span, and emits confirmed findings.

  The module deliberately contains no reasoning loop. Choosing an action and
  chaining its result belongs to a consumer such as a human-facing platform or
  an agent harness; producing the verdict remains deterministic tool logic.
  """

  alias Core.Validation.{Action, Evidence, Request, Result}

  @type subject :: Request.subject()
  @type evidence :: String.t() | Evidence.t()

  @doc "Returns and validates the actions advertised by a validator module."
  @spec actions(validator :: module()) :: [Action.t()]
  def actions(validator) when is_atom(validator) do
    unless Code.ensure_loaded?(validator) and function_exported?(validator, :actions, 0) and
             function_exported?(validator, :validate, 2) do
      raise ArgumentError, "#{inspect(validator)} is not a Core.Validator"
    end

    actions = validator.actions()

    unless is_list(actions) and actions != [] do
      raise ArgumentError, "#{inspect(validator)} must advertise at least one validation action"
    end

    Enum.each(actions, &validate_action!/1)

    duplicates =
      actions
      |> Enum.frequencies_by(& &1.id)
      |> Enum.filter(fn {_id, count} -> count > 1 end)
      |> Enum.map(&elem(&1, 0))

    if duplicates != [] do
      raise ArgumentError,
            "#{inspect(validator)} advertises duplicate action IDs: #{inspect(duplicates)}"
    end

    actions
  end

  @doc "Builds a validation request and derives a stable request ID from its subject."
  @spec request(Action.t(), subject(), keyword()) :: Request.t()
  def request(%Action{} = action, subject, opts \\ []) do
    validate_action!(action)
    type = subject_type!(subject)
    validate_subject!(subject)

    unless type in action.accepts do
      raise ArgumentError,
            "action #{action.id} does not accept #{inspect(type)} subjects"
    end

    context = Keyword.get(opts, :context, %{})
    meta = Keyword.get(opts, :meta, %{})

    unless is_map(context) and is_map(meta) do
      raise ArgumentError, "validation request context and metadata must be maps"
    end

    id = Keyword.get(opts, :request_id) || request_id!(action, subject, type)

    unless nonempty_string?(id) do
      raise ArgumentError, "validation request ID must be a non-empty string"
    end

    %Request{id: id, action: action, subject: subject, context: context, meta: meta}
  end

  @doc "Dispatches one request through a validator with contract and telemetry enforcement."
  @spec run(validator :: module(), Request.t(), keyword()) :: Result.t()
  def run(validator, %Request{} = request, opts \\ []) when is_atom(validator) do
    action = advertised_action!(validator, request.action)
    type = subject_type!(request.subject)
    validate_subject!(request.subject)

    unless type in action.accepts do
      raise ArgumentError,
            "action #{action.id} does not accept #{inspect(type)} subjects"
    end

    request = %{request | action: action}

    metadata = %{
      action: action.id,
      tool: action.tool,
      validation_id: request.id,
      subject_type: type
    }

    Core.Telemetry.span(action.tool, :validation, metadata, fn ->
      result = validator.validate(request, opts)
      validate_result!(result, request)
      Enum.each(result.findings, &Core.Telemetry.finding(action.tool, &1))

      {result,
       Map.merge(metadata, %{
         outcome: result.verdict,
         verdict: result.verdict,
         finding_count: length(result.findings)
       })}
    end)
  end

  @doc "Builds a confirmed result. At least one normalized finding is required."
  @spec confirmed(Request.t(), [Core.Finding.t()], Core.Seed.t(), evidence(), map()) :: Result.t()
  def confirmed(%Request{} = request, findings, %Core.Seed{} = seed, evidence, meta \\ %{})
      when is_list(findings) and is_map(meta) do
    new_result(request, :confirmed, findings, seed, evidence, meta)
  end

  @doc "Builds a refuted result for a hypothesis that was exercised and did not reproduce."
  @spec refuted(Request.t(), Core.Seed.t(), evidence(), map()) :: Result.t()
  def refuted(%Request{} = request, %Core.Seed{} = seed, evidence, meta \\ %{})
      when is_map(meta) do
    new_result(request, :refuted, [], seed, evidence, meta)
  end

  @doc "Builds an inconclusive result when the hypothesis could not be safely decided."
  @spec inconclusive(Request.t(), Core.Seed.t(), evidence(), map()) :: Result.t()
  def inconclusive(%Request{} = request, %Core.Seed{} = seed, evidence, meta \\ %{})
      when is_map(meta) do
    new_result(request, :inconclusive, [], seed, evidence, meta)
  end

  defp new_result(request, verdict, findings, seed, evidence, meta) do
    result = %Result{
      id: request.id,
      request_id: request.id,
      action: request.action,
      tool: request.action.tool,
      verdict: verdict,
      evidence: normalize_evidence!(evidence),
      findings: findings,
      seed: normalize_seed(seed, request),
      observed_at: DateTime.utc_now(),
      meta: meta
    }

    validate_result!(result, request)
    result
  end

  defp advertised_action!(validator, %Action{} = requested) do
    case Enum.find(actions(validator), &(&1.id == requested.id)) do
      nil ->
        raise ArgumentError,
              "#{inspect(validator)} does not advertise validation action #{inspect(requested.id)}"

      %Action{tool: tool} = action when tool == requested.tool ->
        action

      %Action{} = action ->
        raise ArgumentError,
              "action #{action.id} belongs to #{inspect(action.tool)}, not #{inspect(requested.tool)}"
    end
  end

  defp validate_action!(%Action{} = action) do
    valid? =
      Enum.all?([
        versioned_action_id?(action.id),
        named_atom?(action.tool),
        named_atom?(action.name),
        nonempty_string?(action.description),
        valid_accepts?(action.accepts),
        action.side_effects in [:none, :test_execution, :authorized_probe],
        is_map(action.meta)
      ])

    unless valid?, do: raise(ArgumentError, "invalid validation action: #{inspect(action)}")
    :ok
  end

  defp validate_action!(action) do
    raise ArgumentError, "expected Core.Validation.Action, got: #{inspect(action)}"
  end

  defp validate_result!(%Result{} = result, %Request{} = request) do
    valid? =
      Enum.all?([
        matching_request?(result, request),
        result.verdict in [:confirmed, :refuted, :inconclusive],
        valid_evidence?(result.evidence),
        valid_seed?(result.seed),
        valid_findings?(result),
        match?(%DateTime{}, result.observed_at),
        is_map(result.meta)
      ])

    unless valid? do
      raise ArgumentError,
            "validator returned a result that violates the Core.Validation contract: #{inspect(result)}"
    end

    :ok
  end

  defp validate_result!(result, _request) do
    raise ArgumentError,
          "validator must return Core.Validation.Result, got: #{inspect(result)}"
  end

  defp subject_type!(%Core.Finding{}), do: :finding
  defp subject_type!(%Core.Seed{}), do: :seed
  defp subject_type!(%Core.Hypothesis{}), do: :hypothesis

  defp subject_type!(subject) do
    raise ArgumentError,
          "validation subjects must be Core.Finding, Core.Seed, or Core.Hypothesis; got: #{inspect(subject)}"
  end

  defp request_id!(action, subject, type) do
    case subject_id(subject) do
      id when is_binary(id) and id != "" ->
        Core.Finding.dedupe_id(:validation, ["request", action.id, type, id])

      _other ->
        raise ArgumentError,
              "validation subjects require a non-empty ID unless :request_id is supplied"
    end
  end

  defp subject_id(%{id: id}), do: id

  defp validate_subject!(%Core.Finding{id: id}) when is_binary(id) and id != "", do: :ok
  defp validate_subject!(%Core.Seed{id: id}) when is_binary(id) and id != "", do: :ok

  defp validate_subject!(%Core.Hypothesis{} = hypothesis) do
    valid? =
      Enum.all?([
        nonempty_string?(hypothesis.id),
        named_atom?(hypothesis.source),
        named_atom?(hypothesis.kind),
        nonempty_string?(hypothesis.claim),
        is_map(hypothesis.locus),
        optional_struct?(hypothesis.finding, Core.Finding),
        optional_struct?(hypothesis.seed, Core.Seed),
        is_map(hypothesis.meta)
      ])

    unless valid? do
      raise ArgumentError, "invalid Core.Hypothesis: #{inspect(hypothesis)}"
    end

    :ok
  end

  defp validate_subject!(subject) do
    raise ArgumentError,
          "validation subjects require a non-empty ID and valid contract fields: #{inspect(subject)}"
  end

  defp normalize_evidence!(%Evidence{} = evidence) do
    if valid_evidence?(evidence),
      do: evidence,
      else: raise(ArgumentError, "invalid validation evidence: #{inspect(evidence)}")
  end

  defp normalize_evidence!(summary) when is_binary(summary) do
    normalize_evidence!(%Evidence{summary: summary})
  end

  defp normalize_evidence!(evidence) do
    raise ArgumentError, "expected validation evidence, got: #{inspect(evidence)}"
  end

  defp normalize_seed(%Core.Seed{} = seed, request) do
    id = seed.id || Core.Finding.dedupe_id(:validation, ["replay", request.id])
    %{seed | id: id, classes: Enum.uniq([:validation | seed.classes])}
  end

  defp valid_evidence?(%Evidence{} = evidence) do
    nonempty_string?(evidence.summary) and is_map(evidence.facts) and
      is_list(evidence.artifacts) and Enum.all?(evidence.artifacts, &is_map/1)
  end

  defp valid_evidence?(_evidence), do: false

  defp valid_seed?(%Core.Seed{id: id, classes: classes, meta: meta}) do
    nonempty_string?(id) and is_list(classes) and Enum.all?(classes, &named_atom?/1) and
      is_map(meta)
  end

  defp valid_seed?(_seed), do: false

  defp valid_finding?(%Core.Finding{} = finding, tool) do
    Enum.all?([
      nonempty_string?(finding.id),
      finding.source == tool,
      named_atom?(finding.category),
      is_map(finding.locus),
      finding.severity in [:info, :low, :medium, :high, :critical, nil],
      finding.confidence in [:low, :medium, :high],
      nonempty_string?(finding.evidence),
      valid_seed?(finding.seed),
      match?(%DateTime{}, finding.observed_at)
    ])
  end

  defp valid_finding?(_finding, _tool), do: false

  defp matching_request?(result, request) do
    Enum.all?([
      result.id == request.id,
      result.request_id == request.id,
      result.action.id == request.action.id,
      result.tool == request.action.tool
    ])
  end

  defp valid_findings?(%Result{} = result) when is_list(result.findings) do
    Enum.all?(result.findings, &valid_finding?(&1, result.tool)) and
      findings_match_verdict?(result.verdict, result.findings)
  end

  defp valid_findings?(_result), do: false

  defp findings_match_verdict?(:confirmed, [_first | _rest]), do: true
  defp findings_match_verdict?(verdict, []) when verdict in [:refuted, :inconclusive], do: true
  defp findings_match_verdict?(_verdict, _findings), do: false

  defp valid_accepts?(accepts) when is_list(accepts) and accepts != [] do
    Enum.all?(accepts, &(&1 in [:finding, :seed, :hypothesis])) and
      length(Enum.uniq(accepts)) == length(accepts)
  end

  defp valid_accepts?(_accepts), do: false

  defp versioned_action_id?(value) do
    nonempty_string?(value) and Regex.match?(~r/^[a-z0-9][a-z0-9._-]*\.v[1-9][0-9]*$/, value)
  end

  defp optional_struct?(nil, _module), do: true
  defp optional_struct?(value, module), do: is_struct(value, module)

  defp named_atom?(value), do: is_atom(value) and value not in [nil, true, false]
  defp nonempty_string?(value), do: is_binary(value) and String.trim(value) != ""
end
