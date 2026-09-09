defmodule RampartSAST.Behavior do
  @moduledoc """
  Host-selected classifiers that annotate broad inventory facts with possible
  security-relevant behavior. Classifications remain noisy syntax facts.
  """

  alias RampartSAST.{Diagnostic, Fact}

  @type classification :: %{
          required(:behavior) => atom(),
          required(:basis) => atom(),
          optional(:attributes) => map()
        }
  @type specification :: module() | {module(), keyword()}

  @callback id() :: String.t()
  @callback classify(Fact.t(), keyword()) :: [classification()]

  @doc "Runs explicit bounded classifiers and returns behavior facts plus failures."
  @spec classify([Fact.t()], [specification()], timeout_ms :: pos_integer()) ::
          {[Fact.t()], [Diagnostic.t()]}
  def classify(facts, specifications, timeout_ms \\ 5_000)
      when is_list(facts) and is_list(specifications) and is_integer(timeout_ms) and
             timeout_ms > 0 do
    classifiers = specifications |> Enum.map(&resolve!/1) |> ensure_unique_ids!()

    {behavior_facts, diagnostics} =
      Enum.reduce(classifiers, {[], []}, fn classifier, {all_facts, diagnostics} ->
        case run_classifier(facts, classifier, timeout_ms) do
          {:ok, classified} -> {classified ++ all_facts, diagnostics}
          {:error, diagnostic} -> {all_facts, [diagnostic | diagnostics]}
        end
      end)

    behavior_facts =
      Enum.sort_by(behavior_facts, &{&1.span.file, &1.span.start_line, &1.object, &1.id})

    {behavior_facts, Enum.sort_by(diagnostics, & &1.rule_id)}
  end

  defp resolve!(module) when is_atom(module), do: resolve!({module, []})

  defp resolve!({module, options}) when is_atom(module) and is_list(options) do
    valid? =
      Code.ensure_loaded?(module) and function_exported?(module, :id, 0) and
        function_exported?(module, :classify, 2)

    unless valid?,
      do: raise(ArgumentError, "#{inspect(module)} is not a SAST behavior classifier")

    id = module.id()

    unless is_binary(id) and Regex.match?(~r/^[a-z0-9][a-z0-9._-]*\.v[1-9][0-9]*$/, id),
      do: raise(ArgumentError, "SAST behavior classifier IDs must be explicitly versioned")

    %{module: module, options: options, id: id}
  end

  defp resolve!(specification) do
    raise ArgumentError, "invalid SAST behavior classifier: #{inspect(specification)}"
  end

  defp ensure_unique_ids!(classifiers) do
    if length(Enum.uniq_by(classifiers, & &1.id)) == length(classifiers) do
      Enum.sort_by(classifiers, & &1.id)
    else
      raise ArgumentError, "SAST behavior classifiers must expose unique IDs"
    end
  end

  defp run_classifier(facts, classifier, timeout_ms) do
    task = Task.async(fn -> invoke_classifier(facts, classifier) end)

    case Task.yield(task, timeout_ms) || Task.shutdown(task, :brutal_kill) do
      {:ok, {:ok, classified}} ->
        {:ok, classified}

      {:ok, {:error, message}} ->
        {:error, diagnostic(classifier.id, :classifier_failed, message)}

      {:exit, reason} ->
        message = "behavior classifier exited: #{inspect(reason, limit: 20)}"
        {:error, diagnostic(classifier.id, :classifier_failed, message)}

      nil ->
        message = "behavior classifier exceeded #{timeout_ms} ms"
        {:error, diagnostic(classifier.id, :classifier_timeout, message)}
    end
  end

  defp invoke_classifier(facts, classifier) do
    classified =
      Enum.flat_map(facts, fn fact ->
        fact
        |> classifier.module.classify(classifier.options)
        |> Enum.map(&classification_fact(fact, classifier.id, &1))
      end)

    {:ok, classified}
  rescue
    error -> {:error, Exception.message(error)}
  catch
    kind, reason -> {:error, "#{kind}: #{inspect(reason, limit: 20)}"}
  end

  defp classification_fact(
         fact,
         classifier_id,
         %{behavior: behavior, basis: basis} = classification
       )
       when is_atom(behavior) and is_atom(basis) do
    extra = Map.get(classification, :attributes, %{})

    unless is_map(extra),
      do: raise(ArgumentError, "behavior classification attributes must be a map")

    Fact.new!(
      kind: :behavior,
      subject: fact.subject,
      relation: :may_exhibit,
      object: Atom.to_string(behavior),
      span: fact.span,
      source_hash: fact.source_hash,
      attributes:
        Map.merge(extra, %{
          behavior: behavior,
          basis: basis,
          classifier_id: classifier_id,
          via_fact_id: fact.id,
          via_kind: fact.kind,
          via_relation: fact.relation,
          via_object: fact.object,
          origin: Map.get(fact.attributes, :origin)
        })
    )
  end

  defp classification_fact(_fact, _classifier_id, classification) do
    raise ArgumentError, "invalid behavior classification: #{inspect(classification)}"
  end

  defp diagnostic(classifier_id, code, message) do
    Diagnostic.new!(
      level: :error,
      phase: :inventory,
      code: code,
      rule_id: classifier_id,
      message: message
    )
  end
end
