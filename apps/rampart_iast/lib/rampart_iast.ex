defmodule RampartIAST do
  @moduledoc """
  Experimental process-scoped IAST validation for exact-marker reachability.

  The first sensor action proves only that unchanged marker bytes reached a
  reviewed sink argument during one controlled in-process execution. It does
  not claim transformed-value propagation, cross-process taint, or
  exploitability.
  """

  alias RampartIAST.ContextProvider

  @doc "Returns the sensor's versioned validation actions."
  @spec validation_actions() :: [Core.Validation.Action.t()]
  def validation_actions, do: Core.Validation.actions(RampartIAST.Validator)

  @doc """
  Builds an inert exact-marker hypothesis from a provider-reviewed static candidate.

  The current host selects and executes the provider. Callers name only a
  candidate ID and concrete seed; the referenced source and sink declarations
  are resolved again during validation.
  """
  @spec hypothesis!(
          provider :: module(),
          candidate_id :: String.t(),
          seed :: Core.Seed.t(),
          opts :: keyword()
        ) :: Core.Hypothesis.t()
  def hypothesis!(provider, candidate_id, %Core.Seed{value: marker} = seed, opts \\ [])
      when is_atom(provider) and is_binary(candidate_id) and is_list(opts) do
    unless is_binary(marker) and byte_size(marker) > 0 do
      raise ArgumentError, "IAST static hypotheses require a non-empty binary seed"
    end

    opts = Keyword.validate!(opts, [:id, :claim, locus: %{}, meta: %{}])
    context = ContextProvider.context!(provider)

    {candidate, source, sink} =
      ContextProvider.resolve_candidate!(provider, context, candidate_id)

    locus =
      merge_map_option!(opts[:locus], :locus)
      |> Map.merge(%{
        context: context,
        source_id: source.id,
        sink_id: sink.id,
        static_candidate_id: candidate.id
      })

    meta =
      merge_map_option!(opts[:meta], :meta)
      |> Map.merge(%{
        observation_level: :exact_marker,
        static_candidate_id: candidate.id
      })

    %Core.Hypothesis{
      id: opts[:id] || hypothesis_id(candidate.id, seed, marker),
      source: :iast,
      kind: :taint_reaches_sink,
      claim: opts[:claim] || "#{source.id} reaches #{sink.id} unchanged",
      locus: locus,
      seed: seed,
      meta: meta
    }
  end

  @doc "Validates one exact-marker reachability hypothesis under host-owned bindings."
  @spec validate(Core.Hypothesis.t(), keyword()) :: Core.Validation.Result.t()
  def validate(%Core.Hypothesis{} = hypothesis, opts) when is_list(opts) do
    request = Core.Validation.request(RampartIAST.Validator.action(), hypothesis)
    Core.Validation.run(RampartIAST.Validator, request, opts)
  end

  defp hypothesis_id(candidate_id, seed, marker) do
    Core.Finding.dedupe_id(:iast, [
      "static_hypothesis",
      candidate_id,
      seed.id,
      marker_digest(marker)
    ])
  end

  defp marker_digest(marker) do
    :sha256
    |> :crypto.hash(marker)
    |> Base.encode16(case: :lower)
  end

  defp merge_map_option!(value, _name) when is_map(value), do: value

  defp merge_map_option!(value, name) do
    raise ArgumentError, "IAST hypothesis #{name} must be a map, got: #{inspect(value)}"
  end
end
