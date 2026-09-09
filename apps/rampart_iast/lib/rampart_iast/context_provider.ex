defmodule RampartIAST.ContextProvider do
  @moduledoc """
  Behaviour for independently reviewed source and sink maps.

  Providers own executable-context assumptions. A hypothesis names declaration
  IDs, while the current host chooses the provider that resolves those inert
  references.
  """

  alias RampartIAST.{Sink, Source, StaticCandidate}

  @callback context() :: atom()
  @callback sources() :: [Source.t()]
  @callback sinks() :: [Sink.t()]
  @callback candidates() :: [StaticCandidate.t()]

  @optional_callbacks candidates: 0

  @doc "Returns and validates a provider's declared context."
  @spec context!(provider :: module()) :: atom()
  def context!(provider) when is_atom(provider) do
    ensure_provider!(provider)
    context = provider.context()

    if named_atom?(context) do
      context
    else
      raise ArgumentError, "IAST provider #{inspect(provider)} returned an invalid context"
    end
  end

  @doc "Resolves and validates source and sink IDs for one provider context."
  @spec resolve!(
          provider :: module(),
          context :: atom(),
          source_id :: String.t(),
          sink_id :: String.t()
        ) :: {Source.t(), Sink.t()}
  def resolve!(provider, context, source_id, sink_id) when is_atom(provider) do
    ensure_provider!(provider)
    provider_context = provider_context!(provider, context)
    sources = declarations!(provider.sources(), Source, provider)
    sinks = declarations!(provider.sinks(), Sink, provider)

    source = fetch!(sources, source_id, :source, provider)
    sink = fetch!(sinks, sink_id, :sink, provider)

    ensure_context!(source, sink, provider_context)
    {source, sink}
  end

  @doc "Resolves one provider-reviewed static candidate and its referenced declarations."
  @spec resolve_candidate!(
          provider :: module(),
          context :: atom(),
          candidate_id :: String.t()
        ) :: {StaticCandidate.t(), Source.t(), Sink.t()}
  def resolve_candidate!(provider, context, candidate_id) when is_atom(provider) do
    ensure_provider!(provider)
    provider_context = provider_context!(provider, context)

    unless function_exported?(provider, :candidates, 0) do
      raise ArgumentError, "IAST provider #{inspect(provider)} does not expose static candidates"
    end

    candidates = declarations!(provider.candidates(), StaticCandidate, provider)
    candidate = fetch!(candidates, candidate_id, :static_candidate, provider)

    unless candidate.context == provider_context do
      raise ArgumentError, "IAST static candidates must match their provider context"
    end

    {source, sink} = resolve!(provider, context, candidate.source_id, candidate.sink_id)
    {candidate, source, sink}
  end

  defp ensure_provider!(provider) do
    valid? =
      Code.ensure_loaded?(provider) and
        Enum.all?([:context, :sources, :sinks], &function_exported?(provider, &1, 0))

    unless valid?,
      do: raise(ArgumentError, "#{inspect(provider)} is not an IAST context provider")
  end

  defp provider_context!(provider, context) do
    provider_context = context!(provider)

    unless provider_context == context do
      raise ArgumentError,
            "IAST provider #{inspect(provider)} does not serve context #{inspect(context)}"
    end

    provider_context
  end

  defp ensure_context!(source, sink, provider_context) do
    unless source.context == provider_context and sink.context == provider_context do
      raise ArgumentError, "IAST provider declarations must match their provider context"
    end
  end

  defp declarations!(declarations, module, provider) do
    unless is_list(declarations) do
      raise ArgumentError, "IAST provider #{inspect(provider)} returned invalid declarations"
    end

    validated = Enum.map(declarations, &module.validate!/1)

    if length(Enum.uniq_by(validated, & &1.id)) != length(validated) do
      raise ArgumentError, "IAST provider #{inspect(provider)} returned duplicate declaration IDs"
    end

    validated
  end

  defp fetch!(declarations, id, kind, provider) when is_binary(id) and id != "" do
    case Enum.find(declarations, &(&1.id == id)) do
      nil -> raise ArgumentError, "unknown IAST #{kind} #{inspect(id)} for #{inspect(provider)}"
      declaration -> declaration
    end
  end

  defp fetch!(_declarations, id, kind, _provider) do
    raise ArgumentError, "IAST #{kind} ID must be a non-empty string, got: #{inspect(id)}"
  end

  defp named_atom?(value), do: is_atom(value) and value not in [nil, true, false]
end
