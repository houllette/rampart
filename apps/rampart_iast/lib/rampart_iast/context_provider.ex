defmodule RampartIAST.ContextProvider do
  @moduledoc """
  Behaviour for independently reviewed source and sink maps.

  Providers own executable-context assumptions. A hypothesis names declaration
  IDs, while the current host chooses the provider that resolves those inert
  references.
  """

  alias RampartIAST.{Sink, Source}

  @callback context() :: atom()
  @callback sources() :: [Source.t()]
  @callback sinks() :: [Sink.t()]

  @doc "Resolves and validates source and sink IDs for one provider context."
  @spec resolve!(
          provider :: module(),
          context :: atom(),
          source_id :: String.t(),
          sink_id :: String.t()
        ) :: {Source.t(), Sink.t()}
  def resolve!(provider, context, source_id, sink_id) when is_atom(provider) do
    ensure_provider!(provider)
    provider_context = provider.context()

    unless named_atom?(provider_context) and provider_context == context do
      raise ArgumentError,
            "IAST provider #{inspect(provider)} does not serve context #{inspect(context)}"
    end

    sources = declarations!(provider.sources(), Source, provider)
    sinks = declarations!(provider.sinks(), Sink, provider)

    source = fetch!(sources, source_id, :source, provider)
    sink = fetch!(sinks, sink_id, :sink, provider)

    unless source.context == provider_context and sink.context == provider_context do
      raise ArgumentError, "IAST provider declarations must match their provider context"
    end

    {source, sink}
  end

  defp ensure_provider!(provider) do
    valid? =
      Code.ensure_loaded?(provider) and
        Enum.all?([:context, :sources, :sinks], &function_exported?(provider, &1, 0))

    unless valid?,
      do: raise(ArgumentError, "#{inspect(provider)} is not an IAST context provider")
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
