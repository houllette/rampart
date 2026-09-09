defmodule RampartSAST.Rule do
  @moduledoc """
  Behaviour and host-owned resolution for optional static signal rules.

  Rules are ordinary modules selected by the current caller. Rule names from a
  report or transcript are never converted into modules or atoms.
  """

  alias RampartSAST.Rule.Descriptor

  @type specification :: module() | {module(), keyword()}
  @type resolved :: %{module: module(), options: keyword(), descriptor: Descriptor.t()}

  @callback descriptor() :: Descriptor.t()
  @callback run_source(RampartSAST.Source.t(), RampartSAST.Context.t(), keyword()) ::
              [RampartSAST.Match.t()]
  @callback run_project([RampartSAST.Source.t()], RampartSAST.Context.t(), keyword()) ::
              [RampartSAST.Match.t()]

  @optional_callbacks run_source: 3, run_project: 3

  @doc "Resolves, validates, and deduplicates host-selected rule specifications."
  @spec resolve!([specification()]) :: [resolved()]
  def resolve!(specifications) when is_list(specifications) and specifications != [] do
    rules =
      specifications
      |> Enum.map(&resolve_one!/1)
      |> Enum.sort_by(& &1.descriptor.id)

    if length(Enum.uniq_by(rules, & &1.descriptor.id)) == length(rules) do
      rules
    else
      raise ArgumentError, "SAST rules must expose unique descriptor IDs"
    end
  end

  def resolve!([]), do: []

  def resolve!(specifications) do
    raise ArgumentError, "invalid SAST rule list: #{inspect(specifications)}"
  end

  @doc "Finds one resolved rule by its inert descriptor ID."
  @spec fetch!([resolved()], rule_id :: String.t()) :: resolved()
  def fetch!(rules, rule_id) when is_binary(rule_id) do
    case Enum.find(rules, &(&1.descriptor.id == rule_id)) do
      nil -> raise ArgumentError, "unknown SAST rule #{inspect(rule_id)}"
      rule -> rule
    end
  end

  defp resolve_one!(module) when is_atom(module), do: resolve_one!({module, []})

  defp resolve_one!({module, options}) when is_atom(module) and is_list(options) do
    unless Code.ensure_loaded?(module) and function_exported?(module, :descriptor, 0) do
      raise ArgumentError, "#{inspect(module)} is not a SAST rule"
    end

    descriptor = module.descriptor() |> Descriptor.validate!()
    ensure_callback!(module, descriptor.scope)

    %{module: module, options: options, descriptor: descriptor}
  end

  defp resolve_one!(specification) do
    raise ArgumentError, "invalid SAST rule specification: #{inspect(specification)}"
  end

  defp ensure_callback!(module, :source) do
    unless function_exported?(module, :run_source, 3),
      do:
        raise(
          ArgumentError,
          "source-scoped SAST rule #{inspect(module)} must define run_source/3"
        )
  end

  defp ensure_callback!(module, :project) do
    unless function_exported?(module, :run_project, 3),
      do:
        raise(
          ArgumentError,
          "project-scoped SAST rule #{inspect(module)} must define run_project/3"
        )
  end
end
