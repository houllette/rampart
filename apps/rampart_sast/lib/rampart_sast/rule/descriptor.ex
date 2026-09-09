defmodule RampartSAST.Rule.Descriptor do
  @moduledoc "Versioned, machine-readable metadata for one static security rule."

  @type scope :: :source | :project

  @type t :: %__MODULE__{
          id: String.t(),
          schema_version: pos_integer(),
          title: String.t(),
          description: String.t(),
          category: atom(),
          severity: Core.Finding.severity(),
          confidence: Core.Finding.confidence(),
          scope: scope(),
          tags: [atom()]
        }

  @enforce_keys [
    :id,
    :schema_version,
    :title,
    :description,
    :category,
    :severity,
    :confidence,
    :scope
  ]
  defstruct @enforce_keys ++ [tags: []]

  @severities [:info, :low, :medium, :high, :critical]
  @confidences [:low, :medium, :high]
  @scopes [:source, :project]

  @doc "Builds and validates a static rule descriptor."
  @spec new!(attributes :: keyword()) :: t()
  def new!(attributes) when is_list(attributes) do
    attributes =
      Keyword.validate!(attributes, [
        :id,
        :schema_version,
        :title,
        :description,
        :category,
        :severity,
        :confidence,
        :scope,
        tags: []
      ])

    attributes
    |> then(&struct!(__MODULE__, &1))
    |> validate!()
  end

  @doc "Validates a descriptor and returns it."
  @spec validate!(descriptor :: t()) :: t()
  def validate!(%__MODULE__{} = descriptor) do
    valid? =
      Enum.all?([
        versioned_id?(descriptor.id),
        positive_integer?(descriptor.schema_version),
        nonempty_string?(descriptor.title),
        nonempty_string?(descriptor.description),
        named_atom?(descriptor.category),
        descriptor.severity in @severities,
        descriptor.confidence in @confidences,
        descriptor.scope in @scopes,
        valid_tags?(descriptor.tags)
      ])

    if valid?,
      do: descriptor,
      else: raise(ArgumentError, "invalid SAST rule descriptor: #{inspect(descriptor)}")
  end

  @doc "Projects the descriptor into plain evidence data."
  @spec to_map(descriptor :: t()) :: map()
  def to_map(%__MODULE__{} = descriptor) do
    %{
      id: descriptor.id,
      schema_version: descriptor.schema_version,
      title: descriptor.title,
      description: descriptor.description,
      category: descriptor.category,
      severity: descriptor.severity,
      confidence: descriptor.confidence,
      scope: descriptor.scope,
      tags: descriptor.tags
    }
  end

  defp versioned_id?(value) do
    nonempty_string?(value) and Regex.match?(~r/^[a-z0-9][a-z0-9._-]*\.v[1-9][0-9]*$/, value)
  end

  defp valid_tags?(tags) when is_list(tags) do
    Enum.all?(tags, &named_atom?/1) and length(Enum.uniq(tags)) == length(tags)
  end

  defp valid_tags?(_tags), do: false
  defp positive_integer?(value), do: is_integer(value) and value > 0
  defp named_atom?(value), do: is_atom(value) and value not in [nil, true, false]
  defp nonempty_string?(value), do: is_binary(value) and String.trim(value) != ""
end
