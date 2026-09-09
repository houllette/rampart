defmodule RampartIAST.Source do
  @moduledoc """
  A versioned declaration of an attacker-controlled input boundary.

  Source declarations are inert data owned by a context provider. They describe
  where a controlled value enters an execution without carrying an executable
  extractor supplied by a validation subject.
  """

  @type t :: %__MODULE__{
          id: String.t(),
          schema_version: pos_integer(),
          context: atom(),
          category: atom(),
          extraction: map(),
          boundary: atom(),
          provenance: map()
        }

  @enforce_keys [
    :id,
    :schema_version,
    :context,
    :category,
    :extraction,
    :boundary,
    :provenance
  ]
  defstruct @enforce_keys

  @doc "Builds and validates a source declaration."
  @spec new!(attributes :: keyword()) :: t()
  def new!(attributes) when is_list(attributes) do
    attributes =
      Keyword.validate!(attributes, [
        :id,
        :schema_version,
        :context,
        :category,
        :extraction,
        :boundary,
        :provenance
      ])

    attributes
    |> then(&struct!(__MODULE__, &1))
    |> validate!()
  end

  @doc "Validates a source declaration and returns it."
  @spec validate!(source :: t()) :: t()
  def validate!(%__MODULE__{} = source) do
    valid? =
      versioned_id?(source.id) and is_integer(source.schema_version) and
        source.schema_version > 0 and named_atom?(source.context) and
        named_atom?(source.category) and valid_extraction?(source.extraction) and
        named_atom?(source.boundary) and is_map(source.provenance)

    if valid?, do: source, else: raise(ArgumentError, "invalid IAST source: #{inspect(source)}")
  end

  defp valid_extraction?(%{type: type, position: position}) do
    named_atom?(type) and is_integer(position) and position > 0
  end

  defp valid_extraction?(_extraction), do: false

  defp versioned_id?(value) do
    is_binary(value) and Regex.match?(~r/^[a-z0-9][a-z0-9._-]*\.v[1-9][0-9]*$/, value)
  end

  defp named_atom?(value), do: is_atom(value) and value not in [nil, true, false]
end
