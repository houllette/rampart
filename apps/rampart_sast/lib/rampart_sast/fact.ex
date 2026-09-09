defmodule RampartSAST.Fact do
  @moduledoc "A deterministic, syntax-derived project fact for graph queries and hypothesis construction."

  alias RampartSAST.Span

  @type t :: %__MODULE__{
          id: String.t(),
          kind: atom(),
          subject: String.t(),
          relation: atom(),
          object: String.t(),
          span: Span.t(),
          source_hash: String.t(),
          attributes: map()
        }

  @enforce_keys [:id, :kind, :subject, :relation, :object, :span, :source_hash, :attributes]
  defstruct @enforce_keys

  @doc "Builds a stable project fact from a source relationship."
  @spec new!(keyword()) :: t()
  def new!(attributes) when is_list(attributes) do
    attributes =
      Keyword.validate!(attributes, [
        :kind,
        :subject,
        :relation,
        :object,
        :span,
        :source_hash,
        attributes: %{}
      ])

    id =
      Core.Finding.dedupe_id(:sast, [
        "fact",
        attributes[:kind],
        attributes[:subject],
        attributes[:relation],
        attributes[:object],
        attributes[:span].file,
        attributes[:span].start_line,
        attributes[:span].start_column,
        attributes[:source_hash]
      ])

    attributes
    |> Keyword.put(:id, id)
    |> then(&struct!(__MODULE__, &1))
    |> validate!()
  end

  @doc "Validates a project fact and returns it."
  @spec validate!(t()) :: t()
  def validate!(%__MODULE__{} = fact) do
    valid? =
      named_atom?(fact.kind) and nonempty_string?(fact.subject) and named_atom?(fact.relation) and
        nonempty_string?(fact.object) and valid_span?(fact.span) and digest?(fact.source_hash) and
        is_map(fact.attributes)

    if valid?, do: fact, else: raise(ArgumentError, "invalid SAST fact: #{inspect(fact)}")
  end

  @doc "Projects a fact into bounded plain evidence data."
  @spec to_map(t()) :: map()
  def to_map(%__MODULE__{} = fact) do
    %{
      id: fact.id,
      kind: fact.kind,
      subject: fact.subject,
      relation: fact.relation,
      object: fact.object,
      span: Span.to_map(fact.span),
      source_hash: fact.source_hash,
      attributes: fact.attributes
    }
  end

  defp valid_span?(%Span{} = span) do
    Span.validate!(span) == span
  rescue
    ArgumentError -> false
  end

  defp valid_span?(_span), do: false
  defp named_atom?(value), do: is_atom(value) and value not in [nil, true, false]
  defp digest?(value), do: is_binary(value) and byte_size(value) == 64
  defp nonempty_string?(value), do: is_binary(value) and String.trim(value) != ""
end
