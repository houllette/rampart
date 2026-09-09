defmodule RampartSAST.Match do
  @moduledoc """
  One syntactic match emitted by a static rule before scanner normalization.

  The anchor hashes metadata-free AST so line movement does not by itself change
  identity. An occurrence index assigned by the scanner disambiguates identical
  expressions in one file.
  """

  alias RampartSAST.{Source, Span}

  @type t :: %__MODULE__{
          span: Span.t(),
          anchor: String.t(),
          message: String.t(),
          confidence: Core.Finding.confidence() | nil,
          facts: map()
        }

  @enforce_keys [:span, :anchor, :message]
  defstruct [:span, :anchor, :message, :confidence, facts: %{}]

  @confidences [:low, :medium, :high]
  @erlang_ast_tags [
    :ann_type,
    :atom,
    :attribute,
    :bin,
    :bin_element,
    :block,
    :call,
    :case,
    :catch,
    :char,
    :clause,
    :cons,
    :float,
    :fun,
    :function,
    :generate,
    :if,
    :integer,
    :lc,
    :map,
    :map_field_assoc,
    :map_field_exact,
    :match,
    :named_fun,
    nil,
    :op,
    :receive,
    :remote,
    :string,
    :try,
    :tuple,
    :type,
    :user_type,
    :var
  ]

  @doc "Builds a static match from one source AST node."
  @spec from_ast(source :: Source.t(), ast :: term(), options :: keyword()) :: t()
  def from_ast(%Source{} = source, ast, options) when is_list(options) do
    options = Keyword.validate!(options, [:message, :confidence, facts: %{}])

    new!(
      span: Span.from_ast(source.path, ast),
      anchor: anchor(ast, source.language),
      message: Keyword.fetch!(options, :message),
      confidence: options[:confidence],
      facts: options[:facts]
    )
  end

  @doc "Builds and validates a static match."
  @spec new!(attributes :: keyword()) :: t()
  def new!(attributes) when is_list(attributes) do
    attributes =
      Keyword.validate!(attributes, [:span, :anchor, :message, :confidence, facts: %{}])

    attributes
    |> then(&struct!(__MODULE__, &1))
    |> validate!()
  end

  @doc "Validates a static match and returns it."
  @spec validate!(match :: t()) :: t()
  def validate!(%__MODULE__{} = match) do
    valid? =
      valid_span?(match.span) and digest?(match.anchor) and nonempty_string?(match.message) and
        match.confidence in [nil | @confidences] and is_map(match.facts)

    if valid?, do: match, else: raise(ArgumentError, "invalid SAST match: #{inspect(match)}")
  end

  @doc "Returns a stable SHA-256 anchor for metadata-free AST."
  @spec anchor(ast :: term()) :: String.t()
  def anchor(ast), do: anchor(ast, infer_language(ast))

  @doc false
  @spec anchor(ast :: term(), language :: Source.language()) :: String.t()
  def anchor(ast, language) do
    ast
    |> strip_metadata(language)
    |> :erlang.term_to_binary([:deterministic])
    |> then(&:crypto.hash(:sha256, &1))
    |> Base.encode16(case: :lower)
  end

  defp strip_metadata(ast, :elixir), do: Macro.prewalk(ast, &strip_elixir_metadata/1)
  defp strip_metadata(ast, :erlang), do: strip_all_erlang_metadata(ast)

  defp strip_elixir_metadata({form, metadata, arguments}) when is_list(metadata) do
    {form, [], arguments}
  end

  defp strip_elixir_metadata(ast), do: ast

  defp strip_all_erlang_metadata({form, metadata, arguments}) when is_list(metadata) do
    {strip_all_erlang_metadata(form), [], strip_all_erlang_metadata(arguments)}
  end

  defp strip_all_erlang_metadata(ast) when is_tuple(ast) and tuple_size(ast) >= 2 do
    annotation = elem(ast, 1)
    ast = if :erl_anno.is_anno(annotation), do: put_elem(ast, 1, 0), else: ast

    ast
    |> Tuple.to_list()
    |> Enum.map(&strip_all_erlang_metadata/1)
    |> List.to_tuple()
  end

  defp strip_all_erlang_metadata(ast) when is_tuple(ast) do
    ast
    |> Tuple.to_list()
    |> Enum.map(&strip_all_erlang_metadata/1)
    |> List.to_tuple()
  end

  defp strip_all_erlang_metadata(ast) when is_list(ast),
    do: Enum.map(ast, &strip_all_erlang_metadata/1)

  defp strip_all_erlang_metadata(ast) when is_map(ast) do
    Map.new(ast, fn {key, value} ->
      {strip_all_erlang_metadata(key), strip_all_erlang_metadata(value)}
    end)
  end

  defp strip_all_erlang_metadata(ast), do: ast

  defp infer_language(ast) when is_tuple(ast) and tuple_size(ast) >= 2 do
    if elem(ast, 0) in @erlang_ast_tags, do: :erlang, else: :elixir
  end

  defp infer_language(_ast), do: :elixir

  defp valid_span?(%Span{} = span) do
    Span.validate!(span) == span
  rescue
    ArgumentError -> false
  end

  defp valid_span?(_span), do: false
  defp digest?(value), do: is_binary(value) and byte_size(value) == 64
  defp nonempty_string?(value), do: is_binary(value) and String.trim(value) != ""
end
