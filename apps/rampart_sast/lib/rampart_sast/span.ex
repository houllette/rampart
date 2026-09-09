defmodule RampartSAST.Span do
  @moduledoc """
  A repository-relative source location reported by a static rule.

  Spans are syntactic locations, not evidence that an expression executes or
  receives attacker-controlled data.
  """

  @type t :: %__MODULE__{
          file: Path.t(),
          start_line: pos_integer(),
          start_column: pos_integer() | nil,
          end_line: pos_integer(),
          end_column: pos_integer() | nil
        }

  @enforce_keys [:file, :start_line, :end_line]
  defstruct [:file, :start_line, :start_column, :end_line, :end_column]

  @doc "Builds and validates a repository-relative source span."
  @spec new!(attributes :: keyword()) :: t()
  def new!(attributes) when is_list(attributes) do
    attributes =
      Keyword.validate!(attributes, [
        :file,
        :start_line,
        :start_column,
        :end_line,
        :end_column
      ])

    attributes =
      Keyword.put_new_lazy(attributes, :end_line, fn ->
        Keyword.fetch!(attributes, :start_line)
      end)

    attributes
    |> then(&struct!(__MODULE__, &1))
    |> validate!()
  end

  @doc "Builds a span from an AST node's metadata."
  @spec from_ast(file :: Path.t(), ast :: term()) :: t()
  def from_ast(file, {_form, metadata, _arguments}) when is_list(metadata) do
    line = Keyword.get(metadata, :line, 1)
    column = positive_or_nil(Keyword.get(metadata, :column))
    end_line = Keyword.get(metadata, :end_line, line)
    end_column = positive_or_nil(Keyword.get(metadata, :end_column))

    new!(
      file: file,
      start_line: line,
      start_column: column,
      end_line: end_line,
      end_column: end_column
    )
  end

  def from_ast(file, ast) when is_tuple(ast) and tuple_size(ast) >= 2 do
    annotation = elem(ast, 1)

    if :erl_anno.is_anno(annotation) do
      {line, column} = erlang_location(:erl_anno.location(annotation))
      {end_line, end_column} = erlang_end_location(annotation, line, column)

      new!(
        file: file,
        start_line: line,
        start_column: column,
        end_line: end_line,
        end_column: end_column
      )
    else
      new!(file: file, start_line: 1)
    end
  end

  def from_ast(file, _ast), do: new!(file: file, start_line: 1)

  @doc "Validates a source span and returns it."
  @spec validate!(span :: t()) :: t()
  def validate!(%__MODULE__{} = span) do
    valid? =
      valid_file?(span.file) and positive_integer?(span.start_line) and
        positive_integer?(span.end_line) and span.end_line >= span.start_line and
        optional_positive_integer?(span.start_column) and
        optional_positive_integer?(span.end_column) and valid_column_range?(span)

    if valid?, do: span, else: raise(ArgumentError, "invalid SAST source span: #{inspect(span)}")
  end

  @doc "Projects the span into plain evidence data."
  @spec to_map(span :: t()) :: map()
  def to_map(%__MODULE__{} = span) do
    %{
      file: span.file,
      start_line: span.start_line,
      start_column: span.start_column,
      end_line: span.end_line,
      end_column: span.end_column
    }
  end

  @doc false
  @spec valid_file?(file :: term()) :: boolean()
  def valid_file?(file) when is_binary(file) do
    String.trim(file) != "" and Path.type(file) == :relative and ".." not in Path.split(file)
  end

  def valid_file?(_file), do: false

  defp valid_column_range?(%__MODULE__{
         start_line: line,
         end_line: line,
         start_column: start_column,
         end_column: end_column
       })
       when is_integer(start_column) and is_integer(end_column),
       do: end_column >= start_column

  defp valid_column_range?(_span), do: true

  defp erlang_location({line, column}), do: {line, positive_or_nil(column)}
  defp erlang_location(line) when is_integer(line), do: {line, nil}

  defp erlang_end_location(annotation, line, column) do
    case :erl_anno.end_location(annotation) do
      {end_line, end_column} -> {end_line, positive_or_nil(end_column)}
      end_line when is_integer(end_line) -> {end_line, nil}
      _other -> {line, column}
    end
  end

  defp positive_or_nil(value) when is_integer(value) and value > 0, do: value
  defp positive_or_nil(_value), do: nil
  defp positive_integer?(value), do: is_integer(value) and value > 0
  defp optional_positive_integer?(nil), do: true
  defp optional_positive_integer?(value), do: positive_integer?(value)
end
