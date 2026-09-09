defmodule RampartIAST.SourceSpan do
  @moduledoc """
  A repository-relative source range supplied by reviewed static analysis.

  Source spans are candidate localization evidence. They do not prove that a
  particular call site executed unless the owning static candidate also carries
  an accepted localization basis.
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

  @doc "Validates a source span and returns it."
  @spec validate!(span :: t()) :: t()
  def validate!(%__MODULE__{} = span) do
    valid? =
      valid_file?(span.file) and positive_integer?(span.start_line) and
        positive_integer?(span.end_line) and span.end_line >= span.start_line and
        optional_positive_integer?(span.start_column) and
        optional_positive_integer?(span.end_column) and valid_column_range?(span)

    if valid?, do: span, else: raise(ArgumentError, "invalid IAST source span: #{inspect(span)}")
  end

  @doc "Projects a span into plain, transcript-safe data."
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

  defp valid_file?(file) when is_binary(file) do
    String.trim(file) != "" and Path.type(file) == :relative and ".." not in Path.split(file)
  end

  defp valid_file?(_file), do: false

  defp valid_column_range?(%__MODULE__{
         start_line: line,
         end_line: line,
         start_column: start_column,
         end_column: end_column
       })
       when is_integer(start_column) and is_integer(end_column),
       do: end_column >= start_column

  defp valid_column_range?(_span), do: true

  defp positive_integer?(value), do: is_integer(value) and value > 0
  defp optional_positive_integer?(nil), do: true
  defp optional_positive_integer?(value), do: positive_integer?(value)
end
