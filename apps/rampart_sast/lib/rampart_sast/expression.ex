defmodule RampartSAST.Expression do
  @moduledoc "Bounded syntax-only expression descriptions for static relationship facts."

  alias RampartSAST.AST

  @max_preview_bytes 240

  @type description :: %{
          kind: atom(),
          literal: boolean(),
          preview: String.t(),
          preview_truncated: boolean()
        }

  @doc "Describes an expression without evaluating target code or retaining its native AST."
  @spec describe(ast :: term(), language :: :elixir | :erlang) :: description()
  def describe(ast, :elixir) do
    ast
    |> render_elixir()
    |> description(expression_kind(ast), AST.literal?(ast))
  end

  def describe(ast, :erlang) do
    ast
    |> inspect(limit: 20, printable_limit: @max_preview_bytes, width: @max_preview_bytes)
    |> description(erlang_expression_kind(ast), AST.literal?(ast))
  end

  defp description(rendered, kind, literal?) do
    {preview, truncated?} = truncate(rendered)

    %{
      kind: kind,
      literal: literal?,
      preview: preview,
      preview_truncated: truncated?
    }
  end

  defp render_elixir(ast) do
    Macro.to_string(ast)
  rescue
    _error -> inspect(ast, limit: 20, printable_limit: @max_preview_bytes)
  end

  defp expression_kind(value) when is_binary(value) or is_number(value) or is_atom(value),
    do: :literal

  defp expression_kind(values) when is_list(values) do
    if Keyword.keyword?(values), do: :keyword, else: :list
  end

  defp expression_kind({:__aliases__, _, _parts}), do: :module_alias

  defp expression_kind({:<<>>, _, _parts} = ast) do
    if interpolated_binary?(ast), do: :interpolation, else: :binary
  end

  defp expression_kind({:%{}, _, _pairs}), do: :map
  defp expression_kind({:{}, _, _values}), do: :tuple
  defp expression_kind({:fn, _, _clauses}), do: :function

  defp expression_kind({name, metadata, context})
       when is_atom(name) and is_list(metadata) and (is_atom(context) or is_nil(context)),
       do: :variable

  defp expression_kind({{:., _, _target}, metadata, arguments})
       when is_list(metadata) and is_list(arguments),
       do: :remote_call

  defp expression_kind({name, metadata, arguments} = ast)
       when is_atom(name) and is_list(metadata) and is_list(arguments) do
    if sigil_call?(name) and interpolated_binary?(ast), do: :interpolation, else: :call
  end

  defp expression_kind(ast) when is_tuple(ast), do: :tuple
  defp expression_kind(_ast), do: :expression

  defp sigil_call?(name), do: String.starts_with?(Atom.to_string(name), "sigil_")

  defp interpolated_binary?({_form, metadata, arguments}) when is_list(metadata) do
    Keyword.get(metadata, :from_interpolation, false) or interpolated_binary?(arguments)
  end

  defp interpolated_binary?(term) when is_list(term), do: Enum.any?(term, &interpolated_binary?/1)

  defp interpolated_binary?(term) when is_tuple(term) do
    term |> Tuple.to_list() |> Enum.any?(&interpolated_binary?/1)
  end

  defp interpolated_binary?(_term), do: false

  defp erlang_expression_kind({type, _annotation, _rest}) when is_atom(type), do: type
  defp erlang_expression_kind({type, _annotation, _left, _right}) when is_atom(type), do: type
  defp erlang_expression_kind(_ast), do: :expression

  defp truncate(rendered) when byte_size(rendered) <= @max_preview_bytes,
    do: {rendered, false}

  defp truncate(rendered) do
    {valid_prefix(rendered, @max_preview_bytes), true}
  end

  defp valid_prefix(rendered, size) do
    prefix = binary_part(rendered, 0, size)
    if String.valid?(prefix), do: prefix, else: valid_prefix(rendered, size - 1)
  end
end
