defmodule Portico.Discovery.LineStream do
  @moduledoc false

  @max_fragment_bytes 1_048_576

  @spec transform(Enumerable.t(), (String.t() -> term())) :: Enumerable.t()
  def transform(chunks, parser) when is_function(parser, 1) do
    Stream.transform(
      chunks,
      fn -> "" end,
      &split_chunk(&1, &2, parser),
      &flush_fragment(&1, parser),
      fn _fragment -> :ok end
    )
  end

  defp split_chunk(chunk, fragment, parser) when is_binary(chunk) do
    parts = String.split(fragment <> chunk, "\n")
    next_fragment = List.last(parts)

    if byte_size(next_fragment) > @max_fragment_bytes do
      raise Portico.Engine.OutputError,
        engine: :unknown,
        line: next_fragment,
        reason: :line_too_long
    end

    lines = Enum.drop(parts, -1)
    {parse_lines(lines, parser), next_fragment}
  end

  defp flush_fragment("", _parser), do: {[], ""}
  defp flush_fragment(fragment, parser), do: {parse_lines([fragment], parser), ""}

  defp parse_lines(lines, parser) do
    Enum.flat_map(lines, fn line ->
      case parser.(String.trim_trailing(line, "\r")) do
        {:ok, event} -> [event]
        :ignore -> []
        {:error, reason} -> raise reason
      end
    end)
  end
end
