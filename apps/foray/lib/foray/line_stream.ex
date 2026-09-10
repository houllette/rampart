defmodule Foray.LineStream do
  @moduledoc false

  @max_line_bytes 1_048_576
  @chunk_bytes 16_384

  @spec transform(chunks :: Enumerable.t(), parser :: (binary() -> term())) :: Enumerable.t()
  def transform(chunks, parser) when is_function(parser, 1) do
    chunks
    |> Stream.flat_map(&slices/1)
    |> Stream.transform(
      fn -> {[], 0} end,
      &split_chunk(&1, &2, parser),
      &flush_fragment(&1, parser),
      fn _state -> :ok end
    )
  end

  @doc "Checks raw line bytes, excluding one final LF but including any CR."
  @spec check_line(line :: binary()) :: {:ok, binary()} | {:error, Exception.t()}
  def check_line(line) when is_binary(line) do
    line = without_final_lf(line)

    if byte_size(line) <= @max_line_bytes,
      do: {:ok, line},
      else: {:error, output_error(line)}
  end

  defp without_final_lf(<<>>), do: <<>>

  defp without_final_lf(line) do
    if :binary.last(line) == ?\n,
      do: binary_part(line, 0, byte_size(line) - 1),
      else: line
  end

  defp slices(chunk) do
    chunk
    |> IO.iodata_to_binary()
    |> Stream.unfold(fn
      <<>> ->
        nil

      binary ->
        size = min(byte_size(binary), @chunk_bytes)
        <<piece::binary-size(^size), rest::binary>> = binary
        {piece, rest}
    end)
  end

  defp split_chunk(chunk, state, parser) do
    [first | rest] = :binary.split(chunk, "\n", [:global])
    {events, state} = consume_parts(rest, first, state, parser, [])
    {Enum.reverse(events), state}
  end

  defp consume_parts([], part, state, _parser, events),
    do: {events, append_fragment(state, part)}

  defp consume_parts([next | rest], part, state, parser, events) do
    state = append_fragment(state, part)
    events = parse_fragment(state, parser, events)
    consume_parts(rest, next, {[], 0}, parser, events)
  end

  defp append_fragment(state, ""), do: state

  defp append_fragment({parts, size}, part) do
    if size + byte_size(part) > @max_line_bytes do
      # Only copy the preview, never assemble the oversized line.
      prefix =
        case parts do
          [] -> part
          _ -> List.last(parts)
        end

      raise output_error(prefix)
    end

    {[:binary.copy(part) | parts], size + byte_size(part)}
  end

  defp flush_fragment({[], 0} = state, _parser), do: {[], state}
  defp flush_fragment(state, parser), do: {parse_fragment(state, parser, []), {[], 0}}

  defp parse_fragment({parts, _size}, parser, events) do
    line = parts |> Enum.reverse() |> IO.iodata_to_binary() |> String.trim_trailing("\r")

    case parser.(line) do
      {:ok, event} -> [event | events]
      :ignore -> events
      {:error, reason} -> raise reason
    end
  end

  defp output_error(line), do: Foray.OutputError.exception(line: line, reason: :line_too_long)
end
