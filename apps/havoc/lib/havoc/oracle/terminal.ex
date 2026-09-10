defmodule Havoc.Oracle.Terminal do
  @moduledoc false

  @escape 0x1B
  @delete 0x7F
  @max_sequences 16

  @spec unsafe_sequences(binary(), keyword()) ::
          {:ok, [String.t()]} | {:error, :invalid_utf8}
  def unsafe_sequences(output, options) when is_binary(output) and is_list(options) do
    if String.valid?(output) do
      allowed_controls =
        []
        |> allow(Keyword.fetch!(options, :allow_tab), 0x09)
        |> allow(Keyword.fetch!(options, :allow_newline), 0x0A)
        |> MapSet.new()

      {:ok,
       output
       |> scan(allowed_controls, Keyword.fetch!(options, :allow_sgr), [])
       |> Enum.reverse()}
    else
      {:error, :invalid_utf8}
    end
  end

  defp scan(_output, _allowed, _allow_sgr, unsafe) when length(unsafe) >= @max_sequences,
    do: unsafe

  defp scan(<<>>, _allowed, _allow_sgr, unsafe), do: unsafe

  defp scan(<<@escape, ?[, rest::binary>>, allowed, allow_sgr, unsafe) do
    case csi_final(rest) do
      {:ok, ?m, remaining} when allow_sgr ->
        scan(remaining, allowed, allow_sgr, unsafe)

      {:ok, final, remaining} ->
        scan(remaining, allowed, allow_sgr, ["CSI #{csi_final_name(final)}" | unsafe])

      :unterminated ->
        ["unterminated CSI" | unsafe]
    end
  end

  defp scan(<<@escape, ?], rest::binary>>, allowed, allow_sgr, unsafe) do
    scan(rest, allowed, allow_sgr, ["OSC" | unsafe])
  end

  defp scan(<<@escape, rest::binary>>, allowed, allow_sgr, unsafe) do
    scan(rest, allowed, allow_sgr, ["ESC" | unsafe])
  end

  defp scan(<<0xC2, control, rest::binary>>, allowed, allow_sgr, unsafe)
       when control in 0x80..0x9F do
    scan(rest, allowed, allow_sgr, [codepoint_label(control) | unsafe])
  end

  defp scan(<<control, rest::binary>>, allowed, allow_sgr, unsafe)
       when control in 0x00..0x1F or control == @delete do
    if MapSet.member?(allowed, control) do
      scan(rest, allowed, allow_sgr, unsafe)
    else
      scan(rest, allowed, allow_sgr, [codepoint_label(control) | unsafe])
    end
  end

  defp scan(<<_byte, rest::binary>>, allowed, allow_sgr, unsafe) do
    scan(rest, allowed, allow_sgr, unsafe)
  end

  defp csi_final(<<>>), do: :unterminated

  defp csi_final(<<final, rest::binary>>) when final in 0x40..0x7E,
    do: {:ok, final, rest}

  defp csi_final(<<_parameter, rest::binary>>), do: csi_final(rest)

  defp csi_final_name(final) when final in 0x20..0x7E, do: <<final>>
  defp csi_final_name(final), do: "0x" <> Base.encode16(<<final>>, case: :lower)

  defp codepoint_label(control) do
    "U+" <> (control |> Integer.to_string(16) |> String.upcase() |> String.pad_leading(4, "0"))
  end

  defp allow(values, true, value), do: [value | values]
  defp allow(values, false, _value), do: values
end
