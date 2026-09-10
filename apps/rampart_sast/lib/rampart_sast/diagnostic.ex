defmodule RampartSAST.Diagnostic do
  @moduledoc "A bounded scanner diagnostic that is kept separate from security observations."

  @type level :: :warning | :error
  @type phase :: :discovery | :limits | :parse | :suppression | :context | :inventory | :rule

  @type t :: %__MODULE__{
          level: level(),
          phase: phase(),
          code: atom(),
          message: String.t(),
          file: Path.t() | nil,
          rule_id: String.t() | nil
        }

  @enforce_keys [:level, :phase, :code, :message]
  defstruct [:level, :phase, :code, :message, :file, :rule_id]

  @levels [:warning, :error]
  @phases [:discovery, :limits, :parse, :suppression, :context, :inventory, :rule]
  @max_message_bytes 4_096

  @doc "Builds and validates a scanner diagnostic."
  @spec new!(attributes :: keyword()) :: t()
  def new!(attributes) when is_list(attributes) do
    attributes =
      Keyword.validate!(attributes, [:level, :phase, :code, :message, :file, :rule_id])

    attributes
    |> Keyword.update!(:message, &bounded_message/1)
    |> then(&struct!(__MODULE__, &1))
    |> validate!()
  end

  @doc "Validates a diagnostic and returns it."
  @spec validate!(diagnostic :: t()) :: t()
  def validate!(%__MODULE__{} = diagnostic) do
    valid? =
      diagnostic.level in @levels and diagnostic.phase in @phases and
        named_atom?(diagnostic.code) and valid_message?(diagnostic.message) and
        optional_file?(diagnostic.file) and optional_string?(diagnostic.rule_id)

    if valid?,
      do: diagnostic,
      else: raise(ArgumentError, "invalid SAST diagnostic")
  end

  @doc "Projects the diagnostic into plain evidence data."
  @spec to_map(diagnostic :: t()) :: map()
  def to_map(%__MODULE__{} = diagnostic) do
    %{
      level: diagnostic.level,
      phase: diagnostic.phase,
      code: diagnostic.code,
      message: diagnostic.message,
      file: diagnostic.file,
      rule_id: diagnostic.rule_id
    }
  end

  @doc """
  Bounds diagnostic text to 4,096 UTF-8 bytes, including any `...` suffix.

  Invalid bytes become U+FFFD. Only a bounded prefix is traversed; codepoints,
  rather than entire graphemes, are preserved at the truncation boundary.
  """
  @spec bounded_message(message :: term()) :: String.t()
  def bounded_message(message) when is_binary(message) do
    size = byte_size(message)

    if size <= @max_message_bytes and String.valid?(message) do
      :binary.copy(message)
    else
      prefix = binary_part(message, 0, min(size, @max_message_bytes))
      {parts, remaining} = utf8_prefix(prefix, @max_message_bytes, [])
      normalized = parts |> Enum.reverse() |> IO.iodata_to_binary()

      if size > @max_message_bytes or remaining != "" do
        {parts, _rest} = utf8_prefix(normalized, @max_message_bytes - 3, [])
        IO.iodata_to_binary([Enum.reverse(parts), "..."])
      else
        normalized
      end
    end
  end

  def bounded_message(message),
    do: message |> inspect(limit: 20, printable_limit: 512, structs: false) |> bounded_message()

  defp utf8_prefix("", _remaining, parts), do: {parts, ""}

  defp utf8_prefix(<<codepoint::utf8, rest::binary>> = binary, remaining, parts) do
    encoded = <<codepoint::utf8>>

    if byte_size(encoded) <= remaining,
      do: utf8_prefix(rest, remaining - byte_size(encoded), [encoded | parts]),
      else: {parts, binary}
  end

  defp utf8_prefix(<<_invalid, rest::binary>>, remaining, parts) when remaining >= 3,
    do: utf8_prefix(rest, remaining - 3, ["�" | parts])

  defp utf8_prefix(binary, _remaining, parts), do: {parts, binary}

  defp valid_message?(message) when is_binary(message),
    do:
      byte_size(message) <= @max_message_bytes and String.valid?(message) and
        nonempty_string?(message)

  defp valid_message?(_message), do: false
  defp optional_file?(nil), do: true
  defp optional_file?(file), do: RampartSAST.Span.valid_file?(file)
  defp optional_string?(nil), do: true
  defp optional_string?(value), do: nonempty_string?(value)
  defp named_atom?(value), do: is_atom(value) and value not in [nil, true, false]
  defp nonempty_string?(value), do: is_binary(value) and String.trim(value) != ""
end
