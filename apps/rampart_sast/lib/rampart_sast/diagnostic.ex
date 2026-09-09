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
  @max_message_graphemes 1_024

  @doc "Builds and validates a scanner diagnostic."
  @spec new!(attributes :: keyword()) :: t()
  def new!(attributes) when is_list(attributes) do
    attributes =
      Keyword.validate!(attributes, [:level, :phase, :code, :message, :file, :rule_id])

    attributes
    |> Keyword.update!(:message, &truncate/1)
    |> then(&struct!(__MODULE__, &1))
    |> validate!()
  end

  @doc "Validates a diagnostic and returns it."
  @spec validate!(diagnostic :: t()) :: t()
  def validate!(%__MODULE__{} = diagnostic) do
    valid? =
      diagnostic.level in @levels and diagnostic.phase in @phases and
        named_atom?(diagnostic.code) and nonempty_string?(diagnostic.message) and
        optional_file?(diagnostic.file) and optional_string?(diagnostic.rule_id)

    if valid?,
      do: diagnostic,
      else: raise(ArgumentError, "invalid SAST diagnostic: #{inspect(diagnostic)}")
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

  defp truncate(message) when is_binary(message) do
    if String.length(message) <= @max_message_graphemes do
      message
    else
      String.slice(message, 0, @max_message_graphemes) <> "..."
    end
  end

  defp truncate(message), do: inspect(message, limit: 20, printable_limit: 512)
  defp optional_file?(nil), do: true
  defp optional_file?(file), do: RampartSAST.Span.valid_file?(file)
  defp optional_string?(nil), do: true
  defp optional_string?(value), do: nonempty_string?(value)
  defp named_atom?(value), do: is_atom(value) and value not in [nil, true, false]
  defp nonempty_string?(value), do: is_binary(value) and String.trim(value) != ""
end
