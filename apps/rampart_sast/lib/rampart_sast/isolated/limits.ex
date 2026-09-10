defmodule RampartSAST.Isolated.Limits do
  @moduledoc "Finite OS-worker and response limits for isolated static scans."

  @type t :: %__MODULE__{
          timeout_ms: pos_integer(),
          max_response_bytes: pos_integer(),
          max_log_bytes: pos_integer(),
          max_wire_terms: pos_integer(),
          max_wire_depth: pos_integer(),
          max_heap_words: pos_integer(),
          atom_table_size: pos_integer()
        }

  @enforce_keys [
    :timeout_ms,
    :max_response_bytes,
    :max_log_bytes,
    :max_wire_terms,
    :max_wire_depth,
    :max_heap_words,
    :atom_table_size
  ]
  defstruct @enforce_keys

  @defaults [
    timeout_ms: 30_000,
    max_response_bytes: 64_000_000,
    max_log_bytes: 64_000,
    max_wire_terms: 1_000_000,
    max_wire_depth: 64,
    max_heap_words: 8_000_000,
    atom_table_size: 262_144
  ]

  @doc "Builds validated isolation limits from options or an existing limit value."
  @spec new!(attributes :: keyword() | t()) :: t()
  def new!(%__MODULE__{} = limits), do: validate!(limits)

  def new!(attributes) when is_list(attributes) do
    attributes
    |> Keyword.validate!(@defaults)
    |> then(&struct!(__MODULE__, &1))
    |> validate!()
  end

  @doc "Validates isolation limits."
  @spec validate!(limits :: t()) :: t()
  def validate!(%__MODULE__{} = limits) do
    values = Map.from_struct(limits) |> Map.values()

    valid? =
      Enum.all?(values, &(is_integer(&1) and &1 > 0)) and
        limits.atom_table_size >= 8_192 and limits.max_wire_depth <= 256

    if valid?, do: limits, else: raise(ArgumentError, "invalid isolated SAST limits")
  end
end
