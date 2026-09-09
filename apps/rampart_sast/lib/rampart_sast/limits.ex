defmodule RampartSAST.Limits do
  @moduledoc "Finite resource limits for source discovery, parsing, context, and rule execution."

  @type t :: %__MODULE__{
          max_files: pos_integer(),
          max_file_bytes: pos_integer(),
          max_total_bytes: pos_integer(),
          max_concurrency: pos_integer(),
          parse_timeout_ms: pos_integer(),
          context_timeout_ms: pos_integer(),
          behavior_timeout_ms: pos_integer(),
          rule_timeout_ms: pos_integer()
        }

  @enforce_keys [
    :max_files,
    :max_file_bytes,
    :max_total_bytes,
    :max_concurrency,
    :parse_timeout_ms,
    :context_timeout_ms,
    :behavior_timeout_ms,
    :rule_timeout_ms
  ]
  defstruct @enforce_keys

  @defaults [
    max_files: 10_000,
    max_file_bytes: 1_000_000,
    max_total_bytes: 25_000_000,
    max_concurrency: System.schedulers_online(),
    parse_timeout_ms: 5_000,
    context_timeout_ms: 5_000,
    behavior_timeout_ms: 5_000,
    rule_timeout_ms: 5_000
  ]

  @doc "Builds finite scanner limits from a keyword list or existing limits."
  @spec new!(attributes :: keyword() | t()) :: t()
  def new!(%__MODULE__{} = limits), do: validate!(limits)

  def new!(attributes) when is_list(attributes) do
    attributes
    |> Keyword.validate!(@defaults)
    |> then(&struct!(__MODULE__, &1))
    |> validate!()
  end

  @doc "Validates scanner limits and returns them."
  @spec validate!(limits :: t()) :: t()
  def validate!(%__MODULE__{} = limits) do
    valid? =
      Enum.all?(
        [
          limits.max_files,
          limits.max_file_bytes,
          limits.max_total_bytes,
          limits.max_concurrency,
          limits.parse_timeout_ms,
          limits.context_timeout_ms,
          limits.behavior_timeout_ms,
          limits.rule_timeout_ms
        ],
        &positive_integer?/1
      ) and limits.max_file_bytes <= limits.max_total_bytes

    if valid?, do: limits, else: raise(ArgumentError, "invalid SAST limits: #{inspect(limits)}")
  end

  defp positive_integer?(value), do: is_integer(value) and value > 0
end
