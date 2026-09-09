defmodule RampartIAST.Limits do
  @moduledoc "Bounded execution and evidence limits for one trace session."

  @type t :: %__MODULE__{
          timeout_ms: pos_integer(),
          delivery_timeout_ms: pos_integer(),
          max_events: pos_integer(),
          max_argument_bytes: pos_integer(),
          max_mailbox_messages: pos_integer()
        }

  defstruct timeout_ms: 1_000,
            delivery_timeout_ms: 250,
            max_events: 100,
            max_argument_bytes: 4_096,
            max_mailbox_messages: 1_000

  @doc "Builds bounded trace limits from a keyword list."
  @spec new!(options :: keyword() | t()) :: t()
  def new!(%__MODULE__{} = limits), do: validate!(limits)

  def new!(options) when is_list(options) do
    options =
      Keyword.validate!(options, [
        :timeout_ms,
        :delivery_timeout_ms,
        :max_events,
        :max_argument_bytes,
        :max_mailbox_messages
      ])

    __MODULE__
    |> struct!(options)
    |> validate!()
  end

  @doc "Validates trace limits and returns them."
  @spec validate!(limits :: t()) :: t()
  def validate!(%__MODULE__{} = limits) do
    valid? =
      Enum.all?(
        [
          limits.timeout_ms,
          limits.delivery_timeout_ms,
          limits.max_events,
          limits.max_argument_bytes,
          limits.max_mailbox_messages
        ],
        &(is_integer(&1) and &1 > 0)
      )

    if valid?, do: limits, else: raise(ArgumentError, "invalid IAST limits: #{inspect(limits)}")
  end
end
