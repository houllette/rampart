defmodule Havoc.Observation.State do
  @moduledoc "A bounded external-state measurement before, after, and optionally after cleanup."

  @type t :: %__MODULE__{
          before: non_neg_integer(),
          after: non_neg_integer(),
          settled: non_neg_integer() | nil,
          unit: atom(),
          metadata: map()
        }

  @enforce_keys [:before, :after, :unit, :metadata]
  defstruct [:before, :after, :settled, :unit, metadata: %{}]

  @doc "Builds a validated external-state observation."
  @spec new!(keyword()) :: t()
  def new!(attributes) when is_list(attributes) do
    attributes =
      Keyword.validate!(attributes,
        before: nil,
        after: nil,
        settled: nil,
        unit: :entries,
        metadata: %{}
      )

    observation = struct!(__MODULE__, attributes)

    valid? =
      non_negative?(observation.before) and non_negative?(observation.after) and
        (is_nil(observation.settled) or non_negative?(observation.settled)) and
        named_atom?(observation.unit) and is_map(observation.metadata)

    if valid?,
      do: observation,
      else: raise(ArgumentError, "invalid state observation: #{inspect(observation)}")
  end

  defp non_negative?(value), do: is_integer(value) and value >= 0
  defp named_atom?(value), do: is_atom(value) and value not in [nil, true, false]
end
