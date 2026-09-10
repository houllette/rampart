defmodule Havoc.Observation.Cache do
  @moduledoc """
  A two-partition observation at an application-owned shared-cache boundary.

  The caller performs uncached control requests and the cache replay. This
  struct only records the values and correlation facts needed by a separate
  noninterference oracle.
  """

  @type cache_status :: :hit | :miss
  @type t :: %__MODULE__{
          input: term(),
          first_partition: term(),
          second_partition: term(),
          first_cache_key: term(),
          second_cache_key: term(),
          first_value: term(),
          direct_second_value: term(),
          served_second_value: term(),
          second_cache_status: cache_status(),
          metadata: map()
        }

  @enforce_keys [
    :input,
    :first_partition,
    :second_partition,
    :first_cache_key,
    :second_cache_key,
    :first_value,
    :direct_second_value,
    :served_second_value,
    :second_cache_status,
    :metadata
  ]
  defstruct @enforce_keys

  @doc "Builds a validated paired cache observation."
  @spec new!(keyword()) :: t()
  def new!(attributes) when is_list(attributes) do
    attributes =
      Keyword.validate!(attributes,
        input: nil,
        first_partition: nil,
        second_partition: nil,
        first_cache_key: nil,
        second_cache_key: nil,
        first_value: nil,
        direct_second_value: nil,
        served_second_value: nil,
        second_cache_status: nil,
        metadata: %{}
      )

    observation = struct!(__MODULE__, attributes)

    if observation.second_cache_status in [:hit, :miss] and is_map(observation.metadata) do
      observation
    else
      raise ArgumentError, "invalid cache observation: #{inspect(observation)}"
    end
  end
end
