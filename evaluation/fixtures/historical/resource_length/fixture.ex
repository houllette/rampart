defmodule RampartEvaluation.Historical.ResourceLength do
  @moduledoc false

  alias Havoc.Observation.Length

  def vulnerable(input) do
    observation = observe(input, :graphemes)
    observation
  end

  def fixed(input) do
    observation = observe(input, :bytes)
    observation
  end

  defp observe(input, unit) do
    measured = if unit == :bytes, do: byte_size(input), else: String.length(input)

    if measured <= 4 do
      # This is the reduced downstream output, not the validator's claimed count.
      Length.accepted(input, input, %{boundary: :reduced_output})
    else
      Length.rejected(input, :length_limit)
    end
  end
end
