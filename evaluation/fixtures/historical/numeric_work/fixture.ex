defmodule RampartEvaluation.Historical.NumericWork do
  @moduledoc false

  alias Havoc.Observation.Incremental

  def vulnerable(input) do
    observation = observe(input, :unbounded_digits)
    observation
  end

  def fixed(input) do
    observation = observe(input, :bounded_digits)
    observation
  end

  defp observe(chunks, mode) do
    Incremental.capture(
      chunks,
      %{buffer: "", work: 0},
      &step(&1, &2, mode),
      fn state ->
        %{retained_bytes: byte_size(state.buffer), work: state.work}
      end,
      work_unit: :digit_folds,
      max_input_bytes: 128,
      max_chunks: 32
    )
  end

  defp step(chunk, state, mode) do
    buffer = state.buffer <> chunk

    cond do
      # Both controls retain the prior buffer protection; it cannot prove the work bound.
      byte_size(buffer) > 64 ->
        {:rejected, %{state | buffer: ""}}

      String.ends_with?(buffer, "\r\n") ->
        parse(binary_part(buffer, 0, byte_size(buffer) - 2), mode)

      true ->
        {:incomplete, %{state | buffer: buffer}}
    end
  end

  defp parse(digits, :bounded_digits) when byte_size(digits) > 16,
    do: {:rejected, %{buffer: "", work: 0}}

  defp parse(digits, _mode) do
    # Count each actual arbitrary-precision fold, independently of the budget oracle.
    {value, work} =
      for <<digit <- digits>>, reduce: {0, 0} do
        {accumulator, count} ->
          {accumulator * 16 + String.to_integer(<<digit>>, 16), count + 1}
      end

    {:accepted, %{buffer: "", value: value, work: work}}
  end
end
