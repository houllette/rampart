defmodule RampartEvaluation.Historical.IncrementalBuffer do
  @moduledoc false

  alias Havoc.Observation.Incremental

  def vulnerable(input) do
    observation = observe(input, :unbounded)
    observation
  end

  def fixed(input) do
    observation = observe(input, :bounded)
    observation
  end

  defp observe(chunks, mode) do
    Incremental.capture(chunks, "", &step(&1, &2, mode), &%{retained_bytes: byte_size(&1)},
      max_input_bytes: 128,
      max_chunks: 32
    )
  end

  defp step(chunk, buffer, mode) do
    next = buffer <> chunk

    cond do
      mode == :bounded and byte_size(next) > 16 -> {:rejected, ""}
      String.ends_with?(next, "\r\n") -> {:accepted, ""}
      true -> {:incomplete, next}
    end
  end
end
