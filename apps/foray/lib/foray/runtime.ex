defmodule Foray.Runtime do
  @moduledoc false

  alias Foray.{PipelineError, Scan}

  @spec validate!(Scan.t()) :: :ok
  def validate!(%Scan{} = scan) do
    validate_plan!(scan)

    if function_exported?(scan.engine.module, :validate_runtime, 1) do
      case scan.engine.module.validate_runtime(scan.engine.opts) do
        :ok -> :ok
        {:error, reason} -> raise PipelineError, stage: :preflight, reason: reason
        other -> raise PipelineError, stage: :preflight, reason: {:invalid_runtime_check, other}
      end
    end
  end

  defp validate_plan!(%Scan{fuzz_points: []}) do
    raise PipelineError, stage: :plan, reason: :no_fuzz_points
  end

  defp validate_plan!(%Scan{mode: :sniper, wordlists: wordlists}) do
    source_count = wordlists |> Enum.map(& &1.source) |> Enum.uniq() |> length()

    if source_count == 1 do
      :ok
    else
      raise PipelineError, stage: :plan, reason: :sniper_requires_one_input_source
    end
  end

  defp validate_plan!(%Scan{}), do: :ok
end
