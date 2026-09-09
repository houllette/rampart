defmodule Portico.Runtime do
  @moduledoc false

  alias Portico.PipelineError
  alias Portico.Scan.Stage

  @spec validate!(Portico.Scan.t()) :: :ok
  def validate!(%Portico.Scan{discovery: %Stage{} = discovery, enrichment: %Stage{} = enrichment}) do
    validate_stage!(discovery)
    validate_stage!(enrichment)
  end

  defp validate_stage!(stage) do
    if function_exported?(stage.engine, :validate_runtime, 1) do
      case stage.engine.validate_runtime(stage.opts) do
        :ok -> :ok
        {:error, reason} -> raise PipelineError, stage: :preflight, reason: reason
        other -> raise PipelineError, stage: :preflight, reason: {:invalid_runtime_check, other}
      end
    end
  end
end
