defmodule Portico.Discovery.Source do
  @moduledoc false

  alias Portico.{Discovery.Result, Launch, PipelineError, Scan.Stage}

  @spec stream(Portico.Scan.t()) :: Enumerable.t(Result.t())
  def stream(%{discovery: %Stage{} = discovery} = scan) do
    Stream.flat_map(scan.targets, fn target ->
      metadata = %{
        scan_id: scan.id,
        stage: :discovery,
        engine: discovery.engine,
        targets: [target.value]
      }

      scan
      |> Launch.run([target], target.value, metadata, fn ->
        discovery.engine.stream(target, discovery.opts)
      end)
      |> Stream.map(&validate_result!/1)
    end)
  end

  defp validate_result!(%Result{} = result), do: result

  defp validate_result!(other) do
    raise PipelineError, stage: :discovery, reason: {:invalid_engine_result, other}
  end
end
