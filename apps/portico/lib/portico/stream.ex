defmodule Portico.Stream do
  @moduledoc false

  alias Portico.Discovery.Source
  alias Portico.Enrichment.Stage, as: EnrichmentStage
  alias Portico.{Host, PipelineError, RateLimit, Runtime, ScanStream}

  @spec build(Portico.Scan.t()) :: Enumerable.t(Host.t())
  def build(%Portico.Scan{} = scan) do
    scan
    |> authorized_pipeline()
    |> ScanStream.new(scan)
  end

  defp authorized_pipeline(scan) do
    Stream.flat_map([scan], fn scan ->
      Runtime.validate!(scan)

      Core.Scope.ensure_all_authorized!(scan.targets, scan.scope)

      scan
      |> Source.stream()
      |> RateLimit.stream(scan.rate_limit)
      |> Stream.chunk_every(scan.host_batch_size)
      |> Stream.flat_map(&compatible_batches/1)
      |> async_enrich(scan)
      |> Stream.flat_map(&task_hosts/1)
    end)
  end

  defp async_enrich(batches, scan) do
    Task.Supervisor.async_stream_nolink(
      Portico.TaskSupervisor,
      batches,
      &EnrichmentStage.run(&1, scan),
      max_concurrency: scan.max_concurrency,
      ordered: false,
      timeout: :infinity
    )
  end

  defp compatible_batches(entries) do
    entries
    |> Enum.group_by(&{&1.protocol, &1.ports})
    |> Map.values()
  end

  defp task_hosts({:ok, {:ok, hosts}}) when is_list(hosts), do: hosts

  defp task_hosts({:exit, reason}) do
    raise PipelineError, stage: :enrichment, reason: reason
  end
end
