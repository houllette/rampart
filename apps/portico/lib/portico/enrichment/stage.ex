defmodule Portico.Enrichment.Stage do
  @moduledoc false

  alias Portico.{Host, Launch, PipelineError, Scan.Stage, Target}

  @spec run([Portico.Discovery.Result.t()], Portico.Scan.t()) :: {:ok, [Host.t()]}
  def run(entries, %{enrichment: %Stage{} = enrichment} = scan) do
    targets = discovered_targets!(entries)
    target_values = Enum.map(targets, & &1.value)

    metadata = %{
      scan_id: scan.id,
      target: telemetry_target(target_values),
      engine: enrichment.engine,
      host_count: length(entries),
      port_count: Enum.reduce(entries, 0, &(length(&1.ports) + &2))
    }

    result =
      Launch.run(scan, targets, telemetry_target(target_values), metadata, fn ->
        safe_engine_call(enrichment, entries, metadata)
      end)

    case result do
      {:ok, hosts} -> validate_hosts(hosts, entries)
      {:error, reason} -> {:ok, Enum.map(entries, &error_host(&1, reason))}
    end
  end

  defp safe_engine_call(enrichment, entries, metadata) do
    result =
      Core.Telemetry.span(:portico, :enrichment, metadata, fn ->
        result = enrichment.engine.enrich(entries, enrichment.opts)
        {result, Map.put(metadata, :outcome, result_tag(result))}
      end)

    case result do
      {:ok, hosts} -> {:ok, hosts}
      {:error, reason} -> {:error, reason}
      other -> {:error, {:invalid_engine_return, other}}
    end
  rescue
    exception ->
      {:error,
       {:exception, Exception.message(exception), Exception.format_stacktrace(__STACKTRACE__)}}
  catch
    kind, reason ->
      {:error, {kind, inspect(reason)}}
  end

  defp discovered_targets!(entries) do
    Enum.map(entries, fn entry ->
      case Target.parse(entry.ip) do
        {:ok, target} -> target
        {:error, reason} -> raise PipelineError, stage: :discovery, reason: reason
      end
    end)
  end

  defp validate_hosts(hosts, entries) when not is_list(hosts) do
    {:ok, Enum.map(entries, &error_host(&1, {:invalid_engine_result, hosts}))}
  end

  defp validate_hosts(hosts, entries) do
    valid? = length(hosts) == length(entries) and Enum.all?(hosts, &match?(%Host{}, &1))

    if valid? do
      {:ok, hosts}
    else
      {:ok, Enum.map(entries, &error_host(&1, {:invalid_engine_result, hosts}))}
    end
  end

  defp error_host(entry, reason) do
    %Host{
      ip: entry.ip,
      status: :error,
      scanned_at: DateTime.utc_now(),
      meta: %{"engine_error" => inspect(reason)}
    }
  end

  defp telemetry_target([target]), do: target
  defp telemetry_target(targets), do: targets

  defp result_tag({:ok, _hosts}), do: :ok
  defp result_tag({:error, _reason}), do: :error
  defp result_tag(_other), do: :invalid
end
