defmodule Portico.TestDiscoveryEngine do
  @behaviour Portico.Discovery.Engine

  alias Portico.Discovery.Result

  @impl true
  def option_schema do
    [
      observer: [type: :pid, required: true],
      count: [type: :pos_integer, default: 3],
      ports: [type: {:list, :pos_integer}, default: [443]]
    ]
  end

  @impl true
  def stream(target, opts) do
    Stream.resource(
      fn ->
        send(opts[:observer], {:discovery_started, target.value})
        1
      end,
      fn index ->
        if index <= opts[:count] do
          send(opts[:observer], {:discovery_pull, index})
          {[%Result{target: target, ip: "10.0.0.#{index}", ports: opts[:ports]}], index + 1}
        else
          {:halt, index}
        end
      end,
      fn _index -> :ok end
    )
  end
end

defmodule Portico.TestEnrichmentEngine do
  @behaviour Portico.Enrichment.Engine

  alias Portico.{Host, Port}

  @impl true
  def option_schema do
    [
      observer: [type: :pid, required: true],
      block: [type: :boolean, default: false]
    ]
  end

  @impl true
  def enrich(entries, opts) do
    send(opts[:observer], {:enrichment_started, self(), Enum.map(entries, & &1.ip)})

    if opts[:block] do
      receive do
        :release -> :ok
      end
    end

    {:ok,
     Enum.map(entries, fn entry ->
       ports =
         Enum.map(entry.ports, fn number ->
           %Port{number: number, protocol: entry.protocol, state: "open"}
         end)

       %Host{ip: entry.ip, status: :up, scanned_at: DateTime.utc_now(), ports: ports}
     end)}
  end
end
