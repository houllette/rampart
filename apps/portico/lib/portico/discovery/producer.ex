defmodule Portico.Discovery.Producer do
  @moduledoc "Demand-driven Broadway producer for discovery engine streams."

  @behaviour Broadway.Producer
  @behaviour GenStage

  alias Broadway.Message
  alias Portico.Discovery.{Reader, Source}

  @force_stop_timeout 2_000

  @impl GenStage
  def init(opts) do
    scan = Keyword.fetch!(opts, :scan)
    discovery_status = Keyword.fetch!(opts, :discovery_status)
    {:ok, reader} = Reader.start_link(self(), Source.stream(scan))

    state = %{
      reader: reader,
      scan_id: scan.id,
      done?: false,
      draining?: false,
      discovery_status: discovery_status
    }

    {:producer, state}
  end

  @impl GenStage
  def handle_demand(_demand, %{done?: true} = state), do: {:noreply, [], state}

  def handle_demand(demand, state) when demand > 0 do
    :ok = Reader.demand(state.reader, demand)
    {:noreply, [], state}
  end

  @impl GenStage
  def handle_info({Reader, :item, reader, item}, %{reader: reader} = state) do
    message = %Message{
      data: item,
      acknowledger: Broadway.NoopAcknowledger.init(),
      metadata: %{scan_id: state.scan_id}
    }

    {:noreply, [message], state}
  end

  def handle_info({Reader, :done, reader}, %{reader: reader} = state) do
    :atomics.put(state.discovery_status, 1, 1)
    {:noreply, [], %{state | done?: true, reader: nil}}
  end

  def handle_info({__MODULE__, :force_stop, reader}, %{reader: reader} = state) do
    force_stop(reader)
    {:noreply, [], %{state | reader: nil, done?: true}}
  end

  def handle_info(_message, state), do: {:noreply, [], state}

  @doc "Stops pulling discovery output before Broadway cancels consumers."
  @impl Broadway.Producer
  def prepare_for_draining(%{reader: nil} = state), do: {:noreply, [], %{state | draining?: true}}

  def prepare_for_draining(state) do
    :ok = Reader.stop(state.reader)
    Process.send_after(self(), {__MODULE__, :force_stop, state.reader}, @force_stop_timeout)
    {:noreply, [], %{state | draining?: true, done?: true}}
  end

  @impl GenStage
  def terminate(_reason, state) do
    if state.reader, do: force_stop(state.reader)
    :ok
  end

  defp force_stop(reader) do
    if Process.alive?(reader) do
      Process.unlink(reader)
      Process.exit(reader, :kill)
    end
  end
end
