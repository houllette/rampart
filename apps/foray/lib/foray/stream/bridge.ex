defmodule Foray.Stream.Bridge do
  @moduledoc false

  use GenServer

  @type terminal :: :done | :cancelled | {:error, term()}

  @spec start_link() :: GenServer.on_start()
  def start_link, do: GenServer.start_link(__MODULE__, :ok)

  @spec deliver(pid(), Core.Finding.t()) :: :ok | :stop
  def deliver(bridge, finding), do: GenServer.call(bridge, {:deliver, finding}, :infinity)

  @spec next(pid()) :: {:ok, Core.Finding.t()} | :done | {:error, term()}
  def next(bridge), do: GenServer.call(bridge, :next, :infinity)

  @spec complete(pid()) :: :ok
  def complete(bridge), do: GenServer.cast(bridge, :complete)

  @spec fail(pid(), term()) :: :ok
  def fail(bridge, reason), do: GenServer.cast(bridge, {:fail, reason})

  @spec cancel(pid()) :: :ok
  def cancel(bridge), do: GenServer.call(bridge, :cancel, :infinity)

  @spec watch(pid(), pid()) :: :ok
  def watch(bridge, pipeline), do: GenServer.cast(bridge, {:watch, pipeline})

  @spec subscribe(bridge :: pid()) :: :ok | :stop
  def subscribe(bridge) do
    GenServer.call(bridge, {:subscribe, self()})
  catch
    :exit, {:noproc, _call} -> :stop
    :exit, {:normal, _call} -> :stop
    :exit, {:shutdown, _call} -> :stop
    :exit, {:killed, _call} -> :stop
  end

  @spec unsubscribe(bridge :: pid()) :: :ok
  def unsubscribe(bridge), do: GenServer.cast(bridge, {:unsubscribe, self()})

  @impl GenServer
  def init(:ok) do
    {:ok, %{waiting: nil, pending: :queue.new(), terminal: nil, monitor: nil, subscribers: %{}}}
  end

  @impl GenServer
  def handle_call({:subscribe, pid}, _from, %{terminal: nil} = state) do
    {:reply, :ok, %{state | subscribers: Map.put(state.subscribers, pid, Process.monitor(pid))}}
  end

  def handle_call({:subscribe, _pid}, _from, state), do: {:reply, :stop, state}

  def handle_call({:deliver, _finding}, _from, %{terminal: terminal} = state)
      when not is_nil(terminal) do
    {:reply, :stop, state}
  end

  def handle_call({:deliver, finding}, from, %{waiting: nil} = state) do
    {:noreply, %{state | pending: :queue.in({from, finding}, state.pending)}}
  end

  def handle_call({:deliver, finding}, _from, %{waiting: waiting} = state) do
    GenServer.reply(waiting, {:ok, finding})
    {:reply, :ok, %{state | waiting: nil}}
  end

  def handle_call(:next, _from, %{terminal: :done} = state), do: {:reply, :done, state}
  def handle_call(:next, _from, %{terminal: :cancelled} = state), do: {:reply, :done, state}

  def handle_call(:next, _from, %{terminal: {:error, reason}} = state) do
    {:reply, {:error, reason}, state}
  end

  def handle_call(:next, _from, %{waiting: waiting} = state) when not is_nil(waiting) do
    {:reply, {:error, :concurrent_stream_consumers}, state}
  end

  def handle_call(:next, from, state) do
    case :queue.out(state.pending) do
      {{:value, {delivery, finding}}, pending} ->
        GenServer.reply(delivery, :ok)
        {:reply, {:ok, finding}, %{state | pending: pending}}

      {:empty, _pending} ->
        {:noreply, %{state | waiting: from}}
    end
  end

  def handle_call(:cancel, _from, state) do
    state = terminate_waiters(state, :cancelled)
    {:reply, :ok, state}
  end

  @impl GenServer
  def handle_cast({:unsubscribe, pid}, state) do
    {monitor, subscribers} = Map.pop(state.subscribers, pid)
    if monitor, do: Process.demonitor(monitor, [:flush])
    {:noreply, %{state | subscribers: subscribers}}
  end

  def handle_cast(:complete, state), do: {:noreply, terminate_waiters(state, :done)}

  def handle_cast({:fail, reason}, state) do
    {:noreply, terminate_waiters(state, {:error, reason})}
  end

  def handle_cast({:watch, pipeline}, %{monitor: nil} = state) do
    {:noreply, %{state | monitor: Process.monitor(pipeline)}}
  end

  @impl GenServer
  def handle_info({:DOWN, monitor, :process, _pipeline, reason}, %{monitor: monitor} = state) do
    state =
      if is_nil(state.terminal) do
        terminate_waiters(state, {:error, {:pipeline_terminated, reason}})
      else
        state
      end

    {:noreply, state}
  end

  def handle_info({:DOWN, _monitor, :process, pid, _reason}, state) do
    {:noreply, %{state | subscribers: Map.delete(state.subscribers, pid)}}
  end

  defp terminate_waiters(%{terminal: terminal} = state, _new_terminal)
       when not is_nil(terminal),
       do: state

  defp terminate_waiters(state, terminal) do
    if state.waiting do
      reply = if match?({:error, _reason}, terminal), do: terminal, else: :done
      GenServer.reply(state.waiting, reply)
    end

    drain_deliveries(state.pending)
    Enum.each(state.subscribers, fn {pid, _monitor} -> send(pid, {:foray_cancel, self()}) end)
    %{state | waiting: nil, pending: :queue.new(), terminal: terminal}
  end

  defp drain_deliveries(queue) do
    case :queue.out(queue) do
      {{:value, {delivery, _finding}}, queue} ->
        GenServer.reply(delivery, :stop)
        drain_deliveries(queue)

      {:empty, _queue} ->
        :ok
    end
  end
end
