defmodule RampartEvaluation.CrossProcessFrontierProbe.DistributedRemote do
  @moduledoc false

  @message_tag :rampart_distributed_probe
  @idle_timeout_ms 15_000

  @spec setup(pid(), pos_integer(), String.t()) :: map()
  def setup(owner, flow_count, marker) do
    caller = self()
    coordinator = spawn(fn -> coordinate(caller, owner, flow_count, marker) end)

    receive do
      {:rampart_remote_ready, ^coordinator, remote} -> remote
    after
      3_000 -> exit(:remote_setup_timeout)
    end
  end

  @spec delivery(pid()) :: reference()
  def delivery(coordinator) do
    send(coordinator, {:delivery, self()})

    receive do
      {:rampart_remote_delivery, reference} -> reference
    after
      3_000 -> exit(:remote_delivery_timeout)
    end
  end

  @spec cleanup(pid()) :: :ok
  def cleanup(coordinator) do
    if Process.alive?(coordinator) do
      monitor = Process.monitor(coordinator)
      send(coordinator, {:cleanup, self()})

      receive do
        {:rampart_remote_cleaned, ^coordinator} -> :ok
      after
        3_000 -> exit(:remote_cleanup_timeout)
      end

      receive do
        {:DOWN, ^monitor, :process, ^coordinator, :normal} -> :ok
      after
        3_000 -> exit(:remote_cleanup_exit_timeout)
      end
    else
      exit(:remote_coordinator_not_alive)
    end
  end

  @spec runtime() :: map()
  def runtime do
    %{
      otp: List.to_string(:erlang.system_info(:otp_release)),
      elixir: System.version()
    }
  end

  defp coordinate(caller, owner, flow_count, marker) do
    tracer = spawn(fn -> trace_forwarder(owner) end)
    receiver = spawn(fn -> receive_flows(owner, flow_count) end)
    session = :trace.session_create(:rampart_remote_distributed_probe, tracer, [])
    message = {@message_tag, :_, marker}
    1 = :trace.recv(session, [{[:_, :_, message], [], []}], [])
    1 = :trace.process(session, receiver, true, [:receive, :monotonic_timestamp])

    send(caller, {
      :rampart_remote_ready,
      self(),
      %{receiver: receiver, coordinator: self()}
    })

    coordinate_loop(session, receiver, tracer, owner)
  end

  defp coordinate_loop(session, receiver, tracer, owner) do
    receive do
      {:delivery, caller} ->
        reference = :trace.delivered(session, receiver)
        send(caller, {:rampart_remote_delivery, reference})
        coordinate_loop(session, receiver, tracer, owner)

      {:trace_delivered, _tracee, _reference} = message ->
        send(owner, {:rampart_remote_trace, message})
        coordinate_loop(session, receiver, tracer, owner)

      {:cleanup, caller} ->
        :trace.session_destroy(session)
        stop(receiver)
        stop(tracer)
        send(caller, {:rampart_remote_cleaned, self()})
        :ok
    after
      @idle_timeout_ms ->
        :trace.session_destroy(session)
        stop(receiver)
        stop(tracer)
        :ok
    end
  end

  defp receive_flows(owner, remaining) when remaining > 0 do
    receive do
      {@message_tag, id, marker} ->
        send(owner, {:rampart_distributed_acknowledged, id, marker})
        receive_flows(owner, remaining - 1)
    after
      3_000 -> :ok
    end
  end

  defp receive_flows(_owner, 0) do
    receive do
      :stop -> :ok
    after
      @idle_timeout_ms -> :ok
    end
  end

  defp trace_forwarder(owner) do
    receive do
      :stop ->
        :ok

      message ->
        send(owner, {:rampart_remote_trace, message})
        trace_forwarder(owner)
    after
      @idle_timeout_ms -> :ok
    end
  end

  defp stop(process) do
    if Process.alive?(process), do: Process.exit(process, :kill)
  end
end
