defmodule RampartEvaluation.CrossProcessFrontierProbe.PersistentWorker do
  @moduledoc false
  use GenServer

  def start_link(options), do: GenServer.start_link(__MODULE__, options)
  def store(worker, version, marker), do: GenServer.call(worker, {:store, version, marker})
  def read(worker), do: GenServer.call(worker, :read)

  @impl true
  def init(options) do
    table = Keyword.fetch!(options, :table)
    key = Keyword.fetch!(options, :key)

    value =
      case :ets.lookup(table, key) do
        [{^key, stored}] -> stored
        [] -> nil
      end

    {:ok, %{table: table, key: key, value: value}}
  end

  @impl true
  def handle_call({:store, version, marker}, _from, state) do
    value = {version, marker}
    true = :ets.insert(state.table, {state.key, value})
    {:reply, :ok, %{state | value: value}}
  end

  def handle_call(:read, _from, state), do: {:reply, state.value, state}
end

defmodule RampartEvaluation.CrossProcessFrontierProbe.PersistentSupervisor do
  @moduledoc false
  use Supervisor

  alias RampartEvaluation.CrossProcessFrontierProbe.PersistentWorker

  def start_link(options), do: Supervisor.start_link(__MODULE__, options)

  @impl true
  def init(options) do
    Supervisor.init([{PersistentWorker, options}], strategy: :one_for_one)
  end
end

defmodule RampartEvaluation.CrossProcessFrontierProbe do
  @moduledoc false

  alias RampartEvaluation.CrossProcessFrontierProbe.{
    DistributedRemote,
    PersistentSupervisor,
    PersistentWorker
  }

  @persistent_key :rampart_persistent_worker_state
  @persistent_version "rampart-state-version-1"
  @stress_flow_count 64
  @stress_sender_count 16
  @stress_noise_count 512
  @stress_message_tag :rampart_mailbox_pressure_probe
  @distributed_flow_count 4
  @distributed_message_tag :rampart_distributed_probe
  @probe_timeout_ms 5_000

  @spec run!() :: map()
  def run! do
    external_state = probe_external_state_restoration!()
    mailbox_pressure = probe_mailbox_pressure!()
    distributed = probe_distributed_handoff()

    status =
      if external_state.status == :supported and mailbox_pressure.status == :supported and
           distributed.gate_satisfied,
         do: :supported,
         else: :incomplete

    %{
      schema_version: 1,
      status: status,
      external_state_restoration: external_state,
      mailbox_pressure: mailbox_pressure,
      distributed_handoff: distributed,
      duration_us:
        external_state.duration_us + mailbox_pressure.duration_us + distributed.duration_us
    }
  end

  defp probe_external_state_restoration! do
    marker = "rampart-external-state-restoration-marker"
    table = :ets.new(:rampart_external_state_probe, [:set, :public])
    options = [table: table, key: @persistent_key]
    {:ok, supervisor} = PersistentSupervisor.start_link(options)
    old_worker = persistent_worker(supervisor)
    session = :trace.session_create(:rampart_iast_external_state_probe, self(), [])
    started_at = System.monotonic_time()

    try do
      match_spec = [{[table, :_], [], [{:return_trace}]}]
      1 = :trace.function(session, {:ets, :insert, 2}, match_spec, [])
      1 = :trace.function(session, {:ets, :lookup, 2}, match_spec, [])

      1 =
        :trace.process(session, supervisor, true, [
          :procs,
          :call,
          :set_on_spawn,
          :monotonic_timestamp
        ])

      1 = :trace.process(session, old_worker, true, [:procs, :call, :monotonic_timestamp])
      :ok = PersistentWorker.store(old_worker, @persistent_version, marker)
      {@persistent_version, ^marker} = PersistentWorker.read(old_worker)
      :ok = GenServer.stop(old_worker, :normal)
      new_worker = await_persistent_worker(supervisor, old_worker, deadline())
      restored = PersistentWorker.read(new_worker)
      delivery_ref = :trace.delivered(session, :all)

      state =
        collect_until(
          persistent_state(),
          deadline(),
          &persistent_trace_complete?(&1, delivery_ref, supervisor, old_worker, new_worker),
          &record_persistent/2
        )

      versioned_restore = restored == {@persistent_version, marker}

      %{
        status: if(versioned_restore, do: :supported, else: :incomplete),
        old_and_new_worker_distinct: old_worker != new_worker,
        old_worker_exit_observed: Enum.any?(state.exits, &match?({^old_worker, :normal}, &1)),
        replacement_spawn_observed:
          Enum.any?(state.spawns, &match?({^supervisor, ^new_worker}, &1)),
        external_insert_call_count: length(state.inserts),
        replacement_lookup_call_count: length(state.lookups),
        restored_marker_present: versioned_restore,
        restored_version_present: versioned_restore,
        joined_edge_count: if(versioned_restore, do: 1, else: 0),
        false_join_count: 0,
        correlation_basis: :external_store_key_and_write_version,
        application_version_required: true,
        projected_without_version_status: :ambiguous,
        projected_without_version_unique_edge_count: 0,
        process_identity_used_across_replacement: false,
        value_equality_used_as_provenance: false,
        duration_us: elapsed_us(started_at)
      }
    after
      :trace.session_destroy(session)
      if Process.alive?(supervisor), do: Supervisor.stop(supervisor)
      :ets.delete(table)
    end
  end

  defp persistent_worker(supervisor) do
    case Supervisor.which_children(supervisor) do
      [{PersistentWorker, worker, :worker, [PersistentWorker]}] when is_pid(worker) -> worker
      _children -> exit(:persistent_worker_not_found)
    end
  end

  defp await_persistent_worker(supervisor, old_worker, deadline) do
    worker = persistent_worker(supervisor)

    cond do
      worker != old_worker ->
        worker

      System.monotonic_time(:millisecond) >= deadline ->
        exit(:persistent_worker_timeout)

      true ->
        Process.sleep(1)
        await_persistent_worker(supervisor, old_worker, deadline)
    end
  end

  defp record_persistent(
         state,
         {:trace_ts, process, :call,
          {:ets, :insert, [_table, {@persistent_key, {@persistent_version, marker}}]}, timestamp}
       ) do
    %{state | inserts: [{process, marker, timestamp} | state.inserts]}
  end

  defp record_persistent(
         state,
         {:trace_ts, process, :call, {:ets, :lookup, [_table, @persistent_key]}, timestamp}
       ) do
    %{state | lookups: [{process, timestamp} | state.lookups]}
  end

  defp record_persistent(state, {:trace_ts, process, :exit, reason, _timestamp}) do
    %{state | exits: [{process, reason} | state.exits]}
  end

  defp record_persistent(
         state,
         {:trace_ts, parent, :spawn, child, {:proc_lib, :init_p, _arguments}, _timestamp}
       ) do
    %{state | spawns: [{parent, child} | state.spawns]}
  end

  defp record_persistent(state, message), do: record_delivery(state, message)

  defp persistent_trace_complete?(state, delivery_ref, supervisor, old_worker, new_worker) do
    delivered?(state, [delivery_ref]) and length(state.inserts) == 1 and
      Enum.any?(state.lookups, &(elem(&1, 0) == new_worker)) and
      Enum.any?(state.exits, &match?({^old_worker, :normal}, &1)) and
      Enum.any?(state.spawns, &match?({^supervisor, ^new_worker}, &1))
  end

  defp probe_mailbox_pressure! do
    marker = "rampart-mailbox-pressure-marker"
    parent = self()
    receiver = spawn(fn -> pressure_receiver(parent, @stress_flow_count) end)

    senders =
      1..@stress_flow_count
      |> Enum.chunk_every(div(@stress_flow_count, @stress_sender_count))
      |> Enum.map(fn ids -> spawn(fn -> pressure_sender(parent, receiver, ids, marker) end) end)

    Enum.each(1..@stress_noise_count, fn id -> send(receiver, {:unrelated_noise, id}) end)
    send(receiver, :begin_pressure_probe)

    receive do
      {:rampart_pressure_receiver_ready, ^receiver} -> :ok
    after
      @probe_timeout_ms -> exit(:pressure_receiver_ready_timeout)
    end

    session = :trace.session_create(:rampart_iast_mailbox_pressure_probe, self(), [])
    started_at = System.monotonic_time()

    try do
      message = {@stress_message_tag, :_, marker}
      1 = :trace.send(session, [{[receiver, message], [], []}], [])
      1 = :trace.recv(session, [{[:_, :_, message], [], []}], [])

      Enum.each(senders, fn sender ->
        1 = :trace.process(session, sender, true, [:send, :monotonic_timestamp])
      end)

      1 = :trace.process(session, receiver, true, [:receive, :monotonic_timestamp])
      Enum.each(senders, &send(&1, :dispatch))
      deadline = deadline()

      state =
        collect_until(
          pressure_state(),
          deadline,
          &pressure_execution_complete?/1,
          &record_pressure/2
        )

      delivery_refs = Enum.map([receiver | senders], &:trace.delivered(session, &1))

      state =
        collect_until(
          state,
          deadline,
          &pressure_trace_complete?(&1, delivery_refs),
          &record_pressure/2
        )

      send_groups = Enum.group_by(state.sends, &elem(&1, 0))
      receive_groups = Enum.group_by(state.receives, &elem(&1, 0))

      joined =
        Enum.count(1..@stress_flow_count, fn id ->
          with [{^id, recipient}] <- Map.get(send_groups, id, []),
               [{^id, observed_receiver}] <- Map.get(receive_groups, id, []) do
            recipient == observed_receiver
          else
            _unjoinable -> false
          end
        end)

      %{
        status:
          if(joined == @stress_flow_count and state.queue_length == @stress_noise_count,
            do: :supported,
            else: :incomplete
          ),
        flow_count: @stress_flow_count,
        sender_count: @stress_sender_count,
        noise_message_count: @stress_noise_count,
        receiver_queue_length_after_flows: state.queue_length,
        receiver_reductions: state.reductions,
        send_event_count: length(state.sends),
        receive_event_count: length(state.receives),
        joined_edge_count: joined,
        false_join_count: @stress_flow_count - joined,
        value_only_candidate_pair_count: @stress_flow_count * @stress_flow_count,
        value_only_unique_edge_count: 0,
        correlation_basis: :explicit_message_envelope_under_mailbox_pressure,
        value_equality_used_as_provenance: false,
        duration_us: elapsed_us(started_at)
      }
    after
      :trace.session_destroy(session)
      Enum.each([receiver | senders], &stop/1)
    end
  end

  defp pressure_receiver(parent, flow_count) do
    receive do
      :begin_pressure_probe ->
        send(parent, {:rampart_pressure_receiver_ready, self()})
        receive_pressure_flows(parent, flow_count)
    after
      @probe_timeout_ms -> :ok
    end
  end

  defp receive_pressure_flows(parent, remaining) when remaining > 0 do
    receive do
      {@stress_message_tag, id, marker} ->
        send(parent, {:rampart_pressure_acknowledged, id, marker})
        receive_pressure_flows(parent, remaining - 1)
    after
      @probe_timeout_ms -> :ok
    end
  end

  defp receive_pressure_flows(parent, 0) do
    {:message_queue_len, queue_length} = Process.info(self(), :message_queue_len)
    {:reductions, reductions} = Process.info(self(), :reductions)
    send(parent, {:rampart_pressure_complete, queue_length, reductions})
    await_stop()
  end

  defp pressure_sender(parent, receiver, ids, marker) do
    receive do
      :dispatch ->
        Enum.each(ids, fn id -> send(receiver, {@stress_message_tag, id, marker}) end)
        send(parent, :rampart_pressure_sender_done)
        await_stop()
    after
      @probe_timeout_ms -> :ok
    end
  end

  defp pressure_execution_complete?(state) do
    state.acknowledged == @stress_flow_count and
      state.senders_done == @stress_sender_count and is_integer(state.queue_length)
  end

  defp pressure_trace_complete?(state, delivery_refs) do
    delivered?(state, delivery_refs) and length(state.sends) == @stress_flow_count and
      length(state.receives) == @stress_flow_count
  end

  defp record_pressure(
         state,
         {:trace_ts, _sender, :send, {@stress_message_tag, id, _marker}, receiver, _timestamp}
       ) do
    %{state | sends: [{id, receiver} | state.sends]}
  end

  defp record_pressure(
         state,
         {:trace_ts, receiver, :receive, {@stress_message_tag, id, _marker}, _timestamp}
       ) do
    %{state | receives: [{id, receiver} | state.receives]}
  end

  defp record_pressure(state, {:rampart_pressure_acknowledged, _id, _marker}) do
    %{state | acknowledged: state.acknowledged + 1}
  end

  defp record_pressure(state, :rampart_pressure_sender_done) do
    %{state | senders_done: state.senders_done + 1}
  end

  defp record_pressure(state, {:rampart_pressure_complete, queue_length, reductions}) do
    %{state | queue_length: queue_length, reductions: reductions}
  end

  defp record_pressure(state, message), do: record_delivery(state, message)

  defp probe_distributed_handoff do
    required = distributed_required?()
    started_at = System.monotonic_time()

    if required or distributed_enabled?() do
      case ensure_distributed_node() do
        {:ok, distribution_started?} ->
          run_distributed_peer!(required, distribution_started?, started_at)

        {:error, reason} ->
          distributed_unavailable(required, reason, started_at)
      end
    else
      distributed_unavailable(required, :not_requested, started_at)
    end
  end

  defp run_distributed_peer!(required, distribution_started?, started_at) do
    marker = "rampart-distributed-node-marker"
    local_runtime = runtime()

    try do
      peer_options = %{
        name: :rampart_evaluation_peer,
        wait_boot: @probe_timeout_ms,
        args: peer_code_path_arguments()
      }

      case :peer.start_link(peer_options) do
        {:ok, peer, peer_node} ->
          try do
            load_remote_module!(peer_node, DistributedRemote)

            remote =
              :erpc.call(peer_node, DistributedRemote, :setup, [
                self(),
                @distributed_flow_count,
                marker
              ])

            parent = self()
            sender = spawn(fn -> distributed_sender(parent, remote.receiver, marker) end)
            session = :trace.session_create(:rampart_iast_distributed_local_probe, self(), [])

            try do
              message = {@distributed_message_tag, :_, marker}
              1 = :trace.send(session, [{[remote.receiver, message], [], []}], [])
              1 = :trace.process(session, sender, true, [:send, :monotonic_timestamp])
              send(sender, :dispatch)
              deadline = deadline()

              state =
                collect_until(
                  distributed_state(),
                  deadline,
                  &(&1.acknowledged == @distributed_flow_count),
                  &record_distributed/2
                )

              local_delivery_ref = :trace.delivered(session, sender)

              remote_delivery_ref =
                :erpc.call(peer_node, DistributedRemote, :delivery, [remote.coordinator])

              state =
                collect_until(
                  state,
                  deadline,
                  &distributed_trace_complete?(
                    &1,
                    local_delivery_ref,
                    remote_delivery_ref
                  ),
                  &record_distributed/2
                )

              remote_runtime = :erpc.call(peer_node, DistributedRemote, :runtime, [])
              summarize_distributed(state, required, local_runtime, remote_runtime, started_at)
            after
              :trace.session_destroy(session)
              stop(sender)

              :erpc.call(peer_node, DistributedRemote, :cleanup, [remote.coordinator])
            end
          after
            :peer.stop(peer)
          end

        {:error, reason} ->
          distributed_unavailable(required, reason, started_at)
      end
    after
      if distribution_started?, do: :net_kernel.stop()
    end
  end

  defp distributed_sender(owner, receiver, marker) do
    receive do
      :dispatch ->
        Enum.each(1..@distributed_flow_count, fn id ->
          send(receiver, {@distributed_message_tag, id, marker})
        end)

        send(owner, :rampart_distributed_sender_done)
        await_stop()
    after
      @probe_timeout_ms -> :ok
    end
  end

  defp record_distributed(
         state,
         {:trace_ts, _sender, :send, {@distributed_message_tag, id, marker}, receiver, _timestamp}
       ) do
    %{state | sends: [{id, marker, receiver} | state.sends]}
  end

  defp record_distributed(
         state,
         {:rampart_remote_trace,
          {:trace_ts, receiver, :receive, {@distributed_message_tag, id, marker}, _timestamp}}
       ) do
    %{state | receives: [{id, marker, receiver} | state.receives]}
  end

  defp record_distributed(state, {:rampart_distributed_acknowledged, _id, _marker}) do
    %{state | acknowledged: state.acknowledged + 1}
  end

  defp record_distributed(state, :rampart_distributed_sender_done) do
    %{state | sender_done: state.sender_done + 1}
  end

  defp record_distributed(
         state,
         {:trace_delivered, _tracee, reference}
       ) do
    %{state | local_delivered: MapSet.put(state.local_delivered, reference)}
  end

  defp record_distributed(
         state,
         {:rampart_remote_trace, {:trace_delivered, _tracee, reference}}
       ) do
    %{state | remote_delivered: MapSet.put(state.remote_delivered, reference)}
  end

  defp record_distributed(state, _other), do: state

  defp distributed_trace_complete?(state, local_reference, remote_reference) do
    state.local_delivered == MapSet.new([local_reference]) and
      state.remote_delivered == MapSet.new([remote_reference]) and
      state.sender_done == 1 and length(state.sends) == @distributed_flow_count and
      length(state.receives) == @distributed_flow_count
  end

  defp summarize_distributed(state, required, local_runtime, remote_runtime, started_at) do
    send_groups = Enum.group_by(state.sends, &elem(&1, 0))
    receive_groups = Enum.group_by(state.receives, &elem(&1, 0))

    joined =
      Enum.count(1..@distributed_flow_count, fn id ->
        with [{^id, marker, recipient}] <- Map.get(send_groups, id, []),
             [{^id, ^marker, receiver}] <- Map.get(receive_groups, id, []) do
          recipient == receiver
        else
          _unjoinable -> false
        end
      end)

    %{
      status: if(joined == @distributed_flow_count, do: :supported, else: :incomplete),
      gate_satisfied: joined == @distributed_flow_count,
      required: required,
      node_count: 2,
      trace_session_count: 2,
      delivery_barrier_count: 2,
      flow_count: @distributed_flow_count,
      send_event_count: length(state.sends),
      receive_event_count: length(state.receives),
      acknowledged_count: state.acknowledged,
      joined_edge_count: joined,
      false_join_count: @distributed_flow_count - joined,
      correlation_basis: :explicit_distributed_message_envelope,
      cross_node_clock_order_used: false,
      value_equality_used_as_provenance: false,
      local_runtime: local_runtime,
      remote_runtime: remote_runtime,
      duration_us: elapsed_us(started_at)
    }
  end

  defp ensure_distributed_node do
    if Node.alive?() do
      {:ok, false}
    else
      with :ok <- ensure_epmd() do
        case :net_kernel.start([:rampart_evaluation, :shortnames]) do
          {:ok, _pid} -> {:ok, true}
          {:error, reason} -> {:error, reason}
        end
      end
    end
  end

  defp ensure_epmd do
    case System.find_executable("epmd") do
      nil ->
        {:error, :epmd_not_found}

      executable ->
        case System.cmd(executable, ["-daemon"], stderr_to_stdout: true) do
          {_output, 0} -> :ok
          {output, status} -> {:error, {:epmd_start_failed, status, bounded_reason(output)}}
        end
    end
  end

  defp peer_code_path_arguments do
    Enum.flat_map(:code.get_path(), fn path -> [~c"-pa", path] end)
  end

  defp load_remote_module!(peer_node, module) do
    {:ok, _applications} =
      :erpc.call(peer_node, :application, :ensure_all_started, [:elixir])

    file = Path.expand("evaluation/support/distributed_remote.exs")
    source = File.read!(file)
    compiled = :erpc.call(peer_node, Code, :compile_string, [source, file])
    {^module, _binary} = List.keyfind(compiled, module, 0)
    :ok
  end

  defp distributed_unavailable(required, reason, started_at) do
    %{
      status: :unavailable,
      gate_satisfied: not required,
      required: required,
      reason: bounded_reason(reason),
      node_count: 1,
      joined_edge_count: 0,
      false_join_count: 0,
      duration_us: elapsed_us(started_at)
    }
  end

  defp distributed_required? do
    System.get_env("RAMPART_REQUIRE_DISTRIBUTED") in ["1", "true"]
  end

  defp distributed_enabled? do
    System.get_env("RAMPART_ENABLE_DISTRIBUTED") in ["1", "true"]
  end

  defp runtime do
    %{
      otp: List.to_string(:erlang.system_info(:otp_release)),
      elixir: System.version()
    }
  end

  defp bounded_reason(reason) do
    reason
    |> inspect(limit: 5, printable_limit: 200)
    |> String.slice(0, 300)
  end

  defp collect_until(state, deadline, complete?, recorder) do
    if complete?.(state) do
      state
    else
      remaining = max(deadline - System.monotonic_time(:millisecond), 0)

      receive do
        message ->
          state
          |> recorder.(message)
          |> collect_until(deadline, complete?, recorder)
      after
        remaining ->
          raise "frontier cross-process probe timed out: #{inspect(state_summary(state))}"
      end
    end
  end

  defp record_delivery(state, {:trace_delivered, _tracee, reference}) do
    %{state | delivered: MapSet.put(state.delivered, reference)}
  end

  defp record_delivery(state, _other), do: state

  defp delivered?(state, references), do: state.delivered == MapSet.new(references)

  defp state_summary(state) do
    Map.new(state, fn
      {key, value} when is_list(value) -> {key, length(value)}
      {key, %MapSet{} = value} -> {key, MapSet.size(value)}
      pair -> pair
    end)
  end

  defp persistent_state do
    %{inserts: [], lookups: [], exits: [], spawns: [], delivered: MapSet.new()}
  end

  defp pressure_state do
    %{
      sends: [],
      receives: [],
      acknowledged: 0,
      senders_done: 0,
      queue_length: nil,
      reductions: nil,
      delivered: MapSet.new()
    }
  end

  defp distributed_state do
    %{
      sends: [],
      receives: [],
      acknowledged: 0,
      sender_done: 0,
      local_delivered: MapSet.new(),
      remote_delivered: MapSet.new()
    }
  end

  defp deadline, do: System.monotonic_time(:millisecond) + @probe_timeout_ms

  defp elapsed_us(started_at) do
    System.convert_time_unit(System.monotonic_time() - started_at, :native, :microsecond)
  end

  defp await_stop do
    receive do
      :stop -> :ok
    after
      @probe_timeout_ms -> :ok
    end
  end

  defp stop(process) do
    if Process.alive?(process), do: Process.exit(process, :kill)
  end
end
