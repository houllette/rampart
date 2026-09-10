defmodule RampartEvaluation.CrossProcessAdversarialProbe.CastServer do
  @moduledoc false
  use GenServer

  def start_link(owner), do: GenServer.start_link(__MODULE__, owner)
  def consume(server, marker), do: GenServer.cast(server, {:probe_cast_without_id, marker})

  @impl true
  def init(owner), do: {:ok, owner}

  @impl true
  def handle_cast({:probe_cast_without_id, marker}, owner) do
    send(owner, {:rampart_adversarial_cast_acknowledged, marker})
    {:noreply, owner}
  end
end

defmodule RampartEvaluation.CrossProcessAdversarialProbe.TaskFixture do
  @moduledoc false

  @spec crash(pid(), String.t()) :: no_return()
  def crash(owner, _marker) do
    Logger.put_process_level(self(), :none)
    send(owner, {:rampart_adversarial_task_ready, self(), :crash})

    receive do
      :fail -> exit(:rampart_probe_task_failure)
    end
  end

  @spec wait(pid(), String.t()) :: no_return()
  def wait(owner, _marker) do
    send(owner, {:rampart_adversarial_task_ready, self(), :timeout})

    receive do
      :release -> exit(:unexpected_release)
    end
  end

  @spec owner(pid(), String.t()) :: :ok
  def owner(probe, marker) do
    Process.flag(:trap_exit, true)

    receive do
      :dispatch ->
        crash_task = Task.async(__MODULE__, :crash, [self(), marker])
        await_task_ready(crash_task.pid, :crash)
        send(crash_task.pid, :fail)
        crash_outcome = Task.yield(crash_task, 1_000)
        drain_exit(crash_task.pid)

        timeout_task = Task.async(__MODULE__, :wait, [self(), marker])
        await_task_ready(timeout_task.pid, :timeout)
        timeout_outcome = Task.yield(timeout_task, 10)
        shutdown_outcome = Task.shutdown(timeout_task, :brutal_kill)
        drain_exit(timeout_task.pid)

        send(
          probe,
          {:rampart_adversarial_task_owner_done, crash_outcome, timeout_outcome, shutdown_outcome}
        )

        await_stop()
    after
      2_000 -> :ok
    end
  end

  defp await_task_ready(process, kind) do
    receive do
      {:rampart_adversarial_task_ready, ^process, ^kind} -> :ok
    after
      1_000 -> exit(:task_ready_timeout)
    end
  end

  defp drain_exit(process) do
    receive do
      {:EXIT, ^process, _reason} -> :ok
    after
      10 -> :ok
    end
  end

  defp await_stop do
    receive do
      :stop -> :ok
    after
      2_000 -> :ok
    end
  end
end

defmodule RampartEvaluation.CrossProcessAdversarialProbe.ReplacementWorker do
  @moduledoc false
  use GenServer

  def start_link(owner), do: GenServer.start_link(__MODULE__, owner)
  def store(worker, marker), do: GenServer.call(worker, {:store, marker})
  def read(worker), do: GenServer.call(worker, :read)

  @impl true
  def init(owner), do: {:ok, %{owner: owner, marker: nil}}

  @impl true
  def handle_call({:store, marker}, _from, state) do
    {:reply, :ok, %{state | marker: marker}}
  end

  def handle_call(:read, _from, state), do: {:reply, state.marker, state}
end

defmodule RampartEvaluation.CrossProcessAdversarialProbe.ReplacementSupervisor do
  @moduledoc false
  use Supervisor

  alias RampartEvaluation.CrossProcessAdversarialProbe.ReplacementWorker

  def start_link(owner), do: Supervisor.start_link(__MODULE__, owner)

  @impl true
  def init(owner) do
    Supervisor.init([{ReplacementWorker, owner}], strategy: :one_for_one)
  end
end

defmodule RampartEvaluation.CrossProcessAdversarialProbe do
  @moduledoc false

  alias RampartEvaluation.CrossProcessAdversarialProbe.{
    CastServer,
    ReplacementSupervisor,
    ReplacementWorker,
    TaskFixture
  }

  @cast_flow_count 4
  @ets_writer_count 4
  @event_loss_flow_count 4
  @event_loss_tag :rampart_injected_trace_loss
  @ets_key :rampart_adversarial_ets_key
  @probe_timeout_ms 3_000

  @spec run!() :: map()
  def run! do
    cast_without_id = probe_cast_without_id!()
    task_failures = probe_task_failures!()
    ets_mutations = probe_ets_mutations!()
    trace_loss = probe_trace_loss!()
    supervisor_replacement = probe_supervisor_replacement!()

    expected = [
      cast_without_id.status == :ambiguous,
      task_failures.status == :inconclusive,
      ets_mutations.status == :conditional,
      trace_loss.status == :incomplete,
      supervisor_replacement.status == :terminated
    ]

    %{
      schema_version: 1,
      status: if(Enum.all?(expected), do: :fail_closed, else: :incomplete),
      cast_without_id: cast_without_id,
      task_failures: task_failures,
      ets_mutations: ets_mutations,
      trace_loss: trace_loss,
      supervisor_replacement: supervisor_replacement,
      duration_us:
        Enum.sum(
          Enum.map(
            [
              cast_without_id,
              task_failures,
              ets_mutations,
              trace_loss,
              supervisor_replacement
            ],
            &Map.fetch!(&1, :duration_us)
          )
        )
    }
  end

  defp probe_cast_without_id! do
    marker = "rampart-cast-without-id-marker"
    parent = self()
    {:ok, server} = CastServer.start_link(parent)

    clients =
      Enum.map(1..@cast_flow_count, fn _index ->
        spawn(fn -> cast_client(parent, server, marker) end)
      end)

    session = :trace.session_create(:rampart_iast_cast_without_id_probe, self(), [])
    started_at = System.monotonic_time()

    try do
      message = {:"$gen_cast", {:probe_cast_without_id, marker}}
      1 = :trace.send(session, [{[server, message], [], []}], [])
      1 = :trace.recv(session, [{[:_, :_, message], [], []}], [])

      Enum.each(clients, fn client ->
        1 = :trace.process(session, client, true, [:send, :monotonic_timestamp])
      end)

      1 = :trace.process(session, server, true, [:receive, :monotonic_timestamp])
      Enum.each(clients, &send(&1, :dispatch))
      deadline = deadline()

      state =
        collect_until(cast_state(), deadline, &cast_execution_complete?/1, &record_cast/2)

      delivery_refs = Enum.map([server | clients], &:trace.delivered(session, &1))

      state =
        collect_until(
          state,
          deadline,
          &cast_trace_complete?(&1, delivery_refs),
          &record_cast/2
        )

      %{
        status: :ambiguous,
        flow_count: @cast_flow_count,
        send_event_count: length(state.sends),
        receive_event_count: length(state.receives),
        acknowledged_count: state.acknowledged,
        joined_edge_count: 0,
        false_join_count: 0,
        candidate_pair_count: length(state.sends) * length(state.receives),
        unique_edge_count: 0,
        correlation_basis: :none,
        reason: :native_cast_envelope_has_no_request_id,
        timestamp_order_accepted_as_provenance: false,
        value_equality_used_as_provenance: false,
        duration_us: elapsed_us(started_at)
      }
    after
      :trace.session_destroy(session)
      Enum.each(clients, &stop/1)
      if Process.alive?(server), do: GenServer.stop(server)
    end
  end

  defp cast_client(parent, server, marker) do
    receive do
      :dispatch ->
        :ok = CastServer.consume(server, marker)
        send(parent, {:rampart_adversarial_cast_client_done, self()})
        await_stop()
    after
      2_000 -> :ok
    end
  end

  defp cast_execution_complete?(state) do
    state.clients_done == @cast_flow_count and state.acknowledged == @cast_flow_count
  end

  defp cast_trace_complete?(state, delivery_refs) do
    delivered?(state, delivery_refs) and
      length(state.sends) == @cast_flow_count and
      length(state.receives) == @cast_flow_count
  end

  defp record_cast(
         state,
         {:trace_ts, sender, :send, message, receiver, timestamp}
       ) do
    %{state | sends: [{sender, receiver, message, timestamp} | state.sends]}
  end

  defp record_cast(
         state,
         {:trace_ts, receiver, :receive, message, timestamp}
       ) do
    %{state | receives: [{receiver, message, timestamp} | state.receives]}
  end

  defp record_cast(state, {:rampart_adversarial_cast_client_done, _client}) do
    %{state | clients_done: state.clients_done + 1}
  end

  defp record_cast(state, {:rampart_adversarial_cast_acknowledged, _marker}) do
    %{state | acknowledged: state.acknowledged + 1}
  end

  defp record_cast(state, message), do: record_delivery(state, message)

  defp probe_task_failures! do
    marker = "rampart-adversarial-task-marker"
    parent = self()
    owner = spawn(fn -> TaskFixture.owner(parent, marker) end)
    session = :trace.session_create(:rampart_iast_task_failure_probe, self(), [])
    started_at = System.monotonic_time()

    try do
      configure_task_failures!(session, owner, marker)
      send(owner, :dispatch)
      deadline = deadline()

      state =
        collect_until(task_state(), deadline, &(&1.owner_done == 1), &record_task_failure/2)

      delivery_ref = :trace.delivered(session, :all)

      state =
        collect_until(
          state,
          deadline,
          &task_failure_trace_complete?(&1, delivery_ref),
          &record_task_failure/2
        )

      outcomes_supported =
        state.crash_outcome == {:exit, :rampart_probe_task_failure} and
          is_nil(state.timeout_outcome) and is_nil(state.shutdown_outcome)

      correlated_failures = correlate_task_failures(state, owner, marker)

      %{
        status:
          if(outcomes_supported and correlated_failures == 2,
            do: :inconclusive,
            else: :incomplete
          ),
        flow_count: 2,
        handoff_send_event_count: length(state.handoff_sends),
        handoff_receive_event_count: length(state.handoff_receives),
        exit_events_complete: length(state.exits) >= 2,
        down_events_complete: length(state.downs) >= 2,
        correlated_failure_count: correlated_failures,
        joined_edge_count: 0,
        false_join_count: 0,
        crash_outcome: normalize_task_outcome(state.crash_outcome),
        timeout_outcome: normalize_task_outcome(state.timeout_outcome),
        shutdown_outcome: normalize_task_outcome(state.shutdown_outcome),
        confirmation_allowed: false,
        reason: :task_execution_did_not_return_marker,
        correlation_basis: :task_reference_and_spawn_lineage,
        value_equality_used_as_provenance: false,
        duration_us: elapsed_us(started_at)
      }
    after
      :trace.session_destroy(session)
      stop(owner)
    end
  end

  defp configure_task_failures!(session, owner, marker) do
    handoffs =
      Enum.map([:crash, :wait], fn function ->
        message = {owner, :_, :_, :_, {TaskFixture, function, [owner, marker]}}
        {[:_, message], [], []}
      end)

    1 = :trace.send(session, handoffs, [])
    1 = :trace.recv(session, [{[:_, :_, :_], [], []}], [])

    1 =
      :trace.process(session, owner, true, [
        :procs,
        :send,
        :receive,
        :set_on_spawn,
        :monotonic_timestamp
      ])

    :ok
  end

  defp record_task_failure(
         state,
         {:trace_ts, parent, :spawn, child, {Task.Supervised, :reply, _arguments}, _timestamp}
       ) do
    %{state | spawned: [{parent, child} | state.spawned]}
  end

  defp record_task_failure(
         state,
         {:trace_ts, owner, :send,
          {owner, reference, reference, _owners, {TaskFixture, function, [owner, marker]}} =
            message, child, timestamp}
       )
       when function in [:crash, :wait] do
    event = {reference, function, marker, owner, child, message, timestamp}
    %{state | handoff_sends: [event | state.handoff_sends]}
  end

  defp record_task_failure(
         state,
         {:trace_ts, child, :receive,
          {_owner, reference, reference, _owners,
           {TaskFixture, function, [_owner_argument, marker]}} = message, timestamp}
       )
       when function in [:crash, :wait] do
    event = {reference, function, marker, child, message, timestamp}
    %{state | handoff_receives: [event | state.handoff_receives]}
  end

  defp record_task_failure(state, {:trace_ts, child, :exit, reason, timestamp}) do
    %{state | exits: [{child, reason, timestamp} | state.exits]}
  end

  defp record_task_failure(
         state,
         {:trace_ts, owner, :receive, {:DOWN, reference, :process, child, reason}, timestamp}
       ) do
    %{state | downs: [{reference, owner, child, reason, timestamp} | state.downs]}
  end

  defp record_task_failure(
         state,
         {:rampart_adversarial_task_owner_done, crash_outcome, timeout_outcome, shutdown_outcome}
       ) do
    %{
      state
      | owner_done: state.owner_done + 1,
        crash_outcome: crash_outcome,
        timeout_outcome: timeout_outcome,
        shutdown_outcome: shutdown_outcome
    }
  end

  defp record_task_failure(state, message), do: record_delivery(state, message)

  defp task_failure_trace_complete?(state, delivery_ref) do
    delivered?(state, [delivery_ref]) and
      length(state.handoff_sends) == 2 and length(state.handoff_receives) == 2 and
      length(state.exits) >= 2
  end

  defp correlate_task_failures(state, owner, marker) do
    receives = Enum.group_by(state.handoff_receives, &elem(&1, 0))
    spawned = MapSet.new(state.spawned)

    Enum.count(state.handoff_sends, fn
      {reference, function, ^marker, ^owner, child, message, sent_at} ->
        expected_reason = if function == :crash, do: :rampart_probe_task_failure, else: :killed

        with [{^reference, ^function, ^marker, ^child, ^message, received_at}] <-
               Map.get(receives, reference, []),
             [{^child, ^expected_reason, exited_at}] <-
               Enum.filter(state.exits, &(elem(&1, 0) == child)) do
          MapSet.member?(spawned, {owner, child}) and sent_at <= received_at and
            received_at <= exited_at
        else
          _unjoinable -> false
        end
    end)
  end

  defp normalize_task_outcome({:exit, reason}), do: {:exit, reason}
  defp normalize_task_outcome(nil), do: :no_result
  defp normalize_task_outcome(_other), do: :unexpected_result

  defp probe_ets_mutations! do
    marker = "rampart-adversarial-ets-marker"
    parent = self()
    table = :ets.new(:rampart_adversarial_ets_probe, [:set, :public])

    writers =
      Enum.map(1..@ets_writer_count, fn id ->
        spawn(fn -> overwrite_writer(parent, table, id, marker) end)
      end)

    session = :trace.session_create(:rampart_iast_ets_mutation_probe, self(), [])
    started_at = System.monotonic_time()

    try do
      match_spec = [{[table, :_], [], [{:return_trace}]}]
      1 = :trace.function(session, {:ets, :insert, 2}, match_spec, [])
      1 = :trace.function(session, {:ets, :delete, 2}, match_spec, [])
      1 = :trace.function(session, {:ets, :lookup, 2}, match_spec, [])

      Enum.each(writers, fn writer ->
        1 = :trace.process(session, writer, true, [:call, :monotonic_timestamp])
      end)

      Enum.each(writers, &send(&1, :dispatch))
      deadline = deadline()

      state =
        collect_until(
          ets_state(),
          deadline,
          &(&1.writers_done == @ets_writer_count),
          &record_ets/2
        )

      [{@ets_key, {winning_write_id, ^marker}}] = :ets.lookup(table, @ets_key)
      true = :ets.delete(table, @ets_key)
      deleted_read = :ets.lookup(table, @ets_key)
      delivery_refs = Enum.map(writers, &:trace.delivered(session, &1))

      state =
        collect_until(
          state,
          deadline,
          &ets_trace_complete?(&1, delivery_refs),
          &record_ets/2
        )

      %{
        status: :conditional,
        writer_count: @ets_writer_count,
        insert_call_count: length(state.insert_calls),
        insert_return_count: length(state.insert_returns),
        winning_write_id_present: winning_write_id in 1..@ets_writer_count,
        explicit_version_join_count: 1,
        projected_marker_candidate_count: @ets_writer_count,
        projected_marker_unique_edge_count: 0,
        overwrite_status: :ambiguous_without_write_version,
        delete_status: if(deleted_read == [], do: :terminated, else: :incomplete),
        joined_edge_count: 0,
        false_join_count: 0,
        confirmation_allowed_without_write_version: false,
        temporal_order_accepted_as_provenance: false,
        correlation_basis: :explicit_write_version_only,
        value_equality_used_as_provenance: false,
        duration_us: elapsed_us(started_at)
      }
    after
      :trace.session_destroy(session)
      Enum.each(writers, &stop/1)
      :ets.delete(table)
    end
  end

  defp overwrite_writer(parent, table, id, marker) do
    receive do
      :dispatch ->
        true = :ets.insert(table, {@ets_key, {id, marker}})
        send(parent, {:rampart_adversarial_ets_writer_done, self()})
        await_stop()
    after
      2_000 -> :ok
    end
  end

  defp record_ets(
         state,
         {:trace_ts, process, :call, {:ets, :insert, [_table, {@ets_key, {id, marker}}]},
          timestamp}
       ) do
    %{state | insert_calls: [{process, id, marker, timestamp} | state.insert_calls]}
  end

  defp record_ets(
         state,
         {:trace_ts, process, :return_from, {:ets, :insert, 2}, result, timestamp}
       ) do
    %{state | insert_returns: [{process, result, timestamp} | state.insert_returns]}
  end

  defp record_ets(state, {:rampart_adversarial_ets_writer_done, _writer}) do
    %{state | writers_done: state.writers_done + 1}
  end

  defp record_ets(state, message), do: record_delivery(state, message)

  defp ets_trace_complete?(state, delivery_refs) do
    delivered?(state, delivery_refs) and
      length(state.insert_calls) == @ets_writer_count and
      length(state.insert_returns) == @ets_writer_count
  end

  defp probe_trace_loss! do
    marker = "rampart-injected-trace-loss-marker"
    parent = self()
    receiver = spawn(fn -> loss_receiver(parent, @event_loss_flow_count) end)
    sender = spawn(fn -> loss_sender(parent, receiver, marker) end)
    session = :trace.session_create(:rampart_iast_injected_trace_loss_probe, self(), [])
    started_at = System.monotonic_time()

    try do
      message = {@event_loss_tag, :_, marker}
      1 = :trace.send(session, [{[receiver, message], [], []}], [])
      1 = :trace.recv(session, [{[:_, :_, message], [], []}], [])
      1 = :trace.process(session, sender, true, [:send, :monotonic_timestamp])
      1 = :trace.process(session, receiver, true, [:receive, :monotonic_timestamp])
      send(sender, :dispatch)
      deadline = deadline()

      state =
        collect_until(loss_state(), deadline, &loss_execution_complete?/1, &record_loss/2)

      delivery_refs = Enum.map([sender, receiver], &:trace.delivered(session, &1))

      state =
        collect_until(
          state,
          deadline,
          &loss_trace_complete?(&1, delivery_refs),
          &record_loss/2
        )

      supportable_edges =
        state.sends
        |> MapSet.new()
        |> MapSet.intersection(MapSet.new(state.receives))
        |> MapSet.size()

      %{
        status: :incomplete,
        expected_event_count: @event_loss_flow_count,
        send_event_count: length(state.sends),
        receive_event_count: length(state.receives),
        acknowledged_count: state.acknowledged,
        injected_dropped_event_count: state.dropped,
        supportable_edge_count: supportable_edges,
        joined_edge_count: 0,
        false_join_count: 0,
        delivery_barrier_completed: delivered?(state, delivery_refs),
        confirmation_allowed: false,
        reason: :injected_receive_event_loss,
        duration_us: elapsed_us(started_at)
      }
    after
      :trace.session_destroy(session)
      stop(sender)
      stop(receiver)
    end
  end

  defp loss_sender(parent, receiver, marker) do
    receive do
      :dispatch ->
        Enum.each(1..@event_loss_flow_count, fn id ->
          send(receiver, {@event_loss_tag, id, marker})
        end)

        send(parent, :rampart_adversarial_loss_sender_done)
        await_stop()
    after
      2_000 -> :ok
    end
  end

  defp loss_receiver(parent, remaining) when remaining > 0 do
    receive do
      {@event_loss_tag, id, marker} ->
        send(parent, {:rampart_adversarial_loss_acknowledged, id, marker})
        loss_receiver(parent, remaining - 1)
    after
      2_000 -> :ok
    end
  end

  defp loss_receiver(_parent, 0), do: await_stop()

  defp loss_execution_complete?(state) do
    state.sender_done == 1 and state.acknowledged == @event_loss_flow_count
  end

  defp loss_trace_complete?(state, delivery_refs) do
    delivered?(state, delivery_refs) and
      length(state.sends) == @event_loss_flow_count and
      length(state.receives) == @event_loss_flow_count - 1 and state.dropped == 1
  end

  defp record_loss(
         state,
         {:trace_ts, _sender, :send, {@event_loss_tag, id, _marker}, _receiver, _timestamp}
       ) do
    %{state | sends: [id | state.sends]}
  end

  defp record_loss(
         %{dropped: 0} = state,
         {:trace_ts, _receiver, :receive, {@event_loss_tag, _id, _marker}, _timestamp}
       ) do
    %{state | dropped: 1}
  end

  defp record_loss(
         state,
         {:trace_ts, _receiver, :receive, {@event_loss_tag, id, _marker}, _timestamp}
       ) do
    %{state | receives: [id | state.receives]}
  end

  defp record_loss(state, {:rampart_adversarial_loss_acknowledged, _id, _marker}) do
    %{state | acknowledged: state.acknowledged + 1}
  end

  defp record_loss(state, :rampart_adversarial_loss_sender_done) do
    %{state | sender_done: state.sender_done + 1}
  end

  defp record_loss(state, message), do: record_delivery(state, message)

  defp probe_supervisor_replacement! do
    marker = "rampart-supervisor-replacement-marker"
    {:ok, supervisor} = ReplacementSupervisor.start_link(self())
    old_worker = replacement_worker(supervisor)
    session = :trace.session_create(:rampart_iast_supervisor_replacement_probe, self(), [])
    started_at = System.monotonic_time()

    try do
      store_message = {:"$gen_call", :_, {:store, marker}}
      1 = :trace.recv(session, [{[:_, :_, store_message], [], []}], [])

      1 =
        :trace.process(session, supervisor, true, [
          :procs,
          :set_on_spawn,
          :monotonic_timestamp
        ])

      1 = :trace.process(session, old_worker, true, [:procs, :receive, :monotonic_timestamp])
      :ok = ReplacementWorker.store(old_worker, marker)
      ^marker = ReplacementWorker.read(old_worker)
      :ok = GenServer.stop(old_worker, :normal)
      new_worker = await_replacement_worker(supervisor, old_worker, deadline())
      replacement_value = ReplacementWorker.read(new_worker)
      delivery_ref = :trace.delivered(session, :all)

      state =
        collect_until(
          replacement_state(),
          deadline(),
          &replacement_trace_complete?(&1, delivery_ref, supervisor, old_worker, new_worker),
          &record_replacement/2
        )

      %{
        status: if(is_nil(replacement_value), do: :terminated, else: :incomplete),
        old_and_new_worker_distinct: old_worker != new_worker,
        store_receive_event_count: state.store_receives,
        old_worker_exit_observed: Enum.any?(state.exits, &match?({^old_worker, :normal}, &1)),
        replacement_spawn_observed:
          Enum.any?(state.spawns, &match?({^supervisor, ^new_worker}, &1)),
        replacement_value_present: not is_nil(replacement_value),
        joined_edge_count: 0,
        false_join_count: 0,
        confirmation_allowed_across_replacement: false,
        correlation_basis: :process_identity_terminates_at_exit,
        reason: :worker_state_not_transferred_by_supervision,
        external_state_transfer_covered: false,
        value_equality_used_as_provenance: false,
        duration_us: elapsed_us(started_at)
      }
    after
      :trace.session_destroy(session)
      if Process.alive?(supervisor), do: Supervisor.stop(supervisor)
    end
  end

  defp replacement_worker(supervisor) do
    case Supervisor.which_children(supervisor) do
      [{ReplacementWorker, worker, :worker, [ReplacementWorker]}] when is_pid(worker) -> worker
      _children -> exit(:replacement_worker_not_found)
    end
  end

  defp await_replacement_worker(supervisor, old_worker, deadline) do
    worker = replacement_worker(supervisor)

    cond do
      worker != old_worker ->
        worker

      System.monotonic_time(:millisecond) >= deadline ->
        exit(:replacement_worker_timeout)

      true ->
        Process.sleep(1)
        await_replacement_worker(supervisor, old_worker, deadline)
    end
  end

  defp record_replacement(
         state,
         {:trace_ts, _worker, :receive, {:"$gen_call", _from, {:store, _marker}}, _timestamp}
       ) do
    %{state | store_receives: state.store_receives + 1}
  end

  defp record_replacement(state, {:trace_ts, process, :exit, reason, _timestamp}) do
    %{state | exits: [{process, reason} | state.exits]}
  end

  defp record_replacement(
         state,
         {:trace_ts, parent, :spawn, child, {:proc_lib, :init_p, _arguments}, _timestamp}
       ) do
    %{state | spawns: [{parent, child} | state.spawns]}
  end

  defp record_replacement(state, message), do: record_delivery(state, message)

  defp replacement_trace_complete?(state, delivery_ref, supervisor, old_worker, new_worker) do
    delivered?(state, [delivery_ref]) and state.store_receives == 1 and
      Enum.any?(state.exits, &match?({^old_worker, :normal}, &1)) and
      Enum.any?(state.spawns, &match?({^supervisor, ^new_worker}, &1))
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
          summary =
            Map.new(state, fn
              {key, value} when is_list(value) -> {key, length(value)}
              {key, %MapSet{} = value} -> {key, MapSet.size(value)}
              pair -> pair
            end)

          raise "adversarial cross-process probe timed out: #{inspect(summary)}"
      end
    end
  end

  defp record_delivery(state, {:trace_delivered, _tracee, reference}) do
    %{state | delivered: MapSet.put(state.delivered, reference)}
  end

  defp record_delivery(state, _other), do: state

  defp delivered?(state, references), do: state.delivered == MapSet.new(references)

  defp cast_state do
    %{sends: [], receives: [], clients_done: 0, acknowledged: 0, delivered: MapSet.new()}
  end

  defp task_state do
    %{
      spawned: [],
      handoff_sends: [],
      handoff_receives: [],
      exits: [],
      downs: [],
      owner_done: 0,
      crash_outcome: nil,
      timeout_outcome: nil,
      shutdown_outcome: nil,
      delivered: MapSet.new()
    }
  end

  defp ets_state do
    %{insert_calls: [], insert_returns: [], writers_done: 0, delivered: MapSet.new()}
  end

  defp loss_state do
    %{
      sends: [],
      receives: [],
      acknowledged: 0,
      sender_done: 0,
      dropped: 0,
      delivered: MapSet.new()
    }
  end

  defp replacement_state do
    %{store_receives: 0, exits: [], spawns: [], delivered: MapSet.new()}
  end

  defp deadline, do: System.monotonic_time(:millisecond) + @probe_timeout_ms

  defp elapsed_us(started_at) do
    System.convert_time_unit(System.monotonic_time() - started_at, :native, :microsecond)
  end

  defp await_stop do
    receive do
      :stop -> :ok
    after
      2_000 -> :ok
    end
  end

  defp stop(process) do
    if Process.alive?(process), do: Process.exit(process, :kill)
  end
end
