defmodule RampartEvaluation.CrossProcessProbe.Server do
  @moduledoc false
  use GenServer

  def start_link(owner), do: GenServer.start_link(__MODULE__, owner)
  def consume(server, marker), do: GenServer.call(server, {:probe, marker})
  def consume_cast(server, id, marker), do: GenServer.cast(server, {:probe_cast, id, marker})

  @impl true
  def init(owner), do: {:ok, owner}

  @impl true
  def handle_call({:probe, marker}, _from, owner), do: {:reply, marker, owner}

  @impl true
  def handle_cast({:probe_cast, id, marker}, owner) do
    send(owner, {:rampart_probe_cast_acknowledged, id, marker})
    {:noreply, owner}
  end
end

defmodule RampartEvaluation.CrossProcessProbe.TaskFixture do
  @moduledoc false

  @spec run(String.t()) :: String.t()
  def run(marker), do: marker

  @spec owner(pid(), String.t(), pos_integer()) :: :ok
  def owner(probe, marker, flow_count) do
    receive do
      :dispatch ->
        tasks =
          Enum.map(1..flow_count, fn _index ->
            Task.async(__MODULE__, :run, [marker])
          end)

        results = Enum.map(tasks, &Task.await/1)
        send(probe, {:rampart_probe_task_owner_done, self(), results})
        await_stop()
    after
      2_000 -> :ok
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

defmodule RampartEvaluation.CrossProcessProbe do
  @moduledoc false

  alias RampartEvaluation.CrossProcessProbe.{Server, TaskFixture}

  @message_tag :rampart_cross_process_probe
  @process_dictionary_tag :rampart_process_dictionary_probe
  @flow_count 8
  @sender_count 4
  @otp_flow_count 4
  @probe_timeout_ms 3_000

  @spec run!() :: map()
  def run! do
    direct = probe_direct_message!()
    gen_server_call = probe_gen_server_call!()
    gen_server_cast = probe_gen_server_cast!()
    task_async = probe_task_async!()
    ets = probe_ets!()
    process_dictionary = probe_process_dictionary!()
    adversarial = RampartEvaluation.CrossProcessAdversarialProbe.run!()
    frontier = RampartEvaluation.CrossProcessFrontierProbe.run!()

    supported = [direct, gen_server_call, gen_server_cast, task_async, ets]

    %{
      schema_version: 3,
      scenario: :cross_process_boundary_matrix,
      status:
        if(
          Enum.all?(supported, &(&1.status == :supported)) and
            process_dictionary.status == :incomplete and
            adversarial.status == :fail_closed and frontier.status == :supported,
          do: :partial,
          else: :incomplete
        ),
      direct_message: direct,
      gen_server_call: gen_server_call,
      gen_server_cast: gen_server_cast,
      task_async: task_async,
      ets: ets,
      process_dictionary: process_dictionary,
      adversarial: adversarial,
      frontier: frontier,
      duration_us:
        Enum.sum(
          Enum.map(
            supported ++ [process_dictionary, adversarial, frontier],
            &Map.fetch!(&1, :duration_us)
          )
        ),
      unresolved_boundaries: [
        :process_dictionary_targeted_read,
        :distributed_handoff_without_explicit_envelope
      ]
    }
  end

  defp probe_direct_message! do
    marker = "rampart-cross-process-feasibility-marker"
    parent = self()
    receiver = spawn(fn -> receive_flows(parent, @flow_count) end)
    flows = Enum.map(1..@flow_count, &{&1, marker})

    senders =
      flows
      |> Enum.chunk_every(div(@flow_count, @sender_count))
      |> Enum.map(fn assigned -> spawn(fn -> send_flows(parent, receiver, assigned) end) end)

    session = :trace.session_create(:rampart_iast_cross_process_probe, self(), [])
    started_at = System.monotonic_time()

    try do
      configure_direct!(session, receiver, senders, marker)
      Enum.each(senders, &send(&1, :dispatch))
      deadline = deadline()

      state =
        collect_until(direct_state(), deadline, &direct_execution_complete?/1, &record_direct/2)

      delivery_refs = Enum.map([receiver | senders], &:trace.delivered(session, &1))

      state =
        collect_until(
          state,
          deadline,
          &direct_trace_complete?(&1, delivery_refs),
          &record_direct/2
        )

      summarize_direct(state, marker, started_at)
    after
      :trace.session_destroy(session)
      Enum.each([receiver | senders], &stop/1)
    end
  end

  defp configure_direct!(session, receiver, senders, marker) do
    1 =
      :trace.send(
        session,
        [{[receiver, {@message_tag, :_, marker}], [], []}],
        []
      )

    1 =
      :trace.recv(
        session,
        [{[:_, :_, {@message_tag, :_, marker}], [], []}],
        []
      )

    Enum.each(senders, fn sender ->
      1 = :trace.process(session, sender, true, [:send, :monotonic_timestamp])
    end)

    1 = :trace.process(session, receiver, true, [:receive, :monotonic_timestamp])
    :ok
  end

  defp send_flows(parent, receiver, flows) do
    receive do
      :dispatch ->
        Enum.each(flows, fn {id, marker} ->
          send(receiver, {@message_tag, id, marker})
        end)

        send(parent, {:rampart_probe_sender_done, self()})
        await_stop()
    after
      2_000 -> :ok
    end
  end

  defp receive_flows(parent, remaining) when remaining > 0 do
    receive do
      {@message_tag, id, marker} ->
        send(parent, {:rampart_probe_acknowledged, id, marker})
        receive_flows(parent, remaining - 1)
    after
      2_000 -> :ok
    end
  end

  defp receive_flows(_parent, 0), do: await_stop()

  defp direct_execution_complete?(state) do
    state.acknowledged == @flow_count and state.senders_done == @sender_count
  end

  defp direct_trace_complete?(state, delivery_refs) do
    delivered?(state, delivery_refs) and
      length(state.sends) == @flow_count and length(state.receives) == @flow_count
  end

  defp record_direct(
         state,
         {:trace_ts, sender, :send, {@message_tag, id, marker}, receiver, timestamp}
       ) do
    %{state | sends: [{id, marker, sender, receiver, timestamp} | state.sends]}
  end

  defp record_direct(
         state,
         {:trace_ts, receiver, :receive, {@message_tag, id, marker}, timestamp}
       ) do
    %{state | receives: [{id, marker, receiver, timestamp} | state.receives]}
  end

  defp record_direct(state, {:rampart_probe_acknowledged, _id, _marker}) do
    %{state | acknowledged: state.acknowledged + 1}
  end

  defp record_direct(state, {:rampart_probe_sender_done, _sender}) do
    %{state | senders_done: state.senders_done + 1}
  end

  defp record_direct(state, message), do: record_delivery(state, message)

  defp summarize_direct(state, marker, started_at) do
    send_groups = Enum.group_by(state.sends, &elem(&1, 0))
    receive_groups = Enum.group_by(state.receives, &elem(&1, 0))
    ids = Enum.to_list(1..@flow_count)

    joined =
      Enum.count(ids, fn id ->
        with [{^id, ^marker, _sender, recipient, sent_at}] <- Map.get(send_groups, id, []),
             [{^id, ^marker, receiver, received_at}] <- Map.get(receive_groups, id, []) do
          recipient == receiver and sent_at <= received_at
        else
          _unjoinable -> false
        end
      end)

    false_joins = duplicate_or_missing_edges(ids, send_groups, receive_groups, joined)

    %{
      status: if(joined == @flow_count and false_joins == 0, do: :supported, else: :incomplete),
      scenario: :direct_message_with_explicit_envelope,
      flow_count: @flow_count,
      sender_count: @sender_count,
      distinct_marker_count: 1,
      send_event_count: length(state.sends),
      receive_event_count: length(state.receives),
      joined_edge_count: joined,
      false_join_count: false_joins,
      correlation_basis: :explicit_message_envelope,
      application_envelope_id_required: true,
      value_equality_used_as_provenance: false,
      value_only_candidate_pair_count: length(state.sends) * length(state.receives),
      value_only_unique_edge_count: 0,
      duration_us: elapsed_us(started_at)
    }
  end

  defp probe_gen_server_call! do
    marker = "rampart-gen-server-call-feasibility-marker"
    parent = self()
    {:ok, server} = Server.start_link(parent)

    clients =
      Enum.map(1..@otp_flow_count, fn _index ->
        spawn(fn -> gen_server_call_client(parent, server, marker) end)
      end)

    session = :trace.session_create(:rampart_iast_gen_server_call_probe, self(), [])
    started_at = System.monotonic_time()

    try do
      configure_gen_server_call!(session, server, clients, marker)
      Enum.each(clients, &send(&1, :dispatch))
      deadline = deadline()

      state =
        collect_until(
          gen_server_message_state(),
          deadline,
          &(&1.clients_done == @otp_flow_count),
          &record_gen_server_call/2
        )

      delivery_refs = Enum.map([server | clients], &:trace.delivered(session, &1))

      state =
        collect_until(
          state,
          deadline,
          &gen_server_trace_complete?(&1, delivery_refs),
          &record_gen_server_call/2
        )

      summarize_gen_server_call(state, server, started_at)
    after
      :trace.session_destroy(session)
      Enum.each(clients, &stop/1)
      if Process.alive?(server), do: GenServer.stop(server)
    end
  end

  defp configure_gen_server_call!(session, server, clients, marker) do
    message = {:"$gen_call", :_, {:probe, marker}}
    1 = :trace.send(session, [{[server, message], [], []}], [])
    1 = :trace.recv(session, [{[:_, :_, message], [], []}], [])

    Enum.each(clients, fn client ->
      1 = :trace.process(session, client, true, [:send, :monotonic_timestamp])
    end)

    1 = :trace.process(session, server, true, [:receive, :monotonic_timestamp])
    :ok
  end

  defp gen_server_call_client(parent, server, marker) do
    receive do
      :dispatch ->
        ^marker = Server.consume(server, marker)
        send(parent, {:rampart_probe_client_done, self()})
        await_stop()
    after
      2_000 -> :ok
    end
  end

  defp record_gen_server_call(
         state,
         {:trace_ts, sender, :send, {:"$gen_call", _from, {:probe, _marker}} = message, receiver,
          timestamp}
       ) do
    %{state | sends: [{message, sender, receiver, timestamp} | state.sends]}
  end

  defp record_gen_server_call(
         state,
         {:trace_ts, receiver, :receive, {:"$gen_call", _from, {:probe, _marker}} = message,
          timestamp}
       ) do
    %{state | receives: [{message, receiver, timestamp} | state.receives]}
  end

  defp record_gen_server_call(state, {:rampart_probe_client_done, _client}) do
    %{state | clients_done: state.clients_done + 1}
  end

  defp record_gen_server_call(state, message), do: record_delivery(state, message)

  defp summarize_gen_server_call(state, server, started_at) do
    summary = summarize_message_edges(state, server, @otp_flow_count)

    Map.merge(summary, %{
      status:
        if(summary.joined_edge_count == @otp_flow_count and summary.false_join_count == 0,
          do: :supported,
          else: :incomplete
        ),
      scenario: :gen_server_call,
      correlation_basis: :otp_call_alias_envelope,
      application_envelope_id_required: false,
      value_equality_used_as_provenance: false,
      duration_us: elapsed_us(started_at)
    })
  end

  defp probe_gen_server_cast! do
    marker = "rampart-gen-server-cast-feasibility-marker"
    parent = self()
    {:ok, server} = Server.start_link(parent)

    clients =
      Enum.map(1..@otp_flow_count, fn id ->
        spawn(fn -> gen_server_cast_client(parent, server, id, marker) end)
      end)

    session = :trace.session_create(:rampart_iast_gen_server_cast_probe, self(), [])
    started_at = System.monotonic_time()

    try do
      configure_gen_server_cast!(session, server, clients, marker)
      Enum.each(clients, &send(&1, :dispatch))
      deadline = deadline()

      state =
        collect_until(
          gen_server_cast_state(),
          deadline,
          &cast_execution_complete?/1,
          &record_gen_server_cast/2
        )

      delivery_refs = Enum.map([server | clients], &:trace.delivered(session, &1))

      state =
        collect_until(
          state,
          deadline,
          &gen_server_trace_complete?(&1, delivery_refs),
          &record_gen_server_cast/2
        )

      summarize_gen_server_cast(state, server, marker, started_at)
    after
      :trace.session_destroy(session)
      Enum.each(clients, &stop/1)
      if Process.alive?(server), do: GenServer.stop(server)
    end
  end

  defp configure_gen_server_cast!(session, server, clients, marker) do
    message = {:"$gen_cast", {:probe_cast, :_, marker}}
    1 = :trace.send(session, [{[server, message], [], []}], [])
    1 = :trace.recv(session, [{[:_, :_, message], [], []}], [])

    Enum.each(clients, fn client ->
      1 = :trace.process(session, client, true, [:send, :monotonic_timestamp])
    end)

    1 = :trace.process(session, server, true, [:receive, :monotonic_timestamp])
    :ok
  end

  defp gen_server_cast_client(parent, server, id, marker) do
    receive do
      :dispatch ->
        :ok = Server.consume_cast(server, id, marker)
        send(parent, {:rampart_probe_cast_client_done, self()})
        await_stop()
    after
      2_000 -> :ok
    end
  end

  defp cast_execution_complete?(state) do
    state.clients_done == @otp_flow_count and state.acknowledged == @otp_flow_count
  end

  defp record_gen_server_cast(
         state,
         {:trace_ts, sender, :send, {:"$gen_cast", {:probe_cast, id, marker}} = message, receiver,
          timestamp}
       ) do
    %{
      state
      | sends: [{message, sender, receiver, timestamp} | state.sends],
        marker: marker,
        ids: [id | state.ids]
    }
  end

  defp record_gen_server_cast(
         state,
         {:trace_ts, receiver, :receive, {:"$gen_cast", {:probe_cast, _id, _marker}} = message,
          timestamp}
       ) do
    %{state | receives: [{message, receiver, timestamp} | state.receives]}
  end

  defp record_gen_server_cast(state, {:rampart_probe_cast_client_done, _client}) do
    %{state | clients_done: state.clients_done + 1}
  end

  defp record_gen_server_cast(state, {:rampart_probe_cast_acknowledged, _id, _marker}) do
    %{state | acknowledged: state.acknowledged + 1}
  end

  defp record_gen_server_cast(state, message), do: record_delivery(state, message)

  defp summarize_gen_server_cast(state, server, marker, started_at) do
    summary = summarize_message_edges(state, server, @otp_flow_count)
    ids = Enum.uniq(state.ids)

    Map.merge(summary, %{
      status:
        if(
          summary.joined_edge_count == @otp_flow_count and summary.false_join_count == 0 and
            length(ids) == @otp_flow_count and state.marker == marker,
          do: :supported,
          else: :incomplete
        ),
      scenario: :gen_server_cast_with_explicit_application_envelope,
      correlation_basis: :explicit_application_request_id,
      otp_correlation_id_present: false,
      application_envelope_id_required: true,
      value_equality_used_as_provenance: false,
      value_only_candidate_pair_count: length(state.sends) * length(state.receives),
      value_only_unique_edge_count: 0,
      duration_us: elapsed_us(started_at)
    })
  end

  defp probe_task_async! do
    marker = "rampart-task-feasibility-marker"
    parent = self()
    owner = spawn(fn -> TaskFixture.owner(parent, marker, @otp_flow_count) end)
    session = :trace.session_create(:rampart_iast_task_probe, self(), [])
    started_at = System.monotonic_time()

    try do
      configure_task!(session, owner, marker)
      send(owner, :dispatch)
      deadline = deadline()

      state =
        collect_until(
          task_state(),
          deadline,
          &(&1.owner_done == 1),
          &record_task/2
        )

      delivery_ref = :trace.delivered(session, :all)

      state =
        collect_until(
          state,
          deadline,
          &task_trace_complete?(&1, delivery_ref),
          &record_task/2
        )

      summarize_task(state, owner, marker, started_at)
    after
      :trace.session_destroy(session)
      stop(owner)
    end
  end

  defp configure_task!(session, owner, marker) do
    handoff = {owner, :_, :_, :_, {TaskFixture, :run, [marker]}}
    result = {:_, marker}

    1 =
      :trace.send(
        session,
        [
          {[:_, handoff], [], []},
          {[:_, result], [], []}
        ],
        []
      )

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

  defp record_task(
         state,
         {:trace_ts, parent, :spawn, child, {Task.Supervised, :reply, _arguments}, _timestamp}
       ) do
    %{state | spawned: [{parent, child} | state.spawned]}
  end

  defp record_task(
         state,
         {:trace_ts, owner, :send,
          {owner, reference, reference, _owners, {TaskFixture, :run, [marker]}} = message, child,
          timestamp}
       ) do
    event = {reference, marker, owner, child, message, timestamp}
    %{state | handoff_sends: [event | state.handoff_sends]}
  end

  defp record_task(
         state,
         {:trace_ts, child, :receive,
          {_owner, reference, reference, _owners, {TaskFixture, :run, [marker]}} = message,
          timestamp}
       ) do
    event = {reference, marker, child, message, timestamp}
    %{state | handoff_receives: [event | state.handoff_receives]}
  end

  defp record_task(
         state,
         {:trace_ts, child, :send, {reference, marker} = message, reference, timestamp}
       ) do
    event = {reference, marker, child, message, timestamp}
    %{state | result_sends: [event | state.result_sends]}
  end

  defp record_task(
         state,
         {:trace_ts, owner, :receive, {reference, marker} = message, timestamp}
       ) do
    event = {reference, marker, owner, message, timestamp}
    %{state | result_receives: [event | state.result_receives]}
  end

  defp record_task(state, {:rampart_probe_task_owner_done, _owner, results}) do
    %{state | owner_done: state.owner_done + 1, results: results}
  end

  defp record_task(state, message), do: record_delivery(state, message)

  defp task_trace_complete?(state, delivery_ref) do
    delivered?(state, [delivery_ref]) and
      length(state.handoff_sends) == @otp_flow_count and
      length(state.handoff_receives) == @otp_flow_count and
      length(state.result_sends) == @otp_flow_count and
      length(state.result_receives) == @otp_flow_count
  end

  defp summarize_task(state, owner, marker, started_at) do
    handoff_sends = Enum.group_by(state.handoff_sends, &elem(&1, 0))
    handoff_receives = Enum.group_by(state.handoff_receives, &elem(&1, 0))
    result_sends = Enum.group_by(state.result_sends, &elem(&1, 0))
    result_receives = Enum.group_by(state.result_receives, &elem(&1, 0))
    spawned = MapSet.new(state.spawned)
    references = Map.keys(handoff_sends)

    joined =
      Enum.count(references, fn reference ->
        with [{^reference, ^marker, ^owner, child, handoff, handoff_sent_at}] <-
               Map.get(handoff_sends, reference, []),
             [{^reference, ^marker, ^child, ^handoff, handoff_received_at}] <-
               Map.get(handoff_receives, reference, []),
             [{^reference, ^marker, ^child, result, result_sent_at}] <-
               Map.get(result_sends, reference, []),
             [{^reference, ^marker, ^owner, ^result, result_received_at}] <-
               Map.get(result_receives, reference, []) do
          MapSet.member?(spawned, {owner, child}) and
            handoff_sent_at <= handoff_received_at and
            handoff_received_at <= result_sent_at and
            result_sent_at <= result_received_at
        else
          _unjoinable -> false
        end
      end)

    duplicate_references =
      Enum.count(references, fn reference ->
        Enum.any?(
          [handoff_sends, handoff_receives, result_sends, result_receives],
          &(length(Map.get(&1, reference, [])) != 1)
        )
      end)

    false_joins = @otp_flow_count - joined + duplicate_references

    %{
      status:
        if(joined == @otp_flow_count and false_joins == 0, do: :supported, else: :incomplete),
      scenario: :elixir_task_async_handoff,
      flow_count: @otp_flow_count,
      spawn_event_count: length(state.spawned),
      handoff_send_event_count: length(state.handoff_sends),
      handoff_receive_event_count: length(state.handoff_receives),
      result_send_event_count: length(state.result_sends),
      result_receive_event_count: length(state.result_receives),
      joined_edge_count: joined,
      false_join_count: false_joins,
      correlation_basis: :task_reference_and_spawn_lineage,
      implementation_scope: :elixir_task_async,
      application_envelope_id_required: false,
      value_equality_used_as_provenance: false,
      value_only_candidate_pair_count: @otp_flow_count * @otp_flow_count,
      value_only_unique_edge_count: 0,
      completed_result_count: Enum.count(state.results, &(&1 == marker)),
      duration_us: elapsed_us(started_at)
    }
  end

  defp probe_ets! do
    marker = "rampart-ets-feasibility-marker"
    parent = self()
    table = :ets.new(:rampart_cross_process_probe, [:set, :public])

    writers =
      Enum.map(1..@otp_flow_count, fn id ->
        spawn(fn -> ets_writer(parent, table, id, marker) end)
      end)

    readers =
      Enum.map(1..@otp_flow_count, fn id ->
        spawn(fn -> ets_reader(parent, table, id) end)
      end)

    session = :trace.session_create(:rampart_iast_ets_probe, self(), [])
    started_at = System.monotonic_time()

    try do
      configure_ets!(session, table, writers ++ readers)
      Enum.each(writers, &send(&1, :dispatch))
      deadline = deadline()

      state =
        collect_until(ets_state(), deadline, &(&1.writers_done == @otp_flow_count), &record_ets/2)

      Enum.each(readers, &send(&1, :dispatch))

      state =
        collect_until(
          state,
          deadline,
          &(&1.readers_done == @otp_flow_count),
          &record_ets/2
        )

      delivery_refs = Enum.map(writers ++ readers, &:trace.delivered(session, &1))

      state =
        collect_until(
          state,
          deadline,
          &ets_trace_complete?(&1, delivery_refs),
          &record_ets/2
        )

      summarize_ets(state, marker, started_at)
    after
      :trace.session_destroy(session)
      Enum.each(writers ++ readers, &stop/1)
      :ets.delete(table)
    end
  end

  defp configure_ets!(session, table, processes) do
    match_spec = [{[table, :_], [], [{:return_trace}]}]
    1 = :trace.function(session, {:ets, :insert, 2}, match_spec, [])
    1 = :trace.function(session, {:ets, :lookup, 2}, match_spec, [])

    Enum.each(processes, fn process ->
      1 = :trace.process(session, process, true, [:call, :monotonic_timestamp])
    end)

    :ok
  end

  defp ets_writer(parent, table, id, marker) do
    receive do
      :dispatch ->
        true = :ets.insert(table, {id, marker})
        send(parent, {:rampart_probe_ets_writer_done, self()})
        await_stop()
    after
      2_000 -> :ok
    end
  end

  defp ets_reader(parent, table, id) do
    receive do
      :dispatch ->
        result = :ets.lookup(table, id)
        send(parent, {:rampart_probe_ets_reader_done, self(), id, result})
        await_stop()
    after
      2_000 -> :ok
    end
  end

  defp record_ets(
         state,
         {:trace_ts, process, :call, {:ets, :insert, [_table, {id, marker}]}, timestamp}
       ) do
    %{state | write_calls: [{process, id, marker, timestamp} | state.write_calls]}
  end

  defp record_ets(
         state,
         {:trace_ts, process, :return_from, {:ets, :insert, 2}, result, timestamp}
       ) do
    %{state | write_returns: [{process, result, timestamp} | state.write_returns]}
  end

  defp record_ets(
         state,
         {:trace_ts, process, :call, {:ets, :lookup, [_table, id]}, timestamp}
       ) do
    %{state | read_calls: [{process, id, timestamp} | state.read_calls]}
  end

  defp record_ets(
         state,
         {:trace_ts, process, :return_from, {:ets, :lookup, 2}, result, timestamp}
       ) do
    %{state | read_returns: [{process, result, timestamp} | state.read_returns]}
  end

  defp record_ets(state, {:rampart_probe_ets_writer_done, _writer}) do
    %{state | writers_done: state.writers_done + 1}
  end

  defp record_ets(state, {:rampart_probe_ets_reader_done, _reader, id, result}) do
    %{
      state
      | readers_done: state.readers_done + 1,
        observed_results: [{id, result} | state.observed_results]
    }
  end

  defp record_ets(state, message), do: record_delivery(state, message)

  defp ets_trace_complete?(state, delivery_refs) do
    delivered?(state, delivery_refs) and
      Enum.all?(
        [state.write_calls, state.write_returns, state.read_calls, state.read_returns],
        &(length(&1) == @otp_flow_count)
      )
  end

  defp summarize_ets(state, marker, started_at) do
    ids = Enum.to_list(1..@otp_flow_count)

    joined =
      Enum.count(ids, fn id ->
        with [{writer, ^id, ^marker, write_at}] <-
               Enum.filter(state.write_calls, &(elem(&1, 1) == id)),
             [{^writer, true, write_return_at}] <-
               Enum.filter(state.write_returns, &(elem(&1, 0) == writer)),
             [{reader, ^id, read_at}] <- Enum.filter(state.read_calls, &(elem(&1, 1) == id)),
             [{^reader, [{^id, ^marker}], read_return_at}] <-
               Enum.filter(state.read_returns, &(elem(&1, 0) == reader)),
             [{^id, [{^id, ^marker}]}] <-
               Enum.filter(state.observed_results, &(elem(&1, 0) == id)) do
          write_at <= write_return_at and write_return_at <= read_at and read_at <= read_return_at
        else
          _unjoinable -> false
        end
      end)

    event_count =
      Enum.sum(
        Enum.map(
          [state.write_calls, state.write_returns, state.read_calls, state.read_returns],
          &length/1
        )
      )

    false_joins = @otp_flow_count - joined

    %{
      status:
        if(joined == @otp_flow_count and false_joins == 0, do: :supported, else: :incomplete),
      scenario: :ets_cross_process_write_read,
      flow_count: @otp_flow_count,
      event_count: event_count,
      write_call_count: length(state.write_calls),
      write_return_count: length(state.write_returns),
      read_call_count: length(state.read_calls),
      read_return_count: length(state.read_returns),
      joined_edge_count: joined,
      false_join_count: false_joins,
      correlation_basis: :ets_table_unique_key_and_ordered_mutation_window,
      application_key_required: true,
      overwrite_free_window_required: true,
      value_equality_used_as_provenance: false,
      reused_key_candidate_pair_count: @otp_flow_count * @otp_flow_count,
      reused_key_unique_edge_count: 0,
      table_owner_distinct_from_accessors: true,
      duration_us: elapsed_us(started_at)
    }
  end

  defp probe_process_dictionary! do
    marker = "rampart-process-dictionary-feasibility-marker"
    parent = self()

    workers =
      Enum.map(1..@otp_flow_count, fn id ->
        spawn(fn -> process_dictionary_worker(parent, id, marker) end)
      end)

    session = :trace.session_create(:rampart_iast_process_dictionary_probe, self(), [])
    started_at = System.monotonic_time()

    try do
      configure_process_dictionary!(session, workers)
      Enum.each(workers, &send(&1, :dispatch))
      deadline = deadline()

      state =
        collect_until(
          process_dictionary_state(),
          deadline,
          &(&1.workers_done == @otp_flow_count),
          &record_process_dictionary/2
        )

      delivery_refs = Enum.map(workers, &:trace.delivered(session, &1))

      state =
        collect_until(
          state,
          deadline,
          &process_dictionary_trace_complete?(&1, delivery_refs),
          &record_process_dictionary/2
        )

      summarize_process_dictionary(state, marker, started_at)
    after
      :trace.session_destroy(session)
      Enum.each(workers, &stop/1)
    end
  end

  defp configure_process_dictionary!(session, workers) do
    match_spec = [{:_, [], [{:return_trace}]}]
    1 = :trace.function(session, {:erlang, :put, 2}, match_spec, [])
    1 = :trace.function(session, {:erlang, :get, 1}, match_spec, [])
    1 = :trace.function(session, {:erlang, :get, 0}, match_spec, [])

    Enum.each(workers, fn worker ->
      1 = :trace.process(session, worker, true, [:call, :monotonic_timestamp])
    end)

    :ok
  end

  defp process_dictionary_worker(parent, id, marker) do
    receive do
      :dispatch ->
        key = {@process_dictionary_tag, id}
        :undefined = :erlang.put(key, marker)
        targeted = :erlang.get(key)
        snapshot = :erlang.get()
        send(parent, {:rampart_probe_process_dictionary_done, id, targeted, snapshot})
        await_stop()
    after
      2_000 -> :ok
    end
  end

  defp record_process_dictionary(
         state,
         {:trace_ts, process, :call, {:erlang, :put, [key, marker]}, timestamp}
       ) do
    %{state | put_calls: [{process, key, marker, timestamp} | state.put_calls]}
  end

  defp record_process_dictionary(
         state,
         {:trace_ts, process, :return_from, {:erlang, :put, 2}, result, timestamp}
       ) do
    %{state | put_returns: [{process, result, timestamp} | state.put_returns]}
  end

  defp record_process_dictionary(
         state,
         {:trace_ts, process, :call, {:erlang, :get, [key]}, timestamp}
       ) do
    %{state | targeted_get_calls: [{process, key, timestamp} | state.targeted_get_calls]}
  end

  defp record_process_dictionary(
         state,
         {:trace_ts, process, :return_from, {:erlang, :get, 1}, result, timestamp}
       ) do
    %{state | targeted_get_returns: [{process, result, timestamp} | state.targeted_get_returns]}
  end

  defp record_process_dictionary(
         state,
         {:trace_ts, process, :call, {:erlang, :get, []}, timestamp}
       ) do
    %{state | snapshot_get_calls: [{process, timestamp} | state.snapshot_get_calls]}
  end

  defp record_process_dictionary(
         state,
         {:trace_ts, process, :return_from, {:erlang, :get, 0}, result, timestamp}
       ) do
    %{state | snapshot_get_returns: [{process, result, timestamp} | state.snapshot_get_returns]}
  end

  defp record_process_dictionary(
         state,
         {:rampart_probe_process_dictionary_done, id, targeted, snapshot}
       ) do
    %{
      state
      | workers_done: state.workers_done + 1,
        observed_results: [{id, targeted, snapshot} | state.observed_results]
    }
  end

  defp record_process_dictionary(state, message), do: record_delivery(state, message)

  defp process_dictionary_trace_complete?(state, delivery_refs) do
    delivered?(state, delivery_refs) and
      length(state.put_calls) == @otp_flow_count and
      length(state.put_returns) == @otp_flow_count and
      length(state.snapshot_get_calls) == @otp_flow_count and
      length(state.snapshot_get_returns) == @otp_flow_count
  end

  defp summarize_process_dictionary(state, marker, started_at) do
    actual_reads =
      Enum.count(state.observed_results, fn {id, targeted, snapshot} ->
        key = {@process_dictionary_tag, id}
        targeted == marker and List.keyfind(snapshot, key, 0) == {key, marker}
      end)

    snapshot_reads =
      Enum.count(state.snapshot_get_returns, fn {_process, snapshot, _timestamp} ->
        Enum.any?(snapshot, fn
          {{@process_dictionary_tag, _id}, ^marker} -> true
          _entry -> false
        end)
      end)

    targeted_events = length(state.targeted_get_calls) + length(state.targeted_get_returns)

    %{
      status: :incomplete,
      scenario: :process_dictionary_storage,
      flow_count: @otp_flow_count,
      put_call_count: length(state.put_calls),
      put_return_count: length(state.put_returns),
      actual_targeted_read_count: actual_reads,
      targeted_read_trace_event_count: targeted_events,
      broad_snapshot_call_count: length(state.snapshot_get_calls),
      broad_snapshot_return_count: length(state.snapshot_get_returns),
      broad_snapshot_match_count: snapshot_reads,
      joined_edge_count: 0,
      false_join_count: 0,
      correlation_basis: :none,
      reason: :targeted_get_not_observable_by_call_trace,
      process_identity_scopes_dictionary: true,
      broad_snapshot_observable: snapshot_reads == @otp_flow_count,
      broad_snapshot_accepted_as_sensor_strategy: false,
      value_equality_used_as_provenance: false,
      duration_us: elapsed_us(started_at)
    }
  end

  defp summarize_message_edges(state, server, flow_count) do
    send_groups = Enum.group_by(state.sends, &elem(&1, 0))
    receive_groups = Enum.group_by(state.receives, &elem(&1, 0))
    messages = Map.keys(send_groups)

    joined =
      Enum.count(messages, fn message ->
        with [{^message, _client, ^server, sent_at}] <- Map.get(send_groups, message, []),
             [{^message, ^server, received_at}] <- Map.get(receive_groups, message, []) do
          sent_at <= received_at
        else
          _unjoinable -> false
        end
      end)

    duplicates =
      Enum.count(messages, fn message ->
        length(Map.get(send_groups, message, [])) != 1 or
          length(Map.get(receive_groups, message, [])) != 1
      end)

    %{
      flow_count: flow_count,
      send_event_count: length(state.sends),
      receive_event_count: length(state.receives),
      joined_edge_count: joined,
      false_join_count: flow_count - joined + duplicates
    }
  end

  defp duplicate_or_missing_edges(ids, send_groups, receive_groups, joined) do
    duplicates =
      Enum.count(ids, fn id ->
        length(Map.get(send_groups, id, [])) != 1 or
          length(Map.get(receive_groups, id, [])) != 1
      end)

    length(ids) - joined + duplicates
  end

  defp gen_server_trace_complete?(state, delivery_refs) do
    delivered?(state, delivery_refs) and
      length(state.sends) == @otp_flow_count and length(state.receives) == @otp_flow_count
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

          raise "cross-process feasibility probe timed out: #{inspect(summary)}"
      end
    end
  end

  defp record_delivery(state, {:trace_delivered, _tracee, reference}) do
    %{state | delivered: MapSet.put(state.delivered, reference)}
  end

  defp record_delivery(state, _other), do: state

  defp delivered?(state, references), do: state.delivered == MapSet.new(references)

  defp direct_state do
    %{
      sends: [],
      receives: [],
      acknowledged: 0,
      senders_done: 0,
      delivered: MapSet.new()
    }
  end

  defp gen_server_message_state do
    %{sends: [], receives: [], clients_done: 0, delivered: MapSet.new()}
  end

  defp gen_server_cast_state do
    %{
      sends: [],
      receives: [],
      clients_done: 0,
      acknowledged: 0,
      ids: [],
      marker: nil,
      delivered: MapSet.new()
    }
  end

  defp task_state do
    %{
      spawned: [],
      handoff_sends: [],
      handoff_receives: [],
      result_sends: [],
      result_receives: [],
      owner_done: 0,
      results: [],
      delivered: MapSet.new()
    }
  end

  defp ets_state do
    %{
      write_calls: [],
      write_returns: [],
      read_calls: [],
      read_returns: [],
      writers_done: 0,
      readers_done: 0,
      observed_results: [],
      delivered: MapSet.new()
    }
  end

  defp process_dictionary_state do
    %{
      put_calls: [],
      put_returns: [],
      targeted_get_calls: [],
      targeted_get_returns: [],
      snapshot_get_calls: [],
      snapshot_get_returns: [],
      workers_done: 0,
      observed_results: [],
      delivered: MapSet.new()
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
      2_000 -> :ok
    end
  end

  defp stop(process) do
    if Process.alive?(process), do: Process.exit(process, :kill)
  end
end
