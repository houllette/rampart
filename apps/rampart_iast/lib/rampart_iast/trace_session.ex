defmodule RampartIAST.TraceSession do
  @moduledoc false

  alias RampartIAST.{Limits, Observation, Sink, Source}
  alias RampartIAST.TraceSession.{Result, State}

  @type execute :: (binary() -> term())

  @doc "Runs a callback under bounded exact-marker sink tracing."
  @spec run(
          session_id :: String.t(),
          source :: Source.t(),
          sink :: Sink.t(),
          marker :: binary(),
          execute :: execute(),
          limits :: Limits.t(),
          options :: keyword()
        ) :: Result.t()
  def run(
        session_id,
        %Source{} = source,
        %Sink{} = sink,
        marker,
        execute,
        %Limits{} = limits,
        opts \\ []
      )
      when is_binary(session_id) and is_binary(marker) and is_function(execute, 1) do
    state = %State{
      caller: self(),
      run_ref: make_ref(),
      session_id: session_id,
      source: source,
      sink: sink,
      marker: marker,
      execute: execute,
      limits: limits,
      backend: Keyword.get(opts, :trace_backend, RampartIAST.TraceBackend.OTP),
      started_at: System.monotonic_time(:nanosecond)
    }

    {owner, owner_monitor} = spawn_monitor(fn -> own_session(state) end)
    owner_timeout = limits.timeout_ms + limits.delivery_timeout_ms * 2 + 1_000

    receive do
      {:rampart_iast_trace_result, run_ref, %Result{} = result} when run_ref == state.run_ref ->
        Process.demonitor(owner_monitor, [:flush])
        result

      {:DOWN, ^owner_monitor, :process, ^owner, reason} ->
        incomplete_result(
          state.session_id,
          state.started_at,
          :owner_failed,
          {:owner_exit, reason}
        )
    after
      owner_timeout ->
        Process.exit(owner, :kill)
        incomplete_result(state.session_id, state.started_at, :owner_failed, :owner_timeout)
    end
  end

  defp own_session(%State{} = state) do
    Process.flag(:trap_exit, true)
    owner = self()
    caller_monitor = Process.monitor(state.caller)

    {target, target_monitor} =
      spawn_monitor(fn ->
        execution_process(owner, state.run_ref, state.marker, state.execute)
      end)

    Process.link(target)

    {tracer, tracer_monitor} =
      spawn_monitor(fn ->
        collect(%{
          tracee: target,
          session_id: state.session_id,
          source: state.source,
          sink: state.sink,
          marker: state.marker,
          limits: state.limits,
          event_count: 0,
          observations: [],
          limit_failures: MapSet.new()
        })
      end)

    Process.link(tracer)

    state = %{
      state
      | caller_monitor: caller_monitor,
        target: target,
        target_monitor: target_monitor,
        tracer: tracer,
        tracer_monitor: tracer_monitor
    }

    {result, state} = create_and_run(state)
    terminate_process(state.target, state.target_monitor)
    teardown = destroy_session(state.session, state.backend)
    stop_tracer(state.tracer, state.tracer_monitor)
    result = apply_teardown(result, teardown)

    if Process.alive?(state.caller) do
      send(state.caller, {:rampart_iast_trace_result, state.run_ref, result})
    end
  end

  defp create_and_run(%State{} = state) do
    case backend_call(state.backend, :session_create, [:rampart_iast, state.tracer, []]) do
      {:ok, session} ->
        state = %{state | session: session}
        {configure_and_run(state), state}

      {:error, reason} ->
        result = incomplete_result(state.session_id, state.started_at, :setup_failed, reason)
        {result, state}
    end
  end

  defp configure_and_run(%State{} = state) do
    {module, _function, _arity} = state.sink.mfa

    with {:module, ^module} <- Code.ensure_loaded(module),
         {:ok, function_count} when function_count > 0 <-
           backend_call(state.backend, :function, [state.session, state.sink.mfa, true, []]),
         {:ok, 1} <-
           backend_call(state.backend, :process, [
             state.session,
             state.target,
             true,
             [:call, :monotonic_timestamp]
           ]) do
      send(state.target, {:run, state.run_ref})

      {execution, execution_reason, caller_active?} =
        await_execution(
          state.run_ref,
          state.caller_monitor,
          state.target,
          state.target_monitor,
          state.tracer,
          state.tracer_monitor,
          state.limits.timeout_ms
        )

      {snapshot, capture_status, caller_active?} =
        capture(
          caller_active?,
          state.session,
          state.target,
          state.tracer,
          state.tracer_monitor,
          state.caller_monitor,
          state.limits.delivery_timeout_ms,
          state.backend
        )

      build_result(
        state.session_id,
        state.started_at,
        execution,
        execution_reason,
        snapshot,
        capture_status,
        caller_active?
      )
    else
      {:ok, 0} ->
        incomplete_result(
          state.session_id,
          state.started_at,
          :setup_failed,
          {:untraceable_sink, state.sink.mfa}
        )

      {:ok, count} when is_integer(count) ->
        incomplete_result(
          state.session_id,
          state.started_at,
          :setup_failed,
          {:unexpected_tracee_count, count}
        )

      {:error, reason} ->
        incomplete_result(state.session_id, state.started_at, :setup_failed, reason)
    end
  end

  defp await_execution(
         run_ref,
         caller_monitor,
         target,
         target_monitor,
         tracer,
         tracer_monitor,
         timeout_ms
       ) do
    receive do
      {:rampart_iast_execution, ^run_ref, :completed} ->
        {:completed, nil, true}

      {:rampart_iast_execution, ^run_ref, {:callback_failed, reason}} ->
        {:callback_failed, reason, true}

      {:DOWN, ^caller_monitor, :process, _caller, reason} ->
        {:caller_stopped, {:caller_exit, reason}, false}

      {:DOWN, ^target_monitor, :process, ^target, reason} ->
        {:callback_failed, {:execution_exit, reason}, true}

      {:DOWN, ^tracer_monitor, :process, ^tracer, reason} ->
        {:tracer_failed, {:tracer_exit, reason}, true}
    after
      timeout_ms ->
        terminate_process(target, target_monitor)
        {:timeout, :execution_timeout, true}
    end
  end

  defp capture(
         false,
         _session,
         _target,
         _tracer,
         _tracer_monitor,
         _caller_monitor,
         _timeout,
         _backend
       ) do
    {empty_snapshot(), {:error, :caller_stopped}, false}
  end

  defp capture(
         true,
         session,
         target,
         tracer,
         tracer_monitor,
         caller_monitor,
         timeout_ms,
         backend
       ) do
    with {:ok, delivery_ref} <- backend_call(backend, :delivered, [session, target]),
         :ok <-
           await_delivery(
             target,
             delivery_ref,
             tracer,
             tracer_monitor,
             caller_monitor,
             timeout_ms
           ),
         {:ok, snapshot} <- snapshot(tracer, tracer_monitor, caller_monitor, timeout_ms) do
      {snapshot, :ok, true}
    else
      {:caller_stopped, reason} -> {empty_snapshot(), {:error, reason}, false}
      {:error, reason} -> {empty_snapshot(), {:error, reason}, true}
    end
  end

  defp await_delivery(target, delivery_ref, tracer, tracer_monitor, caller_monitor, timeout_ms) do
    receive do
      {:trace_delivered, ^target, ^delivery_ref} ->
        :ok

      {:DOWN, ^tracer_monitor, :process, ^tracer, reason} ->
        {:error, {:tracer_exit, reason}}

      {:DOWN, ^caller_monitor, :process, _caller, reason} ->
        {:caller_stopped, {:caller_exit, reason}}
    after
      timeout_ms -> {:error, :trace_delivery_timeout}
    end
  end

  defp snapshot(tracer, tracer_monitor, caller_monitor, timeout_ms) do
    snapshot_ref = make_ref()
    send(tracer, {:snapshot, self(), snapshot_ref})

    receive do
      {:rampart_iast_snapshot, ^snapshot_ref, snapshot} ->
        {:ok, snapshot}

      {:DOWN, ^tracer_monitor, :process, ^tracer, reason} ->
        {:error, {:tracer_exit, reason}}

      {:DOWN, ^caller_monitor, :process, _caller, reason} ->
        {:caller_stopped, {:caller_exit, reason}}
    after
      timeout_ms -> {:error, :trace_snapshot_timeout}
    end
  end

  defp build_result(
         session_id,
         started_at,
         execution,
         reason,
         snapshot,
         capture_status,
         caller_active?
       ) do
    intact? =
      execution == :completed and capture_status == :ok and caller_active? and
        snapshot.limit_failures == []

    %Result{
      session_id: session_id,
      execution: normalize_execution(execution),
      envelope: if(intact?, do: :intact, else: :incomplete),
      event_count: snapshot.event_count,
      observations: snapshot.observations,
      limit_failures: snapshot.limit_failures,
      teardown: :ok,
      reason: reason || capture_reason(capture_status),
      started_at: started_at,
      completed_at: System.monotonic_time(:nanosecond)
    }
  end

  defp collect(state) do
    receive do
      {:trace_ts, tracee, :call, {module, function, arguments}, timestamp}
      when tracee == state.tracee ->
        state
        |> record_call({module, function, arguments}, timestamp)
        |> collect()

      {:trace, tracee, :call, {module, function, arguments}} when tracee == state.tracee ->
        state
        |> record_call({module, function, arguments}, System.monotonic_time(:nanosecond))
        |> collect()

      {:snapshot, requester, snapshot_ref} ->
        snapshot = %{
          event_count: state.event_count,
          observations: Enum.reverse(state.observations),
          limit_failures: state.limit_failures |> MapSet.to_list() |> Enum.sort()
        }

        send(requester, {:rampart_iast_snapshot, snapshot_ref, snapshot})
        collect(state)

      :stop ->
        :ok

      _other ->
        collect(state)
    end
  end

  defp record_call(state, {module, function, arguments}, timestamp) do
    event_count = state.event_count + 1
    queue_length = self() |> Process.info(:message_queue_len) |> elem(1)

    limit_failures =
      state.limit_failures
      |> maybe_limit(event_count > state.limits.max_events, :event_limit)
      |> maybe_limit(queue_length > state.limits.max_mailbox_messages, :mailbox_limit)

    {argument_bytes, matched_positions, argument_failures} =
      inspect_arguments(arguments, state.sink.argument_positions, state.marker, state.limits)

    observation = %Observation{
      session_id: state.session_id,
      tracee: state.tracee,
      timestamp: timestamp,
      source_id: state.source.id,
      sink_id: state.sink.id,
      mfa: {module, function, length(arguments)},
      argument_positions: state.sink.argument_positions,
      matched_positions: matched_positions,
      argument_bytes: argument_bytes
    }

    observations =
      if event_count <= state.limits.max_events,
        do: [observation | state.observations],
        else: state.observations

    %{
      state
      | event_count: event_count,
        observations: observations,
        limit_failures: Enum.reduce(argument_failures, limit_failures, &MapSet.put(&2, &1))
    }
  end

  defp inspect_arguments(arguments, positions, marker, limits) do
    positions
    |> Enum.reduce({%{}, [], []}, fn position, acc ->
      arguments
      |> Enum.fetch(position - 1)
      |> inspect_argument(position, marker, limits, acc)
    end)
    |> then(fn {sizes, matched, failures} ->
      {sizes, Enum.reverse(matched), Enum.uniq(failures)}
    end)
  end

  defp inspect_argument({:ok, argument}, position, marker, limits, {sizes, matched, failures}) do
    size = argument_size(argument)

    {marker_present?, argument_failures} =
      if size > limits.max_argument_bytes do
        {false, [:argument_bytes]}
      else
        case marker_present?(argument, marker, limits) do
          {:ok, present?} -> {present?, []}
          {:error, failure} -> {false, [failure]}
        end
      end

    {
      Map.put(sizes, position, size),
      if(marker_present?, do: [position | matched], else: matched),
      argument_failures ++ failures
    }
  end

  defp inspect_argument(:error, _position, _marker, _limits, {sizes, matched, failures}) do
    {sizes, matched, [:invalid_argument_position | failures]}
  end

  defp marker_present?(argument, marker, limits) do
    find_marker(
      [{argument, 0}],
      marker,
      limits.max_argument_depth,
      limits.max_argument_terms,
      0
    )
  end

  defp find_marker([], _marker, _max_depth, _max_terms, _visited), do: {:ok, false}

  defp find_marker(_stack, _marker, _max_depth, max_terms, visited)
       when visited >= max_terms,
       do: {:error, :argument_terms}

  defp find_marker([{_term, depth} | _rest], _marker, max_depth, _max_terms, _visited)
       when depth > max_depth,
       do: {:error, :argument_depth}

  defp find_marker([{argument, _depth} | rest], marker, max_depth, max_terms, visited)
       when is_binary(argument) do
    if :binary.match(argument, marker) == :nomatch,
      do: find_marker(rest, marker, max_depth, max_terms, visited + 1),
      else: {:ok, true}
  end

  defp find_marker([{[head | tail], depth} | rest], marker, max_depth, max_terms, visited) do
    find_marker(
      [{head, depth + 1}, {tail, depth} | rest],
      marker,
      max_depth,
      max_terms,
      visited + 1
    )
  end

  defp find_marker([{argument, depth} | rest], marker, max_depth, max_terms, visited)
       when is_tuple(argument) do
    children = Enum.map(Tuple.to_list(argument), &{&1, depth + 1})
    find_marker(children ++ rest, marker, max_depth, max_terms, visited + 1)
  end

  defp find_marker([{argument, depth} | rest], marker, max_depth, max_terms, visited)
       when is_map(argument) do
    children =
      Enum.flat_map(argument, fn {key, value} -> [{key, depth + 1}, {value, depth + 1}] end)

    find_marker(children ++ rest, marker, max_depth, max_terms, visited + 1)
  end

  defp find_marker([_argument | rest], marker, max_depth, max_terms, visited) do
    find_marker(rest, marker, max_depth, max_terms, visited + 1)
  end

  defp argument_size(argument) when is_binary(argument), do: byte_size(argument)
  defp argument_size(argument), do: :erlang.external_size(argument)

  defp maybe_limit(failures, true, reason), do: MapSet.put(failures, reason)
  defp maybe_limit(failures, false, _reason), do: failures

  defp backend_call(backend, function, arguments) do
    {:ok, apply(backend, function, arguments)}
  rescue
    exception -> {:error, {:error, exception, __STACKTRACE__}}
  catch
    kind, reason -> {:error, {kind, reason, __STACKTRACE__}}
  end

  defp execution_process(owner, run_ref, marker, execute) do
    receive do
      {:run, ^run_ref} ->
        outcome =
          try do
            _result = execute.(marker)
            :completed
          rescue
            exception -> {:callback_failed, {:error, exception, __STACKTRACE__}}
          catch
            kind, reason -> {:callback_failed, {kind, reason, __STACKTRACE__}}
          end

        send(owner, {:rampart_iast_execution, run_ref, outcome})
    end
  end

  defp destroy_session(nil, _backend), do: :ok

  defp destroy_session(session, backend) do
    case backend_call(backend, :session_destroy, [session]) do
      {:ok, true} -> :ok
      _failure -> :failed
    end
  end

  defp apply_teardown(%Result{} = result, :ok), do: result

  defp apply_teardown(%Result{} = result, :failed) do
    %{
      result
      | envelope: :incomplete,
        teardown: :failed,
        reason: result.reason || :teardown_failed
    }
  end

  defp terminate_process(process, monitor) do
    if Process.alive?(process), do: Process.exit(process, :kill)

    receive do
      {:DOWN, ^monitor, :process, ^process, _reason} -> :ok
    after
      50 -> Process.demonitor(monitor, [:flush])
    end
  end

  defp stop_tracer(tracer, monitor) do
    if Process.alive?(tracer), do: send(tracer, :stop)

    receive do
      {:DOWN, ^monitor, :process, ^tracer, _reason} -> :ok
    after
      50 ->
        if Process.alive?(tracer), do: Process.exit(tracer, :kill)
        Process.demonitor(monitor, [:flush])
    end
  end

  defp incomplete_result(session_id, started_at, execution, reason) do
    %Result{
      session_id: session_id,
      execution: normalize_execution(execution),
      envelope: :incomplete,
      event_count: 0,
      observations: [],
      limit_failures: [],
      teardown: :ok,
      reason: reason,
      started_at: started_at,
      completed_at: System.monotonic_time(:nanosecond)
    }
  end

  defp empty_snapshot, do: %{event_count: 0, observations: [], limit_failures: []}

  defp normalize_execution(:caller_stopped), do: :owner_failed
  defp normalize_execution(:tracer_failed), do: :owner_failed
  defp normalize_execution(execution), do: execution

  defp capture_reason(:ok), do: nil
  defp capture_reason({:error, reason}), do: reason
end
