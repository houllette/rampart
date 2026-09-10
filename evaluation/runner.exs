Code.require_file("runtime.exs", __DIR__)

defmodule RampartEvaluation.Runner do
  @moduledoc false

  alias Core.Validation.Wire
  alias RampartIAST.{SourceSpan, StaticCandidate, StaticProvenance}
  alias RampartSAST.{Component, Graph, Inventory, Isolated, Workspace}
  alias RampartSAST.Inventory.Artifact

  @spec run!([String.t()]) :: map()
  def run!(arguments) do
    {options, positional, invalid} =
      OptionParser.parse(arguments,
        strict: [json: :boolean, output: :string],
        aliases: [j: :json, o: :output]
      )

    if positional != [] or invalid != [] do
      raise ArgumentError, "usage: mix rampart.eval [--json] [--output PATH]"
    end

    case_specs = RampartEvaluation.Corpus.cases()
    validate_case_specs!(case_specs)
    cases = Enum.map(case_specs, &evaluate/1)
    report = suite_report(cases)
    json_report = report |> Wire.json() |> JSON.encode!()

    if output = options[:output] do
      output |> Path.dirname() |> File.mkdir_p!()
      File.write!(output, json_report <> "\n")
    end

    if options[:json], do: IO.puts(json_report), else: print_report(report)

    failed =
      for evaluation <- report.cases,
          check <- evaluation.checks,
          not check.passed,
          do: "#{evaluation.case_id}: #{check.name}"

    if failed != [] do
      raise "Rampart evaluation failed: #{Enum.join(failed, ", ")}"
    end

    report
  end

  defp validate_case_specs!(case_specs) do
    ids = Enum.map(case_specs, & &1.id)

    unless case_specs != [] and length(ids) == length(Enum.uniq(ids)) do
      raise "Rampart evaluation requires one or more uniquely identified cases"
    end
  end

  defp suite_report(cases) do
    checks_total = Enum.reduce(cases, 0, &(&1.accuracy.checks_total + &2))
    checks_passed = Enum.reduce(cases, 0, &(&1.accuracy.checks_passed + &2))
    false_confirmations = Enum.reduce(cases, 0, &(&1.accuracy.false_confirmations + &2))

    %{
      schema_version: 2,
      status: if(Enum.all?(cases, &(&1.status == :passed)), do: :passed, else: :failed),
      runtime: runtime_manifest(),
      summary: %{
        case_count: length(cases),
        checks_passed: checks_passed,
        checks_total: checks_total,
        false_confirmations: false_confirmations,
        replay_successes: Enum.count(cases, & &1.accuracy.replay_success)
      },
      cases: cases
    }
  end

  defp runtime_manifest do
    otp_release = List.to_string(:erlang.system_info(:otp_release))
    erts_version = List.to_string(:erlang.system_info(:version))
    elixir_version = System.version()

    profile =
      case System.get_env("RAMPART_RUNTIME_PROFILE") do
        value when is_binary(value) and value != "" -> String.slice(value, 0, 80)
        _unset -> "local"
      end

    Map.merge(RampartEvaluation.Runtime.provenance(), %{
      profile: profile,
      runtime_id: "otp-#{otp_release}-erts-#{erts_version}-elixir-#{elixir_version}",
      otp_release: otp_release,
      erts_version: erts_version,
      elixir_version: elixir_version,
      architecture: List.to_string(:erlang.system_info(:system_architecture)),
      schedulers_online: :erlang.system_info(:schedulers_online)
    })
  end

  defp evaluate(%{kind: :exact_marker} = evaluation_case),
    do: evaluate_exact_marker(evaluation_case)

  defp evaluate(%{kind: :unsupported_process_scope} = evaluation_case),
    do: evaluate_unsupported_process_scope(evaluation_case)

  defp evaluate(%{kind: :historical_regression} = evaluation_case),
    do: evaluate_historical_regression(evaluation_case)

  defp evaluate(%{kind: :historical_contract_regression} = evaluation_case),
    do: evaluate_historical_contract_regression(evaluation_case)

  defp evaluate(%{kind: :trace_overhead} = evaluation_case),
    do: evaluate_trace_overhead(evaluation_case)

  defp evaluate(%{kind: :cross_process_feasibility} = evaluation_case),
    do: evaluate_cross_process_feasibility(evaluation_case)

  defp evaluate_exact_marker(evaluation_case) do
    atom_count_before = :erlang.system_info(:atom_count)
    memory_before = :erlang.memory(:total)
    {components, target_component, dependency_component} = components(evaluation_case)

    {scan_us, scan_result} =
      timed(fn ->
        Workspace.inventory(components, scan_options(evaluation_case))
      end)

    expected = evaluation_case.expected
    inventory = scan_result.inventory

    {isolated_scan_us, isolated_result} =
      timed(fn ->
        Isolated.inventory(
          isolation_root(evaluation_case),
          Keyword.put(scan_options(evaluation_case), :include, ["*.ex"])
        )
      end)

    callback_facts = Inventory.query(inventory, kind: :callback, object: expected.callback)

    implementation_facts =
      Inventory.query(inventory,
        kind: :callback_implementation,
        subject: expected.implementation,
        object: expected.callback
      )

    package_facts =
      inventory
      |> Inventory.package_usage(expected.dependency_package)
      |> Enum.filter(&(&1.subject == expected.source_function))

    source_definitions =
      Inventory.query(inventory, kind: :definition, object: expected.source_function)

    sink_calls =
      Inventory.query(inventory, kind: :call, object: expected.sink_function)

    behavior_facts =
      inventory
      |> Inventory.query(
        kind: :behavior,
        subject: expected.dependency_function,
        object: expected.sink_behavior
      )
      |> Enum.filter(&(&1.attributes.via_object == expected.sink_function))

    selected_sink_calls = Enum.filter(sink_calls, &(&1.subject == expected.dependency_function))

    {graph_us, graph} =
      timed(fn ->
        Graph.callees(inventory, expected.source_function,
          max_depth: 4,
          max_nodes: evaluation_case.budgets.max_graph_nodes
        )
      end)

    query_samples = query_samples(inventory, expected.sink_function)
    query_p95_us = percentile(query_samples, 95)

    {artifact_us, artifact} = timed(fn -> Artifact.encode(inventory) end)

    candidate =
      build_candidate!(
        inventory,
        List.first(source_definitions),
        selected_sink_calls,
        expected
      )

    RampartEvaluation.Provider.install_candidate!(candidate)

    try do
      validation = validate_runtime(candidate, evaluation_case)

      model_evidence_bytes =
        validation.confirmed |> Wire.result() |> Wire.encode!() |> byte_size()

      atom_count_after = :erlang.system_info(:atom_count)
      memory_after = :erlang.memory(:total)

      checks =
        checks(evaluation_case, %{
          scan_result: scan_result,
          scan_us: scan_us,
          isolated_result: isolated_result,
          isolated_scan_us: isolated_scan_us,
          callback_facts: callback_facts,
          implementation_facts: implementation_facts,
          package_facts: package_facts,
          source_definitions: source_definitions,
          sink_calls: sink_calls,
          behavior_facts: behavior_facts,
          selected_sink_calls: selected_sink_calls,
          graph: graph,
          graph_us: graph_us,
          query_p95_us: query_p95_us,
          artifact: artifact,
          candidate: candidate,
          validation: validation,
          model_evidence_bytes: model_evidence_bytes
        })

      false_confirmations =
        Enum.count([validation.patched, validation.failure], &(&1.verdict == :confirmed))

      %{
        schema_version: 1,
        case_id: evaluation_case.id,
        tier: evaluation_case.tier,
        status: if(Enum.all?(checks, & &1.passed), do: :passed, else: :failed),
        checks: checks,
        accuracy: %{
          checks_passed: Enum.count(checks, & &1.passed),
          checks_total: length(checks),
          explicit_ambiguities: ambiguity_count(inventory),
          vulnerable_verdict: validation.confirmed.verdict,
          patched_verdict: validation.patched.verdict,
          failure_verdict: validation.failure.verdict,
          false_confirmations: false_confirmations,
          replay_success: replay_success?(validation)
        },
        efficiency: %{
          source_bytes: scan_result.metrics.source_bytes,
          source_count: scan_result.metrics.source_count,
          fact_count: scan_result.metrics.fact_count,
          scan_us: scan_us,
          isolated_scan_us: isolated_scan_us,
          isolated_worker_memory_bytes: isolated_result.worker["memory_bytes"],
          isolated_worker_os_peak_rss_bytes: isolated_result.worker["os_peak_rss_bytes"],
          isolated_worker_cgroup_memory_peak_bytes:
            isolated_result.worker["cgroup_memory_peak_bytes"],
          isolated_worker_atom_count: isolated_result.worker["atom_count"],
          graph_us: graph_us,
          query_p95_us: query_p95_us,
          artifact_us: artifact_us,
          artifact_bytes: artifact.bytes,
          model_evidence_bytes: model_evidence_bytes,
          host_atom_growth: atom_count_after - atom_count_before,
          host_memory_delta_bytes: memory_after - memory_before
        },
        usefulness: %{
          bounded_queries: 5,
          sink_candidates: length(sink_calls),
          selected_sink_candidates: length(selected_sink_calls),
          candidate_reduction_ratio: ratio(length(selected_sink_calls), length(sink_calls)),
          graph_nodes: length(graph.nodes),
          graph_edges: length(graph.edges),
          graph_truncated: graph.truncated,
          compatible_proof_actions: 1,
          replayable_verdicts: 2,
          artifact_id: artifact.id,
          inventory_id: inventory.id
        },
        provenance: %{
          target_checksum: target_component.checksum,
          dependency_checksum: component_checksum(dependency_component),
          static_candidate: StaticCandidate.to_map(candidate)
        }
      }
    after
      RampartEvaluation.Provider.clear()
    end
  end

  defp evaluate_trace_overhead(evaluation_case) do
    expected = evaluation_case.expected

    target_component =
      Component.new!(
        id: "evaluation-trace-overhead",
        kind: :target,
        sources: read_sources(evaluation_case.target_sources)
      )

    {scan_us, scan_result} = timed(fn -> Workspace.inventory([target_component]) end)

    source_definitions =
      Inventory.query(scan_result.inventory, kind: :definition, object: expected.source_function)

    sink_calls =
      Inventory.query(scan_result.inventory, kind: :call, object: expected.sink_function)

    candidate =
      build_overhead_candidate!(
        scan_result.inventory,
        List.first(source_definitions),
        List.first(sink_calls),
        expected
      )

    RampartEvaluation.Provider.install_candidate!(candidate)

    try do
      marker = "rampart-targeted-trace-overhead-marker"
      seed = evaluation_seed(evaluation_case.id, marker)
      hypothesis = RampartIAST.hypothesis!(RampartEvaluation.Provider, candidate.id, seed)

      samples =
        Enum.map(1..expected.sample_count, fn _sample ->
          {baseline_us, baseline_value} =
            timed(fn -> RampartEvaluation.Overhead.Target.run(marker) end)

          {targeted_us, targeted_result} =
            timed(fn ->
              RampartIAST.validate(hypothesis,
                provider: RampartEvaluation.Provider,
                execute: &RampartEvaluation.Overhead.Target.run/1
              )
            end)

          %{
            baseline_us: baseline_us,
            baseline_value: baseline_value,
            targeted_us: targeted_us,
            targeted_result: targeted_result
          }
        end)

      cross_process_hypothesis =
        RampartIAST.hypothesis!(RampartEvaluation.Provider, candidate.id, seed,
          meta: %{required_process_scope: :cross_process}
        )

      caller = self()
      execution_ref = make_ref()

      rejected =
        RampartIAST.validate(cross_process_hypothesis,
          provider: RampartEvaluation.Provider,
          execute: fn value -> send(caller, {:overhead_scope_executed, execution_ref, value}) end
        )

      rejected_executed? =
        receive do
          {:overhead_scope_executed, ^execution_ref, _value} -> true
        after
          0 -> false
        end

      baseline_samples = Enum.map(samples, & &1.baseline_us)
      targeted_samples = Enum.map(samples, & &1.targeted_us)
      baseline_median_us = percentile(baseline_samples, 50)
      targeted_median_us = percentile(targeted_samples, 50)
      targeted_p95_us = percentile(targeted_samples, 95)
      added_median_us = targeted_median_us - baseline_median_us
      overhead_ratio = ratio(targeted_median_us, baseline_median_us)
      targeted_results = Enum.map(samples, & &1.targeted_result)

      evidence_bytes =
        targeted_results
        |> List.first()
        |> Wire.result()
        |> Wire.encode!()
        |> byte_size()

      checks = [
        check("overhead fixture inventory is complete", scan_result.status == :complete),
        check("overhead source is localized", length(source_definitions) == 1),
        check("overhead sink is localized", length(sink_calls) == 1),
        check(
          "disabled baseline preserves the marker",
          Enum.all?(samples, &(&1.baseline_value == marker))
        ),
        check(
          "every targeted trace confirms",
          Enum.all?(targeted_results, &(&1.verdict == :confirmed))
        ),
        check(
          "targeted trace seeds replay identically",
          targeted_results |> Enum.map(& &1.seed.id) |> Enum.uniq() |> length() == 1
        ),
        check(
          "targeted p95 meets wall-time budget",
          targeted_p95_us <= evaluation_case.budgets.max_targeted_trace_ms * 1_000
        ),
        check(
          "overhead measurements are positive",
          baseline_median_us > 0 and targeted_median_us > 0 and overhead_ratio > 0.0
        ),
        check("broader process scope is inconclusive", rejected.verdict == :inconclusive),
        check("broader process scope is rejected before execution", not rejected_executed?),
        check("broader process scope creates no findings", rejected.findings == []),
        check(
          "broader process scope has an explicit reason",
          rejected.evidence.facts.reason == :unsupported_process_scope
        ),
        check(
          "trace evidence meets context budget",
          evidence_bytes <= evaluation_case.budgets.max_model_evidence_bytes
        )
      ]

      %{
        schema_version: 1,
        case_id: evaluation_case.id,
        tier: evaluation_case.tier,
        status: if(Enum.all?(checks, & &1.passed), do: :passed, else: :failed),
        checks: checks,
        accuracy: %{
          checks_passed: Enum.count(checks, & &1.passed),
          checks_total: length(checks),
          explicit_ambiguities: 0,
          targeted_verdict: targeted_results |> List.first() |> Map.fetch!(:verdict),
          unsupported_scope_verdict: rejected.verdict,
          false_confirmations: 0,
          replay_success:
            targeted_results |> Enum.map(& &1.seed.id) |> Enum.uniq() |> length() == 1
        },
        efficiency: %{
          source_bytes: scan_result.metrics.source_bytes,
          source_count: scan_result.metrics.source_count,
          fact_count: scan_result.metrics.fact_count,
          scan_us: scan_us,
          isolated_scan_us: 0,
          isolated_worker_memory_bytes: nil,
          isolated_worker_os_peak_rss_bytes: nil,
          isolated_worker_cgroup_memory_peak_bytes: nil,
          isolated_worker_atom_count: nil,
          graph_us: 0,
          query_p95_us: 0,
          artifact_us: 0,
          artifact_bytes: 0,
          model_evidence_bytes: evidence_bytes,
          host_atom_growth: 0,
          host_memory_delta_bytes: 0,
          sample_count: expected.sample_count,
          baseline_median_us: baseline_median_us,
          targeted_median_us: targeted_median_us,
          targeted_p95_us: targeted_p95_us,
          added_median_us: added_median_us,
          overhead_ratio: overhead_ratio
        },
        usefulness: %{
          bounded_queries: 2,
          sink_candidates: length(sink_calls),
          selected_sink_candidates: 1,
          candidate_reduction_ratio: 1.0,
          graph_nodes: 0,
          graph_edges: 0,
          graph_truncated: false,
          compatible_proof_actions: 1,
          replayable_verdicts: expected.sample_count,
          rejected_process_scope: :cross_process,
          artifact_id: nil,
          inventory_id: scan_result.inventory.id
        },
        provenance: %{
          target_checksum: target_component.checksum,
          static_candidate: StaticCandidate.to_map(candidate)
        }
      }
    after
      RampartEvaluation.Provider.clear()
    end
  end

  defp evaluate_cross_process_feasibility(evaluation_case) do
    expected = evaluation_case.expected
    {probe_us, probe} = timed(&RampartEvaluation.CrossProcessProbe.run!/0)
    {_replay_us, replay} = timed(&RampartEvaluation.CrossProcessProbe.run!/0)
    evidence_bytes = probe |> Wire.json() |> JSON.encode!() |> byte_size()
    replay_success = probe_replay_shape(probe) == probe_replay_shape(replay)

    checks = [
      check(
        "boundary matrix is explicitly partial",
        probe.schema_version == 3 and probe.status == :partial
      ),
      check(
        "direct-message probe is supported",
        probe.direct_message.status == :supported
      ),
      check(
        "all direct-message send and receive events were captured",
        probe.direct_message.send_event_count == expected.direct_flow_count and
          probe.direct_message.receive_event_count == expected.direct_flow_count
      ),
      check(
        "every explicit direct-message envelope joined once",
        probe.direct_message.joined_edge_count == expected.direct_flow_count and
          probe.direct_message.false_join_count == 0
      ),
      check(
        "direct-message probe used several concurrent senders and one repeated marker",
        probe.direct_message.sender_count == expected.sender_count and
          probe.direct_message.distinct_marker_count == 1
      ),
      check(
        "direct-message value-only matching remains ambiguous",
        probe.direct_message.value_only_candidate_pair_count ==
          expected.direct_value_only_candidate_pair_count and
          probe.direct_message.value_only_unique_edge_count == 0
      ),
      check(
        "direct-message correlation requires an application envelope",
        probe.direct_message.correlation_basis == :explicit_message_envelope and
          probe.direct_message.application_envelope_id_required and
          not probe.direct_message.value_equality_used_as_provenance
      ),
      check(
        "GenServer call aliases correlate every request",
        probe.gen_server_call.status == :supported and
          probe.gen_server_call.joined_edge_count == expected.otp_flow_count and
          probe.gen_server_call.false_join_count == 0
      ),
      check(
        "GenServer call send and receive event counts are complete",
        probe.gen_server_call.send_event_count == expected.otp_flow_count and
          probe.gen_server_call.receive_event_count == expected.otp_flow_count
      ),
      check(
        "GenServer call correlation uses the OTP alias without an application ID",
        probe.gen_server_call.correlation_basis == :otp_call_alias_envelope and
          not probe.gen_server_call.application_envelope_id_required and
          not probe.gen_server_call.value_equality_used_as_provenance
      ),
      check(
        "GenServer cast joins only with explicit application request IDs",
        probe.gen_server_cast.status == :supported and
          probe.gen_server_cast.joined_edge_count == expected.otp_flow_count and
          probe.gen_server_cast.false_join_count == 0 and
          probe.gen_server_cast.application_envelope_id_required and
          not probe.gen_server_cast.otp_correlation_id_present
      ),
      check(
        "GenServer cast send and receive event counts are complete",
        probe.gen_server_cast.send_event_count == expected.otp_flow_count and
          probe.gen_server_cast.receive_event_count == expected.otp_flow_count
      ),
      check(
        "GenServer cast value-only matching remains ambiguous",
        probe.gen_server_cast.value_only_candidate_pair_count ==
          expected.boundary_value_only_candidate_pair_count and
          probe.gen_server_cast.value_only_unique_edge_count == 0 and
          not probe.gen_server_cast.value_equality_used_as_provenance
      ),
      check(
        "Task.async references and spawn lineage correlate every handoff",
        probe.task_async.status == :supported and
          probe.task_async.joined_edge_count == expected.otp_flow_count and
          probe.task_async.false_join_count == 0 and
          probe.task_async.correlation_basis == :task_reference_and_spawn_lineage
      ),
      check(
        "Task.async handoff and result trace events are complete",
        probe.task_async.spawn_event_count == expected.otp_flow_count and
          probe.task_async.handoff_send_event_count == expected.otp_flow_count and
          probe.task_async.handoff_receive_event_count == expected.otp_flow_count and
          probe.task_async.result_send_event_count == expected.otp_flow_count and
          probe.task_async.result_receive_event_count == expected.otp_flow_count and
          probe.task_async.completed_result_count == expected.otp_flow_count
      ),
      check(
        "Task correlation is scoped to the observed Elixir Task.async protocol",
        probe.task_async.implementation_scope == :elixir_task_async and
          not probe.task_async.application_envelope_id_required and
          not probe.task_async.value_equality_used_as_provenance
      ),
      check(
        "Task value-only matching remains ambiguous",
        probe.task_async.value_only_candidate_pair_count ==
          expected.boundary_value_only_candidate_pair_count and
          probe.task_async.value_only_unique_edge_count == 0
      ),
      check(
        "ETS unique keys correlate every ordered write/read interval",
        probe.ets.status == :supported and
          probe.ets.joined_edge_count == expected.otp_flow_count and
          probe.ets.false_join_count == 0 and
          probe.ets.correlation_basis == :ets_table_unique_key_and_ordered_mutation_window
      ),
      check(
        "ETS call and return trace events are complete",
        probe.ets.event_count == expected.ets_event_count and
          probe.ets.write_call_count == expected.otp_flow_count and
          probe.ets.write_return_count == expected.otp_flow_count and
          probe.ets.read_call_count == expected.otp_flow_count and
          probe.ets.read_return_count == expected.otp_flow_count
      ),
      check(
        "ETS correlation retains key and mutation-window preconditions",
        probe.ets.application_key_required and probe.ets.overwrite_free_window_required and
          probe.ets.table_owner_distinct_from_accessors and
          not probe.ets.value_equality_used_as_provenance
      ),
      check(
        "ETS reused-key matching remains ambiguous",
        probe.ets.reused_key_candidate_pair_count ==
          expected.boundary_value_only_candidate_pair_count and
          probe.ets.reused_key_unique_edge_count == 0
      ),
      check(
        "process-dictionary targeted reads remain unsupported",
        probe.process_dictionary.status == :incomplete and
          probe.process_dictionary.reason == :targeted_get_not_observable_by_call_trace and
          probe.process_dictionary.joined_edge_count == 0
      ),
      check(
        "process-dictionary fixture executed targeted reads despite no targeted trace event",
        probe.process_dictionary.actual_targeted_read_count == expected.otp_flow_count and
          probe.process_dictionary.targeted_read_trace_event_count == 0 and
          probe.process_dictionary.put_call_count == expected.otp_flow_count and
          probe.process_dictionary.put_return_count == expected.otp_flow_count
      ),
      check(
        "broad process-dictionary snapshots are observable but rejected as a sensor strategy",
        probe.process_dictionary.broad_snapshot_observable and
          probe.process_dictionary.broad_snapshot_match_count == expected.otp_flow_count and
          probe.process_dictionary.broad_snapshot_call_count == expected.otp_flow_count and
          probe.process_dictionary.broad_snapshot_return_count == expected.otp_flow_count and
          not probe.process_dictionary.broad_snapshot_accepted_as_sensor_strategy
      ),
      check(
        "process identity scopes the dictionary without inventing cross-process provenance",
        probe.process_dictionary.process_identity_scopes_dictionary and
          not probe.process_dictionary.value_equality_used_as_provenance
      ),
      check(
        "adversarial boundary matrix fails closed",
        probe.adversarial.schema_version == 1 and probe.adversarial.status == :fail_closed
      ),
      check(
        "casts without application IDs remain ambiguous",
        probe.adversarial.cast_without_id.status == :ambiguous and
          probe.adversarial.cast_without_id.send_event_count ==
            expected.adversarial_flow_count and
          probe.adversarial.cast_without_id.receive_event_count ==
            expected.adversarial_flow_count and
          probe.adversarial.cast_without_id.acknowledged_count ==
            expected.adversarial_flow_count and
          probe.adversarial.cast_without_id.candidate_pair_count ==
            expected.boundary_value_only_candidate_pair_count and
          probe.adversarial.cast_without_id.unique_edge_count == 0 and
          not probe.adversarial.cast_without_id.timestamp_order_accepted_as_provenance
      ),
      check(
        "Task crashes and timeouts correlate failure without confirming value flow",
        probe.adversarial.task_failures.status == :inconclusive and
          probe.adversarial.task_failures.correlated_failure_count ==
            expected.task_failure_flow_count and
          probe.adversarial.task_failures.handoff_send_event_count ==
            expected.task_failure_flow_count and
          probe.adversarial.task_failures.handoff_receive_event_count ==
            expected.task_failure_flow_count and
          probe.adversarial.task_failures.exit_events_complete and
          probe.adversarial.task_failures.down_events_complete and
          not probe.adversarial.task_failures.confirmation_allowed and
          probe.adversarial.task_failures.joined_edge_count == 0
      ),
      check(
        "Task failure outcomes remain explicit",
        probe.adversarial.task_failures.crash_outcome ==
          {:exit, :rampart_probe_task_failure} and
          probe.adversarial.task_failures.timeout_outcome == :no_result and
          probe.adversarial.task_failures.shutdown_outcome == :no_result
      ),
      check(
        "ETS overwrite races require an explicit write version",
        probe.adversarial.ets_mutations.status == :conditional and
          probe.adversarial.ets_mutations.writer_count == expected.adversarial_flow_count and
          probe.adversarial.ets_mutations.insert_call_count ==
            expected.adversarial_flow_count and
          probe.adversarial.ets_mutations.insert_return_count ==
            expected.adversarial_flow_count and
          probe.adversarial.ets_mutations.winning_write_id_present and
          probe.adversarial.ets_mutations.explicit_version_join_count == 1 and
          probe.adversarial.ets_mutations.projected_marker_candidate_count ==
            expected.adversarial_flow_count and
          probe.adversarial.ets_mutations.projected_marker_unique_edge_count == 0 and
          not probe.adversarial.ets_mutations.temporal_order_accepted_as_provenance
      ),
      check(
        "ETS delete invalidates the storage edge",
        probe.adversarial.ets_mutations.delete_status == :terminated and
          not probe.adversarial.ets_mutations.confirmation_allowed_without_write_version and
          probe.adversarial.ets_mutations.joined_edge_count == 0
      ),
      check(
        "injected trace loss prevents confirmation despite a delivery barrier",
        probe.adversarial.trace_loss.status == :incomplete and
          probe.adversarial.trace_loss.send_event_count == expected.adversarial_flow_count and
          probe.adversarial.trace_loss.receive_event_count ==
            expected.trace_loss_observed_event_count and
          probe.adversarial.trace_loss.acknowledged_count ==
            expected.adversarial_flow_count and
          probe.adversarial.trace_loss.injected_dropped_event_count == 1 and
          probe.adversarial.trace_loss.delivery_barrier_completed and
          not probe.adversarial.trace_loss.confirmation_allowed and
          probe.adversarial.trace_loss.joined_edge_count == 0
      ),
      check(
        "ordinary supervisor replacement terminates process-local provenance",
        probe.adversarial.supervisor_replacement.status == :terminated and
          probe.adversarial.supervisor_replacement.old_and_new_worker_distinct and
          probe.adversarial.supervisor_replacement.store_receive_event_count == 1 and
          probe.adversarial.supervisor_replacement.old_worker_exit_observed and
          probe.adversarial.supervisor_replacement.replacement_spawn_observed and
          not probe.adversarial.supervisor_replacement.replacement_value_present and
          not probe.adversarial.supervisor_replacement.confirmation_allowed_across_replacement and
          not probe.adversarial.supervisor_replacement.external_state_transfer_covered
      ),
      check(
        "frontier boundary matrix is supported under its explicit gates",
        probe.frontier.schema_version == 1 and probe.frontier.status == :supported
      ),
      check(
        "versioned external state restores across a supervisor restart",
        probe.frontier.external_state_restoration.status == :supported and
          probe.frontier.external_state_restoration.old_and_new_worker_distinct and
          probe.frontier.external_state_restoration.old_worker_exit_observed and
          probe.frontier.external_state_restoration.replacement_spawn_observed and
          probe.frontier.external_state_restoration.external_insert_call_count == 1 and
          probe.frontier.external_state_restoration.replacement_lookup_call_count == 1 and
          probe.frontier.external_state_restoration.restored_marker_present and
          probe.frontier.external_state_restoration.restored_version_present and
          probe.frontier.external_state_restoration.joined_edge_count ==
            expected.external_state_joined_edge_count and
          probe.frontier.external_state_restoration.false_join_count == 0
      ),
      check(
        "external-state correlation requires key and write version rather than PID or value",
        probe.frontier.external_state_restoration.correlation_basis ==
          :external_store_key_and_write_version and
          probe.frontier.external_state_restoration.application_version_required and
          probe.frontier.external_state_restoration.projected_without_version_status ==
            :ambiguous and
          probe.frontier.external_state_restoration.projected_without_version_unique_edge_count ==
            0 and
          not probe.frontier.external_state_restoration.process_identity_used_across_replacement and
          not probe.frontier.external_state_restoration.value_equality_used_as_provenance
      ),
      check(
        "higher-concurrency mailbox-pressure events remain complete",
        probe.frontier.mailbox_pressure.status == :supported and
          probe.frontier.mailbox_pressure.flow_count == expected.stress_flow_count and
          probe.frontier.mailbox_pressure.sender_count == expected.stress_sender_count and
          probe.frontier.mailbox_pressure.send_event_count == expected.stress_flow_count and
          probe.frontier.mailbox_pressure.receive_event_count == expected.stress_flow_count and
          probe.frontier.mailbox_pressure.joined_edge_count == expected.stress_flow_count and
          probe.frontier.mailbox_pressure.false_join_count == 0
      ),
      check(
        "selective receives preserve unrelated mailbox pressure",
        probe.frontier.mailbox_pressure.noise_message_count == expected.stress_noise_count and
          probe.frontier.mailbox_pressure.receiver_queue_length_after_flows ==
            expected.stress_noise_count and
          probe.frontier.mailbox_pressure.receiver_reductions > 0
      ),
      check(
        "mailbox-pressure correlation still requires explicit envelopes",
        probe.frontier.mailbox_pressure.value_only_candidate_pair_count ==
          expected.stress_value_only_candidate_pair_count and
          probe.frontier.mailbox_pressure.value_only_unique_edge_count == 0 and
          probe.frontier.mailbox_pressure.correlation_basis ==
            :explicit_message_envelope_under_mailbox_pressure and
          not probe.frontier.mailbox_pressure.value_equality_used_as_provenance
      ),
      check(
        "distributed handoff gate is either proven or explicitly optional",
        distributed_frontier_valid?(probe.frontier.distributed_handoff, expected)
      ),
      check(
        "remaining unresolved boundaries are named exactly",
        probe.unresolved_boundaries == expected.unresolved_boundaries
      ),
      check("cross-process probe replays structurally", replay_success),
      check(
        "cross-process probe meets wall-time budget",
        probe_us <= evaluation_case.budgets.max_cross_process_probe_ms * 1_000
      ),
      check(
        "cross-process evidence meets context budget",
        evidence_bytes <= evaluation_case.budgets.max_model_evidence_bytes
      )
    ]

    boundary_results = [
      probe.direct_message,
      probe.gen_server_call,
      probe.gen_server_cast,
      probe.task_async,
      probe.ets,
      probe.process_dictionary
    ]

    adversarial_results = [
      probe.adversarial.cast_without_id,
      probe.adversarial.task_failures,
      probe.adversarial.ets_mutations,
      probe.adversarial.trace_loss,
      probe.adversarial.supervisor_replacement
    ]

    frontier_results = [
      probe.frontier.external_state_restoration,
      probe.frontier.mailbox_pressure,
      probe.frontier.distributed_handoff
    ]

    all_boundary_results = boundary_results ++ adversarial_results ++ frontier_results

    %{
      schema_version: 1,
      case_id: evaluation_case.id,
      tier: evaluation_case.tier,
      status: if(Enum.all?(checks, & &1.passed), do: :passed, else: :failed),
      checks: checks,
      accuracy: %{
        checks_passed: Enum.count(checks, & &1.passed),
        checks_total: length(checks),
        explicit_ambiguities: length(probe.unresolved_boundaries) + 2,
        probe_status: probe.status,
        false_confirmations: Enum.sum(Enum.map(all_boundary_results, & &1.false_join_count)),
        replay_success: replay_success
      },
      efficiency: %{
        source_bytes: 0,
        source_count: 0,
        fact_count: 0,
        scan_us: 0,
        isolated_scan_us: 0,
        isolated_worker_memory_bytes: nil,
        isolated_worker_os_peak_rss_bytes: nil,
        isolated_worker_cgroup_memory_peak_bytes: nil,
        isolated_worker_atom_count: nil,
        graph_us: 0,
        query_p95_us: 0,
        artifact_us: 0,
        artifact_bytes: 0,
        model_evidence_bytes: evidence_bytes,
        host_atom_growth: 0,
        host_memory_delta_bytes: 0,
        probe_us: probe_us,
        external_state_probe_us: probe.frontier.external_state_restoration.duration_us,
        mailbox_pressure_probe_us: probe.frontier.mailbox_pressure.duration_us,
        mailbox_pressure_receiver_reductions: probe.frontier.mailbox_pressure.receiver_reductions,
        distributed_handoff_probe_us: probe.frontier.distributed_handoff.duration_us
      },
      usefulness: %{
        bounded_queries: 0,
        sink_candidates: 0,
        selected_sink_candidates: 0,
        candidate_reduction_ratio: 0.0,
        graph_nodes: 0,
        graph_edges: 0,
        graph_truncated: false,
        compatible_proof_actions: 0,
        replayable_verdicts: 1,
        correlated_edges:
          Enum.sum(Enum.map(boundary_results ++ frontier_results, & &1.joined_edge_count)),
        unresolved_boundaries: probe.unresolved_boundaries,
        artifact_id: nil,
        inventory_id: nil
      },
      provenance: %{
        runtime: "OTP #{List.to_string(:erlang.system_info(:otp_release))}",
        elixir: System.version(),
        trace_api: "trace sessions",
        scenario: probe.scenario
      }
    }
  end

  defp evaluate_unsupported_process_scope(evaluation_case) do
    atom_count_before = :erlang.system_info(:atom_count)
    memory_before = :erlang.memory(:total)
    {components, target_component, dependency_component} = components(evaluation_case)
    expected = evaluation_case.expected

    {scan_us, scan_result} =
      timed(fn -> Workspace.inventory(components, scan_options(evaluation_case)) end)

    inventory = scan_result.inventory

    {isolated_scan_us, isolated_result} =
      timed(fn ->
        Isolated.inventory(
          isolation_root(evaluation_case),
          Keyword.put(scan_options(evaluation_case), :include, ["*.ex"])
        )
      end)

    source_definitions =
      Inventory.query(inventory, kind: :definition, object: expected.source_function)

    sink_calls = Inventory.query(inventory, kind: :call, object: expected.sink_function)

    otp_requests =
      Inventory.query(inventory,
        kind: :behavior,
        subject: expected.request_function,
        object: "otp_request"
      )

    package_facts =
      inventory
      |> Inventory.package_usage(expected.dependency_package)
      |> Enum.filter(&(&1.subject == expected.source_function))

    {graph_us, graph} =
      timed(fn ->
        Graph.callees(inventory, expected.source_function,
          max_depth: 4,
          max_nodes: evaluation_case.budgets.max_graph_nodes
        )
      end)

    query_samples = query_samples(inventory, expected.sink_function)
    query_p95_us = percentile(query_samples, 95)
    {artifact_us, artifact} = timed(fn -> Artifact.encode(inventory) end)

    candidate =
      build_otp_candidate!(
        inventory,
        List.first(source_definitions),
        List.first(sink_calls),
        expected
      )

    RampartEvaluation.Provider.install_candidate!(candidate)

    try do
      {result, execution_called?} = unsupported_process_validation(candidate, evaluation_case)

      {replay, replay_execution_called?} =
        unsupported_process_validation(candidate, evaluation_case)

      model_evidence_bytes = result |> Wire.result() |> Wire.encode!() |> byte_size()
      atom_count_after = :erlang.system_info(:atom_count)
      memory_after = :erlang.memory(:total)

      checks = [
        check("complete OTP static inventory", scan_result.status == :complete),
        check("isolated OTP inventory is complete", isolated_result.status == :complete),
        check("OTP source definition localized", length(source_definitions) == 1),
        check("OTP dependency use attributed", package_facts != []),
        check("GenServer request receives an OTP behavior", length(otp_requests) == 1),
        check("cross-process sink remains statically visible", length(sink_calls) == 1),
        check("bounded graph reaches the request API", expected.request_function in graph.nodes),
        check(
          "bounded graph preserves missing runtime dispatch",
          expected.sink_function not in graph.nodes
        ),
        check("cross-process candidate keeps flow uncertainty", candidate.flow_basis == :unknown),
        check("unsupported process scope is inconclusive", result.verdict == :inconclusive),
        check("unsupported process scope does not execute", not execution_called?),
        check("unsupported process scope produces no findings", result.findings == []),
        check(
          "unsupported reason is explicit",
          result.evidence.facts.reason == :unsupported_process_scope and
            result.evidence.facts.execution == :not_started
        ),
        check(
          "required and supported process scopes remain distinct",
          result.evidence.facts.required_process_scope == :cross_process and
            result.evidence.facts.supported_process_scope == :single_process
        ),
        check(
          "unsupported result retains the static candidate",
          result.evidence.facts.static_candidate.id == candidate.id
        ),
        check(
          "unsupported scope replay is deterministic",
          replay.verdict == result.verdict and replay.seed.id == result.seed.id and
            not replay_execution_called?
        ),
        check("OTP graph did not truncate", not graph.truncated),
        check(
          "OTP scan meets wall-time budget",
          scan_us <= evaluation_case.budgets.max_scan_ms * 1_000
        ),
        check(
          "isolated OTP scan meets wall-time budget",
          isolated_scan_us <= evaluation_case.budgets.max_isolated_scan_ms * 1_000
        ),
        check(
          "OTP query meets p95 budget",
          query_p95_us <= evaluation_case.budgets.max_query_p95_us
        ),
        check(
          "OTP artifact meets byte budget",
          artifact.bytes <= evaluation_case.budgets.max_artifact_bytes
        ),
        check(
          "OTP evidence meets context budget",
          model_evidence_bytes <= evaluation_case.budgets.max_model_evidence_bytes
        )
      ]

      %{
        schema_version: 1,
        case_id: evaluation_case.id,
        tier: evaluation_case.tier,
        status: if(Enum.all?(checks, & &1.passed), do: :passed, else: :failed),
        checks: checks,
        accuracy: %{
          checks_passed: Enum.count(checks, & &1.passed),
          checks_total: length(checks),
          explicit_ambiguities: ambiguity_count(inventory),
          unsupported_scope_verdict: result.verdict,
          false_confirmations: if(result.verdict == :confirmed, do: 1, else: 0),
          replay_success:
            replay.verdict == result.verdict and replay.seed.id == result.seed.id and
              not replay_execution_called?
        },
        efficiency: %{
          source_bytes: scan_result.metrics.source_bytes,
          source_count: scan_result.metrics.source_count,
          fact_count: scan_result.metrics.fact_count,
          scan_us: scan_us,
          isolated_scan_us: isolated_scan_us,
          isolated_worker_memory_bytes: isolated_result.worker["memory_bytes"],
          isolated_worker_os_peak_rss_bytes: isolated_result.worker["os_peak_rss_bytes"],
          isolated_worker_cgroup_memory_peak_bytes:
            isolated_result.worker["cgroup_memory_peak_bytes"],
          isolated_worker_atom_count: isolated_result.worker["atom_count"],
          graph_us: graph_us,
          query_p95_us: query_p95_us,
          artifact_us: artifact_us,
          artifact_bytes: artifact.bytes,
          model_evidence_bytes: model_evidence_bytes,
          host_atom_growth: atom_count_after - atom_count_before,
          host_memory_delta_bytes: memory_after - memory_before
        },
        usefulness: %{
          bounded_queries: 4,
          sink_candidates: length(sink_calls),
          selected_sink_candidates: 1,
          candidate_reduction_ratio: 1.0,
          graph_nodes: length(graph.nodes),
          graph_edges: length(graph.edges),
          graph_truncated: graph.truncated,
          compatible_proof_actions: 0,
          replayable_verdicts: 1,
          required_process_scope: :cross_process,
          artifact_id: artifact.id,
          inventory_id: inventory.id
        },
        provenance: %{
          target_checksum: target_component.checksum,
          dependency_checksum: component_checksum(dependency_component),
          static_candidate: StaticCandidate.to_map(candidate)
        }
      }
    after
      RampartEvaluation.Provider.clear()
    end
  end

  defp evaluate_historical_regression(evaluation_case) do
    atom_count_before = :erlang.system_info(:atom_count)
    memory_before = :erlang.memory(:total)
    {components, target_component, _dependency_component} = components(evaluation_case)
    expected = evaluation_case.expected

    {scan_us, scan_result} = timed(fn -> Workspace.inventory(components) end)
    inventory = scan_result.inventory

    {isolated_scan_us, isolated_result} =
      timed(fn ->
        Isolated.inventory(isolation_root(evaluation_case), include: ["*.ex"])
      end)

    candidate_calls =
      Inventory.query(inventory, kind: :call, object: expected.candidate_function)

    vulnerable_calls =
      Enum.filter(candidate_calls, &(&1.subject == expected.vulnerable_function))

    fixed_calls = Enum.filter(candidate_calls, &(&1.subject == expected.fixed_function))

    upstream_vulnerable_calls =
      Enum.filter(candidate_calls, fn fact ->
        fact.subject == expected.upstream_function and
          fact.attributes.origin.path == expected.upstream_vulnerable_path
      end)

    upstream_fixed_calls =
      Enum.filter(candidate_calls, fn fact ->
        fact.subject == expected.upstream_function and
          fact.attributes.origin.path == expected.upstream_fixed_path
      end)

    upstream_vulnerable_sha256 = source_sha256(expected.upstream_vulnerable_path)
    upstream_fixed_sha256 = source_sha256(expected.upstream_fixed_path)

    {query_us, _facts} =
      timed(fn -> Inventory.query(inventory, object: expected.candidate_function) end)

    {artifact_us, artifact} = timed(fn -> Artifact.encode(inventory) end)

    vulnerable_rejected? = expected.vulnerable_module.invalid_path?([expected.input])
    fixed_rejected? = expected.fixed_module.invalid_path?([expected.input])
    replay_vulnerable? = expected.vulnerable_module.invalid_path?([expected.input])
    replay_fixed? = expected.fixed_module.invalid_path?([expected.input])

    replay_success? =
      replay_vulnerable? == vulnerable_rejected? and replay_fixed? == fixed_rejected?

    evidence = %{
      advisory: evaluation_case.provenance.advisory,
      vulnerable_revision: evaluation_case.provenance.vulnerable_revision,
      fixed_revision: evaluation_case.provenance.fixed_revision,
      input_sha256: sha256(expected.input),
      static_candidate_count: length(candidate_calls),
      upstream_vulnerable_sha256: upstream_vulnerable_sha256,
      upstream_fixed_sha256: upstream_fixed_sha256,
      vulnerable_rejected: vulnerable_rejected?,
      fixed_rejected: fixed_rejected?
    }

    model_evidence_bytes = evidence |> Wire.json() |> JSON.encode!() |> byte_size()
    atom_count_after = :erlang.system_info(:atom_count)
    memory_after = :erlang.memory(:total)

    checks = [
      check("historical static inventory is complete", scan_result.status == :complete),
      check("historical isolated inventory is complete", isolated_result.status == :complete),
      check("vulnerable adapted candidate is retained", length(vulnerable_calls) == 1),
      check("fixed adapted candidate is retained", length(fixed_calls) == 1),
      check(
        "vulnerable upstream source candidate is retained",
        length(upstream_vulnerable_calls) == 1
      ),
      check("fixed upstream source candidate is retained", length(upstream_fixed_calls) == 1),
      check(
        "adapted static candidate does not invent patch semantics",
        static_call_shape(vulnerable_calls) == static_call_shape(fixed_calls)
      ),
      check(
        "upstream static candidate does not invent patch semantics",
        static_call_shape(upstream_vulnerable_calls) == static_call_shape(upstream_fixed_calls)
      ),
      check(
        "upstream vulnerable source matches its pinned digest",
        upstream_vulnerable_sha256 == expected.upstream_vulnerable_sha256
      ),
      check(
        "upstream fixed source matches its pinned digest",
        upstream_fixed_sha256 == expected.upstream_fixed_sha256
      ),
      check(
        "historical snapshots have distinct hashes",
        distinct_source_hashes?(vulnerable_calls, fixed_calls)
      ),
      check("vulnerable predicate accepts the null-byte segment", vulnerable_rejected? == false),
      check("fixed predicate rejects the null-byte segment", fixed_rejected? == true),
      check("historical predicate replay is deterministic", replay_success?),
      check(
        "historical fixture is pinned to a disclosed advisory",
        valid_historical_provenance?(evaluation_case.provenance)
      ),
      check(
        "historical graph artifact is content addressed",
        String.starts_with?(artifact.id, "sha256:")
      ),
      check(
        "historical scan meets wall-time budget",
        scan_us <= evaluation_case.budgets.max_scan_ms * 1_000
      ),
      check(
        "isolated historical scan meets wall-time budget",
        isolated_scan_us <= evaluation_case.budgets.max_isolated_scan_ms * 1_000
      ),
      check(
        "historical query meets budget",
        query_us <= evaluation_case.budgets.max_query_p95_us
      ),
      check(
        "historical artifact meets byte budget",
        artifact.bytes <= evaluation_case.budgets.max_artifact_bytes
      ),
      check(
        "historical evidence meets context budget",
        model_evidence_bytes <= evaluation_case.budgets.max_model_evidence_bytes
      )
    ]

    selected_candidate_count =
      length(vulnerable_calls) + length(fixed_calls) + length(upstream_vulnerable_calls) +
        length(upstream_fixed_calls)

    %{
      schema_version: 1,
      case_id: evaluation_case.id,
      tier: evaluation_case.tier,
      status: if(Enum.all?(checks, & &1.passed), do: :passed, else: :failed),
      checks: checks,
      accuracy: %{
        checks_passed: Enum.count(checks, & &1.passed),
        checks_total: length(checks),
        explicit_ambiguities: ambiguity_count(inventory),
        vulnerable_rejected: vulnerable_rejected?,
        fixed_rejected: fixed_rejected?,
        false_confirmations: 0,
        replay_success: replay_success?
      },
      efficiency: %{
        source_bytes: scan_result.metrics.source_bytes,
        source_count: scan_result.metrics.source_count,
        fact_count: scan_result.metrics.fact_count,
        scan_us: scan_us,
        isolated_scan_us: isolated_scan_us,
        isolated_worker_memory_bytes: isolated_result.worker["memory_bytes"],
        isolated_worker_os_peak_rss_bytes: isolated_result.worker["os_peak_rss_bytes"],
        isolated_worker_cgroup_memory_peak_bytes:
          isolated_result.worker["cgroup_memory_peak_bytes"],
        isolated_worker_atom_count: isolated_result.worker["atom_count"],
        graph_us: 0,
        query_p95_us: query_us,
        artifact_us: artifact_us,
        artifact_bytes: artifact.bytes,
        model_evidence_bytes: model_evidence_bytes,
        host_atom_growth: atom_count_after - atom_count_before,
        host_memory_delta_bytes: memory_after - memory_before
      },
      usefulness: %{
        bounded_queries: 1,
        sink_candidates: length(candidate_calls),
        selected_sink_candidates: selected_candidate_count,
        candidate_reduction_ratio: ratio(selected_candidate_count, length(candidate_calls)),
        graph_nodes: 0,
        graph_edges: 0,
        graph_truncated: false,
        compatible_proof_actions: 1,
        replayable_verdicts: 2,
        artifact_id: artifact.id,
        inventory_id: inventory.id
      },
      provenance: Map.put(evaluation_case.provenance, :target_checksum, target_component.checksum)
    }
  end

  defp evaluate_historical_contract_regression(evaluation_case) do
    atom_count_before = :erlang.system_info(:atom_count)
    memory_before = :erlang.memory(:total)
    {components, target_component, _dependency_component} = components(evaluation_case)
    expected = evaluation_case.expected

    {scan_us, scan_result} =
      timed(fn -> Workspace.inventory(components, scan_options(evaluation_case)) end)

    inventory = scan_result.inventory

    {isolated_scan_us, isolated_result} =
      timed(fn ->
        Isolated.inventory(
          isolation_root(evaluation_case),
          Keyword.put(scan_options(evaluation_case), :include, ["*.ex"])
        )
      end)

    static_facts =
      inventory
      |> Inventory.query(kind: expected.static_kind, object: expected.static_object)
      |> Enum.filter(&(&1.subject in expected.static_subjects))

    expression_facts = historical_expression_facts(inventory, static_facts, expected)
    behavior_facts = historical_behavior_facts(inventory, expected)
    control_facts = historical_control_facts(inventory, expected)

    {query_us, _facts} =
      timed(fn ->
        Inventory.query(inventory, kind: expected.static_kind, object: expected.static_object)
      end)

    {artifact_us, artifact} = timed(fn -> Artifact.encode(inventory) end)
    validation = historical_contract_validation(evaluation_case)

    model_evidence_bytes =
      validation.confirmed |> Wire.result() |> Wire.encode!() |> byte_size()

    atom_count_after = :erlang.system_info(:atom_count)
    memory_after = :erlang.memory(:total)
    replay_success = historical_contract_replay_success?(validation)

    checks = [
      check("historical contract inventory is complete", scan_result.status == :complete),
      check(
        "historical contract isolated inventory is complete",
        isolated_result.status == :complete
      ),
      check(
        "vulnerable and fixed static relationship facts are retained",
        length(static_facts) == length(expected.static_subjects) and
          Enum.sort(Enum.map(static_facts, & &1.subject)) == Enum.sort(expected.static_subjects)
      ),
      check(
        "bounded expression facts expose the hypothesis input",
        useful_historical_expressions?(expression_facts, expected)
      ),
      check(
        "reviewed package behavior exposes the contract boundary when configured",
        useful_historical_behavior?(behavior_facts, expected)
      ),
      check(
        "vulnerable and fixed controls remain separately queryable when modeled",
        useful_historical_controls?(control_facts)
      ),
      check("vulnerable contract execution confirms", validation.confirmed.verdict == :confirmed),
      check(
        "confirmed finding retains the exact contract category",
        confirmed_category(validation.confirmed) == expected.finding_category
      ),
      check(
        "confirmed evidence names the exact oracle",
        validation.confirmed.evidence.facts.oracle_names == [expected.oracle]
      ),
      check(
        "fixed negative control refutes without findings",
        validation.fixed.verdict == :refuted and validation.fixed.findings == []
      ),
      check(
        "fixed negative control exercised the exact oracle",
        validation.fixed.evidence.facts.oracle_names == [expected.oracle]
      ),
      check(
        "harness failure is inconclusive without findings",
        validation.failure.verdict == :inconclusive and validation.failure.findings == []
      ),
      check("historical contract replay is deterministic", replay_success),
      check(
        "historical contract has no false confirmations",
        Enum.all?([validation.fixed, validation.failure], &(&1.verdict != :confirmed))
      ),
      check(
        "historical contract fixture has pinned disclosed provenance",
        valid_contract_provenance?(evaluation_case.provenance)
      ),
      check(
        "historical contract artifact is content addressed",
        String.starts_with?(artifact.id, "sha256:")
      ),
      check(
        "historical contract scan meets wall-time budget",
        scan_us <= evaluation_case.budgets.max_scan_ms * 1_000
      ),
      check(
        "isolated historical contract scan meets wall-time budget",
        isolated_scan_us <= evaluation_case.budgets.max_isolated_scan_ms * 1_000
      ),
      check(
        "historical contract query meets budget",
        query_us <= evaluation_case.budgets.max_query_p95_us
      ),
      check(
        "historical contract artifact meets byte budget",
        artifact.bytes <= evaluation_case.budgets.max_artifact_bytes
      ),
      check(
        "historical contract evidence meets context budget",
        model_evidence_bytes <= evaluation_case.budgets.max_model_evidence_bytes
      )
    ]

    false_confirmations =
      Enum.count([validation.fixed, validation.failure], &(&1.verdict == :confirmed))

    %{
      schema_version: 1,
      case_id: evaluation_case.id,
      tier: evaluation_case.tier,
      status: if(Enum.all?(checks, & &1.passed), do: :passed, else: :failed),
      checks: checks,
      accuracy: %{
        checks_passed: Enum.count(checks, & &1.passed),
        checks_total: length(checks),
        explicit_ambiguities: ambiguity_count(inventory),
        vulnerable_verdict: validation.confirmed.verdict,
        patched_verdict: validation.fixed.verdict,
        failure_verdict: validation.failure.verdict,
        false_confirmations: false_confirmations,
        replay_success: replay_success
      },
      efficiency: %{
        source_bytes: scan_result.metrics.source_bytes,
        source_count: scan_result.metrics.source_count,
        fact_count: scan_result.metrics.fact_count,
        scan_us: scan_us,
        isolated_scan_us: isolated_scan_us,
        isolated_worker_memory_bytes: isolated_result.worker["memory_bytes"],
        isolated_worker_os_peak_rss_bytes: isolated_result.worker["os_peak_rss_bytes"],
        isolated_worker_cgroup_memory_peak_bytes:
          isolated_result.worker["cgroup_memory_peak_bytes"],
        isolated_worker_atom_count: isolated_result.worker["atom_count"],
        graph_us: 0,
        query_p95_us: query_us,
        artifact_us: artifact_us,
        artifact_bytes: artifact.bytes,
        model_evidence_bytes: model_evidence_bytes,
        host_atom_growth: atom_count_after - atom_count_before,
        host_memory_delta_bytes: memory_after - memory_before
      },
      usefulness: %{
        bounded_queries: 2,
        sink_candidates: length(static_facts),
        selected_sink_candidates: length(expression_facts),
        candidate_reduction_ratio: ratio(length(expression_facts), length(static_facts)),
        graph_nodes: 0,
        graph_edges: 0,
        graph_truncated: false,
        compatible_proof_actions: 1,
        replayable_verdicts: 2,
        artifact_id: artifact.id,
        inventory_id: inventory.id
      },
      provenance: Map.put(evaluation_case.provenance, :target_checksum, target_component.checksum)
    }
  end

  defp historical_control_facts(inventory, expected) do
    expected
    |> Map.get(:static_controls, [])
    |> Enum.map(fn control ->
      facts =
        Inventory.query(inventory,
          kind: control.kind,
          object: control.object,
          subject: control.subject
        )

      {control, facts}
    end)
  end

  defp useful_historical_controls?([]), do: true

  defp useful_historical_controls?(controls) do
    Enum.all?(controls, fn
      {expected, [fact]} ->
        expression = fact.attributes.expression

        expression.kind == expected.expression_kind and
          optional_equal?(expression.preview, Map.get(expected, :preview)) and
          optional_contains?(expression.preview, Map.get(expected, :preview_contains)) and
          optional_equal?(
            fact.attributes.source_variables,
            Map.get(expected, :source_variables)
          )

      {_expected, _facts} ->
        false
    end)
  end

  defp optional_equal?(_actual, nil), do: true
  defp optional_equal?(actual, expected), do: actual == expected
  defp optional_contains?(_actual, nil), do: true
  defp optional_contains?(actual, expected), do: String.contains?(actual, expected)

  defp historical_behavior_facts(inventory, expected) do
    case Map.get(expected, :static_behavior) do
      nil ->
        []

      behavior ->
        inventory
        |> Inventory.query(kind: :behavior, object: behavior)
        |> Enum.filter(&(&1.subject in expected.static_subjects))
    end
  end

  defp useful_historical_behavior?([], expected),
    do: is_nil(Map.get(expected, :static_behavior))

  defp useful_historical_behavior?(facts, expected) do
    length(facts) == length(expected.static_subjects) and
      Enum.sort(Enum.map(facts, & &1.subject)) == Enum.sort(expected.static_subjects) and
      Enum.all?(facts, &(&1.attributes.basis == :reviewed_package_api))
  end

  defp historical_expression_facts(inventory, static_facts, expected) do
    case Map.get(expected, :static_argument_position) do
      nil ->
        static_facts

      position ->
        inventory
        |> Inventory.query(
          kind: :call_argument,
          object: "#{expected.static_object}#argument/#{position}"
        )
        |> Enum.filter(&(&1.subject in expected.static_subjects))
    end
  end

  defp useful_historical_expressions?(facts, expected) do
    length(facts) == length(expected.static_subjects) and
      Enum.sort(Enum.map(facts, & &1.subject)) == Enum.sort(expected.static_subjects) and
      Enum.all?(facts, fn fact ->
        fact.attributes.expression.kind == expected.static_expression_kind and
          expected.static_source_variable in fact.attributes.source_variables and
          byte_size(fact.attributes.expression.preview) <= 240
      end)
  end

  defp historical_contract_validation(evaluation_case) do
    expected = evaluation_case.expected

    seed = %Core.Seed{
      id: Core.Finding.dedupe_id(:havoc, ["historical_contract", evaluation_case.id]),
      value: expected.input,
      classes: [:historical_regression, expected.finding_category],
      provenance: :historical_regression,
      meta: %{case: evaluation_case.id, advisory: evaluation_case.provenance.advisory}
    }

    property_options = [
      property_id: "evaluation:#{evaluation_case.id}",
      property_name: "historical contract #{evaluation_case.id}",
      module: __MODULE__,
      oracles: [expected.oracle],
      locus: %{
        case_id: evaluation_case.id,
        advisory: evaluation_case.provenance.advisory,
        project: evaluation_case.provenance.project
      },
      replay: false,
      persist: false
    ]

    vulnerable_target =
      historical_contract_target(
        expected.runtime_module,
        expected.runtime_vulnerable_function,
        expected.observation_shape
      )

    fixed_target =
      historical_contract_target(
        expected.runtime_module,
        expected.runtime_fixed_function,
        expected.observation_shape
      )

    confirmed = Havoc.validate(seed, vulnerable_target, property_options)
    fixed = Havoc.validate(seed, fixed_target, property_options)

    failure =
      Havoc.validate(
        seed,
        fn _input -> raise "deliberate historical contract harness failure" end,
        property_options
      )

    %{
      confirmed: confirmed,
      fixed: fixed,
      failure: failure,
      replay_confirmed: Havoc.validate(seed, vulnerable_target, property_options),
      replay_fixed: Havoc.validate(seed, fixed_target, property_options)
    }
  end

  defp historical_contract_target(module, function, :direct) do
    fn input -> apply(module, function, [input]) end
  end

  defp historical_contract_target(module, function, :terminal_output) do
    fn input -> %{terminal_output: apply(module, function, [input])} end
  end

  defp historical_contract_replay_success?(validation) do
    validation.confirmed.verdict == validation.replay_confirmed.verdict and
      validation.fixed.verdict == validation.replay_fixed.verdict and
      validation.confirmed.seed.id == validation.replay_confirmed.seed.id and
      validation.fixed.seed.id == validation.replay_fixed.seed.id
  end

  defp components(evaluation_case) do
    target =
      Component.new!(
        id: "evaluation-target",
        kind: :target,
        sources: read_sources(evaluation_case.target_sources)
      )

    case evaluation_case.dependency_sources do
      [] ->
        {[target], target, nil}

      dependency_sources ->
        dependency =
          Component.new!(
            id: "evaluation-dependency",
            kind: :dependency,
            package: evaluation_case.expected.dependency_package,
            version: "1.0.0-fixture",
            sources: read_sources(dependency_sources)
          )

        {[target, dependency], target, dependency}
    end
  end

  defp read_sources(paths), do: Enum.map(paths, &{&1, File.read!(&1)})

  defp isolation_root(evaluation_case),
    do: evaluation_case.target_sources |> hd() |> Path.dirname()

  defp scan_options(evaluation_case), do: Map.get(evaluation_case, :scan_options, [])
  defp component_checksum(nil), do: nil
  defp component_checksum(component), do: component.checksum

  defp build_overhead_candidate!(inventory, source_definition, sink_call, expected) do
    unless source_definition && sink_call do
      raise "evaluation cannot build an overhead candidate from missing source or sink facts"
    end

    StaticCandidate.new!(
      id: expected.candidate_id,
      schema_version: 1,
      context: :library,
      source_id: "evaluation.callback-argument.v1",
      sink_id: expected.sink_id,
      source_sites: [source_span(source_definition)],
      sink_sites: [source_span(sink_call)],
      flow_basis: :value_dependence,
      sanitizer_status: :none_observed,
      localization: :unique_static_call_site,
      provenance:
        StaticProvenance.new!(
          analyzer: "rampart_evaluation",
          analyzer_version: "1",
          rule_id: "evaluation.targeted-trace-overhead.v1",
          source_revision: inventory.id,
          plugins: %{}
        )
    )
  end

  defp build_otp_candidate!(inventory, source_definition, sink_call, expected) do
    unless source_definition && sink_call do
      raise "evaluation cannot build an OTP candidate from missing source or sink facts"
    end

    StaticCandidate.new!(
      id: expected.candidate_id,
      schema_version: 1,
      context: :library,
      source_id: "evaluation.callback-argument.v1",
      sink_id: expected.sink_id,
      source_sites: [source_span(source_definition)],
      sink_sites: [source_span(sink_call)],
      flow_basis: :unknown,
      sanitizer_status: :none_observed,
      localization: :unique_static_call_site,
      provenance:
        StaticProvenance.new!(
          analyzer: "rampart_sast",
          analyzer_version: application_version!(:rampart_sast),
          rule_id: "evaluation.otp-request-boundary.v1",
          source_revision: inventory.id,
          plugins: %{"beam_behavior" => "1", "otp_boundary" => "1"}
        )
    )
  end

  defp build_candidate!(inventory, source_definition, sink_calls, expected) do
    unless source_definition && sink_calls != [] do
      raise "evaluation cannot build a static candidate from missing source or sink facts"
    end

    StaticCandidate.new!(
      id: expected.candidate_id,
      schema_version: 1,
      context: :library,
      source_id: "evaluation.callback-argument.v1",
      sink_id: expected.sink_id,
      source_sites: [source_span(source_definition)],
      sink_sites: Enum.map(sink_calls, &source_span/1),
      flow_basis: :unknown,
      sanitizer_status: :none_observed,
      localization: expected.localization,
      provenance:
        StaticProvenance.new!(
          analyzer: "rampart_sast",
          analyzer_version: application_version!(:rampart_sast),
          rule_id: "evaluation.bounded-call-graph.v1",
          source_revision: inventory.id,
          plugins: %{"beam_behavior" => "1"}
        )
    )
  end

  defp source_span(fact) do
    SourceSpan.new!(
      file: fact.attributes.origin.path,
      start_line: fact.span.start_line,
      start_column: fact.span.start_column,
      end_line: fact.span.end_line,
      end_column: fact.span.end_column
    )
  end

  defp validate_runtime(candidate, evaluation_case) do
    expected = evaluation_case.expected
    marker = evaluation_marker(candidate, expected.sink_category)

    seed = %Core.Seed{
      id: Core.Finding.dedupe_id(:iast, ["evaluation", marker]),
      value: marker,
      classes: [:exact_marker, :evaluation],
      provenance: :generated,
      meta: %{case: evaluation_case.id}
    }

    hypothesis =
      RampartIAST.hypothesis!(
        RampartEvaluation.Provider,
        candidate.id,
        seed,
        claim: "callback input reaches the #{expected.sink_category} sink unchanged"
      )

    confirmed =
      RampartIAST.validate(hypothesis,
        provider: RampartEvaluation.Provider,
        execute: execute_function(expected.runtime_module, expected.runtime_function)
      )

    patched =
      RampartIAST.validate(hypothesis,
        provider: RampartEvaluation.Provider,
        execute: execute_function(expected.runtime_module, expected.runtime_patched_function)
      )

    failure =
      RampartIAST.validate(hypothesis,
        provider: RampartEvaluation.Provider,
        execute: fn _marker -> raise "deliberate evaluation callback failure" end
      )

    replay_confirmed =
      RampartIAST.validate(hypothesis,
        provider: RampartEvaluation.Provider,
        execute: execute_function(expected.runtime_module, expected.runtime_function)
      )

    replay_patched =
      RampartIAST.validate(hypothesis,
        provider: RampartEvaluation.Provider,
        execute: execute_function(expected.runtime_module, expected.runtime_patched_function)
      )

    %{
      hypothesis: hypothesis,
      confirmed: confirmed,
      patched: patched,
      failure: failure,
      replay_confirmed: replay_confirmed,
      replay_patched: replay_patched
    }
  end

  defp unsupported_process_validation(candidate, evaluation_case) do
    marker = "rampart-otp-marker-#{candidate.provenance.source_revision}"

    seed = %Core.Seed{
      id: Core.Finding.dedupe_id(:iast, ["otp_evaluation", marker]),
      value: marker,
      classes: [:exact_marker, :evaluation, :cross_process],
      provenance: :generated,
      meta: %{case: evaluation_case.id}
    }

    hypothesis =
      RampartIAST.hypothesis!(RampartEvaluation.Provider, candidate.id, seed,
        claim: "callback input reaches a sink after a GenServer request",
        meta: %{required_process_scope: :cross_process}
      )

    caller = self()
    execution_ref = make_ref()

    result =
      RampartIAST.validate(hypothesis,
        provider: RampartEvaluation.Provider,
        execute: fn value ->
          send(caller, {:otp_evaluation_executed, execution_ref})
          RampartEvaluation.OTP.Target.run(value)
        end
      )

    execution_called? =
      receive do
        {:otp_evaluation_executed, ^execution_ref} -> true
      after
        0 -> false
      end

    {result, execution_called?}
  end

  defp evaluation_seed(case_id, marker) do
    %Core.Seed{
      id: Core.Finding.dedupe_id(:iast, ["evaluation", case_id, marker]),
      value: marker,
      classes: [:exact_marker, :evaluation],
      provenance: :generated,
      meta: %{case: case_id}
    }
  end

  defp evaluation_marker(candidate, :unsafe_deserialization_boundary) do
    :erlang.term_to_binary(%{
      "rampart_evaluation_marker" => candidate.id,
      "source_revision" => candidate.provenance.source_revision
    })
  end

  defp evaluation_marker(candidate, _category) do
    "rampart-evaluation-marker-#{candidate.id}-#{candidate.provenance.source_revision}"
  end

  defp execute_function(module, function) do
    fn marker -> apply(module, function, [marker]) end
  end

  defp checks(evaluation_case, observed) do
    budgets = evaluation_case.budgets
    expected = evaluation_case.expected
    validation = observed.validation

    [
      check("complete static inventory", observed.scan_result.status == :complete),
      check(
        "isolated static inventory is complete",
        observed.isolated_result.status == :complete
      ),
      check(
        "isolated worker reports bounded VM metrics",
        is_integer(observed.isolated_result.worker["memory_bytes"])
      ),
      check("expected callback indexed", length(observed.callback_facts) == 1),
      check("callback implementation linked", length(observed.implementation_facts) == 1),
      check("dependency use attributed", observed.package_facts != []),
      check("source definition localized", length(observed.source_definitions) == 1),
      check(
        "sink candidates retained",
        length(observed.sink_calls) == expected.sink_candidate_count
      ),
      check(
        "real sink receives a typed behavior",
        length(observed.behavior_facts) == expected.selected_sink_candidate_count
      ),
      check(
        "sink candidate narrowed by enclosing function",
        length(observed.selected_sink_calls) == expected.selected_sink_candidate_count
      ),
      check(
        "bounded graph reaches dependency",
        expected.dependency_function in observed.graph.nodes
      ),
      check("bounded graph reaches sink", expected.sink_function in observed.graph.nodes),
      check("bounded graph did not truncate", not observed.graph.truncated),
      check(
        "candidate keeps static uncertainty explicit",
        observed.candidate.flow_basis == :unknown and
          observed.candidate.localization == expected.localization
      ),
      check("vulnerable execution confirms", validation.confirmed.verdict == :confirmed),
      check(
        "confirmed finding retains the sink category",
        confirmed_category(validation.confirmed) == expected.sink_category
      ),
      check(
        "runtime evidence retains the static candidate",
        get_in(validation.confirmed.evidence.facts, [:static_candidate, :id]) ==
          observed.candidate.id
      ),
      check(
        "runtime evidence retains reviewed sink provenance",
        get_in(validation.confirmed.evidence.facts, [:sink_provenance, :origin]) ==
          :reviewed_evaluation_provider
      ),
      check(
        "runtime finding respects static localization",
        valid_runtime_localization?(validation.confirmed, observed.candidate)
      ),
      check(
        "patched execution refutes without findings",
        validation.patched.verdict == :refuted and validation.patched.findings == []
      ),
      check(
        "callback failure is inconclusive without findings",
        validation.failure.verdict == :inconclusive and validation.failure.findings == []
      ),
      check("replay reproduces verdicts", replay_success?(validation)),
      check(
        "no false confirmations",
        Enum.all?([validation.patched, validation.failure], &(&1.verdict != :confirmed))
      ),
      check("scan meets wall-time budget", observed.scan_us <= budgets.max_scan_ms * 1_000),
      check(
        "isolated scan meets wall-time budget",
        observed.isolated_scan_us <= budgets.max_isolated_scan_ms * 1_000
      ),
      check("query meets p95 budget", observed.query_p95_us <= budgets.max_query_p95_us),
      check("artifact meets byte budget", observed.artifact.bytes <= budgets.max_artifact_bytes),
      check(
        "evidence meets context budget",
        observed.model_evidence_bytes <= budgets.max_model_evidence_bytes
      )
    ]
  end

  defp query_samples(inventory, sink_function) do
    Enum.map(1..25, fn _iteration ->
      {elapsed, _facts} = timed(fn -> Inventory.query(inventory, object: sink_function) end)
      elapsed
    end)
  end

  defp percentile(samples, percentile) do
    sorted = Enum.sort(samples)
    index = ceil(length(sorted) * percentile / 100) - 1
    Enum.at(sorted, max(index, 0))
  end

  defp static_call_shape([fact]) do
    {
      fact.object,
      fact.attributes.argument_shapes,
      fact.attributes.arity,
      fact.attributes.resolution
    }
  end

  defp static_call_shape(_facts), do: nil

  defp distinct_source_hashes?([vulnerable], [fixed]) do
    vulnerable.source_hash != fixed.source_hash
  end

  defp distinct_source_hashes?(_vulnerable, _fixed), do: false

  defp valid_historical_provenance?(provenance) do
    Regex.match?(~r/^[0-9a-f]{40}$/, provenance.vulnerable_revision) and
      Regex.match?(~r/^[0-9a-f]{40}$/, provenance.fixed_revision) and
      provenance.advisory == "GHSA-2q6v-32mr-8p8x" and
      provenance.license == "Apache-2.0" and provenance.fixture_kind == :adapted_excerpt
  end

  defp valid_contract_provenance?(provenance) do
    Enum.all?([:project, :advisory, :source_path, :license], fn key ->
      value = Map.get(provenance, key)
      is_binary(value) and value != ""
    end) and
      Regex.match?(~r/^[0-9a-f]{40}$/, provenance.vulnerable_revision) and
      Regex.match?(~r/^[0-9a-f]{40}$/, provenance.fixed_revision) and
      provenance.vulnerable_revision != provenance.fixed_revision and
      provenance.fixture_kind == :adapted_predicate
  end

  defp sha256(value) do
    :sha256 |> :crypto.hash(value) |> Base.encode16(case: :lower)
  end

  defp source_sha256(path), do: path |> File.read!() |> sha256()

  defp ambiguity_count(inventory) do
    Enum.count(inventory.facts, fn fact ->
      Map.get(fact.attributes, :resolution) in [
        :ambiguous_import,
        :dynamic_dispatch,
        :local_or_imported
      ]
    end)
  end

  defp confirmed_category(%{findings: [finding]}), do: finding.category
  defp confirmed_category(_result), do: nil

  defp valid_runtime_localization?(result, %{localization: :unique_static_call_site} = candidate) do
    expected_span = candidate.sink_sites |> List.first() |> SourceSpan.to_map()
    confirmed_sink_span(result) == expected_span
  end

  defp valid_runtime_localization?(result, %{localization: :ambiguous}) do
    is_nil(confirmed_sink_span(result)) and result.meta.static_localization == :ambiguous
  end

  defp confirmed_sink_span(%{findings: [finding]}) do
    get_in(finding.locus, [:sink_source_span])
  end

  defp confirmed_sink_span(_result), do: nil

  defp distributed_frontier_valid?(%{status: :supported} = distributed, expected) do
    distributed.gate_satisfied and distributed.node_count == 2 and
      distributed.trace_session_count == 2 and distributed.delivery_barrier_count == 2 and
      distributed.flow_count == expected.distributed_flow_count and
      distributed.send_event_count == expected.distributed_flow_count and
      distributed.receive_event_count == expected.distributed_flow_count and
      distributed.acknowledged_count == expected.distributed_flow_count and
      distributed.joined_edge_count == expected.distributed_flow_count and
      distributed.false_join_count == 0 and
      distributed.correlation_basis == :explicit_distributed_message_envelope and
      distributed.local_runtime == distributed.remote_runtime and
      not distributed.cross_node_clock_order_used and
      not distributed.value_equality_used_as_provenance
  end

  defp distributed_frontier_valid?(%{status: :unavailable} = distributed, _expected) do
    not distributed.required and distributed.gate_satisfied and distributed.node_count == 1 and
      distributed.joined_edge_count == 0 and distributed.false_join_count == 0 and
      is_binary(distributed.reason) and distributed.reason != ""
  end

  defp distributed_frontier_valid?(_distributed, _expected), do: false

  defp probe_replay_shape(probe), do: strip_probe_timings(probe)

  defp strip_probe_timings(value) when is_map(value) do
    value
    |> Map.drop([:duration_us, :receiver_reductions])
    |> Map.new(fn {key, nested} -> {key, strip_probe_timings(nested)} end)
  end

  defp strip_probe_timings(value) when is_list(value), do: Enum.map(value, &strip_probe_timings/1)
  defp strip_probe_timings(value), do: value

  defp replay_success?(validation) do
    validation.confirmed.verdict == validation.replay_confirmed.verdict and
      validation.patched.verdict == validation.replay_patched.verdict and
      validation.confirmed.seed.id == validation.replay_confirmed.seed.id and
      validation.patched.seed.id == validation.replay_patched.seed.id
  end

  defp ratio(_selected, 0), do: 0.0
  defp ratio(selected, candidates), do: selected / candidates

  defp application_version!(application) do
    case Application.spec(application, :vsn) do
      nil -> raise "evaluation requires #{application} to be loaded"
      version -> to_string(version)
    end
  end

  defp timed(function) do
    started_at = System.monotonic_time()
    value = function.()
    elapsed = System.monotonic_time() - started_at
    {System.convert_time_unit(elapsed, :native, :microsecond), value}
  end

  defp check(name, passed), do: %{name: name, passed: passed}

  defp print_report(report) do
    IO.puts(
      "Rampart evaluation: #{String.upcase(to_string(report.status))} " <>
        "(#{report.summary.case_count} cases, " <>
        "#{report.summary.checks_passed}/#{report.summary.checks_total} checks)"
    )

    Enum.each(report.cases, &print_case/1)
  end

  defp print_case(report) do
    IO.puts("  #{report.case_id}: #{String.upcase(to_string(report.status))}")

    print_verdicts(report.accuracy)
    print_special_metrics(report.efficiency)

    IO.puts(
      "    efficiency: scan=#{report.efficiency.scan_us}us " <>
        "isolated=#{report.efficiency.isolated_scan_us}us " <>
        "query_p95=#{report.efficiency.query_p95_us}us " <>
        "artifact=#{report.efficiency.artifact_bytes}B"
    )

    IO.puts(
      "    usefulness: #{report.usefulness.sink_candidates} sink candidates -> " <>
        "#{report.usefulness.selected_sink_candidates}; " <>
        "#{report.usefulness.graph_nodes} graph nodes; replay=#{report.accuracy.replay_success}"
    )

    Enum.each(report.checks, fn check ->
      IO.puts("      [#{if(check.passed, do: "ok", else: "FAIL")}] #{check.name}")
    end)
  end

  defp print_verdicts(%{vulnerable_verdict: vulnerable} = accuracy) do
    IO.puts(
      "    verdicts: vulnerable=#{vulnerable} " <>
        "patched=#{accuracy.patched_verdict} failure=#{accuracy.failure_verdict}"
    )
  end

  defp print_verdicts(%{targeted_verdict: targeted, unsupported_scope_verdict: unsupported}) do
    IO.puts("    trace: targeted=#{targeted} broader_scope=#{unsupported}")
  end

  defp print_verdicts(%{probe_status: status, false_confirmations: false_joins}) do
    IO.puts("    probe: status=#{status} false_joins=#{false_joins}")
  end

  defp print_verdicts(%{unsupported_scope_verdict: verdict}) do
    IO.puts("    verdict: unsupported_process_scope=#{verdict}")
  end

  defp print_verdicts(%{vulnerable_rejected: vulnerable, fixed_rejected: fixed}) do
    IO.puts("    predicate: vulnerable_rejected=#{vulnerable} fixed_rejected=#{fixed}")
  end

  defp print_special_metrics(
         %{baseline_median_us: baseline, targeted_median_us: targeted} = efficiency
       ) do
    IO.puts(
      "    trace overhead: baseline_median=#{baseline}us targeted_median=#{targeted}us " <>
        "ratio=#{Float.round(efficiency.overhead_ratio, 2)}x"
    )
  end

  defp print_special_metrics(_efficiency), do: :ok
end
