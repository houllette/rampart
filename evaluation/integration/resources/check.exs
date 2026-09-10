Code.require_file("assertions.exs", System.fetch_env!("RAMPART_GATE_SUPPORT"))

defmodule Integration.Resources do
  import ExUnit.Assertions
  alias ResourceFixture.{Sink, Target}

  def run do
    previous = :erlang.system_flag(:scheduler_wall_time, true)

    try do
      cases =
        for concurrency <- [1, 2, 4],
            workload <- [:compute, :binary, :container, :io],
            mode <- [:disabled, :targeted] do
          measure(workload, mode, concurrency)
        end

      overflow!()
      cancellation!()
      sast = scan!()

      Integration.Assertions.finish(%{
        cases: cases,
        sast: sast,
        teardown_trials: 20,
        runtime: %{
          elixir: System.version(),
          otp: System.otp_release(),
          schedulers: System.schedulers_online(),
          architecture: to_string(:erlang.system_info(:system_architecture))
        },
        measurement:
          "sampled VM memory and node mailbox peaks at 10ms; node reductions/GC and scheduler wall time include instrumentation; OS RSS is sampled by the external runner; no hard memory cap or production safety claim"
      })
    after
      :erlang.system_flag(:scheduler_wall_time, previous)
    end
  end

  defp measure(workload, mode, concurrency) do
    fun = fn ->
      1..concurrency
      |> Task.async_stream(fn _ -> exercise(workload, mode) end,
        max_concurrency: concurrency,
        timeout: 10_000
      )
      |> Enum.each(fn result -> assert {:ok, :ok} = result end)
    end

    for _ <- 1..2, do: fun.()
    parent = self()
    sampler = spawn_link(fn -> sample(parent, %{memory_bytes: 0, mailbox_messages: 0}) end)
    before = counters()
    readings = for _ <- 1..7, do: elem(:timer.tc(fun), 0)
    after_sample = counters()
    send(sampler, :stop)

    peaks =
      receive do
        {:peaks, ^sampler, peaks} -> peaks
      after
        1000 -> raise "sampler failed"
      end

    sorted = Enum.sort(readings)

    %{
      workload: workload,
      mode: mode,
      concurrency: concurrency,
      samples_us: readings,
      median_us: Enum.at(sorted, 3),
      p95_us: List.last(sorted),
      sampled_peak_vm_bytes: peaks.memory_bytes,
      sampled_peak_mailbox_messages: peaks.mailbox_messages,
      node_reductions: after_sample.reductions - before.reductions,
      node_gcs: after_sample.gcs - before.gcs,
      scheduler_active_ratio: scheduler_ratio(before.schedulers, after_sample.schedulers)
    }
  end

  defp exercise(workload, :disabled) do
    Target.run(workload, "resource-marker")
    :ok
  end

  defp exercise(workload, :targeted) do
    result = trace(fn marker -> Target.run(workload, marker) end)
    assert result.envelope == :intact
    assert result.teardown == :ok
    assert result.event_count == 1
    assert Enum.any?(result.observations, &(&1.matched_positions == [1]))
    :ok
  end

  defp overflow! do
    result =
      trace(fn marker -> for _ <- 1..100_000, do: Sink.observe(marker) end,
        max_events: 20,
        max_mailbox_messages: 100
      )

    assert result.envelope == :incomplete
    assert result.teardown == :ok
    assert result.event_count <= 21
    assert result.limit_failures != []
  end

  defp cancellation! do
    for _ <- 1..20 do
      parent = self()

      task =
        Task.async(fn ->
          trace(fn _ ->
            send(parent, {:tracee, self()})
            Process.sleep(:infinity)
          end)
        end)

      target =
        receive do
          {:tracee, pid} -> pid
        after
          2000 -> raise "target did not start"
        end

      monitor = Process.monitor(target)
      Task.shutdown(task, :brutal_kill)
      assert_receive {:DOWN, ^monitor, :process, ^target, _}, 2000
      refute Process.alive?(target)
    end

    assert :ok = exercise(:compute, :targeted)
  end

  defp scan! do
    File.mkdir_p!("target/lib")

    for index <- 1..50 do
      calls = Enum.map_join(1..100, "\n", &" def f#{&1}(value), do: String.trim(value)")

      File.write!(
        "target/lib/module#{index}.ex",
        "defmodule ResourceFixture.M#{index} do\n#{calls}\nend\n"
      )
    end

    File.mkdir_p!("target/src")

    File.write!(
      "target/src/worker.erl",
      "-module(worker).\n-export([run/1]).\nrun(Value) -> erlang:byte_size(Value).\n"
    )

    profile = [max_heap_words: 32_000_000, max_wire_terms: 5_000_000]

    {elapsed, inventory} =
      :timer.tc(fn -> RampartSAST.Isolated.inventory("target", isolation: [limits: profile]) end)

    assert inventory.status == :complete, inspect(inventory.diagnostics)
    page = RampartSAST.Isolated.query_page(inventory, kind: :call, limit: 10)
    assert page.returned == 10
    assert page.total >= 5001
    assert inventory.inventory["source_count"] == 51
    assert page.next_offset == 10

    refused =
      RampartSAST.Isolated.inventory("target", isolation: [limits: [max_heap_words: 1024]])

    assert refused.status == :incomplete
    assert refused.inventory["facts"] == []

    %{
      elapsed_us: elapsed,
      isolation_limits: Map.new(profile),
      small_heap: "incomplete",
      inventory_id: inventory.inventory["id"],
      facts: length(inventory.inventory["facts"]),
      calls: page.total,
      fixture_hash:
        "target/{lib,src}/*"
        |> Path.wildcard()
        |> Enum.map(&File.read!/1)
        |> then(&:crypto.hash(:sha256, &1))
        |> Base.encode16(case: :lower)
    }
  end

  defp trace(execute, options \\ []) do
    source =
      RampartIAST.Source.new!(
        id: "resource.input.v1",
        schema_version: 1,
        context: :performance,
        category: :argument,
        extraction: %{type: :argument, position: 1},
        boundary: :function,
        provenance: %{}
      )

    sink =
      RampartIAST.Sink.new!(
        id: "resource.sink.v1",
        schema_version: 1,
        context: :performance,
        mfa: {Sink, :observe, 1},
        argument_positions: [1],
        category: :observation,
        sanitizer_expectations: [],
        severity: :info,
        rationale: "bounded resource fixture",
        provenance: %{}
      )

    limits =
      RampartIAST.Limits.new!(
        Keyword.merge(
          [timeout_ms: 5000, max_argument_bytes: 65_536, max_argument_terms: 8192],
          options
        )
      )

    RampartIAST.TraceSession.run("resources", source, sink, "resource-marker", execute, limits)
  end

  defp sample(parent, peaks) do
    mailbox =
      Process.list()
      |> Enum.map(&Process.info(&1, :message_queue_len))
      |> Enum.map(fn
        {:message_queue_len, count} -> count
        nil -> 0
      end)
      |> Enum.max(fn -> 0 end)

    peaks = %{
      memory_bytes: max(peaks.memory_bytes, :erlang.memory(:total)),
      mailbox_messages: max(peaks.mailbox_messages, mailbox)
    }

    receive do
      :stop -> send(parent, {:peaks, self(), peaks})
    after
      10 -> sample(parent, peaks)
    end
  end

  defp counters do
    %{
      reductions: elem(:erlang.statistics(:reductions), 0),
      gcs: elem(:erlang.statistics(:garbage_collection), 0),
      schedulers: :erlang.statistics(:scheduler_wall_time)
    }
  end

  defp scheduler_ratio(before, after_sample) do
    previous = Map.new(before, fn {id, active, total} -> {id, {active, total}} end)

    {active, total} =
      Enum.reduce(after_sample, {0, 0}, fn {id, active, total}, {sum_active, sum_total} ->
        {old_active, old_total} = Map.fetch!(previous, id)
        {sum_active + active - old_active, sum_total + total - old_total}
      end)

    if total == 0, do: nil, else: active / total
  end
end

Integration.Resources.run()
