Code.require_file("runtime.exs", __DIR__)

defmodule RampartPerformance.Sink do
  @moduledoc false
  def observe(value), do: value
end

defmodule RampartPerformance do
  @moduledoc false

  alias RampartSAST.{Graph, Inventory}

  def run!(arguments) do
    {opts, [], []} = OptionParser.parse(arguments, strict: [output: :string, samples: :integer])
    samples = Keyword.get(opts, :samples, 7)
    unless samples in 3..30, do: raise(ArgumentError, "samples must be between 3 and 30")
    output = Keyword.get(opts, :output, "tmp/rampart-performance.json")

    report = %{
      schema_version: 1,
      fixture_version: "rampart-performance.v1",
      harness_sha256: digest(File.read!(__ENV__.file)),
      runtime:
        Map.merge(RampartEvaluation.Runtime.provenance(), %{
          elixir: System.version(),
          otp: System.otp_release(),
          erts: List.to_string(:erlang.system_info(:version)),
          schedulers: System.schedulers_online(),
          architecture: :erlang.system_info(:system_architecture) |> List.to_string()
        }),
      policy: %{
        samples: samples,
        warmups: 2,
        gc_before_sample: true,
        memory: "process and VM endpoints; not peak RSS",
        reductions: "node-wide, includes child work and VM noise",
        scope:
          "trusted synthetic fixtures; latency includes result construction; no production IAST claim"
      },
      cases:
        graphs(samples) ++
          seeds(samples) ++ corpora(samples) ++ scanner(samples) ++ tracing(samples)
    }

    File.mkdir_p!(Path.dirname(output))
    File.write!(output, JSON.encode!(report))
    IO.puts("Performance evidence written to #{output} (#{length(report.cases)} cases)")
    report
  end

  def compare!(arguments) do
    {options, [before_path, after_path], []} =
      OptionParser.parse(arguments, strict: [output: :string])

    before = before_path |> File.read!() |> JSON.decode!()
    after_report = after_path |> File.read!() |> JSON.decode!()

    unless before["fixture_version"] == after_report["fixture_version"] and
             before["runtime"] == after_report["runtime"],
           do: raise(ArgumentError, "comparisons require matching fixtures and runtimes")

    baseline = Map.new(before["cases"], &{&1["name"], &1})

    cases =
      Enum.map(after_report["cases"], fn current ->
        previous = Map.fetch!(baseline, current["name"])

        unless previous["input"]["fixture_hash"] == current["input"]["fixture_hash"],
          do: raise(ArgumentError, "fixture hash changed for #{current["name"]}")

        %{
          name: current["name"],
          before_median_us: previous["median_us"],
          after_median_us: current["median_us"],
          speedup: ratio(previous["median_us"], current["median_us"])
        }
      end)

    unless map_size(baseline) == length(cases),
      do: raise(ArgumentError, "comparison case set changed")

    output = Keyword.get(options, :output, "tmp/rampart-performance-comparison.json")
    File.mkdir_p!(Path.dirname(output))

    File.write!(
      output,
      JSON.encode!(%{schema_version: 1, cases: cases, before: before_path, after: after_path})
    )

    IO.puts(
      "Performance comparison written to #{output}; ratios are observations, not release thresholds"
    )
  end

  defp ratio(_before, 0), do: nil
  defp ratio(before, after_sample), do: before / after_sample

  defp graphs(samples) do
    source = "defmodule Perf do\ndef run(x), do: String.trim(x)\nend\n"
    base = RampartSAST.inventory_sources([{"lib/perf.ex", source}]).inventory
    [prototype] = Inventory.query(base, kind: :call)

    Enum.flat_map([5_000, 20_000, 50_000, 250_000], fn count ->
      facts =
        for i <- 1..count,
            do: %{prototype | id: "edge-#{i}", subject: "node-#{i}", object: "node-#{i + 1}"}

      {index_us, inventory} = :timer.tc(fn -> index_inventory(base, facts) end)

      metadata = %{
        facts: count,
        fixture_hash: digest([source, Integer.to_string(count), "chain-v1"]),
        index_build_us: index_us
      }

      for depth <- [5, 50, 150] do
        measure("graph/#{count}/#{depth}", Map.put(metadata, :depth, depth), samples, fn ->
          slice =
            Graph.callees(inventory, "node-1",
              relations: [:calls],
              max_depth: depth,
              max_nodes: 200
            )

          unless length(slice.edges) == depth and length(slice.nodes) == depth + 1,
            do: raise("graph result changed")
        end)
      end
    end)
  end

  # The same harness can run against the pre-index revision for comparison.
  defp index_inventory(base, facts) do
    inventory = %{base | facts: facts}

    if Map.has_key?(inventory, :index) do
      Map.put(inventory, :index, apply(RampartSAST.Inventory.Index, :build, [facts]))
    else
      inventory
    end
  end

  defp seeds(samples) do
    raw =
      "apps/foray/test/fixtures/ffuf_v2_2.ndjson"
      |> File.read!()
      |> String.split("\n", trim: true)
      |> hd()
      |> Jason.decode!()

    for count <- [1_000, 10_000] do
      seeds =
        for i <- 1..count,
            do: %Core.Seed{id: "seed-#{i}", value: "value-#{i}", provenance: :wordlist}

      scan = Foray.target("https://app.example") |> Foray.fuzz_path(wordlist: seeds)
      [job] = Foray.JobBuilder.build(scan)

      {:ok, match} =
        raw
        |> Map.put("input", %{"FUZZ" => Base.encode64("value-#{count}")})
        |> Jason.encode!()
        |> Foray.NDJSON.parse_line()

      measure(
        "foray/projection/#{count}",
        %{seeds: count, matches: 1_000, fixture_hash: digest("last-seed-v1/#{count}")},
        samples,
        fn ->
          for _ <- 1..1_000 do
            finding = Foray.Finding.from_match(match, job)
            unless finding.seed.id == "seed-#{count}", do: raise("seed provenance changed")
          end

          :ok
        end
      )
    end
  end

  defp corpora(samples) do
    for count <- [1_000, 5_000] do
      seeds = for i <- 1..count, do: %Core.Seed{id: "seed-#{i}", value: i, provenance: :wordlist}

      path =
        Path.join(System.tmp_dir!(), "rampart-perf-#{System.unique_integer([:positive])}.json")

      try do
        measure(
          "havoc/import/#{count}",
          %{seeds: count, fixture_hash: digest("corpus-integers-v1/#{count}")},
          samples,
          fn ->
            File.rm(path)
            {:ok, ^count} = Havoc.Corpus.import(seeds, path: path)
            unless length(Havoc.Corpus.load(path: path)) == count, do: raise("corpus lost seeds")
          end
        )
      after
        File.rm(path)
      end
    end
  end

  defp scanner(samples) do
    sources =
      for i <- 1..50 do
        {"lib/perf_#{i}.ex",
         "defmodule Perf#{i} do\ndef run(x) do\n" <>
           String.duplicate("String.trim(x)\n", 100) <> "end\nend\n"}
      end

    [
      measure(
        "sast/source-rules",
        %{files: 50, calls: 5_000, fixture_hash: digest(Enum.map(sources, &elem(&1, 1)))},
        samples,
        fn ->
          result = RampartSAST.scan_sources(sources, [RampartSAST.Rules.UnsafeAtom])

          unless result.status == :complete and result.observations == [] and
                   result.metrics.source_count == 50,
                 do: raise("source rule scan changed")
        end
      )
    ]
  end

  defp tracing(samples) do
    source =
      RampartIAST.Source.new!(
        id: "perf.input.v1",
        schema_version: 1,
        context: :performance,
        category: :argument,
        extraction: %{type: :argument, position: 1},
        boundary: :function,
        provenance: %{}
      )

    sink =
      RampartIAST.Sink.new!(
        id: "perf.sink.v1",
        schema_version: 1,
        context: :performance,
        mfa: {RampartPerformance.Sink, :observe, 1},
        argument_positions: [1],
        category: :observation,
        sanitizer_expectations: [],
        severity: :info,
        rationale: "benchmark observation",
        provenance: %{}
      )

    Enum.flat_map([:compute, :binary, :container, :io], fn workload ->
      for mode <- [:disabled, :targeted] do
        measure(
          "iast/#{workload}/#{mode}",
          %{workload: workload, mode: mode, fixture_hash: digest("iast-v1/#{workload}")},
          samples,
          fn ->
            trace(mode, workload, source, sink)
          end
        )
      end
    end)
  end

  defp trace(:disabled, workload, _source, _sink), do: workload(workload, "performance-marker")

  defp trace(:targeted, workload, source, sink) do
    result =
      RampartIAST.TraceSession.run(
        "perf",
        source,
        sink,
        "performance-marker",
        &workload(workload, &1),
        RampartIAST.Limits.new!(timeout_ms: 5_000)
      )

    unless result.envelope == :intact and result.teardown == :ok and result.event_count == 1,
      do: raise("IAST benchmark failed: #{inspect(result)}")

    unless Enum.any?(result.observations, &(&1.matched_positions == [1])),
      do: raise("IAST benchmark lost the marker")
  end

  defp workload(:compute, marker) do
    Enum.reduce(1..50_000, 0, &Bitwise.bxor(&1, &2))
    RampartPerformance.Sink.observe(marker)
  end

  defp workload(:binary, marker),
    do: RampartPerformance.Sink.observe(String.duplicate("x", 2_000) <> marker)

  defp workload(:container, marker),
    do: RampartPerformance.Sink.observe(%{items: List.duplicate({:value, 1}, 100), input: marker})

  defp workload(:io, marker) do
    {:ok, io} = StringIO.open("")

    try do
      :ok = IO.binwrite(io, marker)
      RampartPerformance.Sink.observe(marker)
    after
      StringIO.close(io)
    end
  end

  defp measure(name, metadata, samples, fun) do
    IO.puts("Measuring #{name}")
    for _ <- 1..2, do: fun.()
    readings = for _ <- 1..samples, do: sample(fun)
    times = readings |> Enum.map(& &1.elapsed_us) |> Enum.sort()

    %{
      name: name,
      input: metadata,
      samples: readings,
      median_us: Enum.at(times, div(samples, 2)),
      p95_us: Enum.at(times, ceil(samples * 0.95) - 1)
    }
  end

  defp sample(fun) do
    :erlang.garbage_collect()
    before = counters()
    {elapsed, _result} = :timer.tc(fun)
    after_sample = counters()

    %{
      elapsed_us: elapsed,
      node_reductions: after_sample.reductions - before.reductions,
      node_gcs: after_sample.gcs - before.gcs,
      process_memory_before: before.process_memory,
      process_memory_after: after_sample.process_memory,
      vm_memory_before: before.vm_memory,
      vm_memory_after: after_sample.vm_memory
    }
  end

  defp counters do
    {reductions, _since_last} = :erlang.statistics(:reductions)
    {gcs, _words, _unused} = :erlang.statistics(:garbage_collection)

    %{
      reductions: reductions,
      gcs: gcs,
      process_memory: elem(Process.info(self(), :memory), 1),
      vm_memory: :erlang.memory(:total)
    }
  end

  defp digest(iodata), do: :crypto.hash(:sha256, iodata) |> Base.encode16(case: :lower)
end
