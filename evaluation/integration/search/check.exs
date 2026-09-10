Code.require_file("assertions.exs", System.fetch_env!("RAMPART_GATE_SUPPORT"))

defmodule Integration.Search do
  import ExUnit.Assertions
  alias HavocProper.{Coverage, Guided}
  alias SearchFixture.Target
  @alphabet ~c"RAMPXYZ"
  @budget 200

  def run do
    File.mkdir_p!("proofs")
    trials = for trial <- 1..7, mode <- [:unguided, :guided], do: trial(mode, trial)
    grouped = Enum.group_by(trials, & &1.mode)

    summary =
      Map.new(grouped, fn {mode, rows} ->
        {mode,
         %{
           found: Enum.count(rows, & &1.confirmed),
           trials: length(rows),
           median_covered_lines: median(Enum.map(rows, & &1.covered_line_count)),
           median_max_depth: median(Enum.map(rows, & &1.max_depth)),
           median_us: median(Enum.map(rows, & &1.elapsed_us))
         }}
      end)

    assert Enum.all?(trials, &(&1.target_calls > 0 and &1.target_calls <= @budget + 3))
    assert Enum.all?(trials, &(&1.covered_line_count > 0))

    Integration.Assertions.finish(%{
      search_budget: @budget,
      domain: "four characters from RAMPXYZ",
      trials: trials,
      summary: summary,
      fixture_sha256: hash(File.read!("lib/target.ex")),
      interpretation:
        "paired bounded trials; both arms collect line coverage; no universal effectiveness threshold; guided RNG seed is not publicly configurable in PropEr 1.5, so exact generated sequences are retained"
    })
  end

  defp trial(mode, trial) do
    {:ok, state} = Agent.start_link(fn -> %{inputs: [], covered: MapSet.new(), max_depth: 0} end)

    target = fn payload ->
      result = Target.run(payload)

      Agent.update(state, fn state ->
        %{state | inputs: [payload | state.inputs], max_depth: max(state.max_depth, result.depth)}
      end)

      result
    end

    options = [
      oracles: [:no_500],
      persist: false,
      replay: false,
      property_id: "search",
      property_name: "search",
      module: __MODULE__
    ]

    {elapsed, _} = :timer.tc(fn -> search(mode, trial, target, state, options) end)
    sample = Agent.get(state, & &1)
    inputs = Enum.reverse(sample.inputs)
    # Confirmation is a separate exact execution with the ordinary Havoc oracle.
    found = Enum.find(inputs, &(&1 == ~c"RAMP"))

    if found do
      seed = %Core.Seed{id: "search-#{mode}-#{trial}", value: found, provenance: :generated}
      corpus = "proofs/#{mode}-#{trial}-corpus.json"

      assert %{verdict: :confirmed} =
               Havoc.validate(seed, &Target.run/1, oracles: [:no_500], corpus_path: corpus)

      assert [saved] = Havoc.Corpus.load(path: corpus)

      assert %{verdict: :confirmed} =
               Havoc.validate(saved, &Target.run/1, oracles: [:no_500], persist: false)
    end

    File.write!("proofs/#{mode}-#{trial}-inputs.json", JSON.encode!(inputs))
    Agent.stop(state)

    %{
      mode: mode,
      trial: trial,
      target_calls: length(inputs),
      confirmed: found != nil,
      max_depth: sample.max_depth,
      covered_line_count: MapSet.size(sample.covered),
      elapsed_us: elapsed,
      inputs_sha256: hash(JSON.encode!(inputs)),
      stream_data_seed: if(mode == :unguided, do: [19, 83, trial], else: nil),
      guided_manifest_sha256:
        if(mode == :guided,
          do: hash(File.read!("proofs/guided-#{trial}-manifest.json")),
          else: nil
        )
    }
  end

  defp search(:unguided, trial, target, state, options) do
    generator = StreamData.list_of(StreamData.member_of(@alphabet), length: 4)
    config = Havoc.Property.config!(options)

    Coverage.with_modules([Target], fn ->
      StreamData.check_all(
        generator,
        [initial_seed: {19, 83, trial}, max_runs: @budget, max_shrinking_steps: 0],
        fn payload ->
          {result, lines} =
            Coverage.measure([Target], fn -> Havoc.Property.evaluate(target, payload, config) end)

          cover(state, lines)
          result
        end
      )
    end)
  end

  defp search(:guided, trial, target, state, options) do
    base = PropCheck.BasicTypes.vector(4, PropCheck.BasicTypes.elements(@alphabet))

    generator =
      :proper_gen_next.set_user_nf(base, fn previous, _temperature ->
        neighbours =
          for index <- 0..3, byte <- @alphabet, do: List.replace_at(previous, index, byte)

        PropCheck.BasicTypes.elements(neighbours)
      end)

    Guided.check!(
      generator,
      options ++
        [
          coverage_modules: [Target],
          search_steps: @budget,
          search_strategy: :hill_climbing,
          persist_coverage: false,
          feedback_id: "search-fixture-depth-v1",
          manifest_path: "proofs/guided-#{trial}-manifest.json",
          features: fn sample ->
            cover(state, sample.covered_lines)

            depth =
              case sample.evaluation do
                {:ok, %{depth: depth}} -> depth
                {:error, %Havoc.Property.Failure{observation: %{depth: depth}}} -> depth
              end

            for reached <- 0..depth, do: "depth:#{reached}"
          end
        ],
      target
    )
  rescue
    error in Havoc.PropertyError -> assert error.payload == ~c"RAMP"
  end

  defp cover(state, lines),
    do: Agent.update(state, &%{&1 | covered: MapSet.union(&1.covered, MapSet.new(lines))})

  defp median(values), do: values |> Enum.sort() |> Enum.at(div(length(values), 2))
  defp hash(binary), do: :crypto.hash(:sha256, binary) |> Base.encode16(case: :lower)
end

Integration.Search.run()
