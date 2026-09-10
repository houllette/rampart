defmodule HavocProper.GuidedTest do
  use ExUnit.Case, async: false
  use HavocProper.Case

  alias Core.Seed
  alias Havoc.PropertyError
  alias HavocProper.{Archive, Gen, Guided, Manifest}
  alias HavocProper.TestSupport.CoverageFixture

  setup context do
    path =
      Path.join(
        System.tmp_dir!(),
        "havoc-guided-#{context.test}-#{System.unique_integer([:positive])}.json"
      )

    on_exit(fn -> File.rm_rf(path) end)
    %{path: path}
  end

  guided_security_property "binds payload in the PropEr-backed macro",
    generator: PropCheck.BasicTypes.elements([10]),
    coverage_modules: [CoverageFixture],
    oracles: [:no_500],
    persist: false,
    replay: false,
    persist_coverage: false,
    search_steps: 2 do
    assert payload == 10
    CoverageFixture.classify(payload)
    %{status: 200}
  end

  test "persists coverage-increasing candidates as generated Core seeds", %{path: path} do
    assert :ok =
             Guided.check!(
               PropCheck.BasicTypes.elements([10]),
               property_options(path, "coverage-corpus"),
               fn payload ->
                 CoverageFixture.classify(payload)
                 %{status: 200}
               end
             )

    assert [%Seed{value: 10, provenance: :generated, classes: classes, meta: meta}] =
             Havoc.Corpus.load(path: path)

    assert :coverage_guided in classes
    assert meta.generator == :proper_targeted
    assert meta.coverage_fitness > 0
    assert meta.feature_fitness == 0
    assert meta.covered_features == []
    assert meta.covered_lines != []
  end

  test "uses Havoc to normalize and persist a targeted-search violation", %{path: path} do
    error =
      assert_raise PropertyError, fn ->
        Guided.check!(
          PropCheck.BasicTypes.elements([950]),
          property_options(path, "violation", persist_coverage: false),
          fn payload ->
            status = if CoverageFixture.classify(payload) == :deep, do: 500, else: 200
            %{status: status}
          end
        )
      end

    assert error.payload == 950
    assert [%Core.Finding{source: :havoc, category: :crash}] = error.findings
    assert [%Seed{value: 950, provenance: :counterexample}] = Havoc.Corpus.load(path: path)
  end

  test "ordinary target exceptions do not persist coverage seeds", %{path: path} do
    assert_raise RuntimeError, "broken test fixture", fn ->
      Guided.check!(
        PropCheck.BasicTypes.elements([1]),
        property_options(path, "fixture-error", oracles: [:no_500]),
        fn payload ->
          CoverageFixture.classify(payload)
          raise "broken test fixture"
        end
      )
    end

    assert Havoc.Corpus.load(path: path) == []
  end

  test "custom binary neighbourhood avoids PropEr's default targeted binary path" do
    assert :ok =
             Guided.check!(
               Gen.binary(max_length: 8),
               property_options(nil, "binary", persist: false, persist_coverage: false),
               fn payload ->
                 CoverageFixture.bytes(payload)
                 %{status: 200}
               end
             )
  end

  test "fitness bonuses must be numeric" do
    assert_raise ArgumentError, ~r/fitness_bonus must return a number/, fn ->
      Guided.check!(
        PropCheck.BasicTypes.elements([1]),
        property_options(nil, "fitness", persist: false, fitness_bonus: fn _ -> :high end),
        fn payload ->
          CoverageFixture.classify(payload)
          %{status: 200}
        end
      )
    end
  end

  test "state features contribute fitness and durable seed metadata", %{path: path} do
    assert :ok =
             Guided.check!(
               PropCheck.BasicTypes.elements([10]),
               property_options(path, "features",
                 feedback_id: "fixture-class-v1",
                 features: fn sample ->
                   assert {:ok, %{class: :shallow}} = sample.evaluation
                   ["class:shallow", "class:shallow"]
                 end
               ),
               fn payload ->
                 class = CoverageFixture.classify(payload)
                 %{status: 200, class: class}
               end
             )

    assert [%Seed{meta: meta}] = Havoc.Corpus.load(path: path)
    assert meta.covered_features == ["class:shallow"]
    assert meta.feature_fitness == 1
    assert meta.search_fitness == meta.coverage_fitness + 1
  end

  test "feature novelty retains candidates even when line coverage is unchanged" do
    {:ok, archive} = Archive.start_link(4)
    config = %{property_id: "features", property_name: "features", classes: []}

    assert :ok = Archive.observe(archive, :first, [{CoverageFixture, 1}], ["state:first"], 2)
    assert :ok = Archive.observe(archive, :second, [{CoverageFixture, 1}], ["state:second"], 2)
    assert [%Seed{value: :first}, %Seed{value: :second}] = Archive.seeds(archive, config)

    Agent.stop(archive)
  end

  test "feature feedback requires a stable explicit identity" do
    assert_raise ArgumentError, ~r/explicit non-empty feedback_id/, fn ->
      Guided.check!(
        PropCheck.BasicTypes.elements([1]),
        property_options(nil, "missing-feedback-id",
          persist: false,
          features: fn _sample -> ["state:one"] end
        ),
        fn _payload -> %{status: 200} end
      )
    end
  end

  test "manifests deterministically identify feedback, runtime, and covered BEAM" do
    config =
      Havoc.Property.config!(
        property_id: "GuidedTest:manifest",
        property_name: "manifest",
        module: __MODULE__,
        oracles: [:no_500],
        persist: false,
        replay: false
      )

    guided = %{
      coverage_modules: [CoverageFixture],
      search_steps: 5,
      search_strategy: :hill_climbing,
      feedback_id: "fixture-state-v1",
      features: fn _ -> [] end,
      max_coverage_seeds: 4,
      persist_coverage: false
    }

    first = Manifest.build(config, guided)
    second = Manifest.build(config, guided)

    assert first == second
    assert first["run_id"] =~ ~r/^[a-f0-9]{64}$/
    assert first["search"]["feedback_id"] == "fixture-state-v1"
    assert [%{"beam_sha256" => beam_hash}] = first["coverage_modules"]
    assert beam_hash =~ ~r/^[a-f0-9]{64}$/
    assert first["replay_note"] =~ "retain exact candidate inputs"
  end

  defp property_options(path, id, overrides \\ []) do
    [
      property_id: "GuidedTest:#{id}",
      property_name: id,
      module: __MODULE__,
      coverage_modules: [CoverageFixture],
      corpus_path: path,
      oracles: [:no_500],
      replay: false,
      search_steps: 5,
      max_coverage_seeds: 4
    ]
    |> Keyword.merge(overrides)
  end
end
