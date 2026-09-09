defmodule HavocProper.GuidedTest do
  use ExUnit.Case, async: false
  use HavocProper.Case

  alias Core.Seed
  alias Havoc.PropertyError
  alias HavocProper.{Gen, Guided}
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
