defmodule Havoc.ValidationTest do
  use ExUnit.Case, async: true

  alias Core.Validation.Result
  alias Havoc.Observation.Codec

  setup context do
    path =
      Path.join(
        System.tmp_dir!(),
        "havoc-validation-#{context.test}-#{System.unique_integer([:positive])}.json"
      )

    on_exit(fn -> File.rm_rf(path) end)
    %{path: path}
  end

  test "advertises a deterministic concrete-payload validation action" do
    assert [%Core.Validation.Action{id: "havoc.security-property-reproduces.v1"} = action] =
             Havoc.validation_actions()

    assert action.side_effects == :test_execution
    assert action.meta.generation == :none
  end

  test "confirms, persists, and normalizes a concrete oracle violation", %{path: path} do
    seed = seed("bad")

    assert %Result{verdict: :confirmed, findings: [finding], seed: proof_seed} =
             Havoc.validate(seed, fn _payload -> %{status: 500} end,
               property_id: "Validation:no-500",
               property_name: "specific payload does not return 500",
               module: __MODULE__,
               oracles: [:no_500],
               corpus_path: path
             )

    assert finding.category == :crash
    assert finding.seed == proof_seed
    assert finding.seed.value == "bad"
    assert :validation in proof_seed.classes
    assert [%Core.Seed{value: "bad"}] = Havoc.Corpus.load(path: path)
  end

  test "refutes a violation hypothesis when every oracle passes", %{path: path} do
    assert %Result{verdict: :refuted, findings: [], evidence: evidence, seed: replay} =
             Havoc.validate(seed("safe"), fn _payload -> %{status: 200} end,
               property_id: "Validation:safe",
               property_name: "specific payload is safe",
               module: __MODULE__,
               oracles: [:no_500],
               corpus_path: path
             )

    assert replay.value == "safe"
    assert evidence.facts.oracle_names == [:no_500]
    assert Havoc.Corpus.load(path: path) == []
  end

  test "does not turn a skipped exact oracle into a false refutation", %{path: path} do
    assert %Result{verdict: :inconclusive, findings: [], evidence: evidence} =
             Havoc.validate(seed("input"), fn _payload -> %{body: "missing status"} end,
               property_id: "Validation:skipped",
               property_name: "missing required observation",
               module: __MODULE__,
               oracles: [:no_crash, :no_500],
               corpus_path: path
             )

    assert evidence.facts.skipped_oracle_names == [:no_500]
    assert evidence.facts.passed_oracle_names == [:no_crash]
    assert Havoc.Corpus.load(path: path) == []
  end

  test "distinguishes broken test setup from a security confirmation", %{path: path} do
    assert %Result{verdict: :inconclusive, findings: [], evidence: evidence} =
             Havoc.validate(seed("input"), fn _payload -> raise "fixture unavailable" end,
               property_id: "Validation:inconclusive",
               property_name: "setup failure",
               module: __MODULE__,
               oracles: [:no_500],
               corpus_path: path
             )

    assert evidence.summary =~ "before a security verdict"
    assert evidence.facts.reason =~ "fixture unavailable"
    assert Havoc.Corpus.load(path: path) == []
  end

  test "treats a codec payload/observation mismatch as a broken harness", %{path: path} do
    assert %Result{verdict: :inconclusive, findings: [], evidence: evidence} =
             Havoc.validate(
               seed("input"),
               fn _payload -> Codec.accepted("different", :identity, "different") end,
               property_id: "Validation:codec-mismatch",
               property_name: "codec fixture observes the exact payload",
               module: __MODULE__,
               oracles: [:canonical_encoding],
               corpus_path: path
             )

    assert evidence.facts.reason =~ "does not match"
    assert Havoc.Corpus.load(path: path) == []
  end

  test "no_crash converts the same target exception into a confirmed violation", %{path: path} do
    assert %Result{verdict: :confirmed, findings: [finding]} =
             Havoc.validate(seed("input"), fn _payload -> raise "parser crashed" end,
               property_id: "Validation:no-crash",
               property_name: "parser survives",
               module: __MODULE__,
               oracles: [:no_crash],
               corpus_path: path
             )

    assert finding.category == :crash
    assert finding.evidence =~ "parser crashed"
  end

  test "preserves the originating finding locus when validating a promoted payload", %{path: path} do
    candidate = %Core.Finding{
      id: "foray:candidate",
      source: :foray,
      category: :param_injection,
      locus: %{url: "https://example.test/search", param: "q"},
      confidence: :medium,
      evidence: "database error matched",
      seed: seed("'"),
      observed_at: DateTime.utc_now()
    }

    assert %Result{verdict: :confirmed, findings: [finding]} =
             Havoc.validate(candidate, fn _payload -> %{status: 500} end,
               property_id: "Validation:promoted",
               property_name: "promoted finding",
               module: __MODULE__,
               oracles: [:no_500],
               corpus_path: path
             )

    assert finding.locus.url == "https://example.test/search"
    assert finding.locus.param == "q"
    assert finding.locus.origin_source == :foray
    assert finding.locus.origin_finding_id == "foray:candidate"
  end

  defp seed(value) do
    %Core.Seed{
      id: "seed:#{value}",
      value: value,
      classes: [:sqli],
      provenance: :generated
    }
  end
end
