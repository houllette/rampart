defmodule Foray.ValidationTest do
  use ExUnit.Case, async: true

  alias Core.Validation.Result
  alias Foray.Scope.Allowlist

  test "advertises and confirms an exact HTTP-match replay" do
    assert [%Core.Validation.Action{id: "foray.http-match-reproduces.v1"} = action] =
             Foray.validation_actions()

    assert action.side_effects == :authorized_probe
    scan = scan(Allowlist.new!(["https://app.example/"]))
    candidate = candidate(expected_id(scan))

    assert %Result{verdict: :confirmed, findings: [finding], seed: seed} =
             Foray.validate(candidate, scan)

    assert finding.id == candidate.id
    assert finding.seed == seed

    assert seed.value == %{
             finding_id: candidate.id,
             inputs: %{"FUZZ" => "match-1"},
             scan_id: scan.id
           }

    assert_receive {:job_started, _worker, "foray-validation:1"}
  end

  test "refutes a hypothesis when the exact replay does not produce the same finding" do
    scan = scan(Allowlist.new!(["https://app.example/"]))
    candidate = candidate("foray:not-observed")

    assert %Result{verdict: :refuted, findings: [], evidence: evidence} =
             Foray.validate(candidate, scan)

    assert evidence.summary =~ "did not reproduce"
  end

  test "checks scope before a validation engine starts" do
    scan = scan(Core.Scope.DenyAll)

    assert_raise Core.Scope.Error, fn ->
      Foray.validate(candidate(expected_id(scan)), scan)
    end

    refute_receive {:job_started, _worker, _job_id}
  end

  test "does not broaden exact validation to unrelated jobs in the originating plan" do
    scan =
      Foray.target(["https://not-authorized.example", "https://app.example"],
        scope: Allowlist.new!(["https://app.example/"]),
        scan_id: "foray-validation"
      )
      |> Foray.fuzz_path(wordlist: "paths.txt")
      |> Foray.engine(Foray.TestEngine, observer: self())

    assert %Result{verdict: :confirmed} =
             Foray.validate(candidate(expected_id(scan, 2)), scan)

    assert_receive {:job_started, _worker, "foray-validation:2"}
    refute_receive {:job_started, _worker, "foray-validation:1"}
  end

  defp scan(scope) do
    Foray.target("https://app.example",
      scope: scope,
      scan_id: "foray-validation"
    )
    |> Foray.fuzz_path(wordlist: "paths.txt")
    |> Foray.engine(Foray.TestEngine, observer: self())
  end

  defp candidate(id) do
    seed = %Core.Seed{
      id: "foray-input",
      value: "match-1",
      classes: [:discovery],
      provenance: :wordlist
    }

    %Core.Finding{
      id: id,
      source: :foray,
      category: :exposed_path,
      locus: %{
        url: "https://app.example/match-1",
        method: "GET",
        keyword: "FUZZ",
        input: "match-1",
        status: 200
      },
      confidence: :medium,
      evidence: "matched HTTP 200",
      seed: seed,
      observed_at: DateTime.utc_now()
    }
  end

  defp expected_id(scan, index \\ 1) do
    Core.Finding.dedupe_id(:foray, [scan.id <> ":#{index}", 1])
  end
end
