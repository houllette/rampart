defmodule RampartSAST.ValidationTest do
  use ExUnit.Case, async: true

  alias Core.Validation.{Result, Wire}
  alias RampartSAST.Rules.UnsafeAtom

  test "advertises a side-effect-free syntactic validation action" do
    assert [action] = RampartSAST.validation_actions()
    assert action.id == "sast.rule-matches-source.v1"
    assert action.accepts == [:finding]
    assert action.side_effects == :none
    assert action.meta.proof_level == :syntactic_match
    assert action.meta.exploitability == :not_proven
  end

  test "confirms by re-running the host-selected rule against an exact source snapshot" do
    {source, finding} = unsafe_atom_finding()

    assert %Result{verdict: :confirmed, findings: [confirmed], evidence: evidence} =
             result =
             RampartSAST.validate(finding, rules: [UnsafeAtom])

    assert confirmed.id == finding.id
    assert confirmed.locus.anchor == finding.locus.anchor
    assert evidence.facts.proof_level == :syntactic_match
    assert evidence.facts.attacker_control == :not_evaluated

    projection = Wire.result(result)
    encoded = Wire.encode!(projection)

    refute encoded =~ source
    assert projection["evidence"]["facts"]["proof_level"] == "syntactic_match"
  end

  test "refutes after the dangerous syntax is replaced in the current source" do
    {_source, finding} = unsafe_atom_finding()

    fixed = """
    defmodule Example do
      def run(input), do: String.to_existing_atom(input)
    end
    """

    assert %Result{verdict: :refuted, findings: [], seed: seed, evidence: evidence} =
             RampartSAST.validate(finding, rules: [UnsafeAtom], source: fixed)

    assert seed.value == %{path: "lib/example.ex", content: fixed}
    assert evidence.summary =~ "no longer produced"
  end

  test "returns inconclusive when current source cannot be parsed" do
    {_source, finding} = unsafe_atom_finding()

    assert %Result{verdict: :inconclusive, evidence: evidence} =
             RampartSAST.validate(finding,
               rules: [UnsafeAtom],
               source: "defmodule Broken do"
             )

    assert evidence.facts.reason == :scan_incomplete
    assert Enum.any?(evidence.facts.diagnostics, &(&1.code == :syntax_error))
  end

  test "returns inconclusive when the selected rule fails" do
    source = "defmodule Example do\nend\n"

    scan =
      RampartSAST.scan_sources(
        [{"lib/example.ex", source}],
        [RampartSAST.OptionRuleFixture]
      )

    assert [finding] = scan.findings

    assert %Result{verdict: :inconclusive, evidence: evidence} =
             RampartSAST.validate(finding,
               rules: [{RampartSAST.OptionRuleFixture, fail: true}]
             )

    assert evidence.facts.reason == :scan_incomplete
    assert Enum.any?(evidence.facts.diagnostics, &(&1.rule_id == "test.option-rule.v1"))
  end

  test "source suppressions do not alter proof that syntax remains" do
    {_source, finding} = unsafe_atom_finding()

    suppressed = """
    defmodule Example do
      # rampart:suppress-next-line sast.unsafe-atom.v1 -- reviewed bounded input
      def run(input), do: String.to_atom(input)
    end
    """

    assert %Result{verdict: :confirmed, findings: [confirmed]} =
             RampartSAST.validate(finding, rules: [UnsafeAtom], source: suppressed)

    assert confirmed.locus.anchor == finding.locus.anchor
  end

  test "project rules require an explicit current project snapshot" do
    entries = [
      {"lib/a.ex", "defmodule A do\nend\n"},
      {"lib/b.ex", "defmodule B do\nend\n"}
    ]

    scan = RampartSAST.scan_sources(entries, [RampartSAST.ProjectRuleFixture])
    assert [finding] = scan.findings

    assert %Result{verdict: :inconclusive, evidence: evidence} =
             RampartSAST.validate(finding, rules: [RampartSAST.ProjectRuleFixture])

    assert evidence.facts.reason == :project_sources_required

    assert %Result{verdict: :confirmed} =
             RampartSAST.validate(finding,
               rules: [RampartSAST.ProjectRuleFixture],
               sources: entries
             )
  end

  test "transcript-supplied rule IDs cannot select executable modules" do
    {_source, finding} = unsafe_atom_finding()
    finding = put_in(finding.locus.rule_id, "transcript.rule.v1")

    assert_raise ArgumentError, ~r/unknown SAST rule/, fn ->
      RampartSAST.validate(finding, rules: [UnsafeAtom])
    end
  end

  defp unsafe_atom_finding do
    source = """
    defmodule Example do
      def run(input), do: String.to_atom(input)
    end
    """

    scan = RampartSAST.scan_sources([{"lib/example.ex", source}], [UnsafeAtom])
    assert scan.status == :complete
    assert [finding] = scan.findings
    {source, finding}
  end
end
