defmodule RampartSAST.ScannerTest do
  use ExUnit.Case, async: true

  alias RampartSAST.{Limits, Result}
  alias RampartSAST.Rules.UnsafeAtom

  test "scans sources concurrently but returns deterministic file and rule order" do
    entries = [
      {"lib/z.ex", dynamic_atom_source("Z")},
      {"lib/a.ex", dynamic_atom_source("A")}
    ]

    result = RampartSAST.scan_sources(entries, [UnsafeAtom])

    assert result.status == :complete
    assert Enum.map(result.observations, & &1.span.file) == ["lib/a.ex", "lib/z.ex"]
    assert Enum.map(result.findings, & &1.id) == Enum.map(result.observations, & &1.id)
    assert result.metrics.source_count == 2
    assert result.metrics.observation_count == 2
  end

  test "metadata-free anchors survive line movement" do
    original =
      RampartSAST.scan_sources([{"lib/example.ex", dynamic_atom_source("Example")}], [UnsafeAtom])

    moved =
      RampartSAST.scan_sources(
        [{"lib/example.ex", "\n\n" <> dynamic_atom_source("Example")}],
        [UnsafeAtom]
      )

    assert [first] = original.observations
    assert [second] = moved.observations
    assert first.anchor == second.anchor
    assert first.id == second.id
    refute first.span.start_line == second.span.start_line
  end

  test "occurrence indexes disambiguate identical AST emitted more than once" do
    result =
      RampartSAST.scan_sources(
        [{"lib/example.ex", dynamic_atom_source("Example")}],
        [RampartSAST.DuplicateRuleFixture]
      )

    assert Enum.map(result.observations, & &1.occurrence) == [1, 2]
    assert result.observations |> Enum.map(& &1.id) |> Enum.uniq() |> length() == 2
  end

  test "supports project-scoped rules without baking framework assumptions into the engine" do
    result =
      RampartSAST.scan_sources(
        [{"lib/a.ex", "defmodule A do\nend\n"}, {"lib/b.ex", "defmodule B do\nend\n"}],
        [RampartSAST.ProjectRuleFixture]
      )

    assert result.status == :complete
    assert [observation] = result.observations
    assert observation.rule.scope == :project
    assert observation.span.file == "lib/a.ex"
  end

  test "retains explicit reason-carrying suppressions instead of deleting matches" do
    source = """
    defmodule Example do
      def run(input) do
        # rampart:suppress-next-line sast.unsafe-atom.v1 -- input is a bounded internal enum
        String.to_atom(input)
      end
    end
    """

    result = RampartSAST.scan_sources([{"lib/example.ex", source}], [UnsafeAtom])

    assert result.status == :complete
    assert result.observations == []
    assert result.findings == []
    assert [suppressed] = result.suppressed
    assert suppressed.observation.rule.id == "sast.unsafe-atom.v1"
    assert suppressed.suppression.reason == "input is a bounded internal enum"
    assert Result.all_observations(result) == [suppressed.observation]
  end

  test "Erlang signals support the same visible reason-carrying suppression" do
    source = """
    -module(example).
    run(Input) ->
      % rampart:suppress-next-line sast.unsafe-atom.v1 -- bounded protocol enum
      erlang:binary_to_atom(Input, utf8).
    """

    result = RampartSAST.scan_sources([{"src/example.erl", source}], [UnsafeAtom])

    assert result.status == :complete
    assert result.observations == []
    assert [suppressed] = result.suppressed
    assert suppressed.suppression.reason == "bounded protocol enum"
  end

  test "malformed suppression attempts remain visible and do not hide findings" do
    source = """
    defmodule Example do
      def run(input) do
        # rampart:suppress-next-line sast.unsafe-atom.v1
        String.to_atom(input)
      end
    end
    """

    result = RampartSAST.scan_sources([{"lib/example.ex", source}], [UnsafeAtom])

    assert result.status == :complete
    assert length(result.findings) == 1
    assert Enum.any?(result.diagnostics, &(&1.code == :malformed_suppression))
  end

  test "parse and rule failures make the scan incomplete without laundering partial results" do
    result =
      RampartSAST.scan_sources(
        [
          {"lib/good.ex", dynamic_atom_source("Good")},
          {"lib/broken.ex", "defmodule Broken do"}
        ],
        [UnsafeAtom, RampartSAST.BrokenRuleFixture]
      )

    assert result.status == :incomplete
    assert length(result.findings) == 1
    assert Enum.any?(result.diagnostics, &(&1.code == :syntax_error))
    assert Enum.any?(result.diagnostics, &(&1.rule_id == "test.broken-rule.v1"))
  end

  test "invalid context output fails closed" do
    result =
      RampartSAST.scan_sources(
        [{"lib/example.ex", dynamic_atom_source("Example")}],
        [UnsafeAtom],
        context_providers: [RampartSAST.InvalidContextFixture]
      )

    assert result.status == :incomplete
    assert Enum.any?(result.diagnostics, &(&1.code == :invalid_provider_result))
  end

  test "finite behavior-classifier deadlines turn hangs into diagnostics" do
    limits = Limits.new!(behavior_timeout_ms: 20)

    result =
      RampartSAST.scan_sources(
        [{"lib/example.ex", dynamic_atom_source("Example")}],
        [],
        limits: limits,
        behavior_classifiers: [RampartSAST.SlowBehaviorFixture]
      )

    assert result.status == :incomplete
    assert Enum.any?(result.diagnostics, &(&1.code == :classifier_timeout))
    assert result.inventory.facts != []
  end

  test "finite context deadlines turn hangs into diagnostics" do
    limits = Limits.new!(context_timeout_ms: 20)

    result =
      RampartSAST.scan_sources(
        [{"lib/example.ex", dynamic_atom_source("Example")}],
        [UnsafeAtom],
        limits: limits,
        context_providers: [RampartSAST.SlowContextFixture]
      )

    assert result.status == :incomplete
    assert Enum.any?(result.diagnostics, &(&1.code == :provider_timeout))
  end

  test "finite rule deadlines turn hangs into diagnostics" do
    limits = Limits.new!(rule_timeout_ms: 20)

    result =
      RampartSAST.scan_sources(
        [{"lib/example.ex", dynamic_atom_source("Example")}],
        [RampartSAST.SlowRuleFixture],
        limits: limits
      )

    assert result.status == :incomplete
    assert Enum.any?(result.diagnostics, &(&1.code == :rule_timeout))
  end

  test "total source limits reject the scan rather than silently truncating it" do
    limits = Limits.new!(max_file_bytes: 10, max_total_bytes: 10)

    result =
      RampartSAST.scan_sources(
        [{"lib/a.ex", "123456"}, {"lib/b.ex", "123456"}],
        [UnsafeAtom],
        limits: limits
      )

    assert result.status == :incomplete
    assert result.observations == []
    assert Enum.any?(result.diagnostics, &(&1.code == :total_size_limit))
  end

  test "plain scan projection excludes source snapshots and native AST" do
    source = dynamic_atom_source("Example")
    result = RampartSAST.scan_sources([{"lib/example.ex", source}], [UnsafeAtom])

    projection = Result.to_map(result)
    encoded = inspect(projection)

    refute encoded =~ source
    refute Map.has_key?(projection, :findings)
    refute Map.has_key?(projection.inventory, :facts)
    assert projection.inventory.fact_count > 0
    assert projection.status == :complete
  end

  defp dynamic_atom_source(module) do
    """
    defmodule #{module} do
      def run(input), do: String.to_atom(input)
    end
    """
  end
end
