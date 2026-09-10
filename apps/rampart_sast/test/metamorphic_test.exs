defmodule RampartSAST.MetamorphicTest do
  use ExUnit.Case, async: true

  alias RampartSAST.Inventory

  test "formatting, comments, and equivalent alias spelling preserve resolved relationships" do
    compact = """
    defmodule Metamorphic.Example do
      alias String, as: Text
      def normalize(value), do: Text.trim(value)
    end
    """

    reformatted = """
    # unrelated source commentary
    defmodule Metamorphic.Example do
      def normalize(value) do
        String.trim(
          value
        )
      end
    end
    """

    first = RampartSAST.inventory_sources([{"lib/compact.ex", compact}])
    second = RampartSAST.inventory_sources([{"lib/reformatted.ex", reformatted}])

    assert semantic_relationships(first) == semantic_relationships(second)
    refute first.inventory.id == second.inventory.id

    assert [first_call] = Inventory.calls_to(first.inventory, "String", "trim")
    assert [second_call] = Inventory.calls_to(second.inventory, "String", "trim")
    assert first_call.attributes.resolution == :source_alias
    assert second_call.attributes.resolution == :syntactic
  end

  test "unrelated definitions do not alter the selected relationship semantics" do
    original = """
    defmodule Metamorphic.Stable do
      def normalize(value), do: String.trim(value)
    end
    """

    extended = """
    defmodule Metamorphic.Stable do
      def unrelated(value), do: inspect(value)
      def normalize(value), do: String.trim(value)
    end
    """

    first = RampartSAST.inventory_sources([{"lib/stable.ex", original}])
    second = RampartSAST.inventory_sources([{"lib/stable.ex", extended}])

    assert relationship(first, "Metamorphic.Stable.normalize/1", "String.trim/1") ==
             relationship(second, "Metamorphic.Stable.normalize/1", "String.trim/1")
  end

  test "identical snapshots produce identical inventory and fact identities" do
    entries = [
      {"lib/deterministic.ex",
       "defmodule Metamorphic.Deterministic do\n  def run(v), do: String.trim(v)\nend\n"}
    ]

    first = RampartSAST.inventory_sources(entries)
    second = RampartSAST.inventory_sources(entries)

    assert first.inventory.id == second.inventory.id
    assert Enum.map(first.inventory.facts, & &1.id) == Enum.map(second.inventory.facts, & &1.id)
  end

  defp semantic_relationships(result) do
    result.inventory.facts
    |> Enum.filter(&(&1.kind in [:module, :definition, :call]))
    |> Enum.map(fn
      %{kind: :module} = fact -> {fact.kind, fact.relation, fact.object}
      fact -> {fact.kind, fact.subject, fact.relation, fact.object}
    end)
    |> Enum.sort()
  end

  defp relationship(result, subject, object) do
    result.inventory
    |> Inventory.query(subject: subject, object: object)
    |> Enum.map(fn fact ->
      {fact.kind, fact.subject, fact.relation, fact.object, fact.attributes.target_module,
       fact.attributes.target_function, fact.attributes.arity}
    end)
  end
end
