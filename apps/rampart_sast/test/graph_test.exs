defmodule RampartSAST.GraphTest do
  use ExUnit.Case, async: true

  alias RampartSAST.{Graph, Inventory}
  alias RampartSAST.Inventory.Artifact
  alias RampartSAST.Inventory.Page

  test "builds bounded caller/callee and behavior slices" do
    source = """
    defmodule Example do
      def authorize_request(input) do
        normalized = normalize(input)

        if normalized != "" do
          File.write("/tmp/audit", normalized)
          send(self(), normalized)
        end
      end

      def normalize(input) do
        String.trim(input)
        Jason.decode!(input)
      end
    end
    """

    result = RampartSAST.inventory_sources([{"lib/example.ex", source}])

    assert [_authorization] =
             Inventory.query(result.inventory,
               kind: :behavior,
               object: "authorization_boundary"
             )

    assert [_filesystem] =
             Inventory.query(result.inventory, kind: :behavior, object: "filesystem_access")

    slice = Graph.callees(result.inventory, "Example.authorize_request/1", max_depth: 2)
    assert "File.write/2" in slice.nodes
    assert "behavior:filesystem_access" in slice.nodes
    refute slice.truncated

    [file_write] = Inventory.calls_to(result.inventory, "File", "write")
    control_candidates = Graph.control_slice(result.inventory, file_write.id)
    assert Enum.any?(control_candidates, &(&1.object == "send/2"))

    truncated = Graph.callees(result.inventory, "Example.authorize_request/1", max_nodes: 2)
    assert truncated.truncated
    assert length(truncated.nodes) == 2
    assert length(truncated.edges) == 1

    assert_raise ArgumentError, ~r/accommodate every root/, fn ->
      Graph.slice(result.inventory, ["one", "two"], max_nodes: 1)
    end
  end

  test "links syntactic callback implementations to their declarations" do
    source = """
    defmodule Example.Contract do
      @callback run(term()) :: term()
    end

    defmodule Example.Implementation do
      @behaviour Example.Contract
      def run(value), do: value
    end
    """

    result = RampartSAST.inventory_sources([{"lib/example/callback.ex", source}])
    slice = Graph.callees(result.inventory, "Example.Implementation.run/1", max_depth: 1)

    assert "Example.Contract.run/1" in slice.nodes
    assert Enum.any?(slice.edges, &(&1.kind == :callback_implementation))
  end

  test "finds bounded syntactic data candidates through shared argument variables" do
    source = """
    defmodule Example do
      def normalize(input) do
        String.trim(input)
        Jason.decode!(input)
      end
    end
    """

    result = RampartSAST.inventory_sources([{"lib/example.ex", source}])
    [decode] = Inventory.calls_to(result.inventory, "Jason", "decode!")
    [trim] = Graph.shared_variable_slice(result.inventory, decode.id)

    assert trim.object == "String.trim/1"
    assert trim.attributes.argument_variables == ["input"]
  end

  test "returns paginated facts and a content-addressed inventory artifact manifest" do
    source = "defmodule Example do\n  def run(value), do: String.trim(value)\nend\n"
    result = RampartSAST.inventory_sources([{"lib/example.ex", source}])

    assert %Page{returned: 1, next_offset: next_offset, total: total} =
             Inventory.query_page(result.inventory, limit: 1)

    assert total > 1
    assert next_offset == 1

    first = Artifact.encode(result.inventory)
    second = Artifact.encode(result.inventory)
    assert first.id == second.id
    assert first.payload == second.payload
    refute Artifact.manifest(first) |> Map.has_key?(:payload)

    assert_raise ArgumentError, ~r/exceeds/, fn ->
      Artifact.encode(result.inventory, max_bytes: 1)
    end
  end

  test "filters calls before pagination and exposes complete continuation metadata" do
    source =
      "defmodule Paged do\ndef run(x) do\n" <>
        String.duplicate("String.trim(x)\n", 120) <> "String.upcase(x)\nend\nend\n"

    result = RampartSAST.inventory_sources([{"lib/paged.ex", source}])

    assert [%{object: "String.upcase/1"}] =
             Inventory.calls_to(result.inventory, "String", "upcase")

    assert %Page{returned: 100, total: 120, next_offset: 100} =
             Inventory.calls_to_page(result.inventory, "String", "trim")

    assert %Page{returned: 20, next_offset: nil} =
             Inventory.calls_to_page(result.inventory, "String", "trim", offset: 100)

    assert_raise ArgumentError, ~r/calls_to_page/, fn ->
      Inventory.calls_to(result.inventory, "String", "trim")
    end
  end

  test "bounds parallel edge evidence independently of nodes" do
    source =
      "defmodule Dense do\ndef run(x) do\n" <>
        String.duplicate("String.trim(x)\n", 40) <> "end\nend\n"

    result = RampartSAST.inventory_sources([{"lib/dense.ex", source}])

    slice =
      Graph.callees(result.inventory, "Dense.run/1",
        relations: [:calls],
        max_nodes: 3,
        max_edges: 5
      )

    assert length(slice.nodes) == 2
    assert length(slice.edges) == 5
    assert slice.truncated
    assert :max_edges in slice.limit_reasons
    limited = Graph.callees(result.inventory, "Dense.run/1", max_work: 3)
    assert limited.work_count == 3
    assert :max_work in limited.limit_reasons

    small = Graph.callees(result.inventory, "Dense.run/1", relations: [:calls], max_bytes: 2_000)
    assert byte_size(JSON.encode!(Graph.Slice.to_map(small))) <= 2_000
    assert :max_bytes in small.limit_reasons
  end

  test "exact node capacity and depth boundaries report omitted edges accurately" do
    source =
      "defmodule Depth do\ndef first(x), do: second(x)\ndef second(x), do: String.trim(x)\nend\n"

    result = RampartSAST.inventory_sources([{"lib/depth.ex", source}])

    complete =
      Graph.callees(result.inventory, "Depth.second/1", relations: [:calls], max_nodes: 2)

    refute complete.truncated

    partial =
      Graph.callees(result.inventory, "Depth.first/1",
        relations: [:calls, :invokes],
        max_depth: 1
      )

    assert partial.truncated
    assert :max_depth in partial.limit_reasons
  end

  test "cyclic and multi-root traversal preserves every fact once in both directions" do
    source = "defmodule Cycle do\ndef a(x), do: b(x)\ndef b(x), do: a(x)\nend\n"
    inventory = RampartSAST.inventory_sources([{"lib/cycle.ex", source}]).inventory
    options = [relations: [:invokes], direction: :both, max_nodes: 2, max_edges: 2]
    cycle = Graph.slice(inventory, ["Cycle.a/1"], options)

    roots =
      Graph.slice(inventory, ["Cycle.b/1", "Cycle.a/1"], Keyword.put(options, :max_depth, 1))

    refute cycle.truncated
    refute roots.truncated
    assert cycle.nodes == ["Cycle.a/1", "Cycle.b/1"]
    assert length(cycle.edges) == 2
    assert Enum.map(cycle.edges, & &1.id) == Enum.map(roots.edges, & &1.id)
    assert Inventory.to_map(inventory) == Inventory.to_map(%{inventory | index: nil})
    assert Artifact.encode(inventory).id == Artifact.encode(%{inventory | index: nil}).id
  end
end
