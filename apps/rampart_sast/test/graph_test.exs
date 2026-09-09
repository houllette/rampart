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
end
