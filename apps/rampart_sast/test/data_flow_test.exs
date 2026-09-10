defmodule RampartSAST.DataFlowTest do
  use ExUnit.Case, async: true

  alias RampartSAST.{DataFlow, Inventory}
  alias RampartSAST.DataFlow.Slice

  test "walks lexical assignments, returns, parameters, and resolved local call arguments" do
    source = """
    defmodule Demo.Flow do
      def emit(conn, raw) do
        normalized = normalize(raw)
        header = decorate(normalized)
        Plug.Conn.put_resp_header(conn, "x-demo", header)
      end

      defp normalize(value) when is_binary(value), do: String.trim(value)
      defp decorate(value), do: "prefix-\#{value}"
    end
    """

    result = RampartSAST.inventory_sources([{"lib/demo/flow.ex", source}])

    assert [sink] =
             Inventory.query(result.inventory,
               kind: :call_argument,
               object: "Plug.Conn.put_resp_header/3#argument/3"
             )

    assert %Slice{} = slice = DataFlow.backward(result.inventory, sink.id)
    objects = Enum.map(slice.facts, &{&1.kind, &1.subject, &1.object})

    assert {:binding, "Demo.Flow.emit/2", "header"} in objects
    assert {:binding, "Demo.Flow.emit/2", "normalized"} in objects
    assert {:return, "Demo.Flow.decorate/1", "Demo.Flow.decorate/1#return"} in objects
    assert {:return, "Demo.Flow.normalize/1", "Demo.Flow.normalize/1#return"} in objects
    assert {:parameter, "Demo.Flow.emit/2", "raw"} in objects
    assert {:parameter, "Demo.Flow.normalize/1", "value"} in objects

    assert Enum.any?(slice.edges, &(&1.relation == :may_return_into))
    assert Enum.any?(slice.edges, &(&1.relation == :may_supply_parameter))
    assert Enum.any?(slice.edges, &(&1.basis == :lexical_assignment))

    assert Enum.any?(slice.guards, fn guard ->
             guard.subject == "Demo.Flow.normalize/1" and
               guard.attributes.source_variables == ["value"]
           end)

    assert :syntax_only in slice.uncertainties
    assert :runtime_reachability_unknown in slice.uncertainties
    refute :attacker_control in slice.uncertainties
    refute slice.truncated
  end

  test "retains multiple reaching definitions as explicit uncertainty" do
    source = """
    defmodule Demo.Branches do
      def emit(conn, raw, choose?) do
        value = raw
        value = if choose?, do: String.trim(raw), else: raw
        Plug.Conn.send_resp(conn, 200, value)
      end
    end
    """

    result = RampartSAST.inventory_sources([{"lib/demo/branches.ex", source}])

    assert [sink] =
             Inventory.query(result.inventory,
               kind: :call_argument,
               object: "Plug.Conn.send_resp/3#argument/3"
             )

    slice = DataFlow.backward(result.inventory, sink.id)
    bindings = Enum.filter(slice.facts, &(&1.kind == :binding and &1.object == "value"))

    assert length(bindings) == 2
    assert :multiple_reaching_definitions in slice.uncertainties
    assert :branch_feasibility_unknown in slice.uncertainties
  end

  test "bounds the slice and reports truncation instead of silently dropping work" do
    source = """
    defmodule Demo.BoundedFlow do
      def emit(conn, raw) do
        one = String.trim(raw)
        two = String.upcase(one)
        three = String.reverse(two)
        Plug.Conn.send_resp(conn, 200, three)
      end
    end
    """

    result = RampartSAST.inventory_sources([{"lib/demo/bounded_flow.ex", source}])

    assert [sink] =
             Inventory.query(result.inventory,
               kind: :call_argument,
               object: "Plug.Conn.send_resp/3#argument/3"
             )

    slice = DataFlow.backward(result.inventory, sink.id, max_nodes: 2)
    assert slice.truncated
    assert :max_nodes in slice.limit_reasons
    assert length(slice.facts) <= 2
  end

  test "indexes Erlang assignments, guards, parameters, and returns" do
    source = """
    -module(demo_flow).
    -export([emit/1, normalize/1]).
    emit(Input) ->
      Normalized = normalize(Input),
      io:format("~s", [Normalized]).
    normalize(Value) when is_binary(Value) -> Value.
    """

    result = RampartSAST.inventory_sources([{"src/demo_flow.erl", source}])
    inventory = result.inventory

    assert Enum.any?(Inventory.query(inventory, kind: :binding), fn fact ->
             fact.subject == "demo_flow.emit/1" and fact.object == "Normalized"
           end)

    assert Enum.any?(Inventory.query(inventory, kind: :parameter), fn fact ->
             fact.subject == "demo_flow.normalize/1" and fact.object == "Value"
           end)

    assert Enum.any?(Inventory.query(inventory, kind: :return), fn fact ->
             fact.subject == "demo_flow.normalize/1" and
               fact.attributes.source_variables == ["Value"]
           end)

    assert Enum.any?(Inventory.query(inventory, kind: :guard), fn fact ->
             fact.subject == "demo_flow.normalize/1" and
               fact.attributes.source_variables == ["Value"]
           end)
  end
end
