defmodule RampartSAST.InventoryTest do
  use ExUnit.Case, async: true

  alias RampartSAST.Inventory
  alias RampartSAST.Rules.UnsafeAtom

  test "indexes ordinary structure and correlates host-resolved dependency usage" do
    mix_source = """
    defmodule Demo.MixProject do
      use Mix.Project

      defp deps do
        [
          {:plug, "~> 1.18"},
          {:private_widget, git: "https://example.invalid/widget.git"}
        ]
      end
    end
    """

    app_source = """
    defmodule Demo.Request do
      alias Plug.Conn

      def content_type(conn), do: Conn.get_req_header(conn, "content-type")
    end
    """

    result =
      RampartSAST.scan_sources(
        [{"mix.exs", mix_source}, {"lib/demo/request.ex", app_source}],
        [UnsafeAtom],
        module_owners: %{"Plug" => "plug"}
      )

    assert result.status == :complete

    assert Enum.map(Inventory.query(result.inventory, kind: :dependency), & &1.object) == [
             "plug",
             "private_widget"
           ]

    assert [definition] =
             Inventory.query(result.inventory,
               kind: :definition,
               object: "Demo.Request.content_type/1"
             )

    assert definition.subject == "Demo.Request"

    usage = Inventory.package_usage(result.inventory, "plug")
    assert Enum.any?(usage, &(&1.attributes.via_kind == :directive))
    assert Enum.any?(usage, &(&1.attributes.via_kind == :call))

    assert [call] = Inventory.calls_to(result.inventory, "Plug.Conn", "get_req_header")
    assert call.subject == "Demo.Request.content_type/1"
    assert call.attributes.argument_shapes == [:dynamic, :literal]
    assert call.attributes.resolution == :source_alias

    [first_page] = Inventory.query(result.inventory, kind: :dependency, limit: 1)
    [second_page] = Inventory.query(result.inventory, kind: :dependency, limit: 1, offset: 1)
    refute first_page.id == second_page.id
  end

  test "resolves explicit imports while preserving ambiguous unqualified calls" do
    source = """
    defmodule Demo.Imported do
      alias Plug.Conn, as: Conn
      import Conn, only: [get_req_header: 2]
      import Other.Headers, only: [ambiguous: 1]
      import More.Headers, only: [ambiguous: 1]

      def header(conn), do: get_req_header(conn, "content-type")
      def unresolved(value), do: ambiguous(value)
    end
    """

    result =
      RampartSAST.inventory_sources([{"lib/demo/imported.ex", source}],
        module_owners: %{"Plug" => "plug"}
      )

    assert [resolved] =
             Inventory.query(result.inventory,
               kind: :unqualified_call,
               object: "Plug.Conn.get_req_header/2"
             )

    assert resolved.attributes.resolution == :source_import

    assert Enum.any?(
             Inventory.package_usage(result.inventory, "plug"),
             &(&1.subject == "Demo.Imported.header/1")
           )

    assert [ambiguous] =
             Inventory.query(result.inventory, kind: :unqualified_call, object: "ambiguous/1")

    assert ambiguous.attributes.resolution == :ambiguous_import
    assert ambiguous.attributes.candidate_modules == ["More.Headers", "Other.Headers"]
  end

  test "indexes behavior callbacks, protocols, and their syntactic implementations" do
    source = """
    defmodule Demo.Contract do
      @callback authorize(term()) :: :ok | {:error, term()}
    end

    defmodule Demo.ContractImpl do
      alias Demo.Contract, as: Contract
      @behaviour Contract
      def authorize(_input), do: :ok
    end

    defprotocol Demo.Render do
      def render(value)
    end

    defimpl Demo.Render, for: Demo.Item do
      def render(value), do: inspect(value)
    end
    """

    result = RampartSAST.inventory_sources([{"lib/demo/contracts.ex", source}])

    assert Enum.map(Inventory.query(result.inventory, kind: :callback), & &1.object) == [
             "Demo.Contract.authorize/1",
             "Demo.Render.render/1"
           ]

    assert Enum.map(
             Inventory.query(result.inventory, kind: :callback_implementation),
             &{&1.subject, &1.object}
           ) == [
             {"Demo.ContractImpl.authorize/1", "Demo.Contract.authorize/1"},
             {"Demo.Render.Demo.Item.render/1", "Demo.Render.render/1"}
           ]

    assert [protocol] =
             Inventory.query(result.inventory, kind: :module, object: "Demo.Render")

    assert protocol.attributes.module_kind == :protocol

    assert [implementation] =
             Inventory.query(result.inventory,
               kind: :module,
               object: "Demo.Render.Demo.Item"
             )

    assert implementation.attributes.module_kind == :protocol_implementation

    assert [directive] =
             Inventory.query(result.inventory,
               kind: :directive,
               subject: "Demo.Render.Demo.Item",
               object: "Demo.Render"
             )

    assert directive.attributes.protocol_types == ["Demo.Item"]
  end

  test "keeps dynamic dispatch as an explicit noisy fact" do
    source = """
    defmodule Demo.Dispatch do
      def invoke(module, input), do: module.handle(normalize(input))
      defp normalize(input), do: input
    end
    """

    result = RampartSAST.inventory_sources([{"lib/demo/dispatch.ex", source}])

    assert [call] = Inventory.calls_to(result.inventory, "<dynamic-module>", "handle")
    assert call.subject == "Demo.Dispatch.invoke/2"
    assert call.attributes.resolution == :dynamic_dispatch

    assert [local_call] =
             Inventory.query(result.inventory,
               kind: :unqualified_call,
               object: "Demo.Dispatch.normalize/1"
             )

    assert local_call.attributes.resolution == :local_definition
  end

  test "indexes exact lock versions as facts without evaluating the lock file" do
    lock = """
    %{
      "plug" => {:hex, :plug, "1.18.1", "checksum", [:mix], [], "hexpm", "outer"}
    }
    """

    result = RampartSAST.scan_sources([{"mix.lock", lock}], [])

    assert [fact] = Inventory.query(result.inventory, relation: :locks_dependency)
    assert fact.object == "plug"
    assert fact.attributes.version == "1.18.1"
    assert fact.attributes.source == :hex
  end

  test "indexes Rebar declarations and lock levels without evaluating project code" do
    config = """
    {deps, [
      {cowboy, "2.12.0"},
      {internal_tool, {git, "https://example.invalid/tool.git", {tag, "v1"}}}
    ]}.
    """

    lock = """
    {"1.2.0", [
      {<<"cowboy">>, {pkg, <<"cowboy">>, <<"2.12.0">>}, 0},
      {<<"ranch">>, {pkg, <<"ranch">>, <<"2.1.0">>}, 1}
    ]}.
    """

    result =
      RampartSAST.inventory_sources([{"rebar.config", config}, {"rebar.lock", lock}])

    assert result.status == :complete

    assert Enum.map(
             Inventory.query(result.inventory, relation: :declares_dependency),
             &{&1.object, &1.attributes.source}
           ) == [{"cowboy", :hex}, {"internal_tool", :git}]

    assert Enum.map(
             Inventory.query(result.inventory, relation: :locks_dependency),
             &{&1.object, &1.attributes.directness}
           ) == [{"cowboy", :direct}, {"ranch", :transitive}]
  end

  test "indexes Erlang callback declarations" do
    source = """
    -module(example_behaviour).
    -callback authorize(term()) -> ok | {error, term()}.
    """

    result = RampartSAST.inventory_sources([{"src/example_behaviour.erl", source}])

    assert [callback] =
             Inventory.query(result.inventory,
               kind: :callback,
               object: "example_behaviour.authorize/1"
             )

    assert callback.attributes.callback_kind == :callback
  end

  test "indexes Erlang modules, definitions, and remote calls while rules remain optional signals" do
    source = """
    -module(example).
    -export([run/1]).
    run(Input) -> erlang:binary_to_atom(Input, utf8).
    """

    result = RampartSAST.scan_sources([{"src/example.erl", source}], [UnsafeAtom])

    assert result.status == :complete
    assert [signal] = result.observations
    assert signal.span.start_line == 3
    assert signal.facts.api == ":erlang.binary_to_atom/2"

    assert [_module] = Inventory.query(result.inventory, kind: :module, object: "example")

    assert [_definition] =
             Inventory.query(result.inventory, kind: :definition, object: "example.run/1")

    assert [call] = Inventory.calls_to(result.inventory, "erlang", "binary_to_atom")
    assert call.subject == "example.run/1"
    assert call.attributes.argument_shapes == [:dynamic, :literal]
  end
end
