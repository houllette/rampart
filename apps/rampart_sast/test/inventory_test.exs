defmodule RampartSAST.InventoryTest do
  use ExUnit.Case, async: true

  alias RampartSAST.Behavior.Ash, as: AshBehavior
  alias RampartSAST.Behavior.Ecto, as: EctoBehavior
  alias RampartSAST.Behavior.Phoenix, as: PhoenixBehavior
  alias RampartSAST.Behavior.Plug, as: PlugBehavior
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

  test "resolves __MODULE__-qualified aliases and calls without crashing" do
    source = """
    defmodule Demo.Relative do
      alias __MODULE__.FlowState

      def docs, do: __MODULE__.Docs.short_doc()
      def run(value), do: FlowState.run(value)
    end
    """

    result = RampartSAST.inventory_sources([{"lib/demo/relative.ex", source}])

    assert result.status == :complete

    assert [docs_call] = Inventory.calls_to(result.inventory, "Demo.Relative.Docs", "short_doc")
    assert docs_call.subject == "Demo.Relative.docs/0"
    assert docs_call.attributes.syntactic_module == "__MODULE__.Docs"
    assert docs_call.attributes.resolution == :source_alias

    assert [flow_call] = Inventory.calls_to(result.inventory, "Demo.Relative.FlowState", "run")
    assert flow_call.subject == "Demo.Relative.run/1"
    assert flow_call.attributes.resolution == :source_alias
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

  test "indexes bounded expression, binding, and call-argument facts" do
    source = """
    defmodule Demo.Output do
      import Plug.Conn

      def challenge(conn, metadata_url) do
        header = ~s(Bearer resource_metadata="\#{metadata_url}")
        put_resp_header(conn, "www-authenticate", header)
      end

      def aggregate(query) do
        Ash.aggregate(query, :sum, authorize_fields?: true)
      end
    end
    """

    result = RampartSAST.inventory_sources([{"lib/demo/output.ex", source}])

    assert [binding] =
             Inventory.query(result.inventory,
               kind: :binding,
               object: "header"
             )

    assert binding.subject == "Demo.Output.challenge/2"
    assert binding.attributes.expression.kind == :interpolation
    refute binding.attributes.expression.literal
    assert binding.attributes.source_variables == ["metadata_url"]
    assert String.contains?(binding.attributes.expression.preview, "resource_metadata")

    challenge_arguments =
      Inventory.query(result.inventory,
        kind: :call_argument,
        object_prefix: "Plug.Conn.put_resp_header/3#argument/"
      )

    assert challenge_arguments |> Enum.map(& &1.attributes.position) |> Enum.sort() == [1, 2, 3]

    assert Enum.all?(
             challenge_arguments,
             &(&1.attributes.target_call == "Plug.Conn.put_resp_header/3")
           )

    assert Enum.find(challenge_arguments, &(&1.attributes.position == 2)).attributes.expression ==
             %{
               kind: :literal,
               literal: true,
               preview: "\"www-authenticate\"",
               preview_truncated: false
             }

    assert Enum.find(challenge_arguments, &(&1.attributes.position == 3)).attributes.expression.kind ==
             :variable

    assert Enum.find(challenge_arguments, &(&1.attributes.position == 3)).attributes.source_variables ==
             ["header"]

    assert [aggregate_options] =
             Inventory.query(result.inventory,
               kind: :call_argument,
               object: "Ash.aggregate/3#argument/3"
             )

    assert aggregate_options.attributes.expression.kind == :keyword
    assert aggregate_options.attributes.expression.literal
    assert String.contains?(aggregate_options.attributes.expression.preview, "authorize_fields?")
  end

  test "truncates expression previews without truncating invalid UTF-8" do
    value = String.duplicate("λ", 180)

    result =
      RampartSAST.inventory_sources([
        {"lib/demo/preview.ex",
         "defmodule Demo.Preview do\n  def run, do: IO.puts(#{inspect(value)})\nend\n"}
      ])

    assert [argument] =
             Inventory.query(result.inventory,
               kind: :call_argument,
               object: "IO.puts/1#argument/1"
             )

    assert argument.attributes.expression.preview_truncated
    assert byte_size(argument.attributes.expression.preview) <= 240
    assert String.valid?(argument.attributes.expression.preview)
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

  test "adds reviewed Plug API semantics through an optional package classifier" do
    source = """
    defmodule Demo.PlugResponse do
      def respond(conn, body) do
        conn
        |> Plug.Conn.put_resp_header("x-evaluation", "true")
        |> Plug.Conn.send_resp(200, body)
      end
    end
    """

    result =
      RampartSAST.inventory_sources([{"lib/demo/plug_response.ex", source}],
        behavior_classifiers: [PlugBehavior]
      )

    assert Enum.map(Inventory.query(result.inventory, kind: :behavior), & &1.object) == [
             "http_response_header_write",
             "http_response_write"
           ]

    assert Enum.all?(Inventory.query(result.inventory, kind: :behavior), fn fact ->
             fact.attributes.basis == :reviewed_package_api and
               fact.attributes.classifier_id == "rampart.plug-behaviors.v1"
           end)
  end

  test "adds reviewed Ash aggregate, policy, and tenant-context semantics without verdicts" do
    source = """
    defmodule Demo.AshBehaviors do
      def aggregate(query, field), do: Ash.aggregate(query, {:max, field}, authorize_fields?: true)
      def policy(query, actor), do: Ash.can?(query, actor)
      def tenant(conn), do: Ash.PlugHelpers.get_tenant(conn)
    end
    """

    result =
      RampartSAST.inventory_sources([{"lib/demo/ash_behaviors.ex", source}],
        behavior_classifiers: [AshBehavior],
        module_owners: %{"Ash" => "ash"}
      )

    behaviors = Inventory.query(result.inventory, kind: :behavior)

    assert Enum.map(behaviors, &{&1.object, &1.attributes.via_object}) == [
             {"field_aggregate_read", "Ash.aggregate/3"},
             {"authorization_decision", "Ash.can?/2"},
             {"tenant_context_read", "Ash.PlugHelpers.get_tenant/1"}
           ]

    assert Enum.all?(behaviors, fn behavior ->
             behavior.attributes.basis == :reviewed_package_api and
               behavior.attributes.contract_family == :ash_authorization and
               behavior.attributes.classifier_id == "rampart.ash-behaviors.v1"
           end)

    assert [aggregate_spec] =
             Inventory.query(result.inventory,
               kind: :call_argument,
               object: "Ash.aggregate/3#argument/2"
             )

    assert aggregate_spec.attributes.expression.kind == :tuple
    assert aggregate_spec.attributes.source_variables == ["field"]

    assert Enum.map(Inventory.package_usage(result.inventory, "ash"), & &1.subject) == [
             "Demo.AshBehaviors.aggregate/2",
             "Demo.AshBehaviors.policy/2",
             "Demo.AshBehaviors.tenant/1"
           ]
  end

  test "keeps Phoenix and Ecto semantics in optional package classifiers" do
    source = """
    defmodule Demo.PackageBehaviors do
      import Ecto.Query, only: [fragment: 1]

      def redirect(conn, destination), do: Phoenix.Controller.redirect(conn, to: destination)
      def query(repo, sql), do: Ecto.Adapters.SQL.query(repo, sql, [])
      def fragment_expression(value), do: fragment(value)
      def cast(data, params), do: Ecto.Changeset.cast(data, params, [:role])
    end
    """

    result =
      RampartSAST.inventory_sources([{"lib/demo/package_behaviors.ex", source}],
        behavior_classifiers: [PhoenixBehavior, EctoBehavior],
        module_owners: %{"Phoenix" => "phoenix", "Ecto" => "ecto"}
      )

    behaviors = Inventory.query(result.inventory, kind: :behavior)

    assert Enum.map(behaviors, &{&1.object, &1.attributes.classifier_id}) == [
             {"http_redirect", "rampart.phoenix-behaviors.v1"},
             {"raw_database_query", "rampart.ecto-behaviors.v1"},
             {"database_query_fragment", "rampart.ecto-behaviors.v1"},
             {"external_data_cast", "rampart.ecto-behaviors.v1"}
           ]

    assert Enum.all?(behaviors, &(&1.attributes.basis == :reviewed_package_api))

    assert Enum.map(
             Inventory.package_usage(result.inventory, "phoenix"),
             &{&1.object, &1.attributes.target_module}
           ) == [{"phoenix", "Phoenix.Controller"}]

    assert Enum.map(
             Inventory.package_usage(result.inventory, "ecto"),
             &{&1.object, &1.attributes.target_module, &1.attributes.via_kind}
           ) == [
             {"ecto", "Ecto.Query", :directive},
             {"ecto", "Ecto.Adapters.SQL", :call},
             {"ecto", "Ecto.Query", :unqualified_call},
             {"ecto", "Ecto.Changeset", :call}
           ]
  end

  test "restores the outer lexical module after a nested module" do
    source = """
    defmodule Demo.Outer do
      defmodule Inner do
        def inner(value), do: String.trim(value)
      end

      def outer(value), do: String.upcase(value)
    end
    """

    result = RampartSAST.inventory_sources([{"lib/demo/outer.ex", source}])

    assert Enum.map(Inventory.query(result.inventory, kind: :module), & &1.object) == [
             "Demo.Outer",
             "Demo.Outer.Inner"
           ]

    assert [%{subject: "Demo.Outer.Inner.inner/1"}] =
             Inventory.query(result.inventory, kind: :call, object: "String.trim/1")

    assert [%{subject: "Demo.Outer.outer/1"}] =
             Inventory.query(result.inventory, kind: :call, object: "String.upcase/1")
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
