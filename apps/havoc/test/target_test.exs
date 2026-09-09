defmodule Havoc.TargetTest do
  use ExUnit.Case, async: true
  use Havoc.Case

  alias Havoc.Target
  alias Havoc.Target.{Function, Phoenix}
  alias Havoc.TestSupport.DerivedFunctionFixture

  security_targets "runs dynamically derived targets through the property pipeline",
    targets: [
      %Target{
        id: "custom:parser:input",
        kind: :function,
        generator: StreamData.constant("safe"),
        module: DerivedFunctionFixture,
        function: :decode,
        arity: 1,
        parameter: 1,
        oracles: [:no_crash],
        classes: [:derived],
        locus: %{function: "decode/1", param: 1},
        meta: %{parameter_position: 1}
      }
    ],
    persist: false,
    replay: false,
    runs: 1 do
    assert %Target{id: "custom:parser:input"} = target
    Function.invoke(target, payload)
  end

  test "an empty derived target set fails instead of creating a vacuous property" do
    assert_raise ArgumentError, ~r/no derived Havoc targets/, fn ->
      Target.check_all!([], [property_name: "empty", property_id: "empty"], fn _, _, _, _ ->
        :unreachable
      end)
    end
  end

  test "derives only direct text-like public function arguments from specs" do
    targets = Function.derive(DerivedFunctionFixture)

    assert Enum.map(targets, &{&1.function, &1.parameter}) == [decode: 1, parse: 1]
    refute Enum.any?(targets, &(&1.function in [:count, :undocumented]))
    assert Enum.all?(targets, &(&1.oracles == [:no_crash]))
  end

  test "explicit positions supplement conservative type inference" do
    [target] =
      Function.derive(DerivedFunctionFixture,
        only: [{:count, 1}],
        parameters: %{{:count, 1} => [1]},
        generator: StreamData.constant(7)
      )

    assert target.parameter == 1
    assert Function.invoke(target, 9) == 9
  end

  test "function invocation requires fixtures for non-fuzzed arguments" do
    [target] = Function.derive(DerivedFunctionFixture, only: [{:parse, 2}])

    assert Function.invoke(target, "payload", arguments: ["original", 10]) == {:ok, "payload"}

    assert_raise ArgumentError, ~r/arguments: is required/, fn ->
      Function.invoke(target, "payload")
    end
  end

  test "rejects invalid explicit argument positions" do
    assert_raise ArgumentError, ~r/invalid one-based parameter position/, fn ->
      Function.derive(DerivedFunctionFixture,
        only: [{:count, 1}],
        parameters: %{{:count, 1} => [0]}
      )
    end
  end

  test "derives Phoenix targets only for declared dynamic path segments" do
    routes = [
      %{
        verb: :get,
        path: "/users/:id/files/*path",
        plug: ExampleController,
        plug_opts: :show,
        metadata: %{api: true}
      },
      %{verb: :post, path: "/fixed", plug: ExampleController, plug_opts: :create},
      %{verb: :*, path: "/*path", plug: ExampleController, plug_opts: []}
    ]

    targets = Phoenix.derive_routes(routes, methods: [:get])

    assert Enum.map(targets, & &1.parameter) == ["id", "path"]
    assert Enum.all?(targets, &(&1.function == :show))
    assert Enum.all?(targets, &(&1.locus.method == "GET"))
  end

  test "builds encoded and deliberately raw paths from a route target" do
    [target] =
      Phoenix.derive_routes([
        %{verb: :get, path: "/files/:name", plug: ExampleController, plug_opts: :show}
      ])

    assert Phoenix.path(target, "../secret") == "/files/..%2Fsecret"
    assert Phoenix.path(target, "../secret", encode: false) == "/files/../secret"
  end

  test "Phoenix derivation fails clearly when Phoenix is not installed" do
    refute Code.ensure_loaded?(Module.concat(["Phoenix", "Router"]))

    assert_raise ArgumentError, ~r/Phoenix.Router.routes\/1 is unavailable/, fn ->
      Phoenix.derive(ExampleRouter)
    end
  end
end
