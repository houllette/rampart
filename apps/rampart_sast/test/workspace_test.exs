defmodule RampartSAST.WorkspaceTest do
  use ExUnit.Case, async: true

  alias RampartSAST.{Component, Inventory, Workspace}

  test "cross-package source derives checksummed module ownership and use edges" do
    target =
      Component.new!(
        id: "demo",
        kind: :target,
        sources: [
          {"lib/demo.ex",
           """
           defmodule Demo do
             alias Dependency.Parser
             def decode(input), do: Parser.decode(input)
           end
           """}
        ]
      )

    dependency =
      Component.new!(
        id: "dependency-parser",
        kind: :dependency,
        package: "dependency_parser",
        version: "1.2.3",
        sources: [
          {"lib/dependency/parser.ex",
           """
           defmodule Dependency.Parser do
             def decode(input), do: input
           end
           """}
        ]
      )

    result = Workspace.inventory([target, dependency])

    assert result.status == :complete
    assert result.inventory.module_owners["Dependency.Parser"] == "dependency_parser"

    assert Enum.any?(Inventory.package_usage(result.inventory, "dependency_parser"), fn fact ->
             fact.subject == "Demo.decode/1" and fact.attributes.via_kind == :call
           end)

    assert [module_fact] =
             Inventory.query(result.inventory, kind: :module, object: "Dependency.Parser")

    assert module_fact.span.file == "components/dependency-parser/lib/dependency/parser.ex"
    assert module_fact.attributes.origin.path == "lib/dependency/parser.ex"
    assert module_fact.attributes.origin.version == "1.2.3"
    assert byte_size(module_fact.attributes.origin.checksum) == 64
  end

  test "component checksums detect changed source snapshots" do
    component =
      Component.new!(
        id: "demo",
        kind: :target,
        sources: [{"lib/demo.ex", "defmodule Demo do\nend\n"}]
      )

    assert_raise ArgumentError, ~r/checksum does not match/, fn ->
      Component.new!(
        id: "demo",
        kind: :target,
        checksum: component.checksum,
        sources: [{"lib/demo.ex", "defmodule Changed do\nend\n"}]
      )
    end
  end
end
