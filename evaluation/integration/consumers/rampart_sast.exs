Code.require_file("../assertions.exs", __DIR__)
import ExUnit.Assertions
Integration.Assertions.isolated!()
File.mkdir_p!("target/lib")

File.write!(
  "target/lib/sample.ex",
  "defmodule Sample do\n def decode(value), do: String.to_atom(value)\nend\n"
)

result = RampartSAST.Isolated.inventory("target")
assert result.status == :complete
assert Enum.any?(result.inventory["facts"], &(&1["kind"] == "call"))
Integration.Assertions.finish(%{checks: ["package_isolation", "disposable_worker", "facts"]})
