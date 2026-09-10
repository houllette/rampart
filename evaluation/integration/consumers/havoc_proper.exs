Code.require_file("../assertions.exs", __DIR__)
import ExUnit.Assertions
Integration.Assertions.isolated!()
generator = HavocProper.Gen.binary(max_length: 8)
assert {:ok, binary} = :proper_gen.pick(generator)
assert is_binary(binary) and byte_size(binary) <= 8
Integration.Assertions.finish(%{checks: ["package_isolation", "proper_generation"]})
