defmodule RampartSAST.ModuleOwnersTest do
  use ExUnit.Case, async: true

  alias RampartSAST.ModuleOwners

  test "reads module names directly from BEAM chunks without loading artifact modules" do
    {RampartSAST.Inventory, beam, _path} = :code.get_object_code(RampartSAST.Inventory)

    assert ModuleOwners.from_binaries!([{"rampart_sast", beam}]) == %{
             "Elixir.RampartSAST.Inventory" => "rampart_sast"
           }
  end

  @tag :tmp_dir
  test "reads regular BEAM paths under aggregate limits", %{tmp_dir: tmp_dir} do
    {RampartSAST.Inventory, beam, _path} = :code.get_object_code(RampartSAST.Inventory)
    path = Path.join(tmp_dir, "inventory.beam")
    File.write!(path, beam)

    assert ModuleOwners.from_paths!([{"rampart_sast", path}]) == %{
             "Elixir.RampartSAST.Inventory" => "rampart_sast"
           }

    assert_raise ArgumentError, ~r/total byte limit/, fn ->
      ModuleOwners.from_paths!([{"rampart_sast", path}], max_total_bytes: 10)
    end
  end

  test "drops ambiguous ownership and rejects malformed or oversized artifacts" do
    {RampartSAST.Inventory, beam, _path} = :code.get_object_code(RampartSAST.Inventory)

    assert ModuleOwners.from_binaries!([{"one", beam}, {"two", beam}]) == %{}

    assert_raise ArgumentError, ~r/invalid BEAM artifact header/, fn ->
      ModuleOwners.from_binaries!([{"bad", "not-a-beam"}])
    end

    assert_raise ArgumentError, ~r/exceeds/, fn ->
      ModuleOwners.from_binaries!([{"large", beam}], max_beam_bytes: 10)
    end

    assert_raise ArgumentError, ~r/total byte limit/, fn ->
      ModuleOwners.from_binaries!([{"large-total", beam}], max_total_bytes: 10)
    end

    assert_raise ArgumentError, ~r/invalid BEAM artifact size/, fn ->
      ModuleOwners.from_binaries!([{"trailing", beam <> <<0>>}])
    end
  end
end
