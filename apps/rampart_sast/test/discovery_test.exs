defmodule RampartSAST.DiscoveryTest do
  use ExUnit.Case, async: true

  alias RampartSAST.Rules.UnsafeAtom

  @tag :tmp_dir
  test "scans a bounded root with explicit include and exclude globs", %{tmp_dir: tmp_dir} do
    File.mkdir_p!(Path.join(tmp_dir, "lib/generated"))
    File.write!(Path.join(tmp_dir, "mix.exs"), "defmodule Example.MixProject do\nend\n")
    File.write!(Path.join(tmp_dir, "lib/kept.ex"), dynamic_atom_source("Kept"))
    File.write!(Path.join(tmp_dir, "lib/generated/skipped.ex"), dynamic_atom_source("Skipped"))

    result =
      RampartSAST.scan(tmp_dir, [UnsafeAtom], exclude: ["lib/generated/**/*.ex"])

    assert result.status == :complete
    assert Enum.map(result.observations, & &1.span.file) == ["lib/kept.ex"]
    assert result.metrics.discovered_file_count == 2
  end

  @tag :tmp_dir
  test "does not read a source through a symlinked directory", %{tmp_dir: tmp_dir} do
    project = Path.join(tmp_dir, "project")
    outside = Path.join(tmp_dir, "outside")
    File.mkdir_p!(Path.join(project, "lib"))
    File.mkdir_p!(outside)
    File.write!(Path.join(outside, "leak.ex"), dynamic_atom_source("Leak"))
    File.ln_s!(outside, Path.join(project, "lib/link"))

    result = RampartSAST.scan(project, [UnsafeAtom])

    assert result.status == :complete
    assert result.observations == []
    assert result.metrics.discovered_file_count == 0

    assert Enum.any?(result.diagnostics, fn diagnostic ->
             diagnostic.code == :symlink_ignored and diagnostic.file == "lib/link"
           end)
  end

  @tag :tmp_dir
  test "rejects globs that can escape the selected root", %{tmp_dir: tmp_dir} do
    assert_raise ArgumentError, ~r/remain within the selected root/, fn ->
      RampartSAST.scan(tmp_dir, [UnsafeAtom], include: ["../outside/**/*.ex"])
    end
  end

  defp dynamic_atom_source(module) do
    """
    defmodule #{module} do
      def run(input), do: String.to_atom(input)
    end
    """
  end
end
