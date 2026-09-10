defmodule RampartSAST.IsolatedTest do
  use ExUnit.Case, async: true

  alias RampartSAST.Isolated
  alias RampartSAST.Isolated.Limits
  alias RampartSAST.Rules.UnsafeAtom

  @tag :tmp_dir
  test "scans in a disposable VM without interning source atoms in the host", %{tmp_dir: tmp_dir} do
    unique = "UntrustedIsolatedAtom#{System.unique_integer([:positive])}"
    module_name = "Fixture.#{unique}"

    source = """
    defmodule #{module_name} do
      def convert(value), do: String.to_atom(value)
    end
    """

    assert_raise ArgumentError, fn -> String.to_existing_atom(unique) end

    result =
      Isolated.scan_sources([{"lib/fixture.ex", source}], [UnsafeAtom],
        isolation: [tmp_dir: Path.join(tmp_dir, "worker")]
      )

    assert result.status == :complete
    assert result.worker["response_bytes"] > 0
    assert result.worker["memory_bytes"] > 0

    for key <- [
          "os_rss_bytes",
          "os_peak_rss_bytes",
          "cgroup_memory_current_bytes",
          "cgroup_memory_peak_bytes",
          "cgroup_memory_max_bytes"
        ],
        value = result.worker[key],
        not is_nil(value) do
      assert is_integer(value) and value > 0
    end

    if :os.type() == {:unix, :linux} do
      assert result.worker["os_rss_bytes"] > 0
      assert result.worker["os_peak_rss_bytes"] > 0
    end

    assert [%{"object" => ^module_name}] = Isolated.query(result, kind: :module)
    assert [%{"object" => "String.to_atom/1"}] = Isolated.query(result, kind: :call)
    assert [%{"rule" => %{"id" => "sast.unsafe-atom.v1"}}] = result.observations

    assert_raise ArgumentError, fn -> String.to_existing_atom(unique) end
    assert File.ls!(Path.join(tmp_dir, "worker")) == []
  end

  @tag :tmp_dir
  test "response limit failures are incomplete rather than empty complete scans", %{
    tmp_dir: tmp_dir
  } do
    project = Path.join(tmp_dir, "project")
    File.mkdir_p!(Path.join(project, "lib"))
    File.write!(Path.join([project, "lib", "fixture.ex"]), "defmodule Fixture do\nend\n")

    result =
      Isolated.inventory(project,
        isolation: [
          tmp_dir: Path.join(tmp_dir, "worker"),
          limits: Limits.new!(max_response_bytes: 8)
        ]
      )

    assert result.status == :incomplete
    assert result.inventory["facts"] == []
    assert [%{"code" => "worker_response_limit", "phase" => "isolation"}] = result.diagnostics
  end

  test "rejects executable scanner options at the parent boundary" do
    result =
      Isolated.inventory(".",
        context_providers: [fn -> :not_a_provider end]
      )

    assert result.status == :incomplete
    assert [%{"code" => "invalid_worker_request"}] = result.diagnostics
  end
end
