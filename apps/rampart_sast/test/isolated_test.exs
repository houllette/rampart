defmodule RampartSAST.IsolatedTest do
  use ExUnit.Case, async: true

  alias RampartSAST.Inventory.Page
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

  @tag :tmp_dir
  test "portable indexed pages preserve native filtering, totals, and continuation", %{
    tmp_dir: directory
  } do
    source =
      "defmodule Portable do\ndef run(x) do\n" <>
        String.duplicate("String.trim(x)\n", 120) <> "String.upcase(x)\nend\nend\n"

    entries = [{"lib/portable.ex", source}]
    portable = Isolated.inventory_sources(entries, isolation: [tmp_dir: directory])
    native = RampartSAST.inventory_sources(entries).inventory

    for offset <- [0, 100, 120, 200] do
      options = [kind: :call, target_module: "String", target_function: "trim", offset: offset]
      page = Isolated.query_page(portable, options)

      expected =
        native
        |> RampartSAST.Inventory.query_page(options)
        |> Page.to_map()
        |> JSON.encode!()
        |> JSON.decode!()

      assert JSON.decode!(JSON.encode!(page)) == expected
    end

    assert [%{"object" => "String.upcase/1"}] =
             Isolated.query(portable,
               target_module: "String",
               target_function: "upcase",
               kind: :call
             )
  end

  @tag :tmp_dir
  test "worker log overflow and malformed protocol fail closed and clean files", %{
    tmp_dir: directory
  } do
    for {body, expected, limits} <- [
          {"printf 123456789; exec sleep 30", "worker_log_limit", [max_log_bytes: 8]},
          {"for response do :; done; printf malformed > \"$response\"", "invalid_worker_response",
           []}
        ] do
      executable = Path.join(directory, expected)
      pid_file = executable <> ".pid"
      File.write!(executable, "#!/bin/sh\necho $$ > '#{pid_file}'\n#{body}\n")
      File.chmod!(executable, 0o700)
      protocol = Path.join(directory, "protocol")

      result =
        Isolated.inventory_sources([{"lib/example.ex", "defmodule Example do\nend\n"}],
          isolation: [elixir_executable: executable, tmp_dir: protocol, limits: limits]
        )

      assert result.status == :incomplete
      assert [%{"code" => ^expected}] = result.diagnostics
      refute child_alive?(pid_file)
      assert File.ls!(protocol) == []
    end
  end

  @tag :tmp_dir
  test "timeout reaps a silent worker and removes protocol files", %{tmp_dir: tmp_dir} do
    {executable, pid_file} = silent_worker(tmp_dir)

    result =
      Isolated.inventory_sources([{"lib/fixture.ex", "defmodule Fixture do\nend\n"}],
        isolation: [
          elixir_executable: executable,
          tmp_dir: Path.join(tmp_dir, "protocol"),
          limits: [timeout_ms: 1_000]
        ]
      )

    assert result.status == :incomplete
    assert [%{"code" => "worker_timeout"}] = result.diagnostics
    refute child_alive?(pid_file)
    assert File.ls!(Path.join(tmp_dir, "protocol")) == []
  end

  @tag :tmp_dir
  test "caller death reaps the worker and cleans protocol files", %{tmp_dir: tmp_dir} do
    {executable, pid_file} = silent_worker(tmp_dir)

    caller =
      Task.async(fn ->
        Isolated.inventory_sources([{"lib/fixture.ex", "defmodule Fixture do\nend\n"}],
          isolation: [elixir_executable: executable, tmp_dir: Path.join(tmp_dir, "protocol")]
        )
      end)

    assert eventually(fn -> File.exists?(pid_file) end)
    assert Task.shutdown(caller, :brutal_kill) == nil
    assert eventually(fn -> not child_alive?(pid_file) end)
    assert eventually(fn -> File.ls!(Path.join(tmp_dir, "protocol")) == [] end)
  end

  defp silent_worker(tmp_dir) do
    executable = Path.join(tmp_dir, "elixir-worker")
    pid_file = Path.join(tmp_dir, "child.pid")

    script =
      "#!/bin/sh\necho $$ > '#{pid_file}'\nexec '#{System.find_executable("elixir")}' -e 'Process.sleep(30_000)'\n"

    File.write!(executable, script)
    File.chmod!(executable, 0o700)
    {executable, pid_file}
  end

  defp child_alive?(pid_file) do
    pid = pid_file |> File.read!() |> String.trim()
    {_output, status} = System.cmd("kill", ["-0", pid], stderr_to_stdout: true)
    status == 0
  end

  defp eventually(predicate, attempts \\ 150)
  defp eventually(_predicate, 0), do: false

  defp eventually(predicate, attempts) do
    if predicate.() do
      true
    else
      Process.sleep(20)
      eventually(predicate, attempts - 1)
    end
  end
end
