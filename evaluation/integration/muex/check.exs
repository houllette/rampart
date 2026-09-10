Code.require_file("assertions.exs", System.fetch_env!("RAMPART_GATE_SUPPORT"))

defmodule Integration.Muex do
  import ExUnit.Assertions

  def run do
    {:ok, _} = Application.ensure_all_started(:muex)
    files = Path.wildcard("lib/*.ex")
    before = Map.new(files, &{&1, File.read!(&1)})

    assert {:ok, %{failures: 0, exit_code: 0}} =
             Muex.TestRunner.Port.run_tests(
               [
                 "test/security_test.exs",
                 "test/missing_control_test.exs",
                 "test/timeout_test.exs"
               ],
               cd: File.cwd!(),
               timeout_ms: 30_000
             )

    assert {:ok, %{results: [killed]}} =
             execute("lib/controller.ex,lib/unrelated.ex", "test/security_test.exs", 15_000)

    assert killed.result == :killed
    assert killed.mutation.mutator == MuexSecurity.Mutator.SecurityDecision
    assert killed.mutation.location.file == "lib/controller.ex"

    assert {:ok, %{results: [survived]}} =
             execute(
               "lib/controller.ex,lib/unrelated.ex",
               "test/missing_control_test.exs",
               15_000
             )

    assert survived.result == :survived

    assert {:ok, %{results: [timeout]}} = execute("lib/slow.ex", "test/timeout_test.exs", 2000)
    assert timeout.result == :timeout

    File.write!(
      "lib/injected_compile_failure.ex",
      "defmodule MutationFixture.Broken do\n def broken, do: missing_variable\nend\n"
    )

    try do
      assert {:error, {:compile_error, _}} =
               Muex.TestRunner.Port.run_tests(["test/security_test.exs"],
                 cd: File.cwd!(),
                 timeout_ms: 30_000
               )
    after
      File.rm!("lib/injected_compile_failure.ex")
    end

    assert before == Map.new(files, &{&1, File.read!(&1)})
    assert MutationFixture.Controller.read(:anonymous) == :denied
    assert MutationFixture.Unrelated.label("ok") == "label: ok"

    Integration.Assertions.finish(%{
      checks: [
        "baseline_passes",
        "bypass_killed",
        "missing_control_survives",
        "timeout_distinct",
        "compile_failure_distinct",
        "source_restored",
        "unrelated_code_untouched"
      ],
      killed: 1,
      survived: 1,
      timeout: 1,
      compile_failures: 1,
      muex_version: to_string(Application.spec(:muex, :vsn))
    })
  end

  defp execute(files, tests, timeout) do
    MuexSecurity.run([
      "--files",
      files,
      "--test-paths",
      tests,
      "--mutators",
      "security_decision",
      "--no-filter",
      "--no-optimize",
      "--no-tce",
      "--concurrency",
      "1",
      "--timeout",
      to_string(timeout),
      "--format",
      "json",
      "--fail-at",
      "0"
    ])
  end
end

Integration.Muex.run()
