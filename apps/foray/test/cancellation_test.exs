defmodule Foray.CancellationTest do
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog
  alias Foray.Scope.Allowlist

  @tag :tmp_dir
  test "consumer death interrupts a silent real command and removes its seed files", %{
    tmp_dir: directory
  } do
    exercise_cancellation(directory, false)
  end

  @tag :tmp_dir
  test "taking one match interrupts the next silent read without waiting for maxtime", %{
    tmp_dir: directory
  } do
    exercise_cancellation(directory, true)
  end

  defp exercise_cancellation(directory, emit?) do
    handler = {__MODULE__, self()}

    :ok =
      :telemetry.attach(handler, [:core, :foray, :job, :stop], &__MODULE__.job_stopped/4, self())

    on_exit(fn -> :telemetry.detach(handler) end)
    executable = Path.join(directory, "ffuf-fixture")
    info = Path.join(directory, "child")
    fixture = Path.expand("fixtures/ffuf_v2_2.ndjson", __DIR__)
    output = if emit?, do: "head -n 1 '#{fixture}'", else: ":"

    File.write!(executable, """
    #!/bin/sh
    if [ "$1" = "-V" ]; then echo 'ffuf 2.2.0'; exit 0; fi
    while [ "$#" -gt 0 ]; do
      if [ "$1" = "-w" ]; then shift; corpus="$1"; fi
      shift
    done
    echo "$$ $corpus" > '#{info}'
    #{output}
    exec sleep 30
    """)

    File.chmod!(executable, 0o700)
    registrations = Registry.count(Foray.Registry)
    seed = %Core.Seed{id: "admin", value: "admin", provenance: :wordlist}

    stream =
      Foray.target("https://app.example",
        scope: Allowlist.new!(["https://app.example/"])
      )
      |> Foray.fuzz_path(wordlist: [seed])
      |> Foray.rate(max_time: 300)
      |> Foray.engine(Foray.Fuzz.Ffuf, executable: executable, exit_timeout: 500)
      |> Foray.stream()

    capture_log(fn ->
      consumer =
        Task.async(fn -> consume(stream, emit?) end)

      assert eventually(fn -> File.exists?(info) and File.read!(info) != "" end)
      [pid, corpus] = info |> File.read!() |> String.split()
      corpus = String.replace_suffix(corpus, ":FUZZ", "")
      on_exit(fn -> System.cmd("kill", ["-KILL", pid], stderr_to_stdout: true) end)
      started = System.monotonic_time(:millisecond)

      if emit? do
        assert {:ok, [%Core.Finding{}]} =
                 Task.yield(consumer, 3_000) || Task.shutdown(consumer, :brutal_kill)
      else
        Task.shutdown(consumer, :brutal_kill)
      end

      assert eventually(fn -> not alive?(pid) and not File.exists?(Path.dirname(corpus)) end)
      assert System.monotonic_time(:millisecond) - started < 5_000
      assert eventually(fn -> Registry.count(Foray.Registry) == registrations end)
      expected_count = if emit?, do: 1, else: 0
      assert_receive {:job_stop, %{outcome: :cancelled, finding_count: ^expected_count}}
    end)
  end

  @doc false
  def job_stopped(_event, _measurements, metadata, observer),
    do: send(observer, {:job_stop, metadata})

  defp consume(stream, true), do: Enum.take(stream, 1)
  defp consume(stream, false), do: Enum.to_list(stream)

  defp alive?(pid), do: elem(System.cmd("kill", ["-0", pid], stderr_to_stdout: true), 1) == 0

  defp eventually(predicate, attempts \\ 100)
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
