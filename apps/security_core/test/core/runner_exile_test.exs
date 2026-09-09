defmodule Core.RunnerExileTest do
  use ExUnit.Case, async: true

  alias Core.Runner.Exile, as: ExileRunner
  alias Core.Runner.TimeoutError

  @moduletag :requires_native_process

  test "supports lazy streaming and bounded collection" do
    assert "streamed" =
             ExileRunner.stream(["sh", "-c", "printf streamed"], stderr: :consume)
             |> Stream.map(fn {:stdout, chunk} -> chunk end)
             |> Enum.into("")

    assert {"collected", 0} = ExileRunner.run(["sh", "-c", "printf collected"], timeout: 1_000)
  end

  @tag :tmp_dir
  test "bounded collection times out and reaps the command", %{tmp_dir: tmp_dir} do
    pid_file = Path.join(tmp_dir, "child.pid")
    command = ["sh", "-c", ~s(echo $$ > "$1"; exec sleep 30), "runner-test", pid_file]

    assert_raise TimeoutError, fn -> ExileRunner.run(command, timeout: 200) end
    os_pid = pid_file |> File.read!() |> String.trim() |> String.to_integer()
    assert eventually(fn -> not os_process_alive?(os_pid) end, 5_000)
  end

  test "reaps the external process when its owner is brutally killed" do
    parent = self()

    owner =
      Task.async(fn ->
        {:ok, process} = Exile.Process.start_link(["sh", "-c", "sleep 30"], stderr: :disable)
        {:ok, os_pid} = Exile.Process.os_pid(process)
        send(parent, {:os_pid, os_pid})
        Process.sleep(:infinity)
      end)

    assert_receive {:os_pid, os_pid}, 1_000
    assert os_process_alive?(os_pid)
    assert Task.shutdown(owner, :brutal_kill) == nil
    assert eventually(fn -> not os_process_alive?(os_pid) end, 5_000)
  end

  defp eventually(predicate, timeout) do
    deadline = System.monotonic_time(:millisecond) + timeout
    eventually_until(predicate, deadline)
  end

  defp eventually_until(predicate, deadline) do
    cond do
      predicate.() ->
        true

      System.monotonic_time(:millisecond) >= deadline ->
        false

      true ->
        Process.sleep(20)
        eventually_until(predicate, deadline)
    end
  end

  defp os_process_alive?(pid) do
    case System.cmd("kill", ["-0", Integer.to_string(pid)], stderr_to_stdout: true) do
      {_output, 0} -> true
      {_output, _status} -> false
    end
  end
end
