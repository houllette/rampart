defmodule Foray.JobExecution do
  @moduledoc false

  alias Foray.Stream.Bridge

  @spec run(fun :: (-> result), bridge :: pid() | nil, cancelled :: result) :: result
        when result: var
  def run(fun, nil, _cancelled), do: fun.()

  def run(fun, bridge, cancelled) do
    monitor = Process.monitor(bridge)

    try do
      case Bridge.subscribe(bridge) do
        :stop ->
          cancelled

        :ok ->
          await_job(Task.Supervisor.async(Foray.TaskSupervisor, fun), bridge, monitor, cancelled)
      end
    after
      Process.demonitor(monitor, [:flush])
      Bridge.unsubscribe(bridge)
      flush_cancel(bridge)
    end
  end

  defp await_job(task, bridge, monitor, cancelled) do
    reference = task.ref

    receive do
      {^reference, result} ->
        Task.ignore(task)
        result

      {:DOWN, ^reference, :process, _worker, reason} ->
        exit({:job_worker_failed, reason})

      {:foray_cancel, ^bridge} ->
        stop_job(task)
        cancelled

      {:DOWN, ^monitor, :process, ^bridge, _reason} ->
        stop_job(task)
        cancelled
    end
  end

  defp stop_job(task) do
    Task.yield(task, 750) || Task.shutdown(task, :brutal_kill)
  end

  defp flush_cancel(bridge) do
    receive do
      {:foray_cancel, ^bridge} -> :ok
    after
      0 -> :ok
    end
  end
end
