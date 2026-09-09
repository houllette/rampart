defmodule Portico.Timeout do
  @moduledoc false

  @spec run((-> result), timeout()) :: {:ok, result} | {:exit, term()} | :timeout
        when result: term()
  def run(fun, timeout) when is_function(fun, 0) do
    task = Task.Supervisor.async_nolink(Portico.TaskSupervisor, fun)

    case Task.yield(task, timeout) || Task.shutdown(task, :brutal_kill) do
      {:ok, result} -> {:ok, result}
      {:exit, reason} -> {:exit, reason}
      nil -> :timeout
    end
  end
end
