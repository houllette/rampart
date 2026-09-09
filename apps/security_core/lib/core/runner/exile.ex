defmodule Core.Runner.Exile do
  @moduledoc "Exile-backed implementation of the shared process seam."

  @behaviour Core.Runner

  alias Core.Runner.{Error, TimeoutError}

  @default_timeout 5_000
  @default_chunk_size 65_535

  @impl true
  def stream(argv, opts \\ []), do: Exile.stream!(argv, opts)

  @impl true
  def run(argv, opts \\ []) do
    {timeout, opts} = Keyword.pop(opts, :timeout, @default_timeout)
    {exit_timeout, opts} = Keyword.pop(opts, :exit_timeout, timeout)
    {max_chunk_size, opts} = Keyword.pop(opts, :max_chunk_size, @default_chunk_size)

    validate_positive!(:timeout, timeout)
    validate_positive!(:exit_timeout, exit_timeout)
    validate_positive!(:max_chunk_size, max_chunk_size)

    process_opts = Keyword.put_new(opts, :stderr, :redirect_to_stdout)

    task =
      Task.Supervisor.async_nolink(Core.TaskSupervisor, fn ->
        collect(argv, process_opts, max_chunk_size, exit_timeout)
      end)

    case Task.yield(task, timeout) || Task.shutdown(task, :brutal_kill) do
      {:ok, result} -> result
      {:exit, reason} -> raise Error, reason: reason
      nil -> raise TimeoutError, timeout: timeout
    end
  end

  defp collect(argv, opts, max_chunk_size, exit_timeout) do
    case Exile.Process.start_link(argv, opts) do
      {:ok, process} -> read_all(process, max_chunk_size, exit_timeout, [])
      {:error, reason} -> raise Error, reason: reason
    end
  end

  defp read_all(process, max_chunk_size, exit_timeout, chunks) do
    case Exile.Process.read(process, max_chunk_size) do
      {:ok, chunk} -> read_all(process, max_chunk_size, exit_timeout, [chunk | chunks])
      :eof -> finish(process, exit_timeout, chunks)
      {:error, reason} -> raise Error, reason: reason
    end
  end

  defp finish(process, exit_timeout, chunks) do
    {:ok, status} = Exile.Process.await_exit(process, exit_timeout)
    {chunks |> Enum.reverse() |> IO.iodata_to_binary(), status}
  end

  defp validate_positive!(_name, value) when is_integer(value) and value > 0, do: :ok

  defp validate_positive!(name, value) do
    raise ArgumentError, "#{name} must be a positive integer, got: #{inspect(value)}"
  end
end
