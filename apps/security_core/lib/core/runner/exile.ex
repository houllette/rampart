defmodule Core.Runner.Exile do
  @moduledoc """
  Exile-backed process execution with caller ownership and bounded collection.

  `run/2` limits execution time and total output (1 MiB by default). Timeout,
  output overflow, and caller death close the reader and await Exile's exit
  sequence. Cleanup may take up to `:exit_timeout` after the execution deadline.
  """

  @behaviour Core.Runner
  alias Core.Runner.{Error, TimeoutError}

  @impl true
  def stream(argv, opts \\ []), do: Exile.stream!(argv, opts)

  @impl true
  def run(argv, opts \\ []) do
    {timeout, opts} = Keyword.pop(opts, :timeout, 5_000)
    {exit_timeout, opts} = Keyword.pop(opts, :exit_timeout, 1_000)
    {chunk_size, opts} = Keyword.pop(opts, :max_chunk_size, 65_535)
    {output_limit, opts} = Keyword.pop(opts, :max_output_bytes, 1_048_576)
    {execution_owner, opts} = Keyword.pop(opts, :owner, self())
    unless is_pid(execution_owner), do: raise(ArgumentError, ":owner must be a PID")

    Enum.each(
      [
        timeout: timeout,
        exit_timeout: exit_timeout,
        max_chunk_size: chunk_size,
        max_output_bytes: output_limit
      ],
      fn {name, value} ->
        validate_positive!(name, value)
      end
    )

    caller = self()
    reference = make_ref()
    opts = Keyword.put_new(opts, :stderr, :redirect_to_stdout)

    {owner, monitor} =
      spawn_monitor(fn ->
        result =
          collect_owned(
            execution_owner,
            argv,
            opts,
            timeout,
            exit_timeout,
            chunk_size,
            output_limit
          )

        send(caller, {reference, result})
      end)

    receive do
      {^reference, result} ->
        Process.demonitor(monitor, [:flush])
        unwrap(result)

      {:DOWN, ^monitor, :process, ^owner, reason} ->
        raise Error, reason: reason
    end
  end

  defp collect_owned(caller, argv, opts, timeout, exit_timeout, chunk_size, output_limit) do
    caller_monitor = Process.monitor(caller)

    case Exile.Process.start_link(argv, opts) do
      {:ok, process} ->
        coordinator = self()

        reader =
          Task.Supervisor.async_nolink(Core.TaskSupervisor, fn ->
            owner_monitor = Process.monitor(coordinator)

            receive do
              :read ->
                Process.demonitor(owner_monitor, [:flush])
                read_all(process, chunk_size, output_limit, [], 0)

              {:DOWN, ^owner_monitor, :process, ^coordinator, _reason} ->
                {:error, :owner_stopped}
            end
          end)

        :ok = Exile.Process.change_pipe_owner(process, :stdout, reader.pid)

        if opts[:stderr] == :consume,
          do: :ok = Exile.Process.change_pipe_owner(process, :stderr, reader.pid)

        :ok = Exile.Process.close_stdin(process)
        send(reader.pid, :read)
        outcome = await_reader(reader, caller_monitor, timeout)
        exit_result = Exile.Process.await_exit(process, exit_timeout)
        Process.demonitor(caller_monitor, [:flush])
        finish(outcome, exit_result)

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp await_reader(reader, caller_monitor, timeout) do
    reference = reader.ref

    receive do
      {^reference, result} ->
        Task.ignore(reader)
        result

      {:DOWN, ^reference, :process, _pid, reason} ->
        {:error, {:reader_exit, reason}}

      {:DOWN, ^caller_monitor, :process, _pid, _reason} ->
        Task.shutdown(reader, :brutal_kill)
        {:error, :caller_stopped}
    after
      timeout ->
        Task.shutdown(reader, :brutal_kill)
        {:timeout, timeout}
    end
  end

  defp read_all(process, chunk_size, output_limit, chunks, bytes) do
    case Exile.Process.read_any(process, min(chunk_size, output_limit - bytes + 1)) do
      {:ok, {_pipe, chunk}} ->
        size = IO.iodata_length(chunk)

        if bytes + size > output_limit do
          {:error, {:output_limit, output_limit}}
        else
          read_all(process, chunk_size, output_limit, [chunk | chunks], bytes + size)
        end

      :eof ->
        {:ok, chunks |> Enum.reverse() |> IO.iodata_to_binary()}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp finish({:ok, output}, {:ok, status}), do: {:ok, {output, status}}
  defp finish(failure, _exit_result), do: failure

  defp unwrap({:ok, result}), do: result
  defp unwrap({:error, reason}), do: raise(Error, reason: reason)
  defp unwrap({:timeout, timeout}), do: raise(TimeoutError, timeout: timeout)

  defp validate_positive!(_name, value) when is_integer(value) and value > 0, do: :ok

  defp validate_positive!(name, value) do
    raise ArgumentError, "#{name} must be a positive integer, got: #{inspect(value)}"
  end
end
