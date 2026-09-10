defmodule HavocProper.Coverage do
  @moduledoc """
  Serializes temporary OTP Cover instrumentation and measures executed lines.

  OTP Cover is node-global, not process-local. `with_modules/2` therefore takes
  a global lock and refuses to overwrite an existing non-empty Cover session.
  This protects another coverage tool's data, but cannot prevent unrelated
  processes from calling an instrumented module. Guided properties must run
  with `async: false` and should instrument narrowly scoped modules.
  """

  @type line_id :: {module(), pos_integer()}

  @doc "Temporarily Cover-compiles modules from their BEAM files and restores normal code."
  @spec with_modules([module()], (-> result)) :: result when result: var
  def with_modules(modules, fun) when is_list(modules) and is_function(fun, 0) do
    modules = modules |> Enum.uniq() |> Enum.sort()
    caller = self()
    reference = make_ref()
    {owner, monitor} = spawn_monitor(fn -> own_session(modules, caller, reference) end)

    case await_session(owner, monitor, reference) do
      :ready ->
        try do
          fun.()
        after
          send(owner, {reference, :release})
          :done = await_session(owner, monitor, reference)
          Process.demonitor(monitor, [:flush])
        end
    end
  end

  defp own_session(modules, caller, reference) do
    monitor = Process.monitor(caller)

    :global.trans(
      {{__MODULE__, :session}, caller},
      fn ->
        if Process.alive?(caller), do: instrument(modules, caller, reference, monitor)
      end,
      [node()]
    )

    send(caller, {reference, :done})
  catch
    kind, reason -> send(caller, {reference, {:failed, kind, reason, __STACKTRACE__}})
  end

  defp instrument(modules, caller, reference, monitor) do
    session_running? = is_pid(Process.whereis(:cover_server))
    :ok = start_cover()
    refuse_existing_session!()

    try do
      validate_modules!(modules)
      Enum.each(modules, &compile_beam!/1)
      send(caller, {reference, :ready})

      receive do
        {^reference, :release} -> :ok
        {:DOWN, ^monitor, :process, ^caller, _reason} -> :ok
      end
    after
      :ok = :cover.stop()
      if session_running?, do: :ok = start_cover()
    end
  end

  defp await_session(owner, monitor, reference) do
    receive do
      {^reference, {:failed, kind, reason, stacktrace}} ->
        Process.demonitor(monitor, [:flush])
        :erlang.raise(kind, reason, stacktrace)

      {^reference, status} ->
        status

      {:DOWN, ^monitor, :process, ^owner, reason} ->
        exit({:cover_session_failed, reason})
    end
  end

  @doc "Resets the instrumented modules, executes a candidate, and returns covered line IDs."
  @spec measure([module()], (-> result)) :: {result, [line_id()]} when result: var
  def measure(modules, fun) when is_list(modules) and is_function(fun, 0) do
    Enum.each(modules, fn module -> :ok = :cover.reset(module) end)
    result = fun.()
    {result, covered_lines(modules)}
  end

  @doc "Returns the sorted set of lines executed since the last reset."
  @spec covered_lines([module()]) :: [line_id()]
  def covered_lines(modules) do
    modules
    |> Enum.flat_map(&module_lines/1)
    |> Enum.uniq()
    |> Enum.sort()
  end

  defp start_cover do
    case :cover.start() do
      {:ok, _pid} -> :ok
      {:error, {:already_started, _pid}} -> :ok
    end
  end

  defp refuse_existing_session! do
    case :cover.modules() do
      [] -> :ok
      modules -> raise ArgumentError, "OTP Cover already instruments modules: #{inspect(modules)}"
    end
  end

  defp compile_beam!(module) do
    case :cover.compile_beam(module) do
      {:ok, ^module} ->
        :ok

      {:error, reason} ->
        raise ArgumentError, "cannot Cover-compile #{inspect(module)}: #{inspect(reason)}"
    end
  end

  defp module_lines(module) do
    case :cover.analyse(module, :coverage, :line) do
      {:ok, rows} ->
        for {{^module, line}, {covered, _uncovered}} <- rows,
            covered > 0,
            do: {module, line}

      {:error, reason} ->
        raise "cannot analyze coverage for #{inspect(module)}: #{inspect(reason)}"
    end
  end

  defp validate_modules!([]), do: raise(ArgumentError, "at least one coverage module is required")

  defp validate_modules!(modules) do
    Enum.each(modules, fn module ->
      unless is_atom(module) and Code.ensure_loaded?(module) do
        raise ArgumentError, "coverage module is not loaded: #{inspect(module)}"
      end

      unless is_list(:code.which(module)) do
        raise ArgumentError,
              "coverage module has no BEAM file on the code path: #{inspect(module)}"
      end
    end)
  end
end
