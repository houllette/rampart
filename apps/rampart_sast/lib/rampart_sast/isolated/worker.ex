defmodule RampartSAST.Isolated.Worker do
  @moduledoc false

  alias RampartSAST.Isolated.Wire

  @spec main([String.t()]) :: no_return()
  def main([request_path, response_path]) do
    _started = Application.ensure_all_started(:crypto)

    response =
      request_path
      |> File.read!()
      |> :erlang.binary_to_term()
      |> execute()

    write_response!(response_path, response)
    System.halt(0)
  rescue
    error ->
      write_failure(response_path, "worker_exception", Exception.message(error))
      System.halt(0)
  catch
    kind, reason ->
      write_failure(response_path, "worker_exit", "#{kind}: #{inspect(reason, limit: 20)}")
      System.halt(0)
  end

  def main(_arguments) do
    System.halt(64)
  end

  defp execute(%{operation: :root, root: root, rules: rules, options: options})
       when is_binary(root) and is_list(rules) and is_list(options) do
    measured_scan(fn -> RampartSAST.scan(root, rules, options) end)
  end

  defp execute(%{operation: :sources, entries: entries, rules: rules, options: options})
       when is_list(entries) and is_list(rules) and is_list(options) do
    measured_scan(fn -> RampartSAST.scan_sources(entries, rules, options) end)
  end

  defp execute(_request) do
    Wire.encode_error("invalid_request", "isolated SAST worker received an invalid request")
  end

  defp measured_scan(scan) do
    started_at = System.monotonic_time()
    owner = self()
    sampler = spawn(fn -> sample(owner, initial_sample()) end)
    result = scan.()
    send(sampler, {:stop, self()})

    metrics =
      receive do
        {:worker_sample, ^sampler, sample} ->
          Map.put(sample, :scan_duration_ms, duration_ms(started_at))
      after
        1_000 ->
          Map.put(initial_sample(), :scan_duration_ms, duration_ms(started_at))
      end

    Wire.encode_result(result, metrics)
  end

  defp write_failure(nil, _code, _message), do: :ok

  defp write_failure(response_path, code, message) do
    write_response!(response_path, Wire.encode_error(code, message))
  rescue
    _error -> :ok
  end

  defp write_response!(response_path, response) do
    temporary_path = response_path <> ".part"
    File.write!(temporary_path, response, [:binary, :exclusive])
    File.rename!(temporary_path, response_path)
  end

  defp sample(owner, peak) do
    receive do
      {:stop, ^owner} ->
        send(owner, {:worker_sample, self(), merge_sample(peak, initial_sample())})
    after
      10 -> sample(owner, merge_sample(peak, initial_sample()))
    end
  end

  defp initial_sample do
    %{
      atom_count: :erlang.system_info(:atom_count),
      memory_bytes: :erlang.memory(:total),
      process_count: :erlang.system_info(:process_count)
    }
    |> Map.merge(proc_memory())
    |> Map.merge(cgroup_memory())
  end

  defp proc_memory do
    case File.read("/proc/self/status") do
      {:ok, status} ->
        %{}
        |> put_kilobytes(:os_rss_bytes, status, "VmRSS")
        |> put_kilobytes(:os_peak_rss_bytes, status, "VmHWM")

      {:error, _reason} ->
        %{}
    end
  end

  defp put_kilobytes(metrics, key, status, field) do
    case Regex.run(~r/^#{field}:\s+([0-9]+)\s+kB$/m, status) do
      [_match, kilobytes] -> Map.put(metrics, key, String.to_integer(kilobytes) * 1_024)
      _no_match -> metrics
    end
  end

  defp cgroup_memory do
    with {:ok, membership} <- File.read("/proc/self/cgroup"),
         path when is_binary(path) <- cgroup_v2_path(membership) do
      root = Path.join("/sys/fs/cgroup", String.trim_leading(path, "/"))

      %{}
      |> put_integer_file(:cgroup_memory_current_bytes, Path.join(root, "memory.current"))
      |> put_integer_file(:cgroup_memory_peak_bytes, Path.join(root, "memory.peak"))
      |> put_integer_file(:cgroup_memory_max_bytes, Path.join(root, "memory.max"))
    else
      _unavailable -> %{}
    end
  end

  defp cgroup_v2_path(membership) do
    membership
    |> String.split("\n", trim: true)
    |> Enum.find_value(fn line ->
      case String.split(line, ":", parts: 3) do
        ["0", "", path] -> path
        _other -> nil
      end
    end)
  end

  defp put_integer_file(metrics, key, path) do
    with {:ok, value} <- File.read(path),
         {integer, ""} <- value |> String.trim() |> Integer.parse() do
      Map.put(metrics, key, integer)
    else
      _unavailable -> metrics
    end
  end

  defp merge_sample(left, right) do
    Map.merge(left, right, fn _key, first, second -> max(first, second) end)
  end

  defp duration_ms(started_at) do
    System.convert_time_unit(System.monotonic_time() - started_at, :native, :millisecond)
  end
end
