defmodule Foray.Fuzz.Ffuf.Completion do
  @moduledoc false

  alias Foray.Wordlist.Lease
  @max_audit_bytes 16_777_216

  @spec prepare(job :: Foray.Job.t(), required :: boolean()) :: map() | nil
  def prepare(_job, false), do: nil

  def prepare(job, true) do
    inputs =
      Map.new(job.wordlists, fn
        %{keyword: keyword, source: {:seeds, [%Core.Seed{value: value}]}} -> {keyword, value}
        _other -> raise ArgumentError, "completion proof requires one concrete seed per keyword"
      end)

    suffix = :crypto.strong_rand_bytes(12) |> Base.url_encode64(padding: false)
    directory = Path.join(System.tmp_dir!(), "foray-completion-#{suffix}")
    {:ok, lease} = Lease.start(directory)
    %{lease: lease, path: Path.join(directory, "audit.jsonl"), inputs: inputs, method: job.method}
  end

  @spec arguments(completion :: map() | nil) :: [String.t()]
  def arguments(nil), do: []
  def arguments(completion), do: ["-audit-log", completion.path]

  @spec cleanup(completion :: map() | nil) :: :ok
  def cleanup(nil), do: :ok
  def cleanup(completion), do: Lease.release(completion.lease)

  @spec stdout(chunks :: Enumerable.t(), completion :: map() | nil) :: Enumerable.t()
  def stdout(chunks, nil), do: Stream.transform(chunks, nil, &stdout_chunk/2)

  def stdout(chunks, completion) do
    Stream.transform(chunks, fn -> completion end, &stdout_chunk/2, &finish/1, fn _state ->
      :ok
    end)
  end

  defp stdout_chunk({:stdout, chunk}, state), do: {[IO.iodata_to_binary(chunk)], state}
  defp stdout_chunk({:stderr, _chunk}, state), do: {[], state}
  defp stdout_chunk(chunk, state), do: {[IO.iodata_to_binary(chunk)], state}

  # ffuf's progress counter counts scheduled requests, not completed responses.
  # Refutation requires a response receipt for the exact input, not merely exit 0.
  defp finish(completion) do
    with {:ok, bytes} when is_binary(bytes) and byte_size(bytes) <= @max_audit_bytes <-
           File.open(completion.path, [:read, :binary], &IO.binread(&1, @max_audit_bytes + 1)),
         true <- complete_response?(bytes, completion) do
      {[], completion}
    else
      _missing_or_incomplete -> raise Foray.OutputError, reason: :incomplete_ffuf_execution
    end
  end

  defp complete_response?(bytes, completion) do
    bytes
    |> String.split("\n", trim: true)
    |> Enum.any?(fn line ->
      case Jason.decode(line) do
        {:ok, %{"Type" => "*ffuf.Response", "Data" => data}} ->
          matches_response?(data, completion)

        _other ->
          false
      end
    end)
  end

  defp matches_response?(
         %{
           "Cancelled" => false,
           "StatusCode" => status,
           "Request" => %{"Error" => "", "Input" => input, "Method" => method}
         },
         completion
       )
       when is_integer(status) and status in 100..599 and is_map(input) do
    method == completion.method and
      Enum.all?(completion.inputs, fn {keyword, value} ->
        case Map.get(input, keyword) do
          encoded when is_binary(encoded) -> Base.decode64(encoded) == {:ok, value}
          _missing -> false
        end
      end)
  end

  defp matches_response?(_data, _completion), do: false
end
