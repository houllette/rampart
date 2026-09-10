defmodule Foray.Wordlist.Materializer do
  @moduledoc false

  alias Foray.{Job, Wordlist}
  alias Foray.Wordlist.Lease

  @spec materialize(Job.t()) :: {Job.t(), [pid()]}
  def materialize(%Job{} = job) do
    if Enum.any?(job.wordlists, &match?(%Wordlist{source: {:seeds, _seeds}}, &1)) do
      materialize_seeds(job)
    else
      {job, []}
    end
  end

  @spec cleanup(leases :: [pid()]) :: :ok
  def cleanup(leases), do: Enum.each(leases, &Lease.release/1)

  defp materialize_seeds(job) do
    directory = temporary_directory()
    {:ok, lease} = Lease.start(directory)

    try do
      {wordlists, _next_index} =
        Enum.map_reduce(job.wordlists, 1, fn
          %Wordlist{source: {:seeds, seeds}} = wordlist, index ->
            path = Path.join(directory, "corpus-#{index}.txt")
            write_seeds!(path, seeds)
            {%{wordlist | source: {:file, path}}, index + 1}

          %Wordlist{} = wordlist, index ->
            {wordlist, index}
        end)

      {%{job | wordlists: wordlists}, [lease]}
    rescue
      exception ->
        cleanup([lease])
        reraise exception, __STACKTRACE__
    end
  end

  defp write_seeds!(path, seeds) do
    content = Enum.map(seeds, fn %Core.Seed{value: value} -> [value, "\n"] end)
    File.write!(path, content, [:exclusive])
    File.chmod!(path, 0o600)
  end

  defp temporary_directory do
    suffix =
      "#{System.system_time(:nanosecond)}-#{System.unique_integer([:positive, :monotonic])}"

    Path.join(System.tmp_dir!(), "foray-seeds-#{suffix}")
  end
end
