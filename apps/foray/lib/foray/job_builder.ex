defmodule Foray.JobBuilder do
  @moduledoc "Builds one bounded engine job per normalized target."

  alias Foray.{Job, Scan}

  @doc "Builds the concrete jobs represented by a scan plan."
  @spec build(Scan.t()) :: [Job.t()]
  def build(%Scan{} = scan) do
    concurrency = effective_concurrency(scan)
    request_rate = div(scan.aggregate_rate, concurrency)

    scan.targets
    |> Enum.with_index(1)
    |> Enum.map(fn {target, index} ->
      %Job{
        id: "#{scan.id}:#{index}",
        target: target,
        method: scan.method,
        headers: scan.headers,
        body: scan.body,
        cookies: scan.cookies,
        fuzz_points: scan.fuzz_points,
        wordlists: scan.wordlists,
        oracle: scan.oracle,
        mode: scan.mode,
        threads: scan.threads,
        request_rate: request_rate,
        delay: scan.delay,
        max_time: scan.max_time,
        recursion: scan.recursion,
        meta: scan.metadata
      }
    end)
  end

  @doc "Returns the process concurrency that preserves the aggregate request-rate ceiling."
  @spec effective_concurrency(Scan.t()) :: pos_integer()
  def effective_concurrency(%Scan{} = scan) do
    scan.max_concurrency
    |> min(scan.aggregate_rate)
    |> min(length(scan.targets))
    |> max(1)
  end
end
