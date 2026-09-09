defmodule Foray.TestEngine do
  @behaviour Foray.Fuzz.Engine

  @impl true
  def option_schema do
    [
      observer: [type: :pid, required: true],
      block: [type: :boolean, default: false],
      findings_per_job: [type: :pos_integer, default: 1]
    ]
  end

  @impl true
  def capabilities, do: [:test]

  @impl true
  def stream(job, opts) do
    Stream.resource(
      fn ->
        send(opts[:observer], {:job_started, self(), job.id})
        1
      end,
      fn index ->
        if index <= opts[:findings_per_job] do
          maybe_block(opts[:block])
          send(opts[:observer], {:finding_pulled, job.id, index})
          finding = finding(job, index)
          {[finding], index + 1}
        else
          {:halt, index}
        end
      end,
      fn _state -> send(opts[:observer], {:job_stopped, job.id}) end
    )
  end

  defp maybe_block(false), do: :ok

  defp maybe_block(true) do
    receive do
      :release -> :ok
    after
      500 -> :ok
    end
  end

  defp finding(job, index) do
    url = String.replace(job.target.url, "FUZZ", "match-#{index}")

    %Core.Finding{
      id: Core.Finding.dedupe_id(:foray, [job.id, index]),
      source: :foray,
      category: :exposed_path,
      locus: %{url: url, method: job.method, status: 200},
      confidence: :medium,
      evidence: "test match",
      raw: %{"index" => index},
      observed_at: DateTime.utc_now()
    }
  end
end

defmodule Foray.TestOldRunner do
  @behaviour Core.Runner

  @impl true
  def stream(_command, _opts), do: []

  @impl true
  def run(_command, _opts), do: {"ffuf version: 2.1.0-dev", 0}
end

defmodule Foray.TestChunkRunner do
  @behaviour Core.Runner

  @impl true
  def stream(command, opts) do
    if observer = opts[:observer], do: send(observer, {:command, command})
    Keyword.fetch!(opts, :chunks)
  end

  @impl true
  def run(_command, _opts), do: {"ffuf version: 2.2.0", 0}
end
