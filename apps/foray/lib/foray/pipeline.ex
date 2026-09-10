defmodule Foray.Pipeline do
  @moduledoc """
  Supervised Broadway topology that runs a small number of whole fuzzing jobs.

  `:on_finding` is synchronous and therefore remains in the backpressure path.
  Processor concurrency bounds ffuf processes, not HTTP requests; each job's
  `-rate` enforces its conservative share of the aggregate request ceiling.
  """

  @behaviour Broadway

  alias Broadway.Message
  alias Foray.{Audit, JobBuilder, JobProducer, PipelineError, Runtime, Sink, Target}

  @doc "Starts an authorized finite-job Broadway pipeline."
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts) do
    scan = Keyword.fetch!(opts, :scan)
    name = Keyword.get(opts, :name, __MODULE__)
    sink = Keyword.fetch!(opts, :on_finding)
    on_complete = Keyword.get(opts, :on_complete, fn _outcome -> :ok end)
    jobs = JobBuilder.build(scan)

    Core.Scope.ensure_all_authorized!(Enum.map(jobs, & &1.target), scan.scope)
    Runtime.validate!(scan)

    remaining = :atomics.new(1, [])
    completion = :atomics.new(1, [])
    :atomics.put(remaining, 1, length(jobs))

    Broadway.start_link(__MODULE__,
      name: name,
      shutdown: Keyword.get(opts, :shutdown, default_shutdown(scan)),
      max_restarts: 0,
      context: %{
        scan: scan,
        sink: sink,
        on_complete: on_complete,
        remaining: remaining,
        completion: completion,
        cancel_bridge: Keyword.get(opts, :cancel_bridge)
      },
      producer: producer_options(scan, jobs),
      processors: [
        default: [
          concurrency: JobBuilder.effective_concurrency(scan),
          min_demand: 0,
          max_demand: 1
        ]
      ]
    )
  end

  @doc "Returns a supervisor child specification with bounded ffuf drain grace."
  @spec child_spec(keyword()) :: Supervisor.child_spec()
  def child_spec(opts) do
    scan = Keyword.fetch!(opts, :scan)

    %{
      id: Keyword.get(opts, :name, __MODULE__),
      start: {__MODULE__, :start_link, [opts]},
      shutdown: Keyword.get(opts, :shutdown, default_shutdown(scan))
    }
  end

  @doc "Gracefully drains and stops a named pipeline."
  @spec stop(Broadway.name(), timeout()) :: :ok
  def stop(name, timeout \\ :infinity), do: Broadway.stop(name, :normal, timeout)

  @doc false
  @impl Broadway
  def process_name({:via, Registry, {registry, key}}, base_name) do
    {:via, Registry, {registry, {key, base_name}}}
  end

  def process_name({:via, module, term}, base_name) do
    {:via, module, {term, base_name}}
  end

  def process_name(name, base_name) when is_atom(name) do
    :"#{name}.Broadway.#{base_name}"
  end

  @impl Broadway
  def handle_message(_processor, %Message{data: job} = message, context) do
    case run_job(job, context) do
      {:ok, summary} ->
        finish_job(context, summary.outcome)
        Message.put_data(message, summary)

      {:error, kind, reason, stacktrace} ->
        finish_job(context, {:error, {kind, reason}})
        Message.failed(message, {kind, reason, stacktrace})
    end
  end

  defp run_job(job, context) do
    metadata = %{
      job_id: job.id,
      target: job.target.url,
      engine: context.scan.engine.module
    }

    try do
      counter = :atomics.new(1, [])

      summary =
        Core.Telemetry.span(:foray, :job, metadata, fn ->
          outcome = execute_job(job, context, metadata, counter)
          summary = %{job_id: job.id, outcome: outcome, finding_count: :atomics.get(counter, 1)}
          {summary, Map.merge(metadata, summary)}
        end)

      {:ok, summary}
    rescue
      exception -> {:error, :error, exception, __STACKTRACE__}
    catch
      kind, reason -> {:error, kind, reason, __STACKTRACE__}
    end
  end

  defp execute_job(job, context, metadata, counter) do
    result =
      Foray.JobExecution.run(
        fn -> attempt_job(job, context, metadata, counter) end,
        context.cancel_bridge,
        {:ok, :cancelled}
      )

    case result do
      {:ok, outcome} -> outcome
      {:error, kind, reason, stacktrace} -> :erlang.raise(kind, reason, stacktrace)
    end
  end

  defp attempt_job(job, context, metadata, counter) do
    Core.Scope.ensure_authorized!(job.target, context.scan.scope)
    Audit.emit(context.scan.audit, :job_launch, metadata)
    Core.Telemetry.launch(:foray, job.target.url)
    {outcome, _count} = consume_findings(job, context, counter)
    {:ok, outcome}
  rescue
    exception -> {:error, :error, exception, __STACKTRACE__}
  catch
    kind, reason -> {:error, kind, reason, __STACKTRACE__}
  end

  defp consume_findings(job, context, counter) do
    engine = context.scan.engine.module

    job
    |> engine.stream(context.scan.engine.opts)
    |> Enum.reduce_while({:ok, 0}, fn
      %Core.Finding{} = finding, {_outcome, count} ->
        authorize_finding!(finding, context.scan.scope)

        case Sink.deliver(context.sink, finding) do
          :ok ->
            :atomics.add(counter, 1, 1)
            Core.Telemetry.finding(:foray, finding)
            {:cont, {:ok, count + 1}}

          :stop ->
            {:halt, {:cancelled, count}}
        end

      other, _acc ->
        raise PipelineError, stage: :engine, reason: {:invalid_finding, other}
    end)
  end

  defp authorize_finding!(%Core.Finding{locus: %{url: url}}, scope) when is_binary(url) do
    case Target.parse(url) do
      {:ok, target} ->
        Core.Scope.ensure_authorized!(target, scope)

      {:error, reason} ->
        raise PipelineError, stage: :engine, reason: {:invalid_result_url, reason}
    end
  end

  defp authorize_finding!(_finding, _scope) do
    raise PipelineError, stage: :engine, reason: :finding_missing_url
  end

  defp finish_job(context, {:error, reason}) do
    _remaining = :atomics.sub_get(context.remaining, 1, 1)

    if :atomics.compare_exchange(context.completion, 1, 0, 2) == :ok do
      context.on_complete.({:error, reason})
    end

    :ok
  end

  defp finish_job(context, outcome) do
    remaining = :atomics.sub_get(context.remaining, 1, 1)

    if remaining == 0 and :atomics.compare_exchange(context.completion, 1, 0, 1) == :ok do
      context.on_complete.(outcome)
    end

    :ok
  end

  defp producer_options(scan, jobs) do
    options = [module: {JobProducer, [jobs: jobs]}, concurrency: 1]

    case scan.job_rate_limit do
      nil -> options
      rate_limit -> Keyword.put(options, :rate_limiting, Map.to_list(rate_limit))
    end
  end

  defp default_shutdown(scan), do: scan.max_time * 1_000 + 10_000
end
