defmodule Foray.JobProducer do
  @moduledoc "Demand-driven Broadway producer for a finite queue of coarse fuzzing jobs."

  @behaviour Broadway.Producer
  @behaviour GenStage

  alias Broadway.Message

  @impl GenStage
  def init(opts) do
    jobs = Keyword.fetch!(opts, :jobs)
    {:producer, %{queue: :queue.from_list(jobs), draining?: false}}
  end

  @impl GenStage
  def handle_demand(demand, state) when demand > 0 do
    {jobs, queue} = take(state.queue, demand, [])
    messages = Enum.map(jobs, &message/1)
    {:noreply, messages, %{state | queue: queue}}
  end

  @doc "Drops queued, not-yet-dispatched jobs when Broadway begins draining."
  @impl Broadway.Producer
  def prepare_for_draining(state) do
    {:noreply, [], %{state | queue: :queue.new(), draining?: true}}
  end

  defp take(queue, 0, jobs), do: {Enum.reverse(jobs), queue}

  defp take(queue, remaining, jobs) do
    case :queue.out(queue) do
      {{:value, job}, queue} -> take(queue, remaining - 1, [job | jobs])
      {:empty, queue} -> {Enum.reverse(jobs), queue}
    end
  end

  defp message(job) do
    %Message{
      data: job,
      acknowledger: Broadway.NoopAcknowledger.init(),
      metadata: %{job_id: job.id}
    }
  end
end
