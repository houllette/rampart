defmodule Foray.Stream do
  @moduledoc false

  alias Foray.{Pipeline, PipelineError, Scan}
  alias Foray.Stream.Bridge

  @spec new(Scan.t()) :: Enumerable.t(Core.Finding.t())
  def new(%Scan{} = scan) do
    Stream.resource(
      fn -> start_pipeline(scan) end,
      &next_finding/1,
      &stop_pipeline/1
    )
  end

  defp start_pipeline(scan) do
    {:ok, bridge} = Bridge.start_link()
    name = {:via, Registry, {Foray.Registry, {:stream_pipeline, make_ref()}}}

    on_complete = fn
      {:error, reason} -> Bridge.fail(bridge, reason)
      _outcome -> Bridge.complete(bridge)
    end

    try do
      case Pipeline.start_link(
             scan: scan,
             name: name,
             on_finding: &Bridge.deliver(bridge, &1),
             on_complete: on_complete
           ) do
        {:ok, pipeline} ->
          Process.unlink(pipeline)
          shutdown = scan.max_time * 1_000 + 10_000
          Bridge.watch(bridge, pipeline)
          watch_consumer(bridge, pipeline, name, shutdown)

          %{bridge: bridge, pipeline: pipeline, name: name, shutdown: shutdown}

        {:error, reason} ->
          raise PipelineError, stage: :startup, reason: reason

        :ignore ->
          raise PipelineError, stage: :startup, reason: :ignored
      end
    rescue
      exception ->
        if Process.alive?(bridge), do: GenServer.stop(bridge)
        reraise exception, __STACKTRACE__
    end
  end

  defp watch_consumer(bridge, pipeline, name, shutdown) do
    {:ok, _watcher} =
      Task.Supervisor.start_child(Foray.TaskSupervisor, fn ->
        monitor = Process.monitor(bridge)

        receive do
          {:DOWN, ^monitor, :process, ^bridge, _reason} ->
            if Process.alive?(pipeline), do: Pipeline.stop(name, shutdown)
        end
      end)

    :ok
  end

  defp next_finding(state) do
    case Bridge.next(state.bridge) do
      {:ok, finding} -> {[finding], state}
      :done -> {:halt, state}
      {:error, reason} -> raise PipelineError, stage: :execution, reason: reason
    end
  end

  defp stop_pipeline(state) do
    if Process.alive?(state.bridge), do: Bridge.cancel(state.bridge)
    stop_broadway(state)
    if Process.alive?(state.bridge), do: GenServer.stop(state.bridge, :normal)
  end

  defp stop_broadway(state) do
    if Process.alive?(state.pipeline) do
      Pipeline.stop(state.name, state.shutdown)
    else
      :ok
    end
  catch
    :exit, _reason -> :ok
  end
end
