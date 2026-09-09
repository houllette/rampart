defmodule Portico.ScanStream do
  @moduledoc false

  @enforce_keys [:enumerable, :scan]
  defstruct [:enumerable, :scan]

  @spec new(Enumerable.t(), Portico.Scan.t()) :: t()
  def new(enumerable, scan), do: %__MODULE__{enumerable: enumerable, scan: scan}

  @type t :: %__MODULE__{enumerable: Enumerable.t(), scan: Portico.Scan.t()}
end

defimpl Enumerable, for: Portico.ScanStream do
  def reduce(scan_stream, acc, reducer) do
    target = telemetry_target(scan_stream.scan)
    span = Core.Telemetry.start_span(:portico, :scan, %{target: target})
    counter = :counters.new(1, [])
    consumer_halted = :atomics.new(1, [])

    wrapped_reducer = fn host, reducer_acc ->
      findings = Portico.Finding.emit(host)
      :counters.add(counter, 1, length(findings))
      result = reducer.(host, reducer_acc)
      if match?({:halt, _acc}, result), do: :atomics.put(consumer_halted, 1, 1)
      result
    end

    execute_reduce(
      fn command -> Enumerable.reduce(scan_stream.enumerable, command, wrapped_reducer) end,
      acc,
      span,
      counter,
      consumer_halted,
      target
    )
  end

  def member?(_scan_stream, _value), do: {:error, __MODULE__}
  def count(_scan_stream), do: {:error, __MODULE__}
  def slice(_scan_stream), do: {:error, __MODULE__}

  defp execute_reduce(continuation, command, span, counter, consumer_halted, target) do
    continuation.(command)
    |> handle_result(span, counter, consumer_halted, target)
  catch
    kind, reason ->
      Core.Telemetry.exception_span(span, kind, reason, __STACKTRACE__, %{
        target: target,
        outcome: :error,
        finding_count: :counters.get(counter, 1)
      })

      :erlang.raise(kind, reason, __STACKTRACE__)
  end

  defp handle_result({:done, acc}, span, counter, _consumer_halted, target) do
    stop_span(span, counter, target, :ok)
    {:done, acc}
  end

  defp handle_result({:halted, acc}, span, counter, consumer_halted, target) do
    outcome = if :atomics.get(consumer_halted, 1) == 1, do: :cancelled, else: :ok
    stop_span(span, counter, target, outcome)
    {:halted, acc}
  end

  defp handle_result(
         {:suspended, acc, continuation},
         span,
         counter,
         consumer_halted,
         target
       ) do
    next = fn command ->
      execute_reduce(continuation, command, span, counter, consumer_halted, target)
    end

    {:suspended, acc, next}
  end

  defp stop_span(span, counter, target, outcome) do
    Core.Telemetry.stop_span(span, %{
      target: target,
      outcome: outcome,
      finding_count: :counters.get(counter, 1)
    })
  end

  defp telemetry_target(scan) do
    case Enum.map(scan.targets, & &1.value) do
      [target] -> target
      targets -> targets
    end
  end
end
