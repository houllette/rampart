defmodule Havoc.Harness do
  @moduledoc """
  Executes one exact, host-bound stateful plan as a Havoc target.

  StreamData still owns generation and shrinking. This module executes only the
  concrete payload it receives, resolves inert payload references, runs a finite
  reviewed operation sequence, records replayable observations, and always
  attempts teardown. Its deadline is checked between callbacks; it cannot
  preempt a callback that never returns. Hard CPU/RSS/filesystem/network limits
  remain the external sandbox's responsibility.
  """

  alias Havoc.Harness.{Binding, Error, Result, Step}

  @doc "Returns a one-argument function suitable for `Havoc.Property` or `Havoc.validate/3`."
  @spec target(Binding.t()) :: (term() -> Result.t())
  def target(%Binding{} = binding), do: fn payload -> execute(binding, payload) end

  @doc "Executes the exact bound plan for one concrete generated or replayed payload."
  @spec execute(Binding.t(), payload :: term()) :: Result.t()
  def execute(%Binding{} = binding, payload) do
    started = System.monotonic_time(:millisecond)

    case invoke_setup(binding.setup, payload) do
      {:ok, state} ->
        outcome = run_steps(binding.plan.steps, binding, state, payload, started, [], 0, 0)
        finish(outcome, binding.teardown)

      {:error, reason} ->
        raise Error, stage: :setup, reason: reason
    end
  end

  defp run_steps([], binding, state, payload, _started, observations, count, _bytes) do
    result = %Result{
      plan_id: binding.plan.id,
      plan_sha256: binding.plan.sha256,
      payload_fingerprint: Havoc.TermCodec.fingerprint(payload),
      observations: Enum.reverse(observations),
      completed_steps: count
    }

    {:ok, result, state}
  end

  defp run_steps([step | rest], binding, state, payload, started, observations, count, bytes) do
    with :ok <- within_deadline(started, binding.max_execution_ms),
         {:ok, arguments} <- resolve_arguments(step.arguments, payload),
         {:ok, next_state, observation} <- invoke_operation(binding, step, state, arguments),
         :ok <- within_deadline(started, binding.max_execution_ms),
         {:ok, observation_bytes} <-
           observation_size(observation, binding.max_observation_bytes - bytes) do
      recorded = %{
        step_id: step.id,
        operation: step.operation,
        role: step.role,
        value: observation
      }

      run_steps(
        rest,
        binding,
        next_state,
        payload,
        started,
        [recorded | observations],
        count + 1,
        bytes + observation_bytes
      )
    else
      {:error, reason} -> {:error, %Error{stage: :step, step_id: step.id, reason: reason}, state}
    end
  end

  defp finish({:ok, result, state}, teardown) do
    case invoke_teardown(teardown, state) do
      :ok -> result
      {:error, reason} -> raise Error, stage: :teardown, reason: reason
    end
  end

  defp finish({:error, %Error{} = primary, state}, teardown) do
    case invoke_teardown(teardown, state) do
      :ok ->
        raise primary

      {:error, reason} ->
        raise Error, stage: :teardown, reason: %{primary: primary.reason, teardown: reason}
    end
  end

  defp invoke_setup(setup, payload) do
    case setup.(payload) do
      {:ok, state} -> {:ok, state}
      {:error, reason} -> {:error, reason}
      other -> {:error, {:invalid_setup_result, other}}
    end
  rescue
    error -> {:error, {:exception, error}}
  catch
    kind, reason -> {:error, {kind, reason}}
  end

  defp invoke_operation(binding, %Step{} = step, state, arguments) do
    callback = Map.fetch!(binding.operations, step.operation)

    case callback.(state, arguments) do
      {:ok, next_state, observation} -> {:ok, next_state, observation}
      {:error, reason} -> {:error, reason}
      other -> {:error, {:invalid_operation_result, other}}
    end
  rescue
    error -> {:error, {:exception, error}}
  catch
    kind, reason -> {:error, {kind, reason}}
  end

  defp invoke_teardown(teardown, state) do
    case teardown.(state) do
      :ok -> :ok
      {:error, reason} -> {:error, reason}
      other -> {:error, {:invalid_teardown_result, other}}
    end
  rescue
    error -> {:error, {:exception, error}}
  catch
    kind, reason -> {:error, {kind, reason}}
  end

  defp within_deadline(started, maximum) do
    if System.monotonic_time(:millisecond) - started <= maximum,
      do: :ok,
      else: {:error, {:execution_deadline, maximum}}
  end

  defp resolve_arguments(arguments, payload) do
    {:ok, resolve(arguments, payload)}
  rescue
    error in [ArgumentError, KeyError] ->
      {:error, {:invalid_payload_reference, Exception.message(error)}}
  end

  defp resolve(%{"$payload" => path} = reference, payload) when map_size(reference) == 1 do
    unless is_list(path) and Enum.all?(path, &is_binary/1) do
      raise ArgumentError, "$payload must contain a list of string path segments"
    end

    Enum.reduce(path, payload, &fetch_payload!/2)
  end

  defp resolve(value, payload) when is_list(value), do: Enum.map(value, &resolve(&1, payload))

  defp resolve(value, payload) when is_map(value) do
    Map.new(value, fn {key, nested} -> {key, resolve(nested, payload)} end)
  end

  defp resolve(value, _payload), do: value

  defp fetch_payload!(key, map) when is_map(map) do
    case Map.fetch(map, key) do
      {:ok, value} ->
        value

      :error ->
        fetch_atom_payload!(key, map)
    end
  end

  defp fetch_payload!(key, value), do: raise(KeyError, key: key, term: value)

  defp fetch_atom_payload!(key, map) do
    case Enum.find(map, &atom_key?(&1, key)) do
      {_candidate, value} -> value
      nil -> raise KeyError, key: key, term: map
    end
  end

  defp atom_key?({candidate, _value}, key) when is_atom(candidate),
    do: Atom.to_string(candidate) == key

  defp atom_key?(_entry, _key), do: false

  defp observation_size(_observation, remaining) when remaining < 0,
    do: {:error, :observation_budget_exceeded}

  defp observation_size(observation, remaining) do
    encoded = Havoc.TermCodec.encode(observation)
    {:ok, binary} = Base.decode64(encoded["data"])
    size = byte_size(binary)

    if size <= remaining,
      do: {:ok, size},
      else: {:error, {:observation_budget_exceeded, size, remaining}}
  rescue
    error in ArgumentError -> {:error, {:non_replayable_observation, Exception.message(error)}}
  end
end
