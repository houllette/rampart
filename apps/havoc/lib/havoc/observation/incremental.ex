defmodule Havoc.Observation.Incremental do
  @moduledoc """
  Bounded, sequential delivery of one concrete byte partition to an in-process parser.

  `capture/5` records an initial measurement and one after each delivered chunk,
  stopping on acceptance or rejection. It retains counters, not parser states.
  The host supplies the parser and an independent measurement adapter; a counter
  reported by the target without trustworthy instrumentation is not evidence.

  Input bytes and chunk count are checked before either callback runs. These
  limits bound driver work and sample count, not resource use inside a callback.
  Deadlines, isolation, process ownership and cleanup remain host responsibilities.
  This is a concrete scenario driver; StreamData still owns search and shrinking.
  """

  @type status :: :incomplete | :accepted | :rejected
  @type measurement :: %{
          optional(:retained_bytes) => non_neg_integer() | nil,
          optional(:work) => non_neg_integer() | nil
        }
  @type sample :: %{
          index: non_neg_integer(),
          status: status(),
          received_bytes: non_neg_integer(),
          retained_bytes: non_neg_integer() | nil,
          work: non_neg_integer() | nil
        }
  @type t :: %__MODULE__{
          input: [binary()],
          samples: [sample()],
          status: status(),
          delivered_chunks: non_neg_integer(),
          work_unit: atom() | nil
        }

  @enforce_keys [:input, :samples, :status, :delivered_chunks, :work_unit]
  defstruct @enforce_keys

  @doc """
  Captures a bounded partition with host-owned step and measurement functions.

  `step.(chunk, state)` returns `{status, next_state}`. `measure.(state)` returns
  optional `:retained_bytes` and `:work` nonnegative integer counters; missing or
  nil counters stay unknown. Work is a cumulative counter whose initial value is
  subtracted from later samples. Supply its explicit `:work_unit` when used.
  Decreasing counters are harness errors, even across missing samples.

  Options: `:max_input_bytes` (65,536), `:max_chunks` (64), `:work_unit` (nil).
  Chunks must be nonempty binaries. An empty partition executes no parser step
  and is inconclusive to the budget oracles. Acceptance/rejection can leave a
  suffix undelivered; findings apply only to the observed prefix of this seed.
  """
  @spec capture(
          chunks :: [binary()],
          initial_state :: term(),
          step :: (binary(), term() -> {status(), term()}),
          measure :: (term() -> measurement()),
          opts :: keyword()
        ) :: t()
  def capture(chunks, initial_state, step, measure, opts \\ [])
      when is_list(chunks) and is_function(step, 2) and is_function(measure, 1) do
    config =
      opts
      |> NimbleOptions.validate!(
        max_input_bytes: [type: :non_neg_integer, default: 65_536],
        max_chunks: [type: :pos_integer, default: 64],
        work_unit: [type: :atom, default: nil]
      )
      |> Map.new()

    if config.work_unit in [true, false], do: raise(ArgumentError, "invalid work unit")
    validate_chunks!(chunks, config.max_input_bytes, config.max_chunks)
    initial = measurement!(measure.(initial_state), config.work_unit)
    baseline = initial.work
    first = sample(initial, baseline, :incomplete, 0, 0)

    {samples, status, delivered} =
      deliver(chunks, initial_state, step, measure, config, baseline, initial.work, [first])

    %__MODULE__{
      input: chunks,
      samples: Enum.reverse(samples),
      status: status,
      delivered_chunks: delivered,
      work_unit: config.work_unit
    }
  end

  defp validate_chunks!([], _bytes_left, _chunks_left), do: :ok

  defp validate_chunks!([chunk | rest], bytes_left, chunks_left)
       when is_binary(chunk) and byte_size(chunk) > 0 and byte_size(chunk) <= bytes_left and
              chunks_left > 0 do
    validate_chunks!(rest, bytes_left - byte_size(chunk), chunks_left - 1)
  end

  defp validate_chunks!(_chunks, _bytes_left, _chunks_left) do
    raise ArgumentError, "incremental input is invalid or exceeds its byte/chunk budget"
  end

  defp deliver(
         [],
         _state,
         _step,
         _measure,
         _config,
         _baseline,
         _previous_work,
         [last | _] = samples
       ),
       do: {samples, last.status, last.index}

  defp deliver(
         [chunk | rest],
         state,
         step,
         measure,
         config,
         baseline,
         previous_work,
         [last | _] = samples
       ) do
    {status, next_state} = step!(step.(chunk, state))
    measured = measurement!(measure.(next_state), config.work_unit)
    next_work = monotonic_work!(previous_work, measured.work)

    next =
      sample(measured, baseline, status, last.index + 1, last.received_bytes + byte_size(chunk))

    samples = [next | samples]

    if status == :incomplete do
      deliver(rest, next_state, step, measure, config, baseline, next_work, samples)
    else
      {samples, status, next.index}
    end
  end

  defp step!({status, _state} = result) when status in [:incomplete, :accepted, :rejected],
    do: result

  defp step!(_result), do: raise(ArgumentError, "invalid incremental step result")

  defp measurement!(measurement, unit) when is_map(measurement) do
    valid? =
      Enum.all?(measurement, fn {key, value} ->
        key in [:retained_bytes, :work] and
          (is_nil(value) or (is_integer(value) and value >= 0))
      end)

    if not valid? or (is_integer(measurement[:work]) and is_nil(unit)) do
      raise ArgumentError,
            "incremental measurements require nonnegative counters and an explicit work unit"
    end

    %{retained_bytes: measurement[:retained_bytes], work: measurement[:work]}
  end

  defp measurement!(_measurement, _unit),
    do: raise(ArgumentError, "invalid incremental measurement")

  defp monotonic_work!(previous, current)
       when is_integer(previous) and is_integer(current) and current < previous,
       do: raise(ArgumentError, "incremental work counter decreased")

  defp monotonic_work!(previous, nil), do: previous
  defp monotonic_work!(_previous, current), do: current

  defp sample(measured, baseline, status, index, received_bytes) do
    work = if is_integer(baseline) and is_integer(measured.work), do: measured.work - baseline

    %{
      index: index,
      status: status,
      received_bytes: received_bytes,
      retained_bytes: measured.retained_bytes,
      work: work
    }
  end
end
