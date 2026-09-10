defmodule Havoc.Oracle.Resource do
  @moduledoc false

  alias Havoc.Observation.{Incremental, Length}
  alias Havoc.Oracle

  @spec bounded_length(opts :: keyword()) :: Oracle.t()
  def bounded_length(opts) do
    config =
      opts
      |> NimbleOptions.validate!(
        unit: [type: {:in, [:bytes, :codepoints, :graphemes]}, required: true],
        max_length: [type: :non_neg_integer, required: true],
        max_measurement_bytes: [type: :pos_integer, default: 1_048_576]
      )
      |> Map.new()

    checker = fn
      %Length{input: input}, payload when input !== payload ->
        raise ArgumentError, "length observation input does not match the evaluated payload"

      %Length{status: :rejected}, _payload ->
        :ok

      %Length{status: :accepted, value: value}, _payload when is_binary(value) ->
        check_length(value, config)

      _observation, _payload ->
        :skip
    end

    oracle(:bounded_length, checker, config)
  end

  @spec incremental_buffer_budget(opts :: keyword()) :: Oracle.t()
  def incremental_buffer_budget(opts) do
    config =
      opts
      |> NimbleOptions.validate!(max_bytes: [type: :non_neg_integer, required: true])
      |> Map.new()

    incremental_oracle(
      :incremental_buffer_budget,
      :retained_bytes,
      :bytes,
      config.max_bytes,
      config
    )
  end

  @spec incremental_work_budget(opts :: keyword()) :: Oracle.t()
  def incremental_work_budget(opts) do
    config =
      opts
      |> NimbleOptions.validate!(
        unit: [type: :atom, required: true],
        max_work: [type: :non_neg_integer, required: true]
      )
      |> Map.new()

    if config.unit in [nil, true, false],
      do: raise(ArgumentError, "work budget requires an explicit unit")

    incremental_oracle(:incremental_work_budget, :work, config.unit, config.max_work, config)
  end

  defp oracle(name, checker, config) do
    %Oracle{
      name: name,
      category: :resource_exhaustion,
      confidence: :high,
      check: fn observation, payload, _context -> checker.(observation, payload) end,
      options: config
    }
  end

  defp check_length(value, config) do
    case measure_length(value, config) do
      :unknown ->
        :skip

      actual when actual > config.max_length ->
        {:error,
         "accepted value measured #{count_text(actual)} #{config.unit}, exceeding the declared limit #{count_text(config.max_length)}",
         %{
           unit: config.unit,
           measured_length: actual,
           max_length: config.max_length,
           value_bytes: byte_size(value)
         }}

      _within_budget ->
        :ok
    end
  end

  defp measure_length(value, %{unit: :bytes}), do: byte_size(value)

  defp measure_length(value, %{max_measurement_bytes: maximum}) when byte_size(value) > maximum,
    do: :unknown

  defp measure_length(value, config) do
    if String.valid?(value), do: unicode_length(value, config.unit), else: :unknown
  end

  defp unicode_length(value, :graphemes), do: String.length(value)
  defp unicode_length(value, :codepoints), do: count_codepoints(value, 0)
  defp count_codepoints(<<>>, count), do: count

  defp count_codepoints(<<_codepoint::utf8, rest::binary>>, count),
    do: count_codepoints(rest, count + 1)

  defp incremental_oracle(name, metric, unit, maximum, config) do
    checker = fn
      %Incremental{input: input}, payload when input !== payload ->
        raise ArgumentError, "incremental observation input does not match the evaluated payload"

      %Incremental{delivered_chunks: 0}, _payload ->
        :skip

      %Incremental{work_unit: actual_unit}, _payload
      when metric == :work and actual_unit != unit ->
        :skip

      %Incremental{samples: samples}, _payload ->
        check_samples(samples, metric, unit, maximum)

      _observation, _payload ->
        :skip
    end

    oracle(name, checker, config)
  end

  defp check_samples(samples, metric, unit, maximum) do
    violation =
      Enum.find(samples, fn sample -> is_integer(sample[metric]) and sample[metric] > maximum end)

    cond do
      violation ->
        {:error,
         "incremental #{metric} measured #{count_text(violation[metric])} #{unit}, exceeding the declared limit #{count_text(maximum)} at sample #{count_text(violation.index)}",
         %{
           metric: metric,
           unit: unit,
           maximum: maximum,
           measured: violation[metric],
           sample_index: violation.index,
           status: violation.status,
           received_bytes: violation.received_bytes
         }}

      samples == [] or Enum.any?(samples, &(not valid_counter?(&1[metric]))) ->
        :skip

      true ->
        :ok
    end
  end

  defp valid_counter?(value), do: is_integer(value) and value >= 0

  defp count_text(count) when count > 18_446_744_073_709_551_615,
    do: "more than 18446744073709551615"

  defp count_text(count), do: Integer.to_string(count)
end
