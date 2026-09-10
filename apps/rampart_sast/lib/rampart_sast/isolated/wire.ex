defmodule RampartSAST.Isolated.Wire do
  @moduledoc false

  alias RampartSAST.{Diagnostic, Inventory, Observation, Result, Suppressed}

  @magic <<"RPSI", 1>>

  @spec encode_result(Result.t(), map()) :: binary()
  def encode_result(%Result{} = result, worker_metrics \\ %{}) when is_map(worker_metrics) do
    %{
      "schema_version" => 1,
      "type" => "result",
      "status" => Atom.to_string(result.status),
      "inventory" => Inventory.to_map(result.inventory),
      "observations" => Enum.map(result.observations, &Observation.to_map/1),
      "suppressed" => Enum.map(result.suppressed, &Suppressed.to_map/1),
      "diagnostics" => Enum.map(result.diagnostics, &Diagnostic.to_map/1),
      "metrics" => result.metrics,
      "worker_metrics" => worker_metrics
    }
    |> portable!()
    |> :erlang.term_to_binary([:deterministic])
    |> then(&(@magic <> &1))
  end

  @spec encode_error(code :: String.t(), message :: String.t()) :: binary()
  def encode_error(code, message) when is_binary(code) and is_binary(message) do
    %{
      "schema_version" => 1,
      "type" => "error",
      "code" => code,
      "message" => message
    }
    |> :erlang.term_to_binary([:deterministic])
    |> then(&(@magic <> &1))
  end

  @spec decode!(binary(), keyword()) :: map()
  def decode!(binary, options) when is_binary(binary) and is_list(options) do
    options = Keyword.validate!(options, [:max_bytes, :max_terms, :max_depth])
    max_bytes = Keyword.fetch!(options, :max_bytes)

    if byte_size(binary) > max_bytes do
      raise ArgumentError,
            "isolated SAST response has #{byte_size(binary)} bytes; limit is #{max_bytes}"
    end

    case binary do
      <<@magic, payload::binary>> ->
        payload
        |> :erlang.binary_to_term([:safe])
        |> validate_portable!(options[:max_terms], options[:max_depth])

      _other ->
        raise ArgumentError, "isolated SAST response has an invalid wire header"
    end
  end

  defp portable!(nil), do: nil
  defp portable!(true), do: true
  defp portable!(false), do: false
  defp portable!(value) when is_binary(value) or is_number(value), do: value
  defp portable!(value) when is_atom(value), do: Atom.to_string(value)
  defp portable!(value) when is_list(value), do: Enum.map(value, &portable!/1)
  defp portable!(value) when is_tuple(value), do: value |> Tuple.to_list() |> portable!()

  defp portable!(%_module{} = value) do
    value |> Map.from_struct() |> portable!()
  end

  defp portable!(value) when is_map(value) do
    Enum.reduce(value, %{}, fn {key, item}, portable ->
      key = portable_key!(key)

      if Map.has_key?(portable, key) do
        raise ArgumentError, "isolated SAST output contains colliding portable map keys"
      else
        Map.put(portable, key, portable!(item))
      end
    end)
  end

  defp portable!(value) do
    raise ArgumentError, "isolated SAST output contains a non-portable value: #{inspect(value)}"
  end

  defp portable_key!(key) when is_binary(key), do: key
  defp portable_key!(key) when is_atom(key), do: Atom.to_string(key)
  defp portable_key!(key) when is_integer(key), do: Integer.to_string(key)

  defp portable_key!(key) do
    raise ArgumentError, "isolated SAST output contains a non-portable map key: #{inspect(key)}"
  end

  defp validate_portable!(value, max_terms, max_depth)
       when is_integer(max_terms) and max_terms > 0 and is_integer(max_depth) and max_depth > 0 do
    {_count, value} = validate_value!(value, 0, 0, max_terms, max_depth)
    value
  end

  defp validate_value!(_value, depth, _count, _max_terms, max_depth) when depth > max_depth do
    raise ArgumentError, "isolated SAST response exceeds the wire nesting limit"
  end

  defp validate_value!(value, _depth, count, max_terms, _max_depth)
       when count >= max_terms do
    raise ArgumentError,
          "isolated SAST response exceeds the wire term limit: #{inspect(value, limit: 1)}"
  end

  defp validate_value!(value, _depth, count, _max_terms, _max_depth)
       when is_binary(value) or is_number(value) or is_boolean(value) or is_nil(value),
       do: {count + 1, value}

  defp validate_value!(values, depth, count, max_terms, max_depth) when is_list(values) do
    Enum.reduce(values, {count + 1, []}, fn value, {current_count, validated} ->
      {current_count, value} =
        validate_value!(value, depth + 1, current_count, max_terms, max_depth)

      {current_count, [value | validated]}
    end)
    |> then(fn {current_count, validated} -> {current_count, Enum.reverse(validated)} end)
  end

  defp validate_value!(value, depth, count, max_terms, max_depth) when is_map(value) do
    Enum.reduce(value, {count + 1, %{}}, fn {key, item}, {current_count, validated} ->
      unless is_binary(key),
        do: raise(ArgumentError, "isolated SAST response contains a non-string map key")

      {current_count, item} =
        validate_value!(item, depth + 1, current_count + 1, max_terms, max_depth)

      {current_count, Map.put(validated, key, item)}
    end)
  end

  defp validate_value!(_value, _depth, _count, _max_terms, _max_depth) do
    raise ArgumentError, "isolated SAST response contains a non-portable value"
  end
end
