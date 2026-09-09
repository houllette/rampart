defmodule Havoc.TermCodec do
  @moduledoc false

  @encoding "erlang-term-v1"
  @max_term_bytes 1_048_576

  @spec encode(term :: term()) :: map()
  def encode(term) do
    validate_replayable!(term)
    binary = :erlang.term_to_binary(term, [:deterministic, {:minor_version, 2}])

    if byte_size(binary) > @max_term_bytes do
      raise ArgumentError, "term exceeds the #{@max_term_bytes}-byte persistence limit"
    end

    %{
      "encoding" => @encoding,
      "data" => Base.encode64(binary),
      "sha256" => sha256(binary)
    }
  end

  @spec decode(encoded :: map()) :: {:ok, term()} | {:error, term()}
  def decode(%{"encoding" => @encoding, "data" => data, "sha256" => expected})
      when is_binary(data) and is_binary(expected) do
    with {:ok, binary} <- Base.decode64(data),
         :ok <- check_size(binary),
         :ok <- check_integrity(binary, expected) do
      safe_binary_to_term(binary)
    end
  end

  def decode(_encoded), do: {:error, :invalid_term_encoding}

  @spec fingerprint(term :: term()) :: String.t()
  def fingerprint(term) do
    validate_replayable!(term)

    term
    |> :erlang.term_to_binary([:deterministic, {:minor_version, 2}])
    |> sha256()
  end

  defp check_size(binary) when byte_size(binary) <= @max_term_bytes, do: :ok
  defp check_size(_binary), do: {:error, :term_too_large}

  defp check_integrity(binary, expected) do
    if sha256(binary) == expected, do: :ok, else: {:error, :term_integrity_mismatch}
  end

  defp safe_binary_to_term(binary) do
    term = :erlang.binary_to_term(binary, [:safe])
    validate_replayable!(term)
    {:ok, term}
  rescue
    ArgumentError -> {:error, :unsafe_or_invalid_term}
  end

  defp validate_replayable!(term), do: validate_replayable!(term, 0)

  defp validate_replayable!(_term, depth) when depth > 100 do
    raise ArgumentError, "term exceeds the persistence nesting limit"
  end

  defp validate_replayable!(term, _depth)
       when is_nil(term) or is_boolean(term) or is_number(term) or is_atom(term) or
              is_binary(term),
       do: :ok

  defp validate_replayable!([], _depth), do: :ok

  defp validate_replayable!([head | tail], depth) do
    validate_replayable!(head, depth + 1)
    validate_replayable!(tail, depth + 1)
  end

  defp validate_replayable!(term, depth) when is_tuple(term) do
    term
    |> Tuple.to_list()
    |> Enum.each(&validate_replayable!(&1, depth + 1))
  end

  defp validate_replayable!(term, depth) when is_map(term) do
    Enum.each(term, fn {key, value} ->
      validate_replayable!(key, depth + 1)
      validate_replayable!(value, depth + 1)
    end)
  end

  defp validate_replayable!(term, _depth) do
    raise ArgumentError,
          "term contains a non-replayable value: #{inspect(term, limit: 5)}"
  end

  defp sha256(binary) do
    binary
    |> then(&:crypto.hash(:sha256, &1))
    |> Base.encode16(case: :lower)
  end
end
