defmodule RampartIAST.Argument do
  @moduledoc false

  @spec inspect_marker(argument :: term(), marker :: binary(), limits :: RampartIAST.Limits.t()) ::
          {non_neg_integer(), boolean(), [atom()]}
  def inspect_marker(argument, marker, limits) do
    state = %{terms: 0, bytes: 0, matched: false}

    case walk([{:term, argument, 0}], marker, limits, state) do
      {:ok, state} ->
        bytes =
          if is_binary(argument), do: byte_size(argument), else: :erlang.external_size(argument)

        if bytes > limits.max_argument_bytes,
          do: {bytes, false, [:argument_bytes]},
          else: {bytes, state.matched, []}

      {:error, reason, state} ->
        {state.bytes, false, [reason]}
    end
  end

  defp walk([], _marker, _limits, state), do: {:ok, state}

  defp walk([{:term, term, _depth} | _rest], _marker, _limits, state)
       when is_function(term) or (is_bitstring(term) and not is_binary(term)),
       do: {:error, :unsupported_argument, state}

  defp walk([{:term, _term, depth} | _rest], _marker, limits, state)
       when depth > limits.max_argument_depth, do: {:error, :argument_depth, state}

  defp walk([{:tuple, tuple, position, depth} | rest], marker, limits, state) do
    if position == tuple_size(tuple) do
      walk(rest, marker, limits, state)
    else
      walk(
        [{:term, elem(tuple, position), depth}, {:tuple, tuple, position + 1, depth} | rest],
        marker,
        limits,
        state
      )
    end
  end

  defp walk([{:map, iterator, depth} | rest], marker, limits, state) do
    case :maps.next(iterator) do
      :none ->
        walk(rest, marker, limits, state)

      {key, value, next} ->
        walk(
          [{:term, key, depth}, {:term, value, depth}, {:map, next, depth} | rest],
          marker,
          limits,
          state
        )
    end
  end

  defp walk(_stack, _marker, limits, state) when state.terms >= limits.max_argument_terms,
    do: {:error, :argument_terms, state}

  defp walk([{:term, term, depth} | rest], marker, limits, state) do
    {children, bytes, matched} = children(term, depth, marker, limits.max_argument_bytes)

    state = %{
      state
      | terms: state.terms + 1,
        bytes: state.bytes + bytes,
        matched: state.matched or matched
    }

    if state.bytes > limits.max_argument_bytes,
      do: {:error, :argument_bytes, state},
      else: walk(children ++ rest, marker, limits, state)
  end

  defp children(term, _depth, marker, limit) when is_binary(term),
    do:
      {[], byte_size(term), byte_size(term) <= limit and :binary.match(term, marker) != :nomatch}

  defp children([head | tail], depth, _marker, _limit),
    do: {[{:term, head, depth + 1}, {:term, tail, depth}], 1, false}

  defp children(term, depth, _marker, _limit) when is_tuple(term),
    do: {[{:tuple, term, 0, depth + 1}], 2, false}

  defp children(term, depth, _marker, _limit) when is_map(term),
    do: {[{:map, :maps.iterator(term), depth + 1}], 5, false}

  defp children(term, _depth, _marker, _limit), do: {[], :erlang.external_size(term), false}
end
