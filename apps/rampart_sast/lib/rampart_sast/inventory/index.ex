defmodule RampartSAST.Inventory.Index do
  @moduledoc false

  @fields [:kind, :subject, :relation, :object, :file, :target_module, :target_function]
  @type t :: %{facts: tuple(), exact: map(), outgoing: map(), incoming: map(), ids: map()}

  @spec build(facts :: [map()]) :: t()
  def build(facts) do
    initial = %{facts: List.to_tuple(facts), exact: %{}, outgoing: %{}, incoming: %{}, ids: %{}}

    facts
    |> Enum.with_index()
    |> Enum.reduce(initial, fn {fact, position}, index ->
      exact =
        Enum.reduce(@fields, index.exact, &insert_value(&2, &1, value(fact, &1), position))

      {from, to} = nodes(fact)

      %{
        index
        | exact: exact,
          outgoing: insert(index.outgoing, from, position),
          incoming: insert(index.incoming, to, position),
          ids: Map.put(index.ids, field(fact, :id), position)
      }
    end)
    |> then(fn index ->
      %{
        index
        | exact: ordered(index.exact),
          outgoing: ordered(index.outgoing),
          incoming: ordered(index.incoming)
      }
    end)
  end

  @spec candidates(index :: t(), filters :: keyword()) :: Enumerable.t()
  def candidates(index, filters) do
    choices =
      for {key, value} <- filters,
          key in @fields,
          not is_nil(value),
          do: Map.get(index.exact, {key, normalize(value)}, {0, []})

    case Enum.min_by(choices, &elem(&1, 0), fn -> nil end) do
      nil -> Stream.unfold(0, &next_fact(index.facts, &1))
      {_count, positions} -> Stream.map(positions, &elem(index.facts, &1))
    end
  end

  defp next_fact(facts, position) when position < tuple_size(facts),
    do: {elem(facts, position), position + 1}

  defp next_fact(_facts, _position), do: nil

  @spec page(index :: t(), filters :: keyword(), predicate :: (map() -> boolean())) ::
          {[map()], non_neg_integer()}
  def page(index, filters, predicate) do
    offset = Keyword.fetch!(filters, :offset)
    finish = offset + Keyword.fetch!(filters, :limit)

    {facts, total} =
      index
      |> candidates(filters)
      |> Enum.reduce({[], 0}, fn fact, {facts, total} ->
        if predicate.(fact) do
          {retain(facts, fact, total, offset, finish), total + 1}
        else
          {facts, total}
        end
      end)

    {Enum.reverse(facts), total}
  end

  defp retain(facts, fact, total, offset, finish) when total >= offset and total < finish,
    do: [fact | facts]

  defp retain(facts, _fact, _total, _offset, _finish), do: facts

  defp insert_value(index, _field, nil, _position), do: index
  defp insert_value(index, field, value, position), do: insert(index, {field, value}, position)

  @spec adjacent(index :: t(), node :: String.t(), direction :: :in | :out | :both) ::
          Enumerable.t()
  def adjacent(index, node, direction) do
    positions =
      case direction do
        :out ->
          positions(index.outgoing, node)

        :in ->
          positions(index.incoming, node)

        :both ->
          Stream.unfold(
            {positions(index.outgoing, node), positions(index.incoming, node)},
            &next_position/1
          )
      end

    Stream.map(positions, &elem(index.facts, &1))
  end

  defp next_position({[], []}), do: nil
  defp next_position({[head | tail], []}), do: {head, {tail, []}}
  defp next_position({[], [head | tail]}), do: {head, {[], tail}}
  defp next_position({[head | left], [head | right]}), do: {head, {left, right}}

  defp next_position({[left | rest], [right | _tail] = remaining}) when left < right,
    do: {left, {rest, remaining}}

  defp next_position({left, [head | right]}), do: {head, {left, right}}

  @spec fetch(index :: t(), id :: String.t()) :: map() | nil
  def fetch(index, id) do
    case Map.fetch(index.ids, id) do
      {:ok, position} -> elem(index.facts, position)
      :error -> nil
    end
  end

  @spec nodes(fact :: map()) :: {String.t(), String.t()}
  def nodes(fact) do
    to =
      case normalize(field(fact, :kind)) do
        kind when kind in ["package_use", "dependency"] -> "package:" <> field(fact, :object)
        "behavior" -> "behavior:" <> field(fact, :object)
        _other -> field(fact, :object)
      end

    {field(fact, :subject), to}
  end

  defp value(fact, :file), do: fact |> field(:span) |> field(:file)

  defp value(fact, key) when key in [:target_module, :target_function],
    do: fact |> field(:attributes) |> field(key) |> normalize()

  defp value(fact, key), do: fact |> field(key) |> normalize()
  defp field(nil, _key), do: nil
  defp field(map, key), do: Map.get(map, key, Map.get(map, Atom.to_string(key)))
  defp normalize(value) when is_atom(value) and not is_nil(value), do: Atom.to_string(value)
  defp normalize(value), do: value

  defp insert(map, key, position),
    do:
      Map.update(map, key, {1, [position]}, fn {count, items} ->
        {count + 1, [position | items]}
      end)

  defp ordered(map),
    do: Map.new(map, fn {key, {count, items}} -> {key, {count, Enum.reverse(items)}} end)

  defp positions(map, key), do: map |> Map.get(key, {0, []}) |> elem(1)
end
