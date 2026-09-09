defmodule RampartSAST.Graph do
  @moduledoc "Bounded callers, callees, relationship, and shared-variable slices over an inventory."

  alias RampartSAST.{Fact, Inventory}
  alias RampartSAST.Graph.Slice

  @default_relations [
    :calls,
    :invokes,
    :implements,
    :implements_callback,
    :uses_package,
    :may_exhibit,
    :declares_callback,
    :declares_dependency
  ]

  @doc "Builds a finite breadth-first relationship slice from explicit root nodes."
  @spec slice(Inventory.t(), [String.t()], keyword()) :: Slice.t()
  def slice(%Inventory{} = inventory, roots, options \\ [])
      when is_list(roots) and is_list(options) do
    options =
      Keyword.validate!(options,
        direction: :out,
        relations: @default_relations,
        max_depth: 3,
        max_nodes: 200
      )

    roots = validate_roots!(roots)
    direction = validate_direction!(options[:direction])
    relations = validate_relations!(options[:relations])
    max_depth = non_negative_integer!(options[:max_depth], :max_depth)
    max_nodes = positive_integer!(options[:max_nodes], :max_nodes)
    validate_root_capacity!(roots, max_nodes)

    graph_edges =
      inventory.facts
      |> Enum.filter(&(&1.relation in relations))
      |> Enum.map(&edge/1)

    {nodes, edges, truncated} =
      walk(
        Enum.map(roots, &{&1, 0}),
        MapSet.new(roots),
        %{},
        graph_edges,
        direction,
        max_depth,
        max_nodes
      )

    %Slice{
      inventory_id: inventory.id,
      roots: roots,
      nodes: nodes |> MapSet.to_list() |> Enum.sort(),
      edges: edges |> Map.values() |> Enum.sort_by(& &1.id),
      max_depth: max_depth,
      truncated: truncated
    }
  end

  @doc "Returns a bounded inbound caller slice for one qualified function node."
  @spec callers(Inventory.t(), function :: String.t(), keyword()) :: Slice.t()
  def callers(%Inventory{} = inventory, function, options \\ []) when is_binary(function) do
    slice(inventory, [function], Keyword.put(options, :direction, :in))
  end

  @doc "Returns a bounded outbound callee/effect slice for one qualified function node."
  @spec callees(Inventory.t(), function :: String.t(), keyword()) :: Slice.t()
  def callees(%Inventory{} = inventory, function, options \\ []) when is_binary(function) do
    slice(inventory, [function], Keyword.put(options, :direction, :out))
  end

  @doc "Returns call facts in the same syntactic control regions as a selected call fact."
  @spec control_slice(Inventory.t(), fact_id :: String.t(), keyword()) :: [Fact.t()]
  def control_slice(%Inventory{} = inventory, fact_id, options \\ [])
      when is_binary(fact_id) and is_list(options) do
    options = Keyword.validate!(options, limit: 100)
    limit = positive_integer!(options[:limit], :limit)
    selected = Enum.find(inventory.facts, &(&1.id == fact_id))

    case selected do
      %Fact{kind: kind} = fact when kind in [:call, :unqualified_call] ->
        contexts = MapSet.new(Map.get(fact.attributes, :control_contexts, []))

        inventory.facts
        |> Enum.filter(&shares_control_context?(&1, fact, contexts))
        |> Enum.take(limit)

      _other ->
        []
    end
  end

  @doc "Returns nearby call facts sharing syntactic variables with a selected call fact."
  @spec shared_variable_slice(Inventory.t(), fact_id :: String.t(), keyword()) :: [Fact.t()]
  def shared_variable_slice(%Inventory{} = inventory, fact_id, options \\ [])
      when is_binary(fact_id) and is_list(options) do
    options = Keyword.validate!(options, limit: 100)
    limit = positive_integer!(options[:limit], :limit)
    selected = Enum.find(inventory.facts, &(&1.id == fact_id))

    case selected do
      %Fact{kind: kind} = fact when kind in [:call, :unqualified_call] ->
        variables = MapSet.new(Map.get(fact.attributes, :argument_variables, []))

        inventory.facts
        |> Enum.filter(&shares_variables?(&1, fact, variables))
        |> Enum.take(limit)

      _other ->
        []
    end
  end

  defp walk([], nodes, edges, _graph_edges, _direction, _max_depth, _max_nodes) do
    {nodes, edges, false}
  end

  defp walk([{node, depth} | queue], nodes, edges, graph_edges, direction, max_depth, max_nodes) do
    cond do
      MapSet.size(nodes) >= max_nodes ->
        {nodes, edges, true}

      depth >= max_depth ->
        walk(queue, nodes, edges, graph_edges, direction, max_depth, max_nodes)

      true ->
        adjacent = Enum.filter(graph_edges, &adjacent?(&1, node, direction))

        {queue, nodes, edges} =
          Enum.reduce(adjacent, {queue, nodes, edges}, fn {from, to, fact}, accumulator ->
            add_edge(from, to, fact, node, depth, direction, max_nodes, accumulator)
          end)

        walk(queue, nodes, edges, graph_edges, direction, max_depth, max_nodes)
    end
  end

  defp add_edge(from, to, fact, node, depth, direction, max_nodes, {queue, nodes, edges}) do
    neighbor = neighbor(from, to, node, direction)

    cond do
      MapSet.member?(nodes, neighbor) ->
        {queue, nodes, Map.put(edges, fact.id, fact)}

      MapSet.size(nodes) >= max_nodes ->
        {queue, nodes, edges}

      true ->
        edges = Map.put(edges, fact.id, fact)
        {queue ++ [{neighbor, depth + 1}], MapSet.put(nodes, neighbor), edges}
    end
  end

  defp adjacent?({from, _to, _fact}, node, :out), do: from == node
  defp adjacent?({_from, to, _fact}, node, :in), do: to == node
  defp adjacent?({from, to, _fact}, node, :both), do: from == node or to == node

  defp neighbor(_from, to, _node, :out), do: to
  defp neighbor(from, _to, _node, :in), do: from
  defp neighbor(from, to, node, :both), do: if(from == node, do: to, else: from)

  defp edge(%Fact{kind: :package_use} = fact), do: {fact.subject, "package:#{fact.object}", fact}
  defp edge(%Fact{kind: :behavior} = fact), do: {fact.subject, "behavior:#{fact.object}", fact}
  defp edge(%Fact{kind: :dependency} = fact), do: {fact.subject, "package:#{fact.object}", fact}
  defp edge(%Fact{} = fact), do: {fact.subject, fact.object, fact}

  defp shares_control_context?(candidate, selected, contexts) do
    candidate.id != selected.id and candidate.kind in [:call, :unqualified_call] and
      candidate.subject == selected.subject and
      not MapSet.disjoint?(contexts, candidate_control_contexts(candidate))
  end

  defp candidate_control_contexts(fact) do
    fact.attributes |> Map.get(:control_contexts, []) |> MapSet.new()
  end

  defp shares_variables?(candidate, selected, variables) do
    candidate.id != selected.id and candidate.kind in [:call, :unqualified_call] and
      candidate.subject == selected.subject and
      not MapSet.disjoint?(variables, candidate_variables(candidate))
  end

  defp candidate_variables(fact) do
    fact.attributes |> Map.get(:argument_variables, []) |> MapSet.new()
  end

  defp validate_roots!(roots) do
    if roots != [] and Enum.all?(roots, &(is_binary(&1) and String.trim(&1) != "")) do
      Enum.uniq(roots)
    else
      raise ArgumentError, "SAST graph roots must be non-empty strings"
    end
  end

  defp validate_root_capacity!(roots, max_nodes) do
    if length(roots) > max_nodes,
      do: raise(ArgumentError, "SAST graph max_nodes must accommodate every root")
  end

  defp validate_direction!(direction) when direction in [:in, :out, :both], do: direction

  defp validate_direction!(direction),
    do: raise(ArgumentError, "invalid graph direction: #{inspect(direction)}")

  defp validate_relations!(relations) when is_list(relations) do
    if Enum.all?(relations, &is_atom/1),
      do: Enum.uniq(relations),
      else: raise(ArgumentError, "graph relations must be atoms")
  end

  defp validate_relations!(_relations), do: raise(ArgumentError, "graph relations must be a list")
  defp positive_integer!(value, _name) when is_integer(value) and value > 0, do: value

  defp positive_integer!(value, name),
    do: raise(ArgumentError, "#{name} must be positive: #{inspect(value)}")

  defp non_negative_integer!(value, _name) when is_integer(value) and value >= 0, do: value

  defp non_negative_integer!(value, name),
    do: raise(ArgumentError, "#{name} must be non-negative: #{inspect(value)}")
end
