defmodule RampartSAST.Graph do
  @moduledoc "Bounded callers, callees, relationship, and shared-variable slices over an inventory."

  alias RampartSAST.{Fact, Inventory}
  alias RampartSAST.Graph.Slice
  alias RampartSAST.Inventory.Index

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
        max_nodes: 200,
        max_edges: 500,
        max_work: 10_000,
        max_bytes: 256_000
      )

    roots = validate_roots!(roots)
    direction = validate_direction!(options[:direction])
    relations = validate_relations!(options[:relations])
    max_depth = non_negative_integer!(options[:max_depth], :max_depth)
    max_nodes = positive_integer!(options[:max_nodes], :max_nodes)
    validate_root_capacity!(roots, max_nodes)

    limits = %{
      max_depth: max_depth,
      max_nodes: max_nodes,
      max_edges: positive_integer!(options[:max_edges], :max_edges),
      max_work: positive_integer!(options[:max_work], :max_work),
      max_bytes: positive_integer!(options[:max_bytes], :max_bytes)
    }

    base = %Slice{
      inventory_id: inventory.id,
      roots: roots,
      nodes: Enum.sort(roots),
      edges: [],
      max_depth: max_depth,
      truncated: false
    }

    reserved = %{
      base
      | truncated: true,
        work_count: limits.max_work,
        limit_reasons: [:max_nodes, :max_depth, :max_edges, :max_work, :max_bytes]
    }

    bytes = reserved |> Slice.to_map() |> JSON.encode!() |> byte_size()

    if bytes > limits.max_bytes,
      do: raise(ArgumentError, "graph roots and metadata exceed max_bytes")

    state = %{
      queue: :queue.from_list(Enum.map(roots, &{&1, 0})),
      nodes: MapSet.new(roots),
      edges: %{},
      reasons: MapSet.new(),
      work: 0,
      bytes: bytes,
      stopped: false
    }

    state = walk(state, Inventory.index(inventory), direction, relations, limits)

    %{
      base
      | nodes: state.nodes |> MapSet.to_list() |> Enum.sort(),
        edges: state.edges |> Map.values() |> Enum.sort_by(& &1.id),
        truncated: MapSet.size(state.reasons) > 0,
        limit_reasons: state.reasons |> MapSet.to_list() |> Enum.sort(),
        work_count: state.work
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
    selected = inventory |> Inventory.index() |> Index.fetch(fact_id)

    case selected do
      %Fact{kind: kind} = fact when kind in [:call, :unqualified_call] ->
        contexts = MapSet.new(Map.get(fact.attributes, :control_contexts, []))

        Inventory.index(inventory)
        |> Index.candidates(subject: fact.subject)
        |> Stream.filter(&shares_control_context?(&1, fact, contexts))
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
    selected = inventory |> Inventory.index() |> Index.fetch(fact_id)

    case selected do
      %Fact{kind: kind} = fact when kind in [:call, :unqualified_call] ->
        variables = MapSet.new(Map.get(fact.attributes, :argument_variables, []))

        Inventory.index(inventory)
        |> Index.candidates(subject: fact.subject)
        |> Stream.filter(&shares_variables?(&1, fact, variables))
        |> Enum.take(limit)

      _other ->
        []
    end
  end

  defp walk(%{stopped: true} = state, _index, _direction, _relations, _limits), do: state

  defp walk(state, index, direction, relations, limits) do
    case :queue.out(state.queue) do
      {:empty, _queue} ->
        state

      {{:value, {node, depth}}, queue} ->
        state =
          index
          |> Index.adjacent(node, direction)
          |> Enum.reduce_while(%{state | queue: queue}, fn fact, acc ->
            next = visit(fact, node, depth, direction, relations, limits, acc)
            continue_walk(next)
          end)

        walk(state, index, direction, relations, limits)
    end
  end

  defp continue_walk(%{stopped: true} = state), do: {:halt, state}
  defp continue_walk(state), do: {:cont, state}

  defp visit(_fact, _node, _depth, _direction, _relations, limits, state)
       when state.work >= limits.max_work, do: stop(state, :max_work)

  defp visit(fact, node, depth, direction, relations, limits, state) do
    state = %{state | work: state.work + 1}

    cond do
      fact.relation not in relations or Map.has_key?(state.edges, fact.id) -> state
      depth >= limits.max_depth -> qualify(state, :max_depth)
      map_size(state.edges) >= limits.max_edges -> stop(state, :max_edges)
      true -> add_edge(fact, node, depth, direction, limits, state)
    end
  end

  defp add_edge(fact, node, depth, direction, limits, state) do
    neighbor = neighbor(Index.nodes(fact), node, direction)
    known? = MapSet.member?(state.nodes, neighbor)

    bytes =
      byte_size(JSON.encode!(Fact.to_map(fact))) + 1 + node_bytes(neighbor, known?)

    cond do
      not known? and MapSet.size(state.nodes) >= limits.max_nodes ->
        qualify(state, :max_nodes)

      state.bytes + bytes > limits.max_bytes ->
        stop(state, :max_bytes)

      true ->
        queue = if known?, do: state.queue, else: :queue.in({neighbor, depth + 1}, state.queue)

        %{
          state
          | queue: queue,
            nodes: MapSet.put(state.nodes, neighbor),
            edges: Map.put(state.edges, fact.id, fact),
            bytes: state.bytes + bytes
        }
    end
  end

  defp neighbor({_from, to}, _node, :out), do: to
  defp neighbor({from, _to}, _node, :in), do: from
  defp neighbor({node, to}, node, :both), do: to
  defp neighbor({from, _to}, _node, :both), do: from
  defp node_bytes(_node, true), do: 0
  defp node_bytes(node, false), do: byte_size(JSON.encode!(node)) + 1

  defp qualify(state, reason), do: %{state | reasons: MapSet.put(state.reasons, reason)}
  defp stop(state, reason), do: %{qualify(state, reason) | stopped: true}

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
