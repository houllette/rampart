defmodule RampartSAST.DataFlow do
  @moduledoc """
  Bounded assignment-, return-, parameter-, and call-aware syntax dependence.

  `backward/3` starts from a call argument, binding, return, parameter, or guard
  fact and walks possible lexical value contributors. It can cross an ordinary
  statically resolved call through return and parameter facts, but deliberately
  retains every plausible definition/caller and records ambiguity. This is a
  hypothesis-construction query, not taint analysis or a vulnerability verdict.
  """

  alias RampartSAST.DataFlow.Slice
  alias RampartSAST.Fact
  alias RampartSAST.Inventory
  alias RampartSAST.Inventory.Index

  @supported_kinds [:call_argument, :binding, :return, :parameter, :guard]
  @base_uncertainties [
    :branch_feasibility_unknown,
    :runtime_reachability_unknown,
    :sanitizer_effects_unknown,
    :syntax_only
  ]

  @doc "Returns a bounded backward dependence slice from an exact inventory fact ID."
  @spec backward(Inventory.t(), fact_id :: String.t(), keyword()) :: Slice.t()
  def backward(%Inventory{} = inventory, fact_id, options \\ [])
      when is_binary(fact_id) and is_list(options) do
    options =
      Keyword.validate!(options,
        max_depth: 8,
        max_nodes: 100,
        max_edges: 200,
        max_work: 2_000,
        max_bytes: 256_000,
        max_reaching_definitions: 8,
        include_guards: true
      )

    limits = validate_limits!(options)
    index = Inventory.index(inventory)
    selected = Index.fetch(index, fact_id)
    validate_selected!(selected, fact_id)

    state = %{
      queue: :queue.from_list([{selected, 0}]),
      facts: %{selected.id => selected},
      edges: %{},
      unresolved: %{},
      uncertainties: MapSet.new(@base_uncertainties),
      reasons: MapSet.new(),
      work: 0,
      stopped: false
    }

    state = walk(state, index, limits)
    {guards, state} = guards(state, index, limits, options[:include_guards])
    slice(state, inventory.id, selected.id, guards, limits.max_depth)
  end

  defp walk(%{stopped: true} = state, _index, _limits), do: state

  defp walk(state, index, limits) do
    case :queue.out(state.queue) do
      {:empty, _queue} ->
        state

      {{:value, {_fact, depth}}, queue} when depth >= limits.max_depth ->
        state
        |> Map.put(:queue, queue)
        |> qualify(:max_depth)
        |> walk(index, limits)

      {{:value, {fact, depth}}, queue} ->
        state = %{state | queue: queue}
        state = expand_variables(state, fact, depth, index, limits)
        state = expand_expression_target(state, fact, depth, index, limits)
        state = expand_parameter_callers(state, fact, depth, index, limits)
        walk(state, index, limits)
    end
  end

  defp expand_variables(state, fact, depth, index, limits) do
    fact.attributes
    |> Map.get(:source_variables, [])
    |> Enum.uniq()
    |> Enum.reduce_while(state, fn variable, state ->
      expand_variable(variable, state, fact, depth, index, limits)
    end)
  end

  defp expand_variable(_variable, %{stopped: true} = state, _fact, _depth, _index, _limits),
    do: {:halt, state}

  defp expand_variable(variable, state, fact, depth, index, limits) do
    {sources, uncertainty} = variable_sources(index, fact, variable, limits)
    state = maybe_uncertain(state, uncertainty)
    state = add_variable_sources(sources, state, fact, variable, depth, limits)
    {:cont, state}
  end

  defp add_variable_sources([], state, fact, variable, _depth, limits),
    do: unresolved(state, fact.id, variable, :unresolved_variable, limits)

  defp add_variable_sources(sources, state, fact, variable, depth, limits) do
    Enum.reduce_while(sources, state, fn source, state ->
      edge = edge(source, fact, :may_flow_into, variable, source_basis(source))
      state |> add(source, edge, depth + 1, limits) |> continue()
    end)
  end

  defp expand_expression_target(state, %Fact{} = fact, depth, index, limits)
       when fact.kind in [:binding, :return] do
    case Map.get(fact.attributes, :expression_target) do
      target when is_binary(target) and target != "" ->
        returns = candidates(index, kind: :return, subject: target)
        add_return_sources(returns, state, fact, depth, limits)

      _unknown ->
        state
    end
  end

  defp expand_expression_target(state, _fact, _depth, _index, _limits), do: state

  defp add_return_sources([], state, fact, _depth, limits),
    do: unresolved(state, fact.id, nil, :external_or_dynamic_return, limits)

  defp add_return_sources(returns, state, fact, depth, limits) do
    state = if length(returns) > 1, do: uncertain(state, :multiple_return_sites), else: state

    Enum.reduce_while(returns, state, fn source, state ->
      edge = edge(source, fact, :may_return_into, nil, :resolved_call_target)
      state |> add(source, edge, depth + 1, limits) |> continue()
    end)
  end

  defp expand_parameter_callers(
         state,
         %Fact{kind: :parameter, subject: function, attributes: %{position: position}} = fact,
         depth,
         index,
         limits
       ) do
    object = "#{function}#argument/#{position}"
    arguments = candidates(index, kind: :call_argument, object: object)

    state =
      if length(arguments) > 1,
        do: uncertain(state, :multiple_callers),
        else: state

    if arguments == [] do
      unresolved(state, fact.id, fact.object, :external_or_dynamic_caller, limits)
    else
      Enum.reduce_while(arguments, state, fn source, state ->
        edge = edge(source, fact, :may_supply_parameter, fact.object, :resolved_call_target)
        state |> add(source, edge, depth + 1, limits) |> continue()
      end)
    end
  end

  defp expand_parameter_callers(state, _fact, _depth, _index, _limits), do: state

  defp variable_sources(index, fact, variable, limits) do
    bindings =
      index
      |> candidates(kind: :binding, subject: fact.subject, object: variable)
      |> Enum.reject(&(&1.id == fact.id))
      |> Enum.filter(&lexically_precedes?(&1, fact))
      |> Enum.sort_by(&{-&1.span.start_line, -&1.span.start_column, &1.id})

    {bindings, truncated?} = Enum.split(bindings, limits.max_reaching_definitions)

    cond do
      bindings != [] and truncated? != [] -> {bindings, :reaching_definitions_truncated}
      length(bindings) > 1 -> {bindings, :multiple_reaching_definitions}
      bindings != [] -> {bindings, nil}
      true -> {candidates(index, kind: :parameter, subject: fact.subject, object: variable), nil}
    end
  end

  defp lexically_precedes?(candidate, fact) do
    candidate.span.file == fact.span.file and
      {candidate.span.start_line, candidate.span.start_column} <=
        {fact.span.start_line, fact.span.start_column}
  end

  defp add(%{stopped: true} = state, _fact, _edge, _depth, _limits), do: state

  defp add(state, fact, edge, depth, limits) do
    state = %{state | work: state.work + 1}

    cond do
      state.work > limits.max_work ->
        stop(state, :max_work)

      map_size(state.edges) >= limits.max_edges and not Map.has_key?(state.edges, edge.id) ->
        stop(state, :max_edges)

      map_size(state.facts) >= limits.max_nodes and not Map.has_key?(state.facts, fact.id) ->
        stop(state, :max_nodes)

      true ->
        known? = Map.has_key?(state.facts, fact.id)

        candidate = %{
          state
          | facts: Map.put(state.facts, fact.id, fact),
            edges: Map.put(state.edges, edge.id, edge),
            queue: if(known?, do: state.queue, else: :queue.in({fact, depth}, state.queue))
        }

        if encoded_size(candidate, []) <= limits.max_bytes,
          do: candidate,
          else: stop(state, :max_bytes)
    end
  end

  defp unresolved(state, fact_id, variable, reason, limits) do
    key = {fact_id, variable, reason}
    entry = %{fact_id: fact_id, variable: variable, reason: reason}
    candidate = %{state | unresolved: Map.put(state.unresolved, key, entry)}

    if encoded_size(candidate, []) <= limits.max_bytes,
      do: candidate,
      else: stop(state, :max_bytes)
  end

  defp guards(state, _index, _limits, false), do: {[], state}

  defp guards(state, index, limits, true) do
    subjects = state.facts |> Map.values() |> Enum.map(& &1.subject) |> Enum.uniq()

    candidates =
      subjects
      |> Enum.flat_map(&candidates(index, kind: :guard, subject: &1))
      |> Enum.uniq_by(& &1.id)
      |> Enum.sort_by(& &1.id)

    remaining = max(limits.max_nodes - map_size(state.facts), 0)
    {selected, omitted} = Enum.split(candidates, remaining)
    state = if omitted == [], do: state, else: qualify(state, :max_nodes)
    fit_guards(state, selected, [], limits)
  end

  defp fit_guards(state, [], retained, _limits), do: {Enum.reverse(retained), state}

  defp fit_guards(state, [guard | rest], retained, limits) do
    candidate = [guard | retained]

    if encoded_size(state, candidate) <= limits.max_bytes do
      fit_guards(state, rest, candidate, limits)
    else
      {Enum.reverse(retained), qualify(state, :max_bytes)}
    end
  end

  defp candidates(index, filters) do
    index
    |> Index.candidates(filters)
    |> Stream.filter(fn fact ->
      Enum.all?(filters, fn
        {:kind, value} -> fact.kind == value
        {:subject, value} -> fact.subject == value
        {:object, value} -> fact.object == value
      end)
    end)
    |> Enum.to_list()
  end

  defp edge(source, destination, relation, variable, basis) do
    id =
      Core.Finding.dedupe_id(:sast, [
        "data_flow_edge",
        source.id,
        destination.id,
        relation,
        variable,
        basis
      ])

    %{
      id: id,
      from: source.id,
      to: destination.id,
      relation: relation,
      variable: variable,
      basis: basis
    }
  end

  defp source_basis(%Fact{kind: :binding}), do: :lexical_assignment
  defp source_basis(%Fact{kind: :parameter}), do: :function_parameter
  defp source_basis(_fact), do: :syntax_relationship

  defp slice(state, inventory_id, sink_fact_id, guards, max_depth) do
    %Slice{
      inventory_id: inventory_id,
      sink_fact_id: sink_fact_id,
      facts: state.facts |> Map.values() |> Enum.sort_by(& &1.id),
      edges: state.edges |> Map.values() |> Enum.sort_by(& &1.id),
      guards: guards,
      unresolved: state.unresolved |> Map.values() |> Enum.sort_by(&unresolved_key/1),
      uncertainties: state.uncertainties |> MapSet.to_list() |> Enum.sort(),
      max_depth: max_depth,
      work_count: state.work,
      truncated: MapSet.size(state.reasons) > 0,
      limit_reasons: state.reasons |> MapSet.to_list() |> Enum.sort()
    }
  end

  defp encoded_size(state, guards) do
    %{
      facts: state.facts |> Map.values() |> Enum.map(&Fact.to_map/1),
      edges: Map.values(state.edges),
      guards: Enum.map(guards, &Fact.to_map/1),
      unresolved: Map.values(state.unresolved),
      uncertainties: MapSet.to_list(state.uncertainties),
      limit_reasons: MapSet.to_list(state.reasons),
      work_count: state.work
    }
    |> JSON.encode!()
    |> byte_size()
  end

  defp unresolved_key(entry), do: {entry.fact_id, entry.variable || "", entry.reason}
  defp continue(%{stopped: true} = state), do: {:halt, state}
  defp continue(state), do: {:cont, state}
  defp maybe_uncertain(state, nil), do: state
  defp maybe_uncertain(state, uncertainty), do: uncertain(state, uncertainty)

  defp uncertain(state, uncertainty),
    do: %{state | uncertainties: MapSet.put(state.uncertainties, uncertainty)}

  defp qualify(state, reason), do: %{state | reasons: MapSet.put(state.reasons, reason)}
  defp stop(state, reason), do: %{qualify(state, reason) | stopped: true}

  defp validate_selected!(%Fact{kind: kind}, _id) when kind in @supported_kinds, do: :ok

  defp validate_selected!(%Fact{kind: kind}, _id) do
    raise ArgumentError,
          "data-flow roots must be one of #{inspect(@supported_kinds)}, got: #{inspect(kind)}"
  end

  defp validate_selected!(nil, id),
    do: raise(ArgumentError, "unknown inventory fact ID: #{inspect(id)}")

  defp validate_limits!(options) do
    names = [:max_nodes, :max_edges, :max_work, :max_bytes, :max_reaching_definitions]
    Enum.each(names, &positive!(options[&1], &1))

    unless is_integer(options[:max_depth]) and options[:max_depth] >= 0 do
      raise ArgumentError, ":max_depth must be a non-negative integer"
    end

    Map.new(Keyword.take(options, [:max_depth | names]))
  end

  defp positive!(value, _name) when is_integer(value) and value > 0, do: :ok

  defp positive!(value, name),
    do: raise(ArgumentError, "#{name} must be positive: #{inspect(value)}")
end
