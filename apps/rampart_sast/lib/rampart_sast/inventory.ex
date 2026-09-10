defmodule RampartSAST.Inventory do
  @moduledoc """
  A high-recall, syntax-derived project inventory for deterministic agent queries.

  The inventory deliberately records ordinary definitions, calls, directives,
  dependencies, and host-resolved package-use edges. A fact is reconnaissance,
  not a vulnerability claim. Consumers correlate facts into hypotheses and use
  a separate validator to prove or refute each security-relevant claim.
  """

  alias RampartSAST.{AST, Behavior, Expression, Fact, Source, Span}
  alias RampartSAST.Inventory.Page

  @elixir_control_forms [:case, :cond, :for, :if, :receive, :try, :unless, :with]

  @elixir_non_calls [
    :!,
    :!=,
    :!==,
    :%,
    :%{},
    :&,
    :&&,
    :*,
    :+,
    :++,
    :-,
    :--,
    :.,
    :/,
    :<,
    :<=,
    :=,
    :==,
    :===,
    :=~,
    :>,
    :>=,
    :@,
    :__aliases__,
    :__block__,
    :alias,
    :case,
    :cond,
    :def,
    :defmacro,
    :defmacrop,
    :defmodule,
    :defp,
    :fn,
    :for,
    :if,
    :import,
    :in,
    :|>,
    :not,
    :or,
    :quote,
    :receive,
    :require,
    :rescue,
    :try,
    :{},
    :unless,
    :unquote,
    :unquote_splicing,
    :use,
    :when,
    :with,
    :->,
    :||
  ]

  @type t :: %__MODULE__{
          id: String.t(),
          facts: [Fact.t()],
          diagnostics: [RampartSAST.Diagnostic.t()],
          source_count: non_neg_integer(),
          module_owners: %{optional(String.t()) => String.t()}
        }

  @enforce_keys [:id, :facts, :diagnostics, :source_count, :module_owners]
  defstruct @enforce_keys

  @doc "Builds a deterministic inventory from already parsed source snapshots."
  @spec build([Source.t()], keyword()) :: t()
  def build(sources, options \\ []) when is_list(sources) and is_list(options) do
    options =
      Keyword.validate!(options,
        module_owners: %{},
        behavior_classifiers: [],
        behavior_timeout_ms: 5_000
      )

    host_module_owners = validate_module_owners!(options[:module_owners])

    syntax_facts = Enum.flat_map(sources, &facts/1)
    relationship_facts = callback_implementation_facts(syntax_facts)
    source_facts = syntax_facts ++ relationship_facts

    module_owners =
      sources
      |> derived_module_owners(source_facts)
      |> Map.merge(host_module_owners)

    package_facts = package_use_facts(source_facts, module_owners)

    {behavior_facts, diagnostics} =
      Behavior.classify(
        source_facts ++ package_facts,
        options[:behavior_classifiers],
        options[:behavior_timeout_ms]
      )

    facts = sort_facts(source_facts ++ package_facts ++ behavior_facts)

    %__MODULE__{
      id: inventory_id(facts, module_owners),
      facts: facts,
      diagnostics: diagnostics,
      source_count: length(sources),
      module_owners: module_owners
    }
  end

  @doc "Filters a bounded list of facts by exact fields and subject/object prefixes."
  @spec query(t(), keyword()) :: [Fact.t()]
  def query(%__MODULE__{} = inventory, filters \\ []) when is_list(filters) do
    inventory |> query_page(filters) |> Map.fetch!(:facts)
  end

  @doc "Returns a bounded fact page with inventory identity and continuation metadata."
  @spec query_page(t(), keyword()) :: Page.t()
  def query_page(%__MODULE__{} = inventory, filters \\ []) when is_list(filters) do
    filters = validate_query_filters!(filters)
    limit = filters[:limit]
    offset = filters[:offset]
    matches = Enum.filter(inventory.facts, &matches?(&1, filters))
    facts = matches |> Enum.drop(offset) |> Enum.take(limit)
    returned = length(facts)
    next_offset = if offset + returned < length(matches), do: offset + returned

    %Page{
      inventory_id: inventory.id,
      facts: facts,
      offset: offset,
      limit: limit,
      returned: returned,
      total: length(matches),
      next_offset: next_offset
    }
  end

  @doc "Returns all normalized remote calls to a module, optionally narrowed to a function."
  @spec calls_to(t(), module_name :: String.t(), function_name :: String.t() | nil) :: [Fact.t()]
  def calls_to(%__MODULE__{} = inventory, module_name, function_name \\ nil)
      when is_binary(module_name) and (is_binary(function_name) or is_nil(function_name)) do
    inventory
    |> query(kind: :call, object_prefix: module_name <> ".")
    |> Enum.filter(fn fact ->
      fact.attributes.target_module == module_name and
        (is_nil(function_name) or fact.attributes.target_function == function_name)
    end)
  end

  @doc "Returns host-resolved references to one dependency package."
  @spec package_usage(t(), package :: String.t()) :: [Fact.t()]
  def package_usage(%__MODULE__{} = inventory, package) when is_binary(package) do
    query(inventory, kind: :package_use, object: package)
  end

  @doc "Projects the complete inventory into plain data for host-owned artifact storage."
  @spec to_map(t()) :: map()
  def to_map(%__MODULE__{} = inventory) do
    %{
      id: inventory.id,
      facts: Enum.map(inventory.facts, &Fact.to_map/1),
      diagnostics: Enum.map(inventory.diagnostics, &RampartSAST.Diagnostic.to_map/1),
      source_count: inventory.source_count,
      module_owners: inventory.module_owners
    }
  end

  @doc "Returns bounded inventory counts suitable for a scan-result summary."
  @spec summary(t()) :: map()
  def summary(%__MODULE__{} = inventory) do
    %{
      id: inventory.id,
      source_count: inventory.source_count,
      fact_count: length(inventory.facts),
      diagnostic_count: length(inventory.diagnostics),
      fact_kinds: frequencies(inventory.facts, & &1.kind),
      relations: frequencies(inventory.facts, & &1.relation),
      attributed_packages: inventory.module_owners |> Map.values() |> Enum.uniq() |> Enum.sort()
    }
  end

  defp facts(%Source{language: :elixir} = source) do
    scopes = elixir_scopes(source)

    module_facts(source, scopes) ++
      definition_facts(source, scopes) ++
      binding_facts(source, scopes) ++
      elixir_callback_facts(source, scopes) ++
      protocol_callback_facts(source, scopes) ++
      elixir_directive_facts(source, scopes) ++
      call_facts(source, scopes) ++
      elixir_unqualified_call_facts(source, scopes) ++ mix_dependency_facts(source)
  end

  defp facts(%Source{language: :erlang_terms} = source), do: rebar_dependency_facts(source)

  defp facts(%Source{language: :erlang} = source) do
    scopes = erlang_scopes(source)

    module_facts(source, scopes) ++
      definition_facts(source, scopes) ++
      erlang_callback_facts(source, scopes) ++
      erlang_directive_facts(source, scopes) ++
      call_facts(source, scopes) ++ erlang_unqualified_call_facts(source, scopes)
  end

  defp elixir_scopes(%Source{ast: ast}) do
    {_ast, declarations} = Macro.prewalk(ast, [], &collect_elixir_declaration/2)
    declarations = Enum.reverse(declarations)

    modules =
      Enum.reduce(declarations, [], fn
        {:module, node, name, module_kind, nesting}, modules ->
          parent = if nesting == :relative, do: enclosing_module(modules, ast_line(node))
          qualified_name = qualify_nested_module(parent, name)
          modules ++ [scope(:module, qualified_name, module_kind, node)]

        _declaration, modules ->
          modules
      end)

    definitions =
      for {:definition, node, name, arity, visibility} <- declarations do
        module = enclosing_module(modules, ast_line(node))
        object = qualified_function(module, name, arity)
        scope(:definition, object, visibility, node)
      end

    controls =
      for {:control, node, kind} <- declarations do
        scope(:control, Atom.to_string(kind), nil, node)
      end

    aliases = elixir_aliases(ast, modules)

    %{
      modules: modules,
      definitions: definitions,
      controls: controls,
      aliases: aliases,
      imports: elixir_imports(ast, modules, aliases)
    }
  end

  defp collect_elixir_declaration({:defimpl, _, _arguments} = ast, declarations) do
    case protocol_implementation_module(ast) do
      nil ->
        {ast, declarations}

      module ->
        {ast, [{:module, ast, module, :protocol_implementation, :absolute} | declarations]}
    end
  end

  defp collect_elixir_declaration(
         {kind, _metadata, [{:__aliases__, _, parts} | _rest]} = ast,
         declarations
       )
       when kind in [:defmodule, :defprotocol] do
    module_kind = if kind == :defprotocol, do: :protocol, else: :module
    {nesting, parts} = module_nesting(parts)
    name = AST.alias_name(parts)
    {ast, [{:module, ast, name, module_kind, nesting} | declarations]}
  end

  defp collect_elixir_declaration({kind, _metadata, _arguments} = ast, declarations)
       when kind in @elixir_control_forms do
    {ast, [{:control, ast, kind} | declarations]}
  end

  defp collect_elixir_declaration({kind, _metadata, [head | _rest]} = ast, declarations)
       when kind in [:def, :defp, :defmacro, :defmacrop] do
    case function_head(head) do
      {name, arguments} ->
        visibility = if kind in [:def, :defmacro], do: :public, else: :private
        declaration = {:definition, ast, name, length(arguments), visibility}
        {ast, [declaration | declarations]}

      nil ->
        {ast, declarations}
    end
  end

  defp collect_elixir_declaration(ast, declarations), do: {ast, declarations}

  defp function_head({:when, _metadata, [head | _guards]}), do: function_head(head)
  defp function_head({name, _metadata, nil}) when is_atom(name), do: {name, []}

  defp function_head({name, _metadata, arguments}) when is_atom(name) and is_list(arguments),
    do: {name, arguments}

  defp function_head(_head), do: nil

  defp erlang_scopes(%Source{ast: forms}) do
    module =
      Enum.find_value(forms, fn
        {:attribute, _annotation, :module, name} when is_atom(name) -> Atom.to_string(name)
        _form -> nil
      end)

    modules =
      case Enum.find(forms, &match?({:attribute, _, :module, _}, &1)) do
        nil ->
          []

        node ->
          module_scope = scope(:module, module || "unknown_erlang_module", :module, node)
          [%{module_scope | end_line: max_ast_line(forms, module_scope.start_line)}]
      end

    definitions =
      Enum.flat_map(forms, fn
        {:function, _annotation, name, arity, _clauses} = node ->
          object = qualified_function(module, name, arity)
          [scope(:definition, object, :public_or_private, node)]

        _form ->
          []
      end)

    %{modules: modules, definitions: definitions, controls: [], aliases: [], imports: []}
  end

  defp scope(kind, object, qualifier, ast) do
    start_line = ast_line(ast)

    %{
      kind: kind,
      object: object,
      qualifier: qualifier,
      ast: ast,
      start_line: start_line,
      end_line: ast_end_line(ast, start_line)
    }
  end

  defp module_facts(source, scopes) do
    Enum.map(scopes.modules, fn scope ->
      fact(source, :module, source.path, :defines_module, scope.object, scope.ast, %{
        language: source.language,
        module_kind: scope.qualifier
      })
    end)
  end

  defp definition_facts(source, scopes) do
    Enum.map(scopes.definitions, fn scope ->
      subject = enclosing_module(scopes.modules, scope.start_line) || source.path

      fact(source, :definition, subject, :defines_function, scope.object, scope.ast, %{
        language: source.language,
        visibility: scope.qualifier
      })
    end)
  end

  defp binding_facts(source, scopes) do
    {_ast, bindings} =
      Macro.prewalk(source.ast, [], fn
        {:=, _metadata, [pattern, expression]} = ast, bindings ->
          line = ast_line(ast)
          module = enclosing_module(scopes.modules, line)
          subject = enclosing_definition(scopes.definitions, line) || module || source.path

          facts =
            pattern
            |> binding_variables()
            |> Enum.map(fn variable ->
              fact(source, :binding, subject, :binds_expression, variable, ast, %{
                language: :elixir,
                expression: Expression.describe(expression, :elixir),
                source_variables: argument_variables([expression], :elixir),
                control_contexts: control_contexts(scopes.controls, line)
              })
            end)

          {ast, Enum.reverse(facts, bindings)}

        ast, bindings ->
          {ast, bindings}
      end)

    Enum.reverse(bindings)
  end

  defp binding_variables(pattern) do
    pattern
    |> then(&argument_variables([&1], :elixir))
    |> Enum.reject(&String.starts_with?(&1, "_"))
  end

  defp elixir_callback_facts(source, scopes) do
    {_ast, callbacks} =
      Macro.prewalk(source.ast, [], fn
        {:@, _, [{kind, _, [signature]}]} = ast, callbacks
        when kind in [:callback, :macrocallback] ->
          case callback_head(signature) do
            {name, arguments} ->
              line = ast_line(ast)
              subject = enclosing_module(scopes.modules, line) || source.path
              object = qualified_function(subject, name, length(arguments))
              attributes = %{language: :elixir, callback_kind: kind}

              {ast,
               [
                 fact(source, :callback, subject, :declares_callback, object, ast, attributes)
                 | callbacks
               ]}

            nil ->
              {ast, callbacks}
          end

        ast, callbacks ->
          {ast, callbacks}
      end)

    Enum.reverse(callbacks)
  end

  defp protocol_callback_facts(source, scopes) do
    Enum.flat_map(scopes.definitions, fn definition ->
      case enclosing_module_scope(scopes.modules, definition.start_line) do
        %{qualifier: :protocol, object: protocol} ->
          fact =
            fact(
              source,
              :callback,
              protocol,
              :declares_callback,
              definition.object,
              definition.ast,
              %{language: :elixir, callback_kind: :protocol_function}
            )

          [fact]

        _other ->
          []
      end
    end)
  end

  defp erlang_callback_facts(source, scopes) do
    Enum.flat_map(source.ast, fn
      {:attribute, _annotation, :callback, {{name, arity}, _signatures}} = ast
      when is_atom(name) and is_integer(arity) and arity >= 0 ->
        subject = enclosing_module(scopes.modules, ast_line(ast)) || source.path
        object = qualified_function(subject, name, arity)
        attributes = %{language: :erlang, callback_kind: :callback}
        [fact(source, :callback, subject, :declares_callback, object, ast, attributes)]

      _other ->
        []
    end)
  end

  defp callback_head({:"::", _metadata, [head, _return]}), do: function_head(head)
  defp callback_head({:when, _metadata, [signature | _guards]}), do: callback_head(signature)
  defp callback_head(_signature), do: nil

  defp call_facts(source, scopes) do
    source
    |> AST.calls()
    |> Enum.flat_map(fn call ->
      line = Span.from_ast(source.path, call.ast).start_line
      module = enclosing_module(scopes.modules, line)
      subject = enclosing_definition(scopes.definitions, line) || module || source.path
      {syntactic_module, target_function} = call_target(call)
      target_module = resolve_alias(syntactic_module, scopes.aliases, line, module)
      target = "#{target_module}.#{target_function}/#{length(call.arguments)}"
      resolution = call_resolution(call, syntactic_module, target_module)

      call_fact =
        fact(source, :call, subject, :calls, target, call.ast, %{
          language: source.language,
          syntactic_module: syntactic_module,
          target_module: target_module,
          target_function: target_function,
          arity: length(call.arguments),
          argument_shapes: Enum.map(call.arguments, &argument_shape/1),
          argument_variables: argument_variables(call.arguments, source.language),
          control_contexts: control_contexts(scopes.controls, line),
          piped: call.piped?,
          resolution: resolution
        })

      [call_fact | call_argument_facts(source, call_fact, call.arguments)]
    end)
  end

  defp call_argument_facts(source, call_fact, arguments) do
    arguments
    |> Enum.with_index(1)
    |> Enum.map(fn {argument, position} ->
      fact(
        source,
        :call_argument,
        call_fact.subject,
        :passes_argument,
        "#{call_fact.object}#argument/#{position}",
        expression_span(source.path, argument, call_fact.span),
        %{
          language: source.language,
          via_fact_id: call_fact.id,
          target_call: call_fact.object,
          position: position,
          expression: Expression.describe(argument, source.language),
          source_variables: argument_variables([argument], source.language)
        }
      )
    end)
  end

  defp elixir_unqualified_call_facts(source, scopes) do
    function_heads = elixir_function_heads(source.ast)

    {_ast, facts} =
      Macro.prewalk(source.ast, [], fn ast, facts ->
        collect_elixir_unqualified_call(ast, facts, source, scopes, function_heads)
      end)

    Enum.reverse(facts)
  end

  defp collect_elixir_unqualified_call(
         {function, metadata, arguments} = ast,
         facts,
         source,
         scopes,
         function_heads
       )
       when is_atom(function) and is_list(metadata) and is_list(arguments) do
    if function in @elixir_non_calls or MapSet.member?(function_heads, ast) do
      {ast, facts}
    else
      call_facts = elixir_unqualified_call_facts(ast, source, scopes)
      {ast, Enum.reverse(call_facts, facts)}
    end
  end

  defp collect_elixir_unqualified_call(ast, facts, _source, _scopes, _function_heads) do
    {ast, facts}
  end

  defp elixir_unqualified_call_facts(
         {function, _metadata, arguments} = ast,
         source,
         scopes
       ) do
    line = Span.from_ast(source.path, ast).start_line
    module = enclosing_module(scopes.modules, line)
    subject = enclosing_definition(scopes.definitions, line) || module || source.path
    arity = length(arguments)

    {target_module, resolution, candidates} =
      resolve_unqualified(function, arity, line, module, scopes)

    attributes = %{
      language: :elixir,
      target_module: target_module,
      target_function: Atom.to_string(function),
      candidate_modules: candidates,
      arity: arity,
      argument_shapes: Enum.map(arguments, &argument_shape/1),
      argument_variables: argument_variables(arguments, :elixir),
      control_contexts: control_contexts(scopes.controls, line),
      resolution: resolution
    }

    object = qualified_or_unqualified_call(target_module, function, arity)
    call_fact = fact(source, :unqualified_call, subject, :invokes, object, ast, attributes)
    [call_fact | call_argument_facts(source, call_fact, arguments)]
  end

  defp qualified_or_unqualified_call(nil, function, arity), do: "#{function}/#{arity}"

  defp qualified_or_unqualified_call(target_module, function, arity),
    do: "#{target_module}.#{function}/#{arity}"

  defp elixir_function_heads(ast) do
    {_ast, heads} =
      Macro.prewalk(ast, MapSet.new(), fn
        {kind, _metadata, [head | _rest]} = node, heads
        when kind in [:def, :defp, :defmacro, :defmacrop] ->
          {node, MapSet.put(heads, strip_guard(head))}

        node, heads ->
          {node, heads}
      end)

    heads
  end

  defp strip_guard({:when, _metadata, [head | _guards]}), do: head
  defp strip_guard(head), do: head

  defp erlang_unqualified_call_facts(source, scopes) do
    source.ast
    |> collect_erlang_unqualified_calls([])
    |> Enum.reverse()
    |> Enum.flat_map(fn ast ->
      {:call, _annotation, {:atom, _, function}, arguments} = ast
      line = Span.from_ast(source.path, ast).start_line
      module = enclosing_module(scopes.modules, line)
      subject = enclosing_definition(scopes.definitions, line) || module || source.path

      call_fact =
        fact(
          source,
          :unqualified_call,
          subject,
          :invokes,
          "#{function}/#{length(arguments)}",
          ast,
          %{
            language: :erlang,
            target_function: Atom.to_string(function),
            arity: length(arguments),
            argument_shapes: Enum.map(arguments, &argument_shape/1),
            argument_variables: argument_variables(arguments, :erlang),
            control_contexts: [],
            resolution: :local_or_auto_imported
          }
        )

      [call_fact | call_argument_facts(source, call_fact, arguments)]
    end)
  end

  defp collect_erlang_unqualified_calls(
         {:call, _annotation, {:atom, _, _function}, arguments} = ast,
         calls
       )
       when is_list(arguments) do
    walk_erlang_children(ast, [ast | calls])
  end

  defp collect_erlang_unqualified_calls(ast, calls), do: walk_erlang_children(ast, calls)

  defp walk_erlang_children(ast, calls) when is_list(ast) do
    Enum.reduce(ast, calls, &collect_erlang_unqualified_calls/2)
  end

  defp walk_erlang_children(ast, calls) when is_tuple(ast) do
    ast
    |> Tuple.to_list()
    |> Enum.reduce(calls, &collect_erlang_unqualified_calls/2)
  end

  defp walk_erlang_children(_ast, calls), do: calls

  defp elixir_directive_facts(source, scopes) do
    {_ast, directives} =
      Macro.prewalk(source.ast, [], fn
        {:@, _, [{:behaviour, _, [{:__aliases__, _, parts}]}]} = ast, directives ->
          line = Span.from_ast(source.path, ast).start_line
          module = enclosing_module(scopes.modules, line)
          subject = module || source.path
          syntactic_target = AST.alias_name(parts)
          target = resolve_alias(syntactic_target, scopes.aliases, line, module)
          attributes = %{language: :elixir, target_module: target}

          {ast,
           [fact(source, :directive, subject, :implements, target, ast, attributes) | directives]}

        {:defimpl, _, [{:__aliases__, _, parts} | rest]} = ast, directives ->
          target = AST.alias_name(parts)
          line = Span.from_ast(source.path, ast).start_line
          subject = enclosing_module(scopes.modules, line) || source.path
          protocol_types = protocol_types(rest)

          attributes = %{
            language: :elixir,
            target_module: target,
            protocol_for: List.first(protocol_types),
            protocol_types: protocol_types
          }

          {ast,
           [fact(source, :directive, subject, :implements, target, ast, attributes) | directives]}

        {kind, _metadata, [{:__aliases__, _, parts} | _rest]} = ast, directives
        when kind in [:alias, :import, :require, :use] ->
          line = Span.from_ast(source.path, ast).start_line
          module = enclosing_module(scopes.modules, line)
          subject = module || source.path
          syntactic_target = AST.alias_name(parts)
          target = resolve_alias(syntactic_target, scopes.aliases, line, module)
          attributes = %{language: :elixir, target_module: target}
          {ast, [fact(source, :directive, subject, kind, target, ast, attributes) | directives]}

        ast, directives ->
          {ast, directives}
      end)

    Enum.reverse(directives)
  end

  defp protocol_implementation_module({:defimpl, _, [{:__aliases__, _, protocol_parts} | rest]}) do
    case protocol_types(rest) do
      [protocol_type] ->
        AST.alias_name(protocol_parts) <> "." <> protocol_type

      _other ->
        nil
    end
  end

  defp protocol_implementation_module(_ast), do: nil

  defp protocol_types(rest) do
    rest
    |> Enum.find_value([], fn
      options when is_list(options) ->
        case Keyword.fetch(options, :for) do
          {:ok, types} -> List.wrap(types)
          :error -> nil
        end

      _other ->
        nil
    end)
    |> Enum.flat_map(&protocol_type/1)
    |> Enum.uniq()
    |> Enum.sort()
  end

  defp protocol_type({:__aliases__, _, parts}) do
    [AST.alias_name(parts)]
  end

  defp protocol_type(type) when is_atom(type), do: [Atom.to_string(type)]
  defp protocol_type(_dynamic), do: []

  defp erlang_directive_facts(source, scopes) do
    Enum.flat_map(source.ast, fn
      {:attribute, _annotation, kind, target} = ast
      when kind in [:behaviour, :behavior] and is_atom(target) ->
        subject = enclosing_module(scopes.modules, ast_line(ast)) || source.path
        target = Atom.to_string(target)
        attributes = %{language: :erlang, target_module: target}
        [fact(source, :directive, subject, :implements, target, ast, attributes)]

      _form ->
        []
    end)
  end

  defp rebar_dependency_facts(%Source{} = source) do
    case Path.basename(source.origin.path) do
      "rebar.config" -> rebar_config_facts(source)
      "rebar.lock" -> rebar_lock_facts(source)
      _other -> []
    end
  end

  defp rebar_config_facts(source) do
    source.ast
    |> Enum.flat_map(fn
      {:deps, dependencies} when is_list(dependencies) -> dependencies
      _term -> []
    end)
    |> Enum.flat_map(&rebar_config_dependency(source, &1))
  end

  defp rebar_config_dependency(source, app) when is_atom(app) do
    [rebar_dependency_fact(source, app, nil, :hex, app)]
  end

  defp rebar_config_dependency(source, {app, requirement} = spec) when is_atom(app) do
    {package, source_type} = rebar_package_source(app, requirement)
    [rebar_dependency_fact(source, package, rebar_requirement(requirement), source_type, spec)]
  end

  defp rebar_config_dependency(source, {app, requirement, options} = spec) when is_atom(app) do
    package = rebar_package_option(app, options)
    {package, source_type} = rebar_package_source(package, requirement)
    [rebar_dependency_fact(source, package, rebar_requirement(requirement), source_type, spec)]
  end

  defp rebar_config_dependency(_source, _dependency), do: []

  defp rebar_dependency_fact(source, package, requirement, source_type, spec) do
    package = text(package)

    fact(source, :dependency, source.path, :declares_dependency, package, spec, %{
      app: package,
      requirement: requirement,
      source: source_type,
      specification: project_value(spec),
      direct: true,
      ecosystem: :rebar
    })
  end

  defp rebar_package_source(app, {:git, _url}), do: {app, :git}
  defp rebar_package_source(app, {:git, _url, _ref}), do: {app, :git}
  defp rebar_package_source(app, {:path, _path}), do: {app, :path}
  defp rebar_package_source(_app, {:pkg, package}), do: {package, :hex}
  defp rebar_package_source(_app, {:pkg, package, _version}), do: {package, :hex}
  defp rebar_package_source(app, _requirement), do: {app, :hex}

  defp rebar_package_option(app, options) when is_list(options) do
    case List.keyfind(options, :pkg, 0) do
      {:pkg, package} -> package
      _other -> app
    end
  end

  defp rebar_package_option(app, _options), do: app

  defp rebar_requirement(requirement) when is_binary(requirement), do: requirement
  defp rebar_requirement(requirement) when is_list(requirement), do: to_string(requirement)
  defp rebar_requirement({:pkg, _package, version}), do: text(version)
  defp rebar_requirement(_requirement), do: nil

  defp rebar_lock_facts(source) do
    source.ast
    |> collect_rebar_locks([])
    |> Enum.reverse()
    |> Enum.map(fn {name, {:pkg, package, version}, level} = lock ->
      fact(source, :dependency, source.path, :locks_dependency, text(package), lock, %{
        app: text(name),
        version: text(version),
        source: :hex,
        dependency_level: level,
        directness: if(level == 0, do: :direct, else: :transitive),
        ecosystem: :rebar
      })
    end)
  end

  defp collect_rebar_locks({_name, {:pkg, _package, _version}, level} = lock, locks)
       when is_integer(level) do
    [lock | locks]
  end

  defp collect_rebar_locks(term, locks) when is_list(term) do
    Enum.reduce(term, locks, &collect_rebar_locks/2)
  end

  defp collect_rebar_locks(term, locks) when is_tuple(term) do
    term |> Tuple.to_list() |> Enum.reduce(locks, &collect_rebar_locks/2)
  end

  defp collect_rebar_locks(_term, locks), do: locks

  defp text(value) when is_binary(value), do: value
  defp text(value) when is_atom(value), do: Atom.to_string(value)
  defp text(value) when is_list(value), do: to_string(value)

  defp mix_dependency_facts(%Source{path: path} = source) do
    if Path.basename(path) == "mix.exs" do
      {_ast, dependencies} =
        Macro.prewalk(source.ast, [], &collect_mix_dependencies(source, &1, &2))

      Enum.reverse(dependencies)
    else
      mix_lock_facts(source)
    end
  end

  defp collect_mix_dependencies(source, {kind, _, [head, [do: body]]} = ast, dependencies)
       when kind in [:def, :defp] do
    case function_head(head) do
      {:deps, _arguments} ->
        facts = body |> dependency_nodes() |> Enum.flat_map(&mix_dependency_fact(source, &1, ast))
        {ast, Enum.reverse(facts) ++ dependencies}

      _other ->
        {ast, dependencies}
    end
  end

  defp collect_mix_dependencies(_source, ast, dependencies), do: {ast, dependencies}

  defp dependency_nodes(nodes) when is_list(nodes), do: nodes

  defp dependency_nodes({:++, _metadata, [left, right]}) do
    dependency_nodes(left) ++ dependency_nodes(right)
  end

  defp dependency_nodes(_dynamic), do: []

  defp mix_dependency_fact(source, {app, requirement}, fallback)
       when is_atom(app) and is_binary(requirement) do
    [dependency_fact(source, fallback, app, requirement, [])]
  end

  defp mix_dependency_fact(source, {app, options}, fallback)
       when is_atom(app) and is_list(options) do
    [dependency_fact(source, fallback, app, nil, options)]
  end

  defp mix_dependency_fact(source, {:{}, _metadata, [app, requirement, options]} = ast, _fallback)
       when is_atom(app) and is_binary(requirement) and is_list(options) do
    [dependency_fact(source, ast, app, requirement, options)]
  end

  defp mix_dependency_fact(_source, _node, _fallback), do: []

  defp dependency_fact(source, ast, app, requirement, options) do
    package = options |> Keyword.get(:hex, app) |> to_string()

    fact(source, :dependency, source.path, :declares_dependency, package, ast, %{
      app: Atom.to_string(app),
      requirement: requirement,
      source: dependency_source(options),
      options: project_options(options),
      direct: true
    })
  end

  defp mix_lock_facts(%Source{path: path, ast: {:%{}, _, pairs}} = source) do
    if Path.basename(path) == "mix.lock" do
      Enum.flat_map(pairs, &mix_lock_fact(source, &1))
    else
      []
    end
  end

  defp mix_lock_facts(_source), do: []

  defp mix_lock_fact(source, {package, {:{}, _, [:hex, app, version | rest]} = ast})
       when is_binary(package) and is_atom(app) and is_binary(version) do
    repository = Enum.at(rest, 3)

    [
      fact(source, :dependency, source.path, :locks_dependency, package, ast, %{
        app: Atom.to_string(app),
        version: version,
        source: :hex,
        repository: if(is_binary(repository), do: repository),
        directness: :not_encoded_in_lock
      })
    ]
  end

  defp mix_lock_fact(_source, _entry), do: []

  defp callback_implementation_facts(facts) do
    callbacks = Enum.filter(facts, &(&1.kind == :callback))

    definitions =
      facts
      |> Enum.filter(&(&1.kind == :definition))
      |> Enum.group_by(& &1.object)

    facts
    |> Enum.filter(&(&1.kind == :directive and &1.relation == :implements))
    |> Enum.flat_map(fn directive ->
      callbacks
      |> Enum.filter(&(&1.subject == directive.object))
      |> Enum.flat_map(&callback_implementations(&1, directive, definitions))
    end)
  end

  defp callback_implementations(callback, directive, definitions) do
    prefix = callback.subject <> "."
    signature = String.replace_prefix(callback.object, prefix, "")
    implementation = directive.subject <> "." <> signature

    definitions
    |> Map.get(implementation, [])
    |> Enum.map(fn definition ->
      Fact.new!(
        kind: :callback_implementation,
        subject: definition.object,
        relation: :implements_callback,
        object: callback.object,
        span: definition.span,
        source_hash: definition.source_hash,
        attributes: %{
          callback_fact_id: callback.id,
          definition_fact_id: definition.id,
          directive_fact_id: directive.id,
          origin: Map.get(definition.attributes, :origin)
        }
      )
    end)
  end

  defp derived_module_owners(sources, facts) do
    origins = Map.new(sources, &{&1.path, &1.origin})

    facts
    |> Enum.filter(&(&1.kind == :module))
    |> Enum.reduce(%{}, fn fact, candidates ->
      origin = Map.fetch!(origins, fact.span.file)

      if origin.kind == :dependency and nonempty_string?(Map.get(origin, :package)) do
        Map.update(
          candidates,
          fact.object,
          MapSet.new([origin.package]),
          &MapSet.put(&1, origin.package)
        )
      else
        candidates
      end
    end)
    |> Enum.flat_map(fn {module, packages} ->
      if MapSet.size(packages) == 1, do: [{module, Enum.at(packages, 0)}], else: []
    end)
    |> Map.new()
  end

  defp package_use_facts(_facts, module_owners) when map_size(module_owners) == 0, do: []

  defp package_use_facts(facts, module_owners) do
    facts
    |> Enum.filter(&(&1.kind in [:call, :directive, :unqualified_call]))
    |> Enum.flat_map(fn fact ->
      target_module = Map.get(fact.attributes, :target_module)

      case module_owner(module_owners, target_module) do
        nil ->
          []

        package ->
          [
            Fact.new!(
              kind: :package_use,
              subject: fact.subject,
              relation: :uses_package,
              object: package,
              span: fact.span,
              source_hash: fact.source_hash,
              attributes: %{
                via_fact_id: fact.id,
                via_kind: fact.kind,
                target_module: target_module,
                target: fact.object,
                resolution: :host_module_inventory
              }
            )
          ]
      end
    end)
  end

  defp module_owner(module_owners, target_module) when is_binary(target_module) do
    module_owners
    |> Enum.filter(fn {module, _package} ->
      target_module == module or String.starts_with?(target_module, module <> ".")
    end)
    |> Enum.max_by(fn {module, _package} -> byte_size(module) end, fn -> nil end)
    |> case do
      {_module, package} -> package
      nil -> nil
    end
  end

  defp module_owner(_module_owners, _target_module), do: nil

  defp validate_module_owners!(module_owners) when is_map(module_owners) do
    if Enum.all?(module_owners, fn {module, package} ->
         nonempty_string?(module) and nonempty_string?(package)
       end) do
      module_owners
    else
      raise ArgumentError, "SAST module owners must map module-name strings to package strings"
    end
  end

  defp validate_module_owners!(_module_owners) do
    raise ArgumentError, "SAST module owners must be a map"
  end

  defp fact(source, kind, subject, relation, object, ast_or_span, attributes) do
    Fact.new!(
      kind: kind,
      subject: subject,
      relation: relation,
      object: object,
      span: fact_span(source.path, ast_or_span),
      source_hash: source.hash,
      attributes: Map.put(attributes, :origin, source.origin)
    )
  end

  defp fact_span(_path, %Span{} = span), do: span
  defp fact_span(path, ast), do: Span.from_ast(path, ast)

  defp expression_span(path, {_form, metadata, _arguments} = ast, fallback)
       when is_list(metadata) do
    if positive_integer?(Keyword.get(metadata, :line)),
      do: Span.from_ast(path, ast),
      else: fallback
  end

  defp expression_span(path, ast, fallback) when is_tuple(ast) and tuple_size(ast) >= 2 do
    annotation = elem(ast, 1)

    if :erl_anno.is_anno(annotation) and positive_erlang_line?(annotation),
      do: Span.from_ast(path, ast),
      else: fallback
  end

  defp expression_span(_path, _ast, fallback), do: fallback

  defp positive_erlang_line?(annotation) do
    case :erl_anno.location(annotation) do
      {line, _column} -> positive_integer?(line)
      line -> positive_integer?(line)
    end
  end

  defp positive_integer?(value), do: is_integer(value) and value > 0

  defp call_target(%AST.Call{module: {:alias, module}, function: function}) do
    {module, Atom.to_string(function)}
  end

  defp call_target(%AST.Call{module: {:atom, module}, function: function}) do
    {Atom.to_string(module), Atom.to_string(function)}
  end

  defp call_target(%AST.Call{module: {:dynamic, label}, function: function}) do
    {label, Atom.to_string(function)}
  end

  defp call_resolution(%AST.Call{module: {:dynamic, _label}}, _syntactic, _target),
    do: :dynamic_dispatch

  defp call_resolution(_call, module, module), do: :syntactic
  defp call_resolution(_call, _syntactic, _target), do: :source_alias

  defp elixir_aliases(ast, modules) do
    {_ast, aliases} =
      Macro.prewalk(ast, [], fn
        {:alias, _, [{:__aliases__, _, parts}, options]} = node, aliases
        when is_list(options) ->
          target = AST.alias_name(parts)
          short = alias_short_name(parts, Keyword.get(options, :as))
          {node, [alias_scope(node, short, target, modules) | aliases]}

        {:alias, _, [{:__aliases__, _, parts}]} = node, aliases ->
          target = AST.alias_name(parts)
          short = parts |> List.last() |> alias_part_name()
          {node, [alias_scope(node, short, target, modules) | aliases]}

        node, aliases ->
          {node, aliases}
      end)

    Enum.reverse(aliases)
  end

  defp alias_scope(node, short, target, modules) do
    line = ast_line(node)
    module = enclosing_module(modules, line)
    target = expand_current_module(target, module)
    %{short: short, target: target, line: line, module: module}
  end

  defp elixir_imports(ast, modules, aliases) do
    {_ast, imports} =
      Macro.prewalk(ast, [], fn
        {:import, _, [{:__aliases__, _, parts} | rest]} = node, imports ->
          line = ast_line(node)

          module = enclosing_module(modules, line)
          target = AST.alias_name(parts)

          import = %{
            target: resolve_alias(target, aliases, line, module),
            line: line,
            module: module,
            only: import_filter(rest, :only),
            except: import_filter(rest, :except)
          }

          {node, [import | imports]}

        node, imports ->
          {node, imports}
      end)

    Enum.reverse(imports)
  end

  defp import_filter([options | _rest], key) when is_list(options) do
    case Keyword.get(options, key) do
      values when is_list(values) -> MapSet.new(values)
      _other -> nil
    end
  end

  defp import_filter(_options, _key), do: nil

  defp alias_short_name(_parts, {:__aliases__, _, as_parts}) do
    AST.alias_name(as_parts)
  end

  defp alias_short_name(parts, _as), do: parts |> List.last() |> alias_part_name()

  defp alias_part_name(part), do: AST.alias_name([part])

  defp resolve_alias(module, _aliases, _line, enclosing_module)
       when module == "__MODULE__" and is_binary(enclosing_module),
       do: enclosing_module

  defp resolve_alias("__MODULE__." <> tail, _aliases, _line, enclosing_module)
       when is_binary(enclosing_module),
       do: enclosing_module <> "." <> tail

  defp resolve_alias(module, aliases, line, enclosing_module) do
    [head | tail] = String.split(module, ".")

    aliases
    |> Enum.filter(fn alias_scope ->
      alias_scope.short == head and alias_scope.module == enclosing_module and
        alias_scope.line <= line
    end)
    |> Enum.max_by(& &1.line, fn -> nil end)
    |> case do
      %{target: target} -> Enum.join([target | tail], ".")
      nil -> module
    end
  end

  defp expand_current_module("__MODULE__", enclosing_module) when is_binary(enclosing_module),
    do: enclosing_module

  defp expand_current_module("__MODULE__." <> tail, enclosing_module)
       when is_binary(enclosing_module),
       do: enclosing_module <> "." <> tail

  defp expand_current_module(module, _enclosing_module), do: module

  defp resolve_unqualified(function, arity, line, module, scopes) do
    local =
      module && Enum.any?(scopes.definitions, &(&1.object == "#{module}.#{function}/#{arity}"))

    candidates =
      scopes.imports
      |> Enum.filter(&import_candidate?(&1, function, arity, line, module))
      |> Enum.map(& &1.target)
      |> Enum.uniq()
      |> Enum.sort()

    cond do
      local -> {module, :local_definition, [module]}
      length(candidates) == 1 -> {List.first(candidates), :source_import, candidates}
      candidates != [] -> {nil, :ambiguous_import, candidates}
      true -> {nil, :local_or_imported, []}
    end
  end

  defp import_candidate?(import, function, arity, line, module) do
    signature = {function, arity}

    import.module == module and import.line <= line and
      (is_nil(import.only) or MapSet.member?(import.only, signature)) and
      (is_nil(import.except) or not MapSet.member?(import.except, signature))
  end

  defp argument_shape(argument), do: if(AST.literal?(argument), do: :literal, else: :dynamic)

  defp argument_variables(arguments, language) do
    arguments
    |> Enum.reduce(MapSet.new(), &collect_variables(&1, language, &2))
    |> MapSet.to_list()
    |> Enum.sort()
  end

  defp collect_variables({:var, _annotation, name}, :erlang, variables) when is_atom(name) do
    MapSet.put(variables, Atom.to_string(name))
  end

  defp collect_variables({:"::", _metadata, [value, _type]}, :elixir, variables) do
    collect_variables(value, :elixir, variables)
  end

  defp collect_variables({name, metadata, context}, :elixir, variables)
       when is_atom(name) and is_list(metadata) and (is_atom(context) or is_nil(context)) do
    MapSet.put(variables, Atom.to_string(name))
  end

  defp collect_variables(term, language, variables) when is_list(term) do
    Enum.reduce(term, variables, &collect_variables(&1, language, &2))
  end

  defp collect_variables(term, language, variables) when is_tuple(term) do
    term
    |> Tuple.to_list()
    |> Enum.reduce(variables, &collect_variables(&1, language, &2))
  end

  defp collect_variables(_term, _language, variables), do: variables

  defp enclosing_definition(definitions, line) do
    definitions
    |> Enum.filter(&contains_line?(&1, line))
    |> Enum.max_by(& &1.start_line, fn -> nil end)
    |> case do
      nil -> nil
      definition -> definition.object
    end
  end

  defp enclosing_module(modules, line) do
    case enclosing_module_scope(modules, line) do
      nil -> nil
      module -> module.object
    end
  end

  defp enclosing_module_scope(modules, line) do
    modules
    |> Enum.filter(&contains_line?(&1, line))
    |> Enum.max_by(& &1.start_line, fn -> nil end)
  end

  defp control_contexts(controls, line) do
    controls
    |> Enum.filter(&contains_line?(&1, line))
    |> Enum.map(&%{kind: &1.object, start_line: &1.start_line, end_line: &1.end_line})
    |> Enum.sort_by(&{&1.start_line, &1.end_line, &1.kind})
  end

  defp contains_line?(scope, line), do: line >= scope.start_line and line <= scope.end_line

  defp qualified_function(nil, name, arity), do: "#{name}/#{arity}"
  defp qualified_function(module, name, arity), do: "#{module}.#{name}/#{arity}"

  defp module_nesting([:"Elixir" | parts]), do: {:absolute, parts}
  defp module_nesting(parts), do: {:relative, parts}

  defp qualify_nested_module(nil, name), do: name
  defp qualify_nested_module(_parent, ""), do: ""
  defp qualify_nested_module(parent, name), do: "#{parent}.#{name}"

  defp ast_line({_form, metadata, _arguments}) when is_list(metadata),
    do: Keyword.get(metadata, :line, 1)

  defp ast_line(ast) when is_tuple(ast) and tuple_size(ast) >= 2 do
    annotation = elem(ast, 1)
    if :erl_anno.is_anno(annotation), do: :erl_anno.line(annotation), else: 1
  end

  defp ast_line(_ast), do: 1

  defp ast_end_line({_form, metadata, _arguments} = ast, initial) when is_list(metadata) do
    case Keyword.get(metadata, :end) do
      end_metadata when is_list(end_metadata) -> Keyword.get(end_metadata, :line, initial)
      _no_end_metadata -> max_ast_line(ast, initial)
    end
  end

  defp ast_end_line(ast, initial), do: max_ast_line(ast, initial)

  defp max_ast_line(ast, initial), do: walk_max_line(ast, initial)

  defp walk_max_line(ast, maximum) when is_list(ast) do
    Enum.reduce(ast, maximum, &walk_max_line/2)
  end

  defp walk_max_line(ast, maximum) when is_tuple(ast) do
    maximum = max(maximum, ast_line(ast))
    ast |> Tuple.to_list() |> Enum.reduce(maximum, &walk_max_line/2)
  end

  defp walk_max_line(_ast, maximum), do: maximum

  defp dependency_source(options) do
    cond do
      Keyword.has_key?(options, :git) -> :git
      Keyword.has_key?(options, :github) -> :github
      Keyword.has_key?(options, :path) -> :path
      true -> :hex
    end
  end

  defp project_options(options) do
    Map.new(options, fn {key, value} -> {key, project_value(value)} end)
  end

  defp project_value(value)
       when is_binary(value) or is_number(value) or is_atom(value) or is_boolean(value) or
              is_nil(value),
       do: value

  defp project_value(values) when is_list(values), do: Enum.map(values, &project_value/1)
  defp project_value(value), do: inspect(value, limit: 20, printable_limit: 200)

  defp matches?(fact, filters) do
    exact_match?(fact, filters, :kind) and exact_match?(fact, filters, :subject) and
      exact_match?(fact, filters, :relation) and exact_match?(fact, filters, :object) and
      file_match?(fact, filters[:file]) and prefix_match?(fact.subject, filters[:subject_prefix]) and
      prefix_match?(fact.object, filters[:object_prefix])
  end

  defp validate_query_filters!(filters) do
    filters =
      Keyword.validate!(filters, [
        :kind,
        :subject,
        :relation,
        :object,
        :file,
        :subject_prefix,
        :object_prefix,
        limit: 100,
        offset: 0
      ])

    positive_integer!(filters[:limit], :limit)
    non_negative_integer!(filters[:offset], :offset)
    filters
  end

  defp exact_match?(fact, filters, key) do
    case Keyword.fetch(filters, key) do
      {:ok, expected} -> Map.fetch!(fact, key) == expected
      :error -> true
    end
  end

  defp file_match?(_fact, nil), do: true
  defp file_match?(fact, file), do: fact.span.file == file
  defp prefix_match?(_value, nil), do: true
  defp prefix_match?(value, prefix) when is_binary(prefix), do: String.starts_with?(value, prefix)

  defp inventory_id(facts, module_owners) do
    {Enum.map(facts, & &1.id), Enum.sort(module_owners)}
    |> :erlang.term_to_binary([:deterministic])
    |> then(&:crypto.hash(:sha256, &1))
    |> Base.encode16(case: :lower)
  end

  defp frequencies(facts, key_function) do
    facts
    |> Enum.frequencies_by(key_function)
    |> Enum.sort()
    |> Map.new()
  end

  defp sort_facts(facts) do
    Enum.sort_by(facts, fn fact ->
      {fact.span.file, fact.span.start_line, fact.span.start_column || 0, fact.kind, fact.object,
       fact.id}
    end)
  end

  defp positive_integer!(value, _name) when is_integer(value) and value > 0, do: value

  defp positive_integer!(value, name) do
    raise ArgumentError,
          "SAST inventory #{name} must be a positive integer, got: #{inspect(value)}"
  end

  defp non_negative_integer!(value, _name) when is_integer(value) and value >= 0, do: value

  defp non_negative_integer!(value, name) do
    raise ArgumentError,
          "SAST inventory #{name} must be a non-negative integer, got: #{inspect(value)}"
  end

  defp nonempty_string?(value), do: is_binary(value) and String.trim(value) != ""
end
