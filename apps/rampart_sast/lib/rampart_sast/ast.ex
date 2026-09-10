defmodule RampartSAST.AST do
  @moduledoc "Helpers for conservative, syntax-only call extraction."

  alias RampartSAST.Source

  defmodule Call do
    @moduledoc "A normalized remote call, including effective pipeline arguments."

    @type module_name :: {:alias, String.t()} | {:atom, atom()} | {:dynamic, String.t()}
    @type t :: %__MODULE__{
            module: module_name(),
            function: atom(),
            arguments: [Macro.t()],
            ast: Macro.t(),
            piped?: boolean()
          }

    @enforce_keys [:module, :function, :arguments, :ast, :piped?]
    defstruct @enforce_keys
  end

  @doc "Returns normalized remote calls in source order."
  @spec calls(source :: Source.t()) :: [Call.t()]
  def calls(%Source{language: :elixir, ast: ast}), do: elixir_calls(ast)
  def calls(%Source{language: :erlang, ast: forms}), do: erlang_calls(forms)

  defp elixir_calls(ast) do
    {_ast, calls} = Macro.prewalk(ast, [], &collect_elixir_call/2)

    calls = Enum.reverse(calls)

    pipeline_rhs =
      calls
      |> Enum.filter(& &1.piped?)
      |> MapSet.new(fn %Call{ast: {:|>, _, [_left, right]}} -> right end)

    calls
    |> Enum.reject(&(not &1.piped? and MapSet.member?(pipeline_rhs, &1.ast)))
    |> Enum.uniq_by(&{&1.ast, &1.arguments})
  end

  defp erlang_calls(forms) do
    forms
    |> walk_erlang([])
    |> Enum.reverse()
  end

  @doc "Returns whether an AST value is fully literal without evaluating it."
  @spec literal?(ast :: Macro.t()) :: boolean()
  def literal?(value) when is_binary(value) or is_number(value) or is_atom(value), do: true
  def literal?(values) when is_list(values), do: Enum.all?(values, &literal?/1)
  def literal?({:__aliases__, _, parts}) when is_list(parts), do: true
  def literal?({:{}, _, values}) when is_list(values), do: Enum.all?(values, &literal?/1)

  def literal?({type, _annotation, _value})
      when type in [:atom, :char, :float, :integer, :string], do: true

  def literal?({nil, _annotation}), do: true
  def literal?({key, value}), do: literal?(key) and literal?(value)

  def literal?({:tuple, _annotation, values}) when is_list(values),
    do: Enum.all?(values, &literal?/1)

  def literal?({:cons, _annotation, head, tail}) do
    literal?(head) and literal?(tail)
  end

  def literal?({:%{}, _, pairs}) when is_list(pairs) do
    Enum.all?(pairs, fn
      {key, value} -> literal?(key) and literal?(value)
      _other -> false
    end)
  end

  def literal?(_ast), do: false

  @doc "Returns a stable syntax-only name for Elixir alias segments."
  @spec alias_name(parts :: [Macro.t()]) :: String.t()
  def alias_name(parts) when is_list(parts) do
    Enum.map_join(parts, ".", &alias_segment/1)
  end

  @doc "Returns a stable printable name for a normalized call."
  @spec call_name(Call.t()) :: String.t()
  def call_name(%Call{module: {:alias, module}, function: function, arguments: arguments}) do
    "#{module}.#{function}/#{length(arguments)}"
  end

  def call_name(%Call{module: {:atom, module}, function: function, arguments: arguments}) do
    ":#{module}.#{function}/#{length(arguments)}"
  end

  def call_name(%Call{module: {:dynamic, label}, function: function, arguments: arguments}) do
    "#{label}.#{function}/#{length(arguments)}"
  end

  defp collect_elixir_call(
         {:|>, _, [left, {{:., _, [module_ast, function]}, _, arguments}]} = ast,
         calls
       )
       when is_atom(function) and is_list(arguments) do
    call = %Call{
      module: module_name(module_ast),
      function: function,
      arguments: [left | arguments],
      ast: ast,
      piped?: true
    }

    {ast, [call | calls]}
  end

  defp collect_elixir_call({{:., _, [module_ast, function]}, _, arguments} = ast, calls)
       when is_atom(function) and is_list(arguments) do
    call = %Call{
      module: module_name(module_ast),
      function: function,
      arguments: arguments,
      ast: ast,
      piped?: false
    }

    {ast, [call | calls]}
  end

  defp collect_elixir_call(ast, calls), do: {ast, calls}

  defp collect_erlang_call(
         {:call, _annotation, {:remote, _, {:atom, _, module}, {:atom, _, function}}, arguments} =
           ast,
         calls
       )
       when is_atom(module) and is_atom(function) and is_list(arguments) do
    call = %Call{
      module: {:atom, module},
      function: function,
      arguments: arguments,
      ast: ast,
      piped?: false
    }

    {ast, [call | calls]}
  end

  defp collect_erlang_call(
         {:call, _annotation, {:remote, _, module_ast, function_ast}, arguments} = ast,
         calls
       )
       when is_list(arguments) do
    call = %Call{
      module: erlang_module_name(module_ast),
      function: erlang_function_name(function_ast),
      arguments: arguments,
      ast: ast,
      piped?: false
    }

    {ast, [call | calls]}
  end

  defp collect_erlang_call(ast, calls), do: {ast, calls}

  defp walk_erlang(term, calls) do
    {_term, calls} = collect_erlang_call(term, calls)

    cond do
      is_list(term) -> Enum.reduce(term, calls, &walk_erlang/2)
      is_tuple(term) -> term |> Tuple.to_list() |> Enum.reduce(calls, &walk_erlang/2)
      true -> calls
    end
  end

  defp module_name({:__aliases__, _, parts}) when is_list(parts) do
    name = alias_name(parts)

    if String.contains?(name, "<dynamic-module>"),
      do: {:dynamic, name},
      else: {:alias, name}
  end

  defp module_name(module) when is_atom(module), do: {:atom, module}
  defp module_name(_module), do: {:dynamic, "<dynamic-module>"}

  defp alias_segment(segment) when is_atom(segment), do: Atom.to_string(segment)

  defp alias_segment({:__MODULE__, metadata, context})
       when is_list(metadata) and is_atom(context),
       do: "__MODULE__"

  defp alias_segment(_segment), do: "<dynamic-module>"

  defp erlang_module_name({:atom, _annotation, module}), do: {:atom, module}
  defp erlang_module_name(_module_ast), do: {:dynamic, "<dynamic-module>"}

  defp erlang_function_name({:atom, _annotation, function}), do: function
  defp erlang_function_name(_function_ast), do: :"<dynamic-function>"
end
