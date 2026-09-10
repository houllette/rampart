defmodule RampartSAST.Context.Elixir do
  @moduledoc """
  General Elixir module facts extracted once for framework-aware rules.

  This provider records module declarations, aliases, imports, `use` targets,
  and common Phoenix roles. It does not infer trust or taint from a role.
  """

  @behaviour RampartSAST.ContextProvider

  alias RampartSAST.{AST, Source}

  @id "rampart.elixir-context.v1"

  @impl true
  @spec id() :: String.t()
  def id, do: @id

  @impl true
  @spec build([Source.t()], keyword()) :: {:ok, RampartSAST.ContextProvider.contribution()}
  def build(sources, _options) do
    source_facts =
      sources
      |> Enum.filter(&(&1.language == :elixir))
      |> Map.new(&{&1.path, facts(&1)})

    project = %{
      modules:
        source_facts |> Map.values() |> Enum.flat_map(& &1.modules) |> Enum.uniq() |> Enum.sort(),
      phoenix_controllers: paths_with_role(source_facts, :phoenix_controller),
      phoenix_endpoints: paths_with_role(source_facts, :phoenix_endpoint),
      phoenix_live_views: paths_with_role(source_facts, :phoenix_live_view),
      phoenix_routers: paths_with_role(source_facts, :phoenix_router)
    }

    {:ok, %{project: project, sources: source_facts}}
  end

  defp facts(%Source{ast: ast}) do
    {_ast, facts} = Macro.prewalk(ast, initial_facts(), &collect/2)

    %{
      modules: facts.modules |> Enum.uniq() |> Enum.sort(),
      aliases: facts.aliases,
      imports: facts.imports |> Enum.uniq() |> Enum.sort(),
      uses: facts.uses |> Enum.uniq() |> Enum.sort(),
      roles: facts.roles |> Enum.uniq() |> Enum.sort()
    }
  end

  defp initial_facts do
    %{modules: [], aliases: %{}, imports: [], uses: [], roles: []}
  end

  defp collect({:defmodule, _, [{:__aliases__, _, parts} | _]} = ast, facts) do
    {ast, %{facts | modules: [module_name(parts) | facts.modules]}}
  end

  defp collect({:alias, _, [{:__aliases__, _, parts}, options]} = ast, facts)
       when is_list(options) do
    short_name = alias_name(parts, Keyword.get(options, :as))
    aliases = Map.put(facts.aliases, short_name, module_name(parts))
    {ast, %{facts | aliases: aliases}}
  end

  defp collect({:alias, _, [{:__aliases__, _, parts}]} = ast, facts) do
    aliases = Map.put(facts.aliases, alias_short_name(parts), module_name(parts))
    {ast, %{facts | aliases: aliases}}
  end

  defp collect({:import, _, [{:__aliases__, _, parts} | _]} = ast, facts) do
    {ast, %{facts | imports: [module_name(parts) | facts.imports]}}
  end

  defp collect({:use, _, [{:__aliases__, _, parts} | arguments]} = ast, facts) do
    module = module_name(parts)
    roles = roles(module, arguments) ++ facts.roles
    {ast, %{facts | uses: [module | facts.uses], roles: roles}}
  end

  defp collect(ast, facts), do: {ast, facts}

  defp roles("Phoenix.Endpoint", _arguments), do: [:phoenix_endpoint]
  defp roles("Phoenix.Router", _arguments), do: [:phoenix_router]
  defp roles("Phoenix.LiveView", _arguments), do: [:phoenix_live_view]
  defp roles("Phoenix.Controller", _arguments), do: [:phoenix_controller]
  defp roles(_module, [:controller | _rest]), do: [:phoenix_controller]
  defp roles(_module, [:endpoint | _rest]), do: [:phoenix_endpoint]
  defp roles(_module, [:live_view | _rest]), do: [:phoenix_live_view]
  defp roles(_module, [:router | _rest]), do: [:phoenix_router]
  defp roles(_module, _arguments), do: []

  defp alias_name(_parts, {:__aliases__, _, as_parts}), do: module_name(as_parts)
  defp alias_name(parts, _as), do: alias_short_name(parts)
  defp alias_short_name(parts), do: parts |> List.last() |> then(&AST.alias_name([&1]))
  defp module_name(parts), do: AST.alias_name(parts)

  defp paths_with_role(source_facts, role) do
    source_facts
    |> Enum.filter(fn {_path, facts} -> role in facts.roles end)
    |> Enum.map(&elem(&1, 0))
    |> Enum.sort()
  end
end
