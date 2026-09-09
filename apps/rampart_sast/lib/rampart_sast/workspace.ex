defmodule RampartSAST.Workspace do
  @moduledoc "Cross-package source assembly with explicit component identity and checksums."

  alias RampartSAST.Component

  @doc "Scans target and dependency components as one provenance-preserving workspace."
  @spec scan([Component.t()], [RampartSAST.Rule.specification()], keyword()) ::
          RampartSAST.Result.t()
  def scan(components, rules, options \\ [])
      when is_list(components) and is_list(rules) and is_list(options) do
    components = validate_components!(components)
    {entries, origins} = flatten(components)

    if Keyword.has_key?(options, :source_origins) do
      raise ArgumentError, "workspace source origins are derived from components"
    end

    RampartSAST.scan_sources(entries, rules, Keyword.put(options, :source_origins, origins))
  end

  @doc "Builds only the broad inventory for target and dependency components."
  @spec inventory([Component.t()], keyword()) :: RampartSAST.Result.t()
  def inventory(components, options \\ []) do
    scan(components, [], options)
  end

  defp validate_components!(components) when components != [] do
    unless Enum.all?(components, &match?(%Component{}, &1)),
      do: raise(ArgumentError, "SAST workspaces accept Component structs")

    ids = Enum.map(components, & &1.id)

    unless length(Enum.uniq(ids)) == length(ids),
      do: raise(ArgumentError, "SAST workspace component IDs must be unique")

    Enum.sort_by(components, & &1.id)
  end

  defp validate_components!(_components) do
    raise ArgumentError, "SAST workspaces require at least one component"
  end

  defp flatten(components) do
    Enum.reduce(components, {[], %{}}, fn component, {entries, origins} ->
      Enum.reduce(component.sources, {entries, origins}, fn {path, content}, {entries, origins} ->
        workspace_path = Path.join(["components", component.id, path])

        origin = %{
          component_id: component.id,
          kind: component.kind,
          path: path,
          package: component.package,
          version: component.version,
          checksum: component.checksum
        }

        {[{workspace_path, content} | entries], Map.put(origins, workspace_path, origin)}
      end)
    end)
    |> then(fn {entries, origins} -> {Enum.sort_by(entries, &elem(&1, 0)), origins} end)
  end
end
