defmodule RampartSAST.Graph.Slice do
  @moduledoc "A bounded deterministic graph slice over static inventory facts."

  alias RampartSAST.Fact

  @type t :: %__MODULE__{
          inventory_id: String.t(),
          roots: [String.t()],
          nodes: [String.t()],
          edges: [Fact.t()],
          max_depth: non_neg_integer(),
          truncated: boolean()
        }

  @enforce_keys [:inventory_id, :roots, :nodes, :edges, :max_depth, :truncated]
  defstruct @enforce_keys

  @doc "Projects a bounded graph slice into plain agent-facing data."
  @spec to_map(t()) :: map()
  def to_map(%__MODULE__{} = slice) do
    %{
      inventory_id: slice.inventory_id,
      roots: slice.roots,
      nodes: slice.nodes,
      edges: Enum.map(slice.edges, &Fact.to_map/1),
      max_depth: slice.max_depth,
      truncated: slice.truncated
    }
  end
end
