defmodule RampartSAST.DataFlow.Slice do
  @moduledoc """
  A bounded syntax-derived dependence slice.

  Edges mean only that source syntax may contribute a value to destination
  syntax under lexical assignment/call relationships. They do not prove
  attacker control, runtime reachability, branch feasibility, sanitization, or
  exploitability. `uncertainties` and `unresolved` are load-bearing evidence,
  not diagnostic decoration.
  """

  alias RampartSAST.Fact

  @type edge :: %{
          id: String.t(),
          from: String.t(),
          to: String.t(),
          relation: atom(),
          variable: String.t() | nil,
          basis: atom()
        }

  @type unresolved :: %{
          fact_id: String.t(),
          variable: String.t() | nil,
          reason: atom()
        }

  @type t :: %__MODULE__{
          inventory_id: String.t(),
          sink_fact_id: String.t(),
          facts: [Fact.t()],
          edges: [edge()],
          guards: [Fact.t()],
          unresolved: [unresolved()],
          uncertainties: [atom()],
          max_depth: non_neg_integer(),
          work_count: non_neg_integer(),
          truncated: boolean(),
          limit_reasons: [atom()]
        }

  @enforce_keys [
    :inventory_id,
    :sink_fact_id,
    :facts,
    :edges,
    :guards,
    :unresolved,
    :uncertainties,
    :max_depth,
    :work_count,
    :truncated,
    :limit_reasons
  ]
  defstruct @enforce_keys

  @doc "Projects a dependence slice into deterministic portable evidence."
  @spec to_map(t()) :: map()
  def to_map(%__MODULE__{} = slice) do
    %{
      inventory_id: slice.inventory_id,
      sink_fact_id: slice.sink_fact_id,
      facts: Enum.map(slice.facts, &Fact.to_map/1),
      edges: slice.edges,
      guards: Enum.map(slice.guards, &Fact.to_map/1),
      unresolved: slice.unresolved,
      uncertainties: slice.uncertainties,
      max_depth: slice.max_depth,
      work_count: slice.work_count,
      truncated: slice.truncated,
      limit_reasons: slice.limit_reasons
    }
  end
end
