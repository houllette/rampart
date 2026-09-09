defmodule RampartSAST.Inventory.Page do
  @moduledoc "A bounded page of inventory facts suitable for an agent tool response."

  alias RampartSAST.Fact

  @type t :: %__MODULE__{
          inventory_id: String.t(),
          facts: [Fact.t()],
          offset: non_neg_integer(),
          limit: pos_integer(),
          returned: non_neg_integer(),
          total: non_neg_integer(),
          next_offset: non_neg_integer() | nil
        }

  @enforce_keys [:inventory_id, :facts, :offset, :limit, :returned, :total, :next_offset]
  defstruct @enforce_keys

  @doc "Projects a fact page into plain transcript-safe data."
  @spec to_map(t()) :: map()
  def to_map(%__MODULE__{} = page) do
    %{
      inventory_id: page.inventory_id,
      facts: Enum.map(page.facts, &Fact.to_map/1),
      offset: page.offset,
      limit: page.limit,
      returned: page.returned,
      total: page.total,
      next_offset: page.next_offset
    }
  end
end
