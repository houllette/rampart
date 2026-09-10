defmodule RampartEvaluation.Historical.AshFieldPolicy.Static do
  @moduledoc false

  def vulnerable(query, field) do
    options = []
    Ash.aggregate(query, {:max, field}, options)
  end

  def fixed(query, field) do
    options = [authorize_fields?: true]
    Ash.aggregate(query, {:max, field}, options)
  end
end
