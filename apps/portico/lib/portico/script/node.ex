defmodule Portico.Script.Node do
  @moduledoc "A typed node in nested NSE script output."

  @type node_type :: :table | :element

  @type t :: %__MODULE__{
          type: node_type(),
          key: String.t() | nil,
          value: String.t() | nil,
          children: [t()]
        }

  @enforce_keys [:type]
  defstruct [:type, :key, :value, children: []]
end
