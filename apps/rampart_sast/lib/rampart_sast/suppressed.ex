defmodule RampartSAST.Suppressed do
  @moduledoc "A static observation retained with the explicit suppression that hid it from findings."

  alias RampartSAST.{Observation, Suppression}

  @type t :: %__MODULE__{
          observation: Observation.t(),
          suppression: Suppression.t()
        }

  @enforce_keys [:observation, :suppression]
  defstruct @enforce_keys

  @doc "Projects a suppressed observation into plain evidence data."
  @spec to_map(suppressed :: t()) :: map()
  def to_map(%__MODULE__{} = suppressed) do
    %{
      observation: Observation.to_map(suppressed.observation),
      suppression: Suppression.to_map(suppressed.suppression)
    }
  end
end
