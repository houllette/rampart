defmodule Havoc.Oracle.Checked do
  @moduledoc "Marks an observation that has already passed an explicit oracle assertion."

  @type t :: %__MODULE__{observation: term()}

  @enforce_keys [:observation]
  defstruct [:observation]
end
