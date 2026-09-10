defmodule Havoc.Oracle.Checked do
  @moduledoc "Marks an observation that has already passed an explicit oracle assertion."

  @type t :: %__MODULE__{observation: term(), report: Havoc.Oracle.Report.t() | nil}

  @enforce_keys [:observation]
  defstruct [:observation, :report]
end
