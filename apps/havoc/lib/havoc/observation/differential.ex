defmodule Havoc.Observation.Differential do
  @moduledoc "A paired control/treatment observation for independent relational oracles."

  @type t :: %__MODULE__{control: term(), treatment: term(), metadata: map()}

  @enforce_keys [:control, :treatment, :metadata]
  defstruct @enforce_keys

  @doc "Builds a paired observation without assigning security meaning to either side."
  @spec new!(control :: term(), treatment :: term(), metadata :: map()) :: t()
  def new!(control, treatment, metadata \\ %{}) when is_map(metadata) do
    %__MODULE__{control: control, treatment: treatment, metadata: metadata}
  end
end
