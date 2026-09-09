defmodule RampartSAST.Result do
  @moduledoc "A deterministic inventory and rule-signal result with explicit completeness."

  alias RampartSAST.{Diagnostic, Inventory, Observation, Suppressed}

  @type status :: :complete | :incomplete

  @type t :: %__MODULE__{
          status: status(),
          observations: [Observation.t()],
          findings: [Core.Finding.t()],
          inventory: Inventory.t(),
          suppressed: [Suppressed.t()],
          diagnostics: [Diagnostic.t()],
          metrics: map()
        }

  @enforce_keys [
    :status,
    :observations,
    :findings,
    :inventory,
    :suppressed,
    :diagnostics,
    :metrics
  ]
  defstruct @enforce_keys

  @doc "Returns all observations, including explicitly suppressed matches."
  @spec all_observations(result :: t()) :: [Observation.t()]
  def all_observations(%__MODULE__{} = result) do
    suppressed = Enum.map(result.suppressed, & &1.observation)
    Enum.sort_by(result.observations ++ suppressed, & &1.id)
  end

  @doc "Projects bounded scan metadata without source snapshots or native AST."
  @spec to_map(result :: t()) :: map()
  def to_map(%__MODULE__{} = result) do
    %{
      status: result.status,
      observations: Enum.map(result.observations, &Observation.to_map/1),
      inventory: Inventory.summary(result.inventory),
      suppressed: Enum.map(result.suppressed, &Suppressed.to_map/1),
      diagnostics: Enum.map(result.diagnostics, &Diagnostic.to_map/1),
      metrics: result.metrics
    }
  end
end
