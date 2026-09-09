defmodule Core.Validation.Evidence do
  @moduledoc """
  Structured proof or refutation returned by a validation action.

  `summary` is suitable for a person or finding description. `facts` contains
  stable machine-consumable observations, while `artifacts` names external or
  persisted proof objects without prescribing an artifact store. Prefer
  content-addressed references with an ID, SHA-256, byte size, media type,
  content schema, and scope; a locator is never authority. `raw` remains
  action-owned for lossless detail and is omitted by `Core.Validation.Wire`.
  """

  @type t :: %__MODULE__{
          summary: String.t(),
          facts: %{optional(atom()) => term()},
          artifacts: [map()],
          raw: term()
        }

  @enforce_keys [:summary]
  defstruct [:summary, :raw, facts: %{}, artifacts: []]
end
