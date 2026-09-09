defmodule Core.Validation.Action do
  @moduledoc """
  Discoverable description of one deterministic validation capability.

  Action IDs are versioned strings because they are an interchange boundary,
  not Elixir implementation details. Changing an action's hypothesis semantics
  requires a new ID. Agent transports should expose actions through a
  host-owned `Core.Validation.Binding` and derive transcript-safe schemas and
  results with `Core.Validation.Wire`; executable authority never belongs in
  `meta`.
  """

  @type subject_type :: :finding | :seed | :hypothesis
  @type side_effects :: :none | :test_execution | :authorized_probe

  @type t :: %__MODULE__{
          id: String.t(),
          tool: atom(),
          name: atom(),
          description: String.t(),
          accepts: [subject_type()],
          side_effects: side_effects(),
          meta: map()
        }

  @enforce_keys [:id, :tool, :name, :description, :accepts, :side_effects]
  defstruct [:id, :tool, :name, :description, :accepts, :side_effects, meta: %{}]
end
