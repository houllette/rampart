defmodule Core.Seed do
  @moduledoc "A corpus, payload, target, or counterexample exchanged between suite tools."

  @type provenance :: :wordlist | :generated | :counterexample | :promoted_finding | atom()
  @type origin :: {source_tool :: atom(), finding_id :: String.t()} | nil

  @type t :: %__MODULE__{
          id: String.t() | nil,
          value: term(),
          classes: [atom()],
          provenance: provenance() | nil,
          origin: origin(),
          meta: map()
        }

  defstruct [:id, :value, classes: [], provenance: nil, origin: nil, meta: %{}]
end
