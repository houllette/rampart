defmodule Core.Validation.Result do
  @moduledoc """
  Deterministic verdict and replay material produced by a validation action.

  A confirmed result carries at least one normalized finding. Refuted and
  inconclusive results carry no findings. Every result includes a concrete
  `Core.Seed` so the exact validation input can be replayed independently of a
  generator's future behavior.
  """

  alias Core.Validation.{Action, Evidence}

  @type verdict :: :confirmed | :refuted | :inconclusive

  @type t :: %__MODULE__{
          id: String.t(),
          request_id: String.t(),
          action: Action.t(),
          tool: atom(),
          verdict: verdict(),
          evidence: Evidence.t(),
          findings: [Core.Finding.t()],
          seed: Core.Seed.t(),
          observed_at: DateTime.t(),
          meta: map()
        }

  @enforce_keys [
    :id,
    :request_id,
    :action,
    :tool,
    :verdict,
    :evidence,
    :seed,
    :observed_at
  ]
  defstruct [
    :id,
    :request_id,
    :action,
    :tool,
    :verdict,
    :evidence,
    :seed,
    :observed_at,
    findings: [],
    meta: %{}
  ]
end
