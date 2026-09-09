defmodule RampartIAST.TraceSession.Result do
  @moduledoc false

  @type execution :: :completed | :timeout | :callback_failed | :setup_failed | :owner_failed
  @type envelope :: :intact | :incomplete

  @type t :: %__MODULE__{
          session_id: String.t(),
          execution: execution(),
          envelope: envelope(),
          event_count: non_neg_integer(),
          observations: [RampartIAST.Observation.t()],
          limit_failures: [atom()],
          teardown: :ok | :failed,
          reason: term(),
          started_at: integer(),
          completed_at: integer()
        }

  @enforce_keys [
    :session_id,
    :execution,
    :envelope,
    :event_count,
    :observations,
    :limit_failures,
    :teardown,
    :started_at,
    :completed_at
  ]
  defstruct [
    :session_id,
    :execution,
    :envelope,
    :event_count,
    :observations,
    :limit_failures,
    :teardown,
    :reason,
    :started_at,
    :completed_at
  ]
end
