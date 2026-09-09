defmodule RampartIAST.Observation do
  @moduledoc "A bounded exact-marker observation emitted by one sink call."

  @type t :: %__MODULE__{
          session_id: String.t(),
          tracee: pid(),
          timestamp: integer(),
          source_id: String.t(),
          sink_id: String.t(),
          mfa: RampartIAST.Sink.sink_mfa(),
          argument_positions: [pos_integer()],
          matched_positions: [pos_integer()],
          argument_bytes: %{pos_integer() => non_neg_integer()}
        }

  @enforce_keys [
    :session_id,
    :tracee,
    :timestamp,
    :source_id,
    :sink_id,
    :mfa,
    :argument_positions,
    :matched_positions,
    :argument_bytes
  ]
  defstruct @enforce_keys
end
