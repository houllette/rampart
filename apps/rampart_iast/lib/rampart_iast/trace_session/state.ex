defmodule RampartIAST.TraceSession.State do
  @moduledoc false

  @enforce_keys [
    :caller,
    :run_ref,
    :session_id,
    :source,
    :sink,
    :marker,
    :execute,
    :limits,
    :backend,
    :started_at
  ]
  defstruct [
    :caller,
    :caller_monitor,
    :run_ref,
    :session_id,
    :source,
    :sink,
    :marker,
    :execute,
    :limits,
    :backend,
    :started_at,
    :session,
    :target,
    :target_monitor,
    :tracer,
    :tracer_monitor
  ]
end
