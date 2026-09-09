defmodule RampartIAST.TraceBackend do
  @moduledoc false

  @callback session_create(name :: atom(), tracer :: pid(), options :: []) :: term()
  @callback function(
              session :: term(),
              mfa :: RampartIAST.Sink.sink_mfa(),
              match_spec :: term(),
              flags :: list()
            ) :: non_neg_integer()
  @callback process(session :: term(), tracee :: pid(), enabled :: boolean(), flags :: list()) ::
              non_neg_integer()
  @callback delivered(session :: term(), tracee :: pid()) :: reference()
  @callback session_destroy(session :: term()) :: boolean()
end

defmodule RampartIAST.TraceBackend.OTP do
  @moduledoc false
  @behaviour RampartIAST.TraceBackend

  @impl true
  def session_create(name, tracer, options), do: :trace.session_create(name, tracer, options)

  @impl true
  def function(session, mfa, match_spec, flags),
    do: :trace.function(session, mfa, match_spec, flags)

  @impl true
  def process(session, tracee, enabled, flags),
    do: :trace.process(session, tracee, enabled, flags)

  @impl true
  def delivered(session, tracee), do: :trace.delivered(session, tracee)

  @impl true
  def session_destroy(session), do: :trace.session_destroy(session)
end
