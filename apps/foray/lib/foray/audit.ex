defmodule Foray.Audit do
  @moduledoc "Synchronous audit hook invoked before a fuzzing job launches."

  @type event :: :job_launch
  @type hook :: module() | {module(), term()} | (event(), map() -> term())

  @callback handle_event(event(), metadata :: map(), state :: term()) :: :ok

  @doc false
  @spec emit(hook() | nil, event(), map()) :: :ok
  def emit(nil, _event, _metadata), do: :ok

  def emit(hook, event, metadata) when is_function(hook, 2) do
    validate_return(hook.(event, metadata))
  end

  def emit({module, state}, event, metadata) when is_atom(module) do
    validate_return(module.handle_event(event, metadata, state))
  end

  def emit(module, event, metadata) when is_atom(module) do
    validate_return(module.handle_event(event, metadata, nil))
  end

  defp validate_return(:ok), do: :ok
  defp validate_return(other), do: raise("audit hook returned #{inspect(other)}, expected :ok")
end
