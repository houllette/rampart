defmodule Portico.Sink do
  @moduledoc "Synchronous result sink used by the supervised Broadway topology."

  alias Portico.Host

  @type sink :: (Host.t() -> :ok) | module() | {module(), term()}

  @callback handle_result(Host.t(), state :: term()) :: :ok

  @doc false
  @spec deliver(sink(), Host.t()) :: :ok
  def deliver(sink, host) when is_function(sink, 1) do
    case sink.(host) do
      :ok -> :ok
      other -> raise "result sink returned #{inspect(other)}, expected :ok"
    end
  end

  def deliver({module, state}, host) do
    validate_return(module.handle_result(host, state))
  end

  def deliver(module, host) when is_atom(module) do
    validate_return(module.handle_result(host, nil))
  end

  defp validate_return(:ok), do: :ok
  defp validate_return(other), do: raise("result sink returned #{inspect(other)}, expected :ok")
end
