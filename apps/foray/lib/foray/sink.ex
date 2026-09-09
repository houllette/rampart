defmodule Foray.Sink do
  @moduledoc "Normalizes synchronous finding-sink callbacks."

  @type t :: (Core.Finding.t() -> :ok | :stop)

  @spec deliver(t(), Core.Finding.t()) :: :ok | :stop
  def deliver(sink, %Core.Finding{} = finding) when is_function(sink, 1) do
    case sink.(finding) do
      result when result in [:ok, :stop] -> result
      other -> raise "finding sink returned #{inspect(other)}, expected :ok or :stop"
    end
  end
end
