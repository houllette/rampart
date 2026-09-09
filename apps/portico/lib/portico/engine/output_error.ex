defmodule Portico.Engine.OutputError do
  @moduledoc "Raised when scanner output violates the pinned parser contract."

  defexception [:engine, :line, :reason, message: "scanner output is invalid"]

  @impl true
  def exception(opts) do
    engine = Keyword.fetch!(opts, :engine)
    line = Keyword.get(opts, :line)
    reason = Keyword.fetch!(opts, :reason)

    %__MODULE__{
      engine: engine,
      line: line,
      reason: reason,
      message: "#{engine} output is invalid: #{inspect(reason)} in #{inspect(line)}"
    }
  end
end
