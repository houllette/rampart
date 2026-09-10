defmodule Portico.Engine.OutputError do
  @moduledoc "Raised when scanner output violates the pinned parser contract."

  defexception [:engine, :line, :reason, message: "scanner output is invalid"]

  @impl true
  def exception(opts) do
    engine = Keyword.fetch!(opts, :engine)
    line = preview(Keyword.get(opts, :line))
    reason = Keyword.fetch!(opts, :reason)

    %__MODULE__{
      engine: engine,
      line: line,
      reason: reason,
      message:
        "#{engine} output is invalid: #{inspect(reason, limit: 10, printable_limit: 256)} " <>
          "in #{inspect(line, limit: 10, printable_limit: 256)}"
    }
  end

  defp preview(nil), do: nil
  defp preview(line), do: :binary.copy(binary_part(line, 0, min(byte_size(line), 1_024)))
end
