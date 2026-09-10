defmodule Foray.OutputError do
  @moduledoc "Raised when ffuf output violates the pinned NDJSON contract."

  @type t :: %__MODULE__{line: String.t() | nil, reason: term(), message: String.t()}

  defexception [:line, :reason, message: "invalid ffuf NDJSON output"]

  @impl true
  def exception(opts) do
    line = preview(Keyword.get(opts, :line))
    reason = Keyword.fetch!(opts, :reason)

    %__MODULE__{
      line: line,
      reason: reason,
      message: "invalid ffuf NDJSON output: #{inspect(reason, limit: 10, printable_limit: 256)}"
    }
  end

  defp preview(nil), do: nil
  defp preview(line), do: :binary.copy(binary_part(line, 0, min(byte_size(line), 1_024)))
end
