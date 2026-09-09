defmodule Foray.OutputError do
  @moduledoc "Raised when ffuf output violates the pinned NDJSON contract."

  @type t :: %__MODULE__{line: String.t() | nil, reason: term(), message: String.t()}

  defexception [:line, :reason, message: "invalid ffuf NDJSON output"]

  @impl true
  def exception(opts) do
    line = Keyword.get(opts, :line)
    reason = Keyword.fetch!(opts, :reason)

    %__MODULE__{
      line: line,
      reason: reason,
      message: "invalid ffuf NDJSON output: #{inspect(reason)}"
    }
  end
end
