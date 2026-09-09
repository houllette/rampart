defmodule Havoc.Corpus.Error do
  @moduledoc "Raised when a persistent Havoc corpus is malformed, unsafe, or inaccessible."

  defexception [:message, :reason, :path]

  @impl true
  def exception(opts) do
    reason = Keyword.fetch!(opts, :reason)
    path = Keyword.get(opts, :path)
    location = if path, do: " at #{path}", else: ""

    %__MODULE__{
      message: "invalid Havoc corpus#{location}: #{format_reason(reason)}",
      reason: reason,
      path: path
    }
  end

  defp format_reason(:term_integrity_mismatch), do: "term integrity check failed"
  defp format_reason(reason), do: inspect(reason)
end
