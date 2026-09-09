defmodule Core.Runner.Error do
  @moduledoc "Raised when a process backend cannot start or read a command."

  defexception [:reason, message: "external process failed"]

  @impl true
  def exception(opts) do
    reason = Keyword.fetch!(opts, :reason)
    %__MODULE__{reason: reason, message: "external process failed: #{inspect(reason)}"}
  end
end
