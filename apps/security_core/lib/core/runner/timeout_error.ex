defmodule Core.Runner.TimeoutError do
  @moduledoc "Raised when bounded process collection exceeds its deadline."

  defexception [:timeout, message: "external process timed out"]

  @impl true
  def exception(opts) do
    timeout = Keyword.fetch!(opts, :timeout)
    %__MODULE__{timeout: timeout, message: "external process timed out after #{timeout}ms"}
  end
end
