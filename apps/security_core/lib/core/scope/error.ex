defmodule Core.Scope.Error do
  @moduledoc "Raised when a tool attempts to operate outside its authorized scope."

  defexception [:target, message: "target is outside authorized scope"]

  @impl true
  def exception(opts) do
    target = Keyword.fetch!(opts, :target)
    %__MODULE__{target: target, message: "target is outside authorized scope: #{inspect(target)}"}
  end
end
