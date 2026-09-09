defmodule Foray.PipelineError do
  @moduledoc "Raised when a Foray execution stage fails."

  defexception [:stage, :reason, message: "Foray pipeline failed"]

  @impl true
  def exception(opts) do
    stage = Keyword.fetch!(opts, :stage)
    reason = Keyword.fetch!(opts, :reason)

    %__MODULE__{
      stage: stage,
      reason: reason,
      message: "Foray #{stage} failed: #{inspect(reason)}"
    }
  end
end
