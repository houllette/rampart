defmodule Portico.PipelineError do
  @moduledoc "Raised for pipeline-level failures that cannot be represented by one host result."

  defexception [:stage, :reason, message: "Portico pipeline failed"]

  @impl true
  def exception(opts) do
    stage = Keyword.fetch!(opts, :stage)
    reason = Keyword.fetch!(opts, :reason)

    %__MODULE__{
      stage: stage,
      reason: reason,
      message: "Portico #{stage} stage failed: #{Exception.format_exit(reason)}"
    }
  end
end
