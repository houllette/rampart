defmodule Havoc.Harness.Error do
  @moduledoc "A host-fixture failure that must remain inconclusive without a separate crash oracle."
  defexception [:stage, :reason, :step_id]

  @impl true
  def message(%__MODULE__{stage: stage, reason: reason, step_id: step_id}) do
    location = if step_id, do: " at step #{step_id}", else: ""

    "Havoc harness #{stage} failed#{location}: #{inspect(reason, limit: 20, printable_limit: 2_000)}"
  end
end
