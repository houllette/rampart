defmodule Havoc.Harness.Result do
  @moduledoc "A replayable observation sequence from one reviewed harness plan."

  @type observation :: %{
          step_id: String.t(),
          operation: String.t(),
          role: Havoc.Harness.Step.role(),
          value: term()
        }

  @type t :: %__MODULE__{
          plan_id: String.t(),
          plan_sha256: String.t(),
          payload_fingerprint: String.t(),
          observations: [observation()],
          completed_steps: non_neg_integer()
        }

  @enforce_keys [:plan_id, :plan_sha256, :payload_fingerprint, :observations, :completed_steps]
  defstruct @enforce_keys

  @doc "Returns observations having the selected semantic role."
  @spec observations(t(), Havoc.Harness.Step.role()) :: [observation()]
  def observations(%__MODULE__{} = result, role) do
    Enum.filter(result.observations, &(&1.role == role))
  end
end
