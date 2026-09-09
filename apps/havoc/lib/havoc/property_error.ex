defmodule Havoc.PropertyError do
  @moduledoc "Raised after a security-property violation is shrunk, persisted, and normalized."

  defexception [:message, :property_id, :payload, findings: []]

  @impl true
  def exception(opts) do
    property_id = Keyword.fetch!(opts, :property_id)
    payload = Keyword.fetch!(opts, :payload)
    findings = Keyword.fetch!(opts, :findings)

    evidence = Enum.map_join(findings, "; ", & &1.evidence)

    %__MODULE__{
      message: "security property #{property_id} failed with #{inspect(payload)}: #{evidence}",
      property_id: property_id,
      payload: payload,
      findings: findings
    }
  end
end
