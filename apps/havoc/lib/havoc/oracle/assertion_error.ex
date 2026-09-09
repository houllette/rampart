defmodule Havoc.Oracle.AssertionError do
  @moduledoc false

  defexception [:message, :violations, :observation, :payload]

  @impl true
  def exception(opts) do
    violations = Keyword.fetch!(opts, :violations)

    message =
      violations
      |> Enum.map_join("; ", &"#{&1.oracle}: #{&1.evidence}")
      |> then(&"security oracle failed: #{&1}")

    %__MODULE__{
      message: message,
      violations: violations,
      observation: Keyword.get(opts, :observation),
      payload: Keyword.get(opts, :payload)
    }
  end
end
