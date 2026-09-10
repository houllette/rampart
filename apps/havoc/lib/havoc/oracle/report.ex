defmodule Havoc.Oracle.Report do
  @moduledoc "A complete oracle evaluation retaining passes, skips, and violations."

  @type t :: %__MODULE__{
          passed: [atom()],
          skipped: [atom()],
          violations: [Havoc.Oracle.Violation.t()]
        }

  @enforce_keys [:passed, :skipped, :violations]
  defstruct @enforce_keys
end
